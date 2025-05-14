// Copyright 2025 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ProcessSecurityManager.h"

#include <coolbpf/security/type.h>

#include <memory>
#include <mutex>
#include <utility>

#include "collection_pipeline/CollectionPipelineContext.h"
#include "collection_pipeline/queue/ProcessQueueItem.h"
#include "collection_pipeline/queue/ProcessQueueManager.h"
#include "common/HashUtil.h"
#include "common/TimeUtil.h"
#include "common/magic_enum.hpp"
#include "common/queue/blockingconcurrentqueue.h"
#include "common/timer/Timer.h"
#include "ebpf/Config.h"
#include "ebpf/EBPFServer.h"
#include "ebpf/plugin/AbstractManager.h"
#include "ebpf/plugin/ProcessCacheManager.h"
#include "ebpf/type/AggregateEvent.h"
#include "ebpf/type/table/BaseElements.h"

namespace logtail::ebpf {
ProcessSecurityManager::ProcessSecurityManager(const std::shared_ptr<ProcessCacheManager>& processCacheManager,
                                               const std::shared_ptr<EBPFAdapter>& eBPFAdapter,
                                               moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>>& queue,
                                               const PluginMetricManagerPtr& metricManager)
    : AbstractManager(processCacheManager, eBPFAdapter, queue, metricManager),
      mAggregateTree(
          4096,
          [](std::unique_ptr<ProcessEventGroup>& base, const std::shared_ptr<CommonEvent>& other) {
              base->mInnerEvents.emplace_back(other);
          },
          [](const std::shared_ptr<CommonEvent>& in, [[maybe_unused]] std::shared_ptr<SourceBuffer>& sourceBuffer) {
              return std::make_unique<ProcessEventGroup>(in->mPid, in->mKtime);
          }) {
}

int ProcessSecurityManager::Init(
    [[maybe_unused]] const std::variant<SecurityOptions*, ObserverNetworkOption*>& options) {
    // just set timer ...
    // register base manager ...
    mFlag = true;
    mSuspendFlag = false;

    auto processCacheMgr = GetProcessCacheManager();
    if (processCacheMgr == nullptr) {
        LOG_WARNING(sLogger, ("ProcessCacheManager is null", ""));
        return 1;
    }

    processCacheMgr->MarkProcessEventFlushStatus(true);

    std::shared_ptr<ScheduleConfig> scheduleConfig
        = std::make_shared<ScheduleConfig>(PluginType::PROCESS_SECURITY, std::chrono::seconds(2));
    ScheduleNext(std::chrono::steady_clock::now(), scheduleConfig);

    return 0;
}

int ProcessSecurityManager::Destroy() {
    mFlag = false;
    auto processCacheMgr = GetProcessCacheManager();
    if (processCacheMgr == nullptr) {
        LOG_WARNING(sLogger, ("ProcessCacheManager is null", ""));
        return 1;
    }
    processCacheMgr->MarkProcessEventFlushStatus(false);
    return 0;
}

std::array<size_t, 1> GenerateAggKeyForProcessEvent(const std::shared_ptr<CommonEvent>& event) {
    // calculate agg key
    std::array<size_t, 1> hashResult{};
    std::hash<uint64_t> hasher;

    std::array<uint64_t, 2> arr = {uint64_t(event->mPid), event->mKtime};
    for (uint64_t x : arr) {
        AttrHashCombine(hashResult[0], hasher(x));
    }
    return hashResult;
}

int ProcessSecurityManager::HandleEvent(const std::shared_ptr<CommonEvent>& event) {
    if (!event) {
        return 1;
    }
    auto* processEvent = static_cast<ProcessEvent*>(event.get());
    LOG_DEBUG(sLogger,
              ("receive event, pid", event->mPid)("ktime", event->mKtime)("eventType",
                                                                          magic_enum::enum_name(event->mEventType)));
    if (processEvent == nullptr) {
        LOG_ERROR(sLogger,
                  ("failed to convert CommonEvent to ProcessEvent, kernel event type",
                   magic_enum::enum_name(event->GetKernelEventType()))("PluginType",
                                                                       magic_enum::enum_name(event->GetPluginType())));
        return 1;
    }

    // calculate agg key
    std::array<size_t, 1> hashResult = GenerateAggKeyForProcessEvent(event);
    {
        WriteLock lk(mLock);
        bool ret = mAggregateTree.Aggregate(event, hashResult);
        LOG_DEBUG(sLogger, ("after aggregate", ret));
    }

    return 0;
}

StringBuffer ToStringBuffer(std::shared_ptr<SourceBuffer> sourceBuffer, int32_t val) {
    auto buf = sourceBuffer->AllocateStringBuffer(kMaxInt32Width);
    auto end = fmt::format_to_n(buf.data, buf.capacity, "{}", val);
    *end.out = '\0';
    buf.size = end.size;
    return buf;
}

bool ProcessSecurityManager::ScheduleNext(const std::chrono::steady_clock::time_point& execTime,
                                          const std::shared_ptr<ScheduleConfig>& config) {
    std::chrono::steady_clock::time_point nextTime = execTime + config->mInterval;
    Timer::GetInstance()->PushEvent(std::make_unique<AggregateEvent>(nextTime, config));
    return ConsumeAggregateTree(execTime);
}

bool ProcessSecurityManager::ConsumeAggregateTree(
    [[maybe_unused]] const std::chrono::steady_clock::time_point& execTime) {
    if (!mFlag || mSuspendFlag) {
        return false;
    }

    WriteLock lk(mLock);
    SIZETAggTree<ProcessEventGroup, std::shared_ptr<CommonEvent>> aggTree = this->mAggregateTree.GetAndReset();
    lk.unlock();

    // read aggregator
    auto nodes = aggTree.GetNodesWithAggDepth(1);
    LOG_DEBUG(sLogger, ("enter aggregator ...", nodes.size()));
    if (nodes.empty()) {
        LOG_DEBUG(sLogger, ("empty nodes...", ""));
        return true;
    }

    auto sourceBuffer = std::make_shared<SourceBuffer>();
    PipelineEventGroup sharedEventGroup(sourceBuffer);
    PipelineEventGroup eventGroup(sourceBuffer);
    for (auto& node : nodes) {
        LOG_DEBUG(sLogger, ("child num", node->mChild.size()));
        // convert to a item and push to process queue
        aggTree.ForEach(node, [&](const ProcessEventGroup* group) {
            auto sharedEvent = sharedEventGroup.CreateLogEvent();
            // represent a process ...
            auto processCacheMgr = GetProcessCacheManager();
            if (processCacheMgr == nullptr) {
                LOG_WARNING(sLogger, ("ProcessCacheManager is null", ""));
                return;
            }
            auto hit = processCacheMgr->FinalizeProcessTags(group->mPid, group->mKtime, *sharedEvent);
            if (!hit) {
                LOG_WARNING(sLogger, ("cannot find tags for pid", group->mPid)("ktime", group->mKtime));
                return;
            }
            for (const auto& innerEvent : group->mInnerEvents) {
                auto* logEvent = eventGroup.AddLogEvent();
                for (const auto& it : *sharedEvent) {
                    logEvent->SetContentNoCopy(it.first, it.second);
                }
                struct timespec ts = ConvertKernelTimeToUnixTime(innerEvent->mTimestamp);
                logEvent->SetTimestamp(ts.tv_sec, ts.tv_nsec);
                switch (innerEvent->mEventType) {
                    case KernelEventType::PROCESS_EXECVE_EVENT: {
                        logEvent->SetContentNoCopy(kCallName.LogKey(), ProcessSecurityManager::kExecveValue);
                        // ? kprobe or execve
                        logEvent->SetContentNoCopy(kEventType.LogKey(), ProcessSecurityManager::kKprobeValue);
                        break;
                    }
                    case KernelEventType::PROCESS_EXIT_EVENT: {
                        CommonEvent* ce = innerEvent.get();
                        auto* exitEvent = static_cast<ProcessExitEvent*>(ce);
                        logEvent->SetContentNoCopy(kCallName.LogKey(), StringView(ProcessSecurityManager::kExitValue));
                        logEvent->SetContentNoCopy(kEventType.LogKey(), StringView(AbstractManager::kKprobeValue));
                        auto exitCode = ToStringBuffer(eventGroup.GetSourceBuffer(), exitEvent->mExitCode);
                        auto exitTid = ToStringBuffer(eventGroup.GetSourceBuffer(), exitEvent->mExitTid);
                        logEvent->SetContentNoCopy(ProcessSecurityManager::kExitCodeKey,
                                                   StringView(exitCode.data, exitCode.size));
                        logEvent->SetContentNoCopy(ProcessSecurityManager::kExitTidKey,
                                                   StringView(exitTid.data, exitTid.size));
                        break;
                    }
                    case KernelEventType::PROCESS_CLONE_EVENT: {
                        logEvent->SetContentNoCopy(kCallName.LogKey(), ProcessSecurityManager::kCloneValue);
                        logEvent->SetContentNoCopy(kEventType.LogKey(), ProcessSecurityManager::kKprobeValue);
                        break;
                    }
                    default:
                        break;
                }
            }
        });
    }
    {
        std::lock_guard lk(mContextMutex);
        if (this->mPipelineCtx == nullptr) {
            return true;
        }
        LOG_DEBUG(sLogger, ("event group size", eventGroup.GetEvents().size()));
        ADD_COUNTER(mPushLogsTotal, eventGroup.GetEvents().size());
        ADD_COUNTER(mPushLogGroupTotal, 1);
        std::unique_ptr<ProcessQueueItem> item
            = std::make_unique<ProcessQueueItem>(std::move(eventGroup), this->mPluginIndex);
        if (QueueStatus::OK != ProcessQueueManager::GetInstance()->PushQueue(mQueueKey, std::move(item))) {
            LOG_WARNING(sLogger,
                        ("configName", mPipelineCtx->GetConfigName())("pluginIdx", this->mPluginIndex)(
                            "[ProcessSecurityEvent] push queue failed!", ""));
        }
    }

    return true;
}
} // namespace logtail::ebpf
