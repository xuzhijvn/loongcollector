/*
 * Copyright 2024 iLogtail Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "prometheus/schedulers/TargetSubscriberScheduler.h"

#include <cstdlib>

#include <chrono>
#include <memory>
#include <string>

#include "AppConfig.h"
#include "SelfMonitorMetricEvent.h"
#include "common/JsonUtil.h"
#include "common/StringTools.h"
#include "common/TimeUtil.h"
#include "common/http/Constant.h"
#include "common/timer/HttpRequestTimerEvent.h"
#include "logger/Logger.h"
#include "monitor/Monitor.h"
#include "monitor/metric_constants/MetricConstants.h"
#include "prometheus/Constants.h"
#include "prometheus/Utils.h"
#include "prometheus/async/PromFuture.h"
#include "prometheus/async/PromHttpRequest.h"
#include "prometheus/schedulers/ScrapeScheduler.h"

using namespace std;

namespace logtail {

std::chrono::steady_clock::time_point TargetSubscriberScheduler::mLastUpdateTime = std::chrono::steady_clock::now();
uint64_t TargetSubscriberScheduler::sDelaySeconds = 0;
TargetSubscriberScheduler::TargetSubscriberScheduler()
    : mQueueKey(0), mInputIndex(0), mServicePort(0), mUnRegisterMs(0) {
}

bool TargetSubscriberScheduler::Init(const Json::Value& scrapeConfig) {
    mScrapeConfigPtr = std::make_shared<ScrapeConfig>();
    if (!mScrapeConfigPtr->Init(scrapeConfig)) {
        return false;
    }
    mJobName = mScrapeConfigPtr->mJobName;
    mInterval = prometheus::RefeshIntervalSeconds;

    return true;
}

bool TargetSubscriberScheduler::operator<(const TargetSubscriberScheduler& other) const {
    return mJobName < other.mJobName;
}

void TargetSubscriberScheduler::OnSubscription(HttpResponse& response, uint64_t timestampMilliSec) {
    mSelfMonitor->AddCounter(METRIC_PLUGIN_PROM_SUBSCRIBE_TOTAL, response.GetStatusCode());
    mSelfMonitor->AddCounter(METRIC_PLUGIN_PROM_SUBSCRIBE_TIME_MS,
                             response.GetStatusCode(),
                             GetCurrentTimeInMilliSeconds() - timestampMilliSec);
    if (response.GetStatusCode() == 304) {
        // not modified
        return;
    }
    if (response.GetStatusCode() != 200) {
        return;
    }
    if (response.GetHeader().count(prometheus::ETAG)) {
        mETag = response.GetHeader().at(prometheus::ETAG);
    }
    const string& content = *response.GetBody<string>();
    vector<PromTargetInfo> targetGroup;
    if (!ParseScrapeSchedulerGroup(content, targetGroup)) {
        return;
    }
    std::unordered_map<std::string, std::shared_ptr<ScrapeScheduler>> newScrapeSchedulerSet
        = BuildScrapeSchedulerSet(targetGroup);
    UpdateScrapeScheduler(newScrapeSchedulerSet);
    SET_GAUGE(mPromSubscriberTargets, mScrapeSchedulerMap.size());
    ADD_COUNTER(mTotalDelayMs, GetCurrentTimeInMilliSeconds() - timestampMilliSec);
}

void TargetSubscriberScheduler::UpdateScrapeScheduler(
    std::unordered_map<std::string, std::shared_ptr<ScrapeScheduler>>& newScrapeSchedulerMap) {
    {
        WriteLock lock(mRWLock);
        vector<string> toRemove;

        // remove obsolete scrape work
        for (const auto& [k, v] : mScrapeSchedulerMap) {
            if (newScrapeSchedulerMap.find(k) == newScrapeSchedulerMap.end()) {
                toRemove.push_back(k);
            }
        }

        for (auto& k : toRemove) {
            mScrapeSchedulerMap[k]->Cancel();
            mScrapeSchedulerMap.erase(k);
        }

        // save new scrape work
        auto added = 0;
        auto total = 0;
        for (const auto& [k, v] : newScrapeSchedulerMap) {
            if (mScrapeSchedulerMap.find(k) == mScrapeSchedulerMap.end()) {
                added++;
                mScrapeSchedulerMap[k] = v;
                auto tmpCurrentMilliSeconds = GetCurrentTimeInMilliSeconds();
                auto tmpRandSleepMilliSec
                    = GetRandSleepMilliSec(v->GetId(), v->GetScrapeIntervalSeconds(), tmpCurrentMilliSeconds);

                // zero-cost upgrade
                if ((mUnRegisterMs > 0
                     && (tmpCurrentMilliSeconds + tmpRandSleepMilliSec - v->GetScrapeIntervalSeconds() * 1000
                         > mUnRegisterMs)
                     && (tmpCurrentMilliSeconds + tmpRandSleepMilliSec - v->GetScrapeIntervalSeconds() * 1000 * 2
                         < mUnRegisterMs))
                    || (v->GetReBalanceMs() > 0
                        && (tmpCurrentMilliSeconds + tmpRandSleepMilliSec - v->GetScrapeIntervalSeconds() * 1000
                            > v->GetReBalanceMs())
                        && (tmpCurrentMilliSeconds + tmpRandSleepMilliSec - v->GetScrapeIntervalSeconds() * 1000 * 2
                            < v->GetReBalanceMs()))) {
                    // scrape once just now
                    LOG_INFO(sLogger, ("scrape zero cost", ToString(tmpCurrentMilliSeconds)));
                    v->SetScrapeOnceTime(chrono::steady_clock::now(), chrono::system_clock::now());
                }
                v->ScheduleNext();
            }
        }
        total = mScrapeSchedulerMap.size();
        LOG_INFO(sLogger, ("prom job", mJobName)("targets removed", toRemove.size())("added", added)("total", total));
    }
}

bool TargetSubscriberScheduler::ParseScrapeSchedulerGroup(const std::string& content,
                                                          std::vector<PromTargetInfo>& scrapeSchedulerGroup) {
    string errs;
    Json::Value root;
    if (!ParseJsonTable(content, root, errs) || !root.isArray()) {
        LOG_ERROR(sLogger,
                  ("http service discovery from operator failed", "Failed to parse JSON: " + errs)("job", mJobName));
        return false;
    }
    for (const auto& element : root) {
        if (!element.isObject()) {
            LOG_ERROR(
                sLogger,
                ("http service discovery from operator failed", "Invalid target group item found")("job", mJobName));
            return false;
        }

        // Parse targets
        vector<string> targets;
        if (element.isMember(prometheus::TARGETS) && element[prometheus::TARGETS].isArray()) {
            for (const auto& target : element[prometheus::TARGETS]) {
                if (target.isString()) {
                    targets.push_back(target.asString());
                } else {
                    LOG_ERROR(
                        sLogger,
                        ("http service discovery from operator failed", "Invalid target item found")("job", mJobName));
                    return false;
                }
            }
        }
        if (targets.empty()) {
            continue;
        }
        PromTargetInfo targetInfo;
        // Parse labels https://www.robustperception.io/life-of-a-label/
        Labels labels;
        if (element.isMember(prometheus::LABELS) && element[prometheus::LABELS].isObject()) {
            for (const string& labelKey : element[prometheus::LABELS].getMemberNames()) {
                labels.Set(labelKey, element[prometheus::LABELS][labelKey].asString());
            }
        }
        std::ostringstream rawHashStream;
        rawHashStream << std::setw(16) << std::setfill('0') << std::hex << labels.Hash();
        string rawAddress = labels.Get(prometheus::ADDRESS_LABEL_NAME);
        targetInfo.mHash = mScrapeConfigPtr->mJobName + rawAddress + rawHashStream.str();
        targetInfo.mInstance = targets[0];

        for (const auto& pair : mScrapeConfigPtr->mParams) {
            if (!pair.second.empty()) {
                labels.Set(prometheus::PARAM_LABEL_NAME + pair.first, pair.second[0]);
            }
        }

        if (element.isMember(prometheus::LABELS) && element[prometheus::LABELS].isObject()) {
            for (const string& labelKey : element[prometheus::LABELS].getMemberNames()) {
                labels.Set(labelKey, element[prometheus::LABELS][labelKey].asString());
            }
        }
        if (labels.Get(prometheus::JOB).empty()) {
            labels.Set(prometheus::JOB, mJobName);
        }
        if (labels.Get(prometheus::SCHEME_LABEL_NAME).empty()) {
            labels.Set(prometheus::SCHEME_LABEL_NAME, mScrapeConfigPtr->mScheme);
        }
        if (labels.Get(prometheus::METRICS_PATH_LABEL_NAME).empty()) {
            labels.Set(prometheus::METRICS_PATH_LABEL_NAME, mScrapeConfigPtr->mMetricsPath);
        }
        if (labels.Get(prometheus::ADDRESS_LABEL_NAME).empty()) {
            continue;
        }

        targetInfo.mLabels = labels;
        scrapeSchedulerGroup.push_back(targetInfo);
    }
    return true;
}

std::unordered_map<std::string, std::shared_ptr<ScrapeScheduler>>
TargetSubscriberScheduler::BuildScrapeSchedulerSet(std::vector<PromTargetInfo>& targetGroups) {
    std::unordered_map<std::string, std::shared_ptr<ScrapeScheduler>> scrapeSchedulerMap;
    for (auto& targetInfo : targetGroups) {
        // Relabel Config
        auto& resultLabel = targetInfo.mLabels;
        if (!mScrapeConfigPtr->mRelabelConfigs.Process(resultLabel)) {
            continue;
        }
        resultLabel.RemoveMetaLabels();
        if (resultLabel.Size() == 0) {
            continue;
        }

        string address = resultLabel.Get(prometheus::ADDRESS_LABEL_NAME);
        if (resultLabel.Get(prometheus::INSTANCE).empty()) {
            resultLabel.Set(prometheus::INSTANCE, address);
        }

        auto m = address.find(':');
        int32_t port = 0;
        if (m == string::npos) {
            // if no port, use default port
            if (resultLabel.Get(prometheus::SCHEME_LABEL_NAME) == prometheus::HTTP) {
                port = 80;
            } else if (resultLabel.Get(prometheus::SCHEME_LABEL_NAME) == prometheus::HTTPS) {
                port = 443;
            } else {
                continue;
            }
        } else {
            // parse port
            try {
                port = stoi(address.substr(m + 1));
            } catch (...) {
                continue;
            }
        }

        string host = address.substr(0, m);
        string scheme = resultLabel.Get(prometheus::SCHEME_LABEL_NAME);
        if (scheme.empty()) {
            scheme = mScrapeConfigPtr->mScheme;
        }


        auto buildFullMetricsPath = [](Labels& labels, const string& rawMetricsPath) {
            string metricsPath = labels.Get(prometheus::METRICS_PATH_LABEL_NAME);
            if (metricsPath.empty()) {
                metricsPath = rawMetricsPath;
            }
            if (metricsPath[0] != '/') {
                metricsPath = "/" + metricsPath;
            }
            map<string, string> params;
            labels.Range([&params](const string& key, const string& value) {
                if (StartWith(key, prometheus::PARAM_LABEL_NAME)) {
                    params[key.substr(strlen(prometheus::PARAM_LABEL_NAME))] = value;
                }
            });
            string paramsStr;
            for (const auto& pair : params) {
                if (!paramsStr.empty()) {
                    paramsStr += "&";
                }
                paramsStr += pair.first + "=" + pair.second;
            }
            string optionalQuestion;
            if (!paramsStr.empty()) {
                optionalQuestion = "?";
                if (metricsPath.find('?') != string::npos) {
                    optionalQuestion = "&";
                }
            }
            return metricsPath + optionalQuestion + paramsStr;
        };
        auto metricsPath = buildFullMetricsPath(resultLabel, mScrapeConfigPtr->mMetricsPath);

        auto scrapeIntervalSeconds = DurationToSecond(resultLabel.Get(prometheus::SCRAPE_INTERVAL_LABEL_NAME));
        if (scrapeIntervalSeconds == 0) {
            scrapeIntervalSeconds = mScrapeConfigPtr->mScrapeIntervalSeconds;
        }
        auto scrapeTimeoutSeconds = DurationToSecond(resultLabel.Get(prometheus::SCRAPE_TIMEOUT_LABEL_NAME));
        if (scrapeTimeoutSeconds == 0) {
            scrapeTimeoutSeconds = mScrapeConfigPtr->mScrapeTimeoutSeconds;
        }
        if (scrapeIntervalSeconds == 0 || scrapeTimeoutSeconds == 0) {
            LOG_ERROR(sLogger,
                      ("job", mJobName)("scrapeIntervalSeconds:", scrapeIntervalSeconds)("scrapeTimeoutSeconds:",
                                                                                         scrapeTimeoutSeconds));
            continue;
        }

        auto scrapeScheduler = std::make_shared<ScrapeScheduler>(mScrapeConfigPtr,
                                                                 host,
                                                                 port,
                                                                 scheme,
                                                                 metricsPath,
                                                                 scrapeIntervalSeconds,
                                                                 scrapeTimeoutSeconds,
                                                                 mQueueKey,
                                                                 mInputIndex,
                                                                 targetInfo);

        scrapeScheduler->SetComponent(mEventPool);

        auto randSleepMilliSec
            = GetRandSleepMilliSec(scrapeScheduler->GetId(), scrapeIntervalSeconds, GetCurrentTimeInMilliSeconds());
        auto firstExecTime = std::chrono::steady_clock::now() + std::chrono::milliseconds(randSleepMilliSec);
        auto firstScrapeTIme = std::chrono::system_clock::now() + std::chrono::milliseconds(randSleepMilliSec);
        scrapeScheduler->SetFirstExecTime(firstExecTime, firstScrapeTIme);
        scrapeScheduler->InitSelfMonitor(mDefaultLabels);

        scrapeSchedulerMap[scrapeScheduler->GetId()] = scrapeScheduler;
    }
    return scrapeSchedulerMap;
}


string TargetSubscriberScheduler::GetId() const {
    return mJobName;
}

void TargetSubscriberScheduler::ScheduleNext() {
    auto future = std::make_shared<PromFuture<HttpResponse&, uint64_t>>();
    future->AddDoneCallback([this](HttpResponse& response, uint64_t timestampMilliSec) {
        this->OnSubscription(response, timestampMilliSec);
        this->ExecDone();
        this->ScheduleNext();
        return true;
    });
    if (IsCancelled()) {
        mFuture->Cancel();
        return;
    }

    {
        WriteLock lock(mLock);
        mFuture = future;
    }

    auto event = BuildSubscriberTimerEvent(GetNextExecTime());
    Timer::GetInstance()->PushEvent(std::move(event));
}

void TargetSubscriberScheduler::Cancel() {
    mFuture->Cancel();
    {
        WriteLock lock(mLock);
        mValidState = false;
    }
    CancelAllScrapeScheduler();
}

void TargetSubscriberScheduler::SubscribeOnce(std::chrono::steady_clock::time_point execTime) {
    auto future = std::make_shared<PromFuture<HttpResponse&, uint64_t>>();
    future->AddDoneCallback([this](HttpResponse& response, uint64_t timestampNanoSec) {
        this->OnSubscription(response, timestampNanoSec);
        return true;
    });
    mFuture = future;
    auto event = BuildSubscriberTimerEvent(execTime);
    Timer::GetInstance()->PushEvent(std::move(event));
}

std::unique_ptr<TimerEvent>
TargetSubscriberScheduler::BuildSubscriberTimerEvent(std::chrono::steady_clock::time_point execTime) {
    map<string, string> httpHeader;
    httpHeader[prometheus::ACCEPT] = prometheus::APPLICATION_JSON;
    httpHeader[prometheus::X_PROMETHEUS_REFRESH_INTERVAL_SECONDS] = ToString(prometheus::RefeshIntervalSeconds);
    httpHeader[prometheus::USER_AGENT] = prometheus::PROMETHEUS_PREFIX + mPodName;
    if (!mETag.empty()) {
        httpHeader[prometheus::IF_NONE_MATCH] = mETag;
    }
    auto body = TargetsInfoToString();
    auto request = std::make_unique<PromHttpRequest>(HTTP_GET,
                                                     false,
                                                     mServiceHost,
                                                     mServicePort,
                                                     "/jobs/" + URLEncode(GetId()) + "/targets",
                                                     "collector_id=" + mPodName,
                                                     httpHeader,
                                                     body,
                                                     HttpResponse(),
                                                     prometheus::RefeshIntervalSeconds,
                                                     1,
                                                     this->mFuture);
    auto timerEvent = std::make_unique<HttpRequestTimerEvent>(execTime, std::move(request));

    return timerEvent;
}

string TargetSubscriberScheduler::TargetsInfoToString() const {
    Json::Value root;

    SelfMonitorMetricEvent wantAgentEvent;
    LoongCollectorMonitor::GetInstance()->GetAgentMetric(wantAgentEvent);
    SelfMonitorMetricEvent wantRunnerEvent;
    LoongCollectorMonitor::GetInstance()->GetRunnerMetric(METRIC_LABEL_VALUE_RUNNER_NAME_HTTP_SINK, wantRunnerEvent);

    root[prometheus::AGENT_INFO][prometheus::CPU_USAGE] = wantAgentEvent.GetGauge(METRIC_AGENT_CPU); // double
    root[prometheus::AGENT_INFO][prometheus::CPU_LIMIT] = AppConfig::GetInstance()->GetCpuUsageUpLimit(); // float
    root[prometheus::AGENT_INFO][prometheus::MEM_USAGE] = wantAgentEvent.GetGauge(METRIC_AGENT_MEMORY); // double
    root[prometheus::AGENT_INFO][prometheus::MEM_LIMIT] = AppConfig::GetInstance()->GetMemUsageUpLimit(); // int64_t
    root[prometheus::AGENT_INFO][prometheus::HTTP_SINK_IN_ITEMS_TOTAL]
        = wantRunnerEvent.GetCounter(METRIC_RUNNER_IN_ITEMS_TOTAL); // uint64_t
    root[prometheus::AGENT_INFO][prometheus::HTTP_SINK_OUT_FAILED]
        = wantRunnerEvent.GetCounter(METRIC_RUNNER_SINK_OUT_FAILED_ITEMS_TOTAL); // uint64_t
    {
        ReadLock lock(mRWLock);
        for (const auto& [k, v] : mScrapeSchedulerMap) {
            Json::Value targetInfo;
            targetInfo[prometheus::HASH] = v->GetId();
            targetInfo[prometheus::SIZE] = v->GetLastScrapeSize();
            sDelaySeconds += v->mExecDelayCount;
            v->mExecDelayCount = 0;
            root[prometheus::TARGETS_INFO].append(targetInfo);
        }
    }
    auto curTime = std::chrono::steady_clock::now();
    auto needToClear = curTime - mLastUpdateTime >= std::chrono::seconds(prometheus::RefeshIntervalSeconds);
    root[prometheus::AGENT_INFO][prometheus::SCRAPE_DELAY_SECONDS] = sDelaySeconds;
    if (needToClear) {
        sDelaySeconds = 0;
        mLastUpdateTime = curTime;
    }
    return root.toStyledString();
}

void TargetSubscriberScheduler::CancelAllScrapeScheduler() {
    ReadLock lock(mRWLock);
    for (const auto& [k, v] : mScrapeSchedulerMap) {
        v->Cancel();
    }
}

void TargetSubscriberScheduler::InitSelfMonitor(const MetricLabels& defaultLabels) {
    mDefaultLabels = defaultLabels;
    mDefaultLabels.emplace_back(METRIC_LABEL_KEY_JOB, mJobName);
    mDefaultLabels.emplace_back(METRIC_LABEL_KEY_POD_NAME, mPodName);
    mDefaultLabels.emplace_back(METRIC_LABEL_KEY_SERVICE_HOST, mServiceHost);
    mDefaultLabels.emplace_back(METRIC_LABEL_KEY_SERVICE_PORT, ToString(mServicePort));

    static const std::unordered_map<std::string, MetricType> sSubscriberMetricKeys = {
        {METRIC_PLUGIN_PROM_SUBSCRIBE_TOTAL, MetricType::METRIC_TYPE_COUNTER},
        {METRIC_PLUGIN_PROM_SUBSCRIBE_TIME_MS, MetricType::METRIC_TYPE_COUNTER},
    };

    mSelfMonitor = std::make_shared<PromSelfMonitorUnsafe>();
    mSelfMonitor->InitMetricManager(sSubscriberMetricKeys, mDefaultLabels);

    WriteMetrics::GetInstance()->PrepareMetricsRecordRef(
        mMetricsRecordRef, MetricCategory::METRIC_CATEGORY_PLUGIN_SOURCE, std::move(mDefaultLabels));
    mPromSubscriberTargets = mMetricsRecordRef.CreateIntGauge(METRIC_PLUGIN_PROM_SUBSCRIBE_TARGETS);
    mTotalDelayMs = mMetricsRecordRef.CreateCounter(METRIC_PLUGIN_TOTAL_DELAY_MS);
}

} // namespace logtail
