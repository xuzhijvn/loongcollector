/*
 * Copyright 2023 iLogtail Authors
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

#pragma once

#include <cstdint>

#include <string>

#include "json/json.h"

#include "collection_pipeline/GlobalConfig.h"
#include "collection_pipeline/queue/QueueKey.h"
#include "logger/Logger.h"
#include "models/PipelineEventGroup.h"
#include "monitor/AlarmManager.h"

namespace logtail {

class CollectionPipeline;
class FlusherSLS;

class CollectionPipelineContext {
public:
    CollectionPipelineContext() {}
    CollectionPipelineContext(const CollectionPipelineContext&) = delete;
    CollectionPipelineContext(CollectionPipelineContext&&) = delete;
    CollectionPipelineContext operator=(const CollectionPipelineContext&) = delete;
    CollectionPipelineContext operator=(CollectionPipelineContext&&) = delete;

    const std::string& GetConfigName() const { return mConfigName; }
    void SetConfigName(const std::string& configName) { mConfigName = configName; }
    uint32_t GetCreateTime() const { return mCreateTime; }
    void SetCreateTime(uint32_t time) { mCreateTime = time; }
    const GlobalConfig& GetGlobalConfig() const { return mGlobalConfig; }
    bool InitGlobalConfig(const Json::Value& config, Json::Value& extendedParams) {
        return mGlobalConfig.Init(config, *this, extendedParams);
    }
    void SetProcessQueueKey(QueueKey key) { mProcessQueueKey = key; }
    QueueKey GetProcessQueueKey() const { return mProcessQueueKey; }
    const CollectionPipeline& GetPipeline() const { return *mPipeline; }
    CollectionPipeline& GetPipeline() { return *mPipeline; }
    void SetPipeline(CollectionPipeline& pipeline) { mPipeline = &pipeline; }

    const std::string& GetProjectName() const;
    const std::string& GetLogstoreName() const;
    const std::string& GetRegion() const;
    QueueKey GetLogstoreKey() const;
    const FlusherSLS* GetSLSInfo() const { return mSLSInfo; }
    void SetSLSInfo(const FlusherSLS* flusherSLS) { mSLSInfo = flusherSLS; }

    bool RequiringJsonReader() const { return mRequiringJsonReader; }
    void SetRequiringJsonReaderFlag(bool flag) { mRequiringJsonReader = flag; }
    bool IsFirstProcessorApsara() const { return mIsFirstProcessorApsara; }
    void SetIsFirstProcessorApsaraFlag(bool flag) { mIsFirstProcessorApsara = flag; }
    bool IsFirstProcessorJson() const { return mIsFirstProcessorJson; }
    void SetIsFirstProcessorJsonFlag(bool flag) { mIsFirstProcessorJson = flag; }
    bool IsExactlyOnceEnabled() const { return mEnableExactlyOnce; }
    void SetExactlyOnceFlag(bool flag) { mEnableExactlyOnce = flag; }
    bool HasNativeProcessors() const { return mHasNativeProcessors; }
    void SetHasNativeProcessorsFlag(bool flag) { mHasNativeProcessors = flag; }
    bool IsFlushingThroughGoPipeline() const { return mIsFlushingThroughGoPipeline; }
    void SetIsFlushingThroughGoPipelineFlag(bool flag) { mIsFlushingThroughGoPipeline = flag; }

    const Logger::logger& GetLogger() const { return mLogger; }
    AlarmManager& GetAlarm() const { return *mAlarm; };

private:
    static const std::string sEmptyString;

    std::string mConfigName;
    uint32_t mCreateTime;
    GlobalConfig mGlobalConfig;
    QueueKey mProcessQueueKey = -1;
    CollectionPipeline* mPipeline = nullptr;

    const FlusherSLS* mSLSInfo = nullptr;
    // for input_file only
    bool mRequiringJsonReader = false;
    bool mIsFirstProcessorApsara = false;
    bool mIsFirstProcessorJson = false;
    bool mEnableExactlyOnce = false;
    bool mHasNativeProcessors = false;
    bool mIsFlushingThroughGoPipeline = false;

    Logger::logger mLogger = sLogger;
    AlarmManager* mAlarm = AlarmManager::GetInstance();
};

} // namespace logtail
