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

#include <unistd.h>

#include <chrono>
#include <memory>
#include <string>

#include "FileSystemUtil.h"
#include "common/http/Curl.h"
#include "common/http/HttpResponse.h"
#include "common/timer/Timer.h"
#include "models/RawEvent.h"
#include "prometheus/Constants.h"
#include "prometheus/async/PromFuture.h"
#include "prometheus/component/StreamScraper.h"
#include "prometheus/labels/Labels.h"
#include "prometheus/schedulers/ScrapeConfig.h"
#include "prometheus/schedulers/ScrapeScheduler.h"
#include "unittest/Unittest.h"

using namespace std;

namespace logtail {
class ScrapeSchedulerUnittest : public testing::Test {
public:
    void TestInitscrapeScheduler();
    void TestProcess();
    void TestStreamMetricWriteCallback();
    void TestReceiveMessage();

    void TestScheduler();
    void TestTokenUpdate();
    void TestQueueIsFull();
    void TestExactlyScrape();

protected:
    void SetUp() override {
        OverwriteFile(mFilePath, mKey);
        mScrapeConfig = make_shared<ScrapeConfig>();
        mScrapeConfig->mJobName = "test_job";
        mScrapeConfig->mScheme = "http";
        mScrapeConfig->mScrapeIntervalSeconds = 10;
        mScrapeConfig->mScrapeTimeoutSeconds = 10;
        mScrapeConfig->mMetricsPath = "/metrics";
        mScrapeConfig->mRequestHeaders = {{"Authorization", "Bearer xxxxx"}};
        mScrapeConfig->mAuthType = "Bearer";
        mScrapeConfig->mBearerTokenPath = "test_password.file";
    }

    void TearDown() override {
        Timer::GetInstance()->Clear();
        remove(mFilePath.c_str());
    }

private:
    std::shared_ptr<ScrapeConfig> mScrapeConfig;

    string mFilePath = "prom_password.file";
    string mKey = "test_password.file";
};

void ScrapeSchedulerUnittest::TestInitscrapeScheduler() {
    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    labels.Set("testb", "valueb");
    labels.Set("testa", "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_joblocalhost:8080887d0db7cce49fc7";
    ScrapeScheduler event(mScrapeConfig, "localhost", 8080, "http", "/metrics", 15, 15, 0, 0, targetInfo);

    APSARA_TEST_EQUAL(event.GetId(), "test_joblocalhost:8080887d0db7cce49fc7");
}

void ScrapeSchedulerUnittest::TestProcess() {
    EventPool eventPool{true};

    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_hash";
    ScrapeScheduler event(mScrapeConfig, "localhost", 8080, "http", "/metrics", 15, 15, 0, 0, targetInfo);
    auto streamScraper = prom::StreamScraper(labels, 0, 0, event.GetId(), nullptr, std::chrono::system_clock::now());
    HttpResponse httpResponse = HttpResponse(&streamScraper, [](void*) {}, prom::StreamScraper::MetricWriteCallback);
    auto defaultLabels = MetricLabels();
    event.InitSelfMonitor(defaultLabels);
    // APSARA_TEST_EQUAL(event.GetId(), "test_jobhttp://localhost:8080/metrics" + ToString(labels.Hash()));
    // if status code is not 200, no data will be processed
    // but will continue running, sending self-monitoring metrics
    httpResponse.SetStatusCode(503);
    httpResponse.SetNetworkStatus(NetworkCode::Ok, "");
    event.OnMetricResult(httpResponse, 0);
    APSARA_TEST_EQUAL(1UL, streamScraper.mItem.size());
    streamScraper.mItem.clear();

    httpResponse.SetStatusCode(503);
    httpResponse.SetNetworkStatus(GetNetworkStatus(CURLE_COULDNT_CONNECT), "");
    event.OnMetricResult(httpResponse, 0);
    APSARA_TEST_EQUAL(
        streamScraper.mItem[0]->mEventGroup.GetMetadata(EventGroupMetaKey::PROMETHEUS_SCRAPE_STATE).to_string(),
        "ERR_CONN_FAILED");
    APSARA_TEST_EQUAL(1UL, streamScraper.mItem.size());
    streamScraper.mItem.clear();

    httpResponse.SetStatusCode(200);
    httpResponse.SetNetworkStatus(NetworkCode::Ok, "");
    string body1 = "# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.\n"
                   "# TYPE go_gc_duration_seconds summary\n"
                   "go_gc_duration_seconds{quantile=\"0\"} 1.5531e-05\n"
                   "go_gc_duration_seconds{quantile=\"0.25\"} 3.9357e-05\n"
                   "go_gc_duration_seconds{quantile=\"0.5\"} 4.1114e-05\n"
                   "go_gc_duration_seconds{quantile=\"0.75\"} 4.3372e-05\n"
                   "go_gc_duration_seconds{quantile=\"1\"} 0.000112326\n"
                   "go_gc_duration_seconds_sum 0.034885631\n"
                   "go_gc_duration_seconds_count 850\n"
                   "# HELP go_goroutines Number of goroutines that currently exist.\n"
                   "# TYPE go_goroutines gauge\n"
                   "go_goroutines 7\n"
                   "# HELP go_info Information about the Go environment.\n"
                   "# TYPE go_info gauge\n"
                   "go_info{version=\"go1.22.3\"} 1\n"
                   "# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.\n"
                   "# TYPE go_memstats_alloc_bytes gauge\n"
                   "go_memstats_alloc_bytes 6.742688e+06\n"
                   "# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.\n"
                   "# TYPE go_memstats_alloc_bytes_total counter\n"
                   "go_memstats_alloc_bytes_total 1.5159292e+08";
    prom::StreamScraper::MetricWriteCallback(
        body1.data(), (size_t)1, (size_t)body1.length(), (void*)httpResponse.GetBody<prom::StreamScraper>());
    event.OnMetricResult(httpResponse, 0);
    APSARA_TEST_EQUAL(1UL, streamScraper.mItem.size());
    APSARA_TEST_EQUAL(11UL, streamScraper.mItem[0]->mEventGroup.GetEvents().size());
}

void ScrapeSchedulerUnittest::TestStreamMetricWriteCallback() {
    EventPool eventPool{true};

    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_hash";
    ScrapeScheduler event(mScrapeConfig, "localhost", 8080, "http", "/metrics", 15, 15, 0, 0, targetInfo);
    auto streamScraper = prom::StreamScraper(labels, 0, 0, event.GetId(), nullptr, std::chrono::system_clock::now());
    HttpResponse httpResponse = HttpResponse(&streamScraper, [](void*) {}, prom::StreamScraper::MetricWriteCallback);
    // APSARA_TEST_EQUAL(event.GetId(), "test_jobhttp://localhost:8080/metrics" + ToString(labels.Hash()));

    string body1 = "# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.\n"
                   "# TYPE go_gc_duration_seconds summary\n"
                   "go_gc_duration_seconds{quantile=\"0\"} 1.5531e-05\n"
                   "go_gc_duration_seconds{quantile=\"0.25\"} 3.9357e-05\n"
                   "go_gc_duration_seconds{quantile=\"0.5\"} 4.1114e-05\n"
                   "go_gc_duration_seconds{quantile=\"0.75\"} 4.3372e-05\n"
                   "go_gc_duration_seconds{quantile=\"1\"} 0.000112326\n"
                   "go_gc_duration_seconds_sum 0.034885631\n"
                   "go_gc_duration_seconds_count 850\n"
                   "# HELP go_goroutines Number of goroutines t"
                   "hat currently exist.\n"
                   "# TYPE go_goroutines gauge\n"
                   "go_go";
    string body2 = "routines 7\n"
                   "# HELP go_info Information about the Go environment.\n"
                   "# TYPE go_info gauge\n"
                   "go_info{version=\"go1.22.3\"} 1\n"
                   "# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.\n"
                   "# TYPE go_memstats_alloc_bytes gauge\n"
                   "go_memstats_alloc_bytes 6.742688e+06\n"
                   "# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.\n"
                   "# TYPE go_memstats_alloc_bytes_total counter\n"
                   "go_memstats_alloc_bytes_total 1.5159292e+08";
    prom::StreamScraper::MetricWriteCallback(
        body1.data(), (size_t)1, (size_t)body1.length(), (void*)httpResponse.GetBody<prom::StreamScraper>());
    auto& res = httpResponse.GetBody<prom::StreamScraper>()->mEventGroup;
    APSARA_TEST_EQUAL(7UL, res.GetEvents().size());
    APSARA_TEST_EQUAL("go_gc_duration_seconds{quantile=\"0\"} 1.5531e-05",
                      res.GetEvents()[0].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_gc_duration_seconds{quantile=\"0.25\"} 3.9357e-05",
                      res.GetEvents()[1].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_gc_duration_seconds{quantile=\"0.5\"} 4.1114e-05",
                      res.GetEvents()[2].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_gc_duration_seconds{quantile=\"0.75\"} 4.3372e-05",
                      res.GetEvents()[3].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_gc_duration_seconds{quantile=\"1\"} 0.000112326",
                      res.GetEvents()[4].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_gc_duration_seconds_sum 0.034885631", res.GetEvents()[5].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_gc_duration_seconds_count 850", res.GetEvents()[6].Cast<RawEvent>().GetContent());
    // httpResponse.GetBody<MetricResponseBody>()->mEventGroup = PipelineEventGroup(std::make_shared<SourceBuffer>());
    prom::StreamScraper::MetricWriteCallback(
        body2.data(), (size_t)1, (size_t)body2.length(), (void*)httpResponse.GetBody<prom::StreamScraper>());
    httpResponse.GetBody<prom::StreamScraper>()->FlushCache();
    APSARA_TEST_EQUAL(11UL, res.GetEvents().size());

    APSARA_TEST_EQUAL("go_goroutines 7", res.GetEvents()[7].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_info{version=\"go1.22.3\"} 1", res.GetEvents()[8].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_memstats_alloc_bytes 6.742688e+06", res.GetEvents()[9].Cast<RawEvent>().GetContent());
    APSARA_TEST_EQUAL("go_memstats_alloc_bytes_total 1.5159292e+08", res.GetEvents()[10].Cast<RawEvent>().GetContent());
}

void ScrapeSchedulerUnittest::TestReceiveMessage() {
    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_hash";
    auto event
        = make_shared<ScrapeScheduler>(mScrapeConfig, "localhost", 8080, "http", "/metrics", 15, 15, 0, 0, targetInfo);


    // before
    APSARA_TEST_EQUAL(true, event->IsCancelled());


    // after
    APSARA_TEST_EQUAL(false, event->IsCancelled());
}

void ScrapeSchedulerUnittest::TestScheduler() {
    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_hash";
    ScrapeScheduler event(mScrapeConfig, "localhost", 8080, "http", "/metrics", 15, 15, 0, 0, targetInfo);
    auto timer = make_shared<Timer>();
    EventPool eventPool{true};
    event.SetComponent(&eventPool);
    event.ScheduleNext();

    APSARA_TEST_TRUE(Timer::GetInstance()->mQueue.size() == 1);

    event.Cancel();

    APSARA_TEST_TRUE(event.mValidState == false);
    APSARA_TEST_TRUE(event.mFuture->mState == PromFutureState::Done);
}

void ScrapeSchedulerUnittest::TestTokenUpdate() {
    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_hash";
    ScrapeScheduler event(mScrapeConfig, "localhost", 8080, "http", "/metrics", 15, 15, 0, 0, targetInfo);
    EventPool eventPool{true};
    event.SetComponent(&eventPool);
    event.SetFirstExecTime(chrono::steady_clock::now(), chrono::system_clock::now());
    event.ScheduleNext();

    auto streamScraper = prom::StreamScraper(labels, 0, 0, event.GetId(), nullptr, std::chrono::system_clock::now());
    HttpResponse httpResponse = HttpResponse(&streamScraper, [](void*) {}, prom::StreamScraper::MetricWriteCallback);
    auto defaultLabels = MetricLabels();
    event.InitSelfMonitor(defaultLabels);
    httpResponse.SetStatusCode(401);
    httpResponse.SetNetworkStatus(NetworkCode::Other, "");

    // success update
    event.mFuture->Process(httpResponse, 0);
    auto curTime = chrono::system_clock::now();
    APSARA_TEST_TRUE(chrono::duration_cast<chrono::seconds>(curTime - mScrapeConfig->mLastUpdateTime)
                     <= chrono::seconds(1));

    // fail update, no change
    curTime = mScrapeConfig->mLastUpdateTime;
    this_thread::sleep_for(chrono::milliseconds(10));
    event.mFuture->Process(httpResponse, 0);
    APSARA_TEST_EQUAL(curTime, mScrapeConfig->mLastUpdateTime);

    // success update
    mScrapeConfig->mLastUpdateTime = curTime - chrono::minutes(6);
    curTime = chrono::system_clock::now();
    this_thread::sleep_for(chrono::milliseconds(10));
    event.mFuture->Process(httpResponse, 0);
    APSARA_TEST_TRUE(chrono::duration_cast<chrono::seconds>(curTime - mScrapeConfig->mLastUpdateTime)
                     <= chrono::seconds(1));
}

void ScrapeSchedulerUnittest::TestQueueIsFull() {
    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_hash";
    ScrapeScheduler event(mScrapeConfig, "localhost", 8080, "http", "/metrics", 15, 15, 0, 0, targetInfo);
    auto defaultLabels = MetricLabels();
    event.InitSelfMonitor(defaultLabels);
    EventPool eventPool{true};
    event.SetComponent(&eventPool);
    auto now = std::chrono::steady_clock::now();
    auto nowScrape = std::chrono::system_clock::now();
    event.SetFirstExecTime(now, nowScrape);
    event.ScheduleNext();

    APSARA_TEST_TRUE(Timer::GetInstance()->mQueue.size() == 1);

    const auto& e = Timer::GetInstance()->mQueue.top();
    APSARA_TEST_EQUAL(now, e->GetExecTime());
    APSARA_TEST_FALSE(e->IsValid());
    Timer::GetInstance()->mQueue.pop();
    // queue is full, so it should schedule next after 1 second
    APSARA_TEST_EQUAL(1UL, Timer::GetInstance()->mQueue.size());
    const auto& next = Timer::GetInstance()->mQueue.top();
    APSARA_TEST_EQUAL(now + std::chrono::seconds(1), next->GetExecTime());
}

void ScrapeSchedulerUnittest::TestExactlyScrape() {
    Labels labels;
    labels.Set(prometheus::ADDRESS_LABEL_NAME, "localhost:8080");
    PromTargetInfo targetInfo;
    targetInfo.mLabels = labels;
    targetInfo.mHash = "test_hash";
    ScrapeScheduler event(mScrapeConfig, "localhost", 8080, "http", "/metrics", 10, 10, 0, 0, targetInfo);
    auto defaultLabels = MetricLabels();
    event.InitSelfMonitor(defaultLabels);
    EventPool eventPool{true};
    event.SetComponent(&eventPool);
    auto execTime = std::chrono::steady_clock::now();
    auto scrapeTime = std::chrono::system_clock::now();
    event.SetFirstExecTime(execTime, scrapeTime);

    auto firstScrapeTime = event.mLatestScrapeTime;
    event.ExecDone();
    auto secondScrapeTime = event.mLatestScrapeTime;
    event.ExecDone();
    event.DelayExecTime(1);
    auto thirdScrapeTime = event.mLatestScrapeTime;
    event.ExecDone();
    auto fourthScrapeTime = event.mLatestScrapeTime;
    APSARA_TEST_EQUAL(firstScrapeTime, scrapeTime);
    APSARA_TEST_EQUAL(secondScrapeTime - firstScrapeTime, std::chrono::seconds(mScrapeConfig->mScrapeIntervalSeconds));
    APSARA_TEST_EQUAL(thirdScrapeTime - firstScrapeTime,
                      std::chrono::seconds(mScrapeConfig->mScrapeIntervalSeconds * 2 + 1));
    APSARA_TEST_EQUAL(fourthScrapeTime - firstScrapeTime,
                      std::chrono::seconds(mScrapeConfig->mScrapeIntervalSeconds * 3));
}

UNIT_TEST_CASE(ScrapeSchedulerUnittest, TestInitscrapeScheduler)
UNIT_TEST_CASE(ScrapeSchedulerUnittest, TestProcess)
UNIT_TEST_CASE(ScrapeSchedulerUnittest, TestStreamMetricWriteCallback)
UNIT_TEST_CASE(ScrapeSchedulerUnittest, TestScheduler)
UNIT_TEST_CASE(ScrapeSchedulerUnittest, TestQueueIsFull)
UNIT_TEST_CASE(ScrapeSchedulerUnittest, TestExactlyScrape)
UNIT_TEST_CASE(ScrapeSchedulerUnittest, TestTokenUpdate)


} // namespace logtail

UNIT_TEST_MAIN
