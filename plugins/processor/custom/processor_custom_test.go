// Copyright 2024 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package custom

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"github.com/alibaba/ilogtail/plugins/test/mock"
)

// 模拟外部API的响应数据
type mockAPIResponse struct {
	EnrichedData string `json:"enriched_data"`
}

type mockContext struct {
	pipeline.Context
}

func (m *mockContext) Collector() pipeline.PipelineCollector {
	return &mockCollector{}
}

type mockCollector struct{}

func (m *mockCollector) Collect(group *models.GroupInfo, events ...models.PipelineEvent) {
	// do nothing in test
}

func (m *mockCollector) CollectList(events ...*models.PipelineGroupEvents) {
	// do nothing in test
}

func (m *mockCollector) AddData(tags map[string]string, fields map[string]string, t ...time.Time) {
	// do nothing in test
}

func (m *mockCollector) Close() {
	// do nothing in test
}

func (m *mockCollector) Observe() chan *models.PipelineGroupEvents {
	return make(chan *models.PipelineGroupEvents)
}

func (m *mockCollector) ToArray() []*models.PipelineGroupEvents {
	return nil
}

func TestProcessorCustom_Process(t *testing.T) {
	// 1. 启动模拟的HTTP服务
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 读取请求体
		var requestData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// 保持原始数据，添加新字段
		requestData["enriched_data"] = "processed_data"

		// 返回完整的数据
		json.NewEncoder(w).Encode(requestData)
	}))
	defer mockServer.Close()

	// 2. 创建测试上下文
	ctx := mock.NewEmptyContext("p", "l", "c")

	// 3. 创建并初始化processor
	processor := &ProcessorCustom{
		IgnoreError: true,
	}
	// 设置mock server的URL
	processor.URL = mockServer.URL
	err := processor.Init(ctx)
	require.NoError(t, err)

	// 4. 准备测试数据
	rawData := []byte(`{"test_key":"test_value"}`)
	events := make([]models.PipelineEvent, 0)
	events = append(events, models.ByteArray(rawData))

	groupEvents := &models.PipelineGroupEvents{
		Group:  models.NewGroup(models.NewMetadata(), models.NewTags()),
		Events: events,
	}

	// 5. 处理数据
	mockCtx := &mockContext{}
	processor.Process(groupEvents, mockCtx)

	// 6. 验证处理结果
	processedData, ok := groupEvents.Events[0].(models.ByteArray)
	require.True(t, ok)

	var processedJSON map[string]interface{}
	err = json.Unmarshal(processedData, &processedJSON)
	require.NoError(t, err)

	require.Equal(t, "test_value", processedJSON["test_key"])
	require.Equal(t, "processed_data", processedJSON["enriched_data"])
}
