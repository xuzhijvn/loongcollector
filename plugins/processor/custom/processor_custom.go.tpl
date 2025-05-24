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
	"fmt"
	"net/http"
	"time"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
)

type ProcessorCustom struct {
	// 这里可以添加一些通用配置参数
	IgnoreError bool // Whether to ignore processing errors

	context pipeline.Context
	// 在这里可以定义处理所需的客户端
	httpClient *http.Client
	// redisClient *redis.Client
	// 其他客户端...
}

const pluginName = "processor_custom"

func (p *ProcessorCustom) Init(context pipeline.Context) error {
	p.context = context

	// 初始化所需的客户端
	p.httpClient = &http.Client{
		Timeout: time.Second * 10,
	}

	// 初始化其他客户端
	// p.redisClient = redis.NewClient(&redis.Options{
	//     Addr: "localhost:6379",
	// })

	return nil
}

func (p *ProcessorCustom) Description() string {
	return "custom processor that can handle any data format and do any processing"
}

// Process 处理数据的主函数
func (p *ProcessorCustom) Process(in *models.PipelineGroupEvents) (*models.PipelineGroupEvents, error) {
	if in == nil || len(in.Events) == 0 {
		return in, nil
	}

	for i := range in.Events {
		if err := p.processEvent(in.Events[i]); err != nil {
			logger.Warning(p.context.GetRuntimeContext(), "CUSTOM_PROCESSOR_ALARM", "process event error", err)
			if !p.IgnoreError {
				return nil, err
			}
		}
	}

	return in, nil
}

// processEvent 处理单个事件
func (p *ProcessorCustom) processEvent(event models.PipelineEvent) error {
	// 根据事件类型进行不同处理
	switch e := event.(type) {
	case models.ByteArray:
		return p.processByteArray(e)
	case *models.Metric:
		return p.processMetric(e)
	case *models.Log:
		return p.processLog(e)
	default:
		return fmt.Errorf("unsupported event type: %T", event)
	}
}

// processByteArray 处理字节数组类型的数据
func (p *ProcessorCustom) processByteArray(data models.ByteArray) error {
	// 在这里实现字节数组的处理逻辑
	// 例如:

	// 1. 调用HTTP接口
	// resp, err := p.httpClient.Post("http://api.example.com", "application/json", bytes.NewReader(data))
	// if err != nil {
	//     return err
	// }
	// defer resp.Body.Close()

	// 2. 操作Redis
	// err := p.redisClient.Set(ctx, "key", string(data), 0).Err()
	// if err != nil {
	//     return err
	// }

	// 3. 其他处理...

	return nil
}

// processMetric 处理指标类型的数据
func (p *ProcessorCustom) processMetric(metric *models.Metric) error {
	// 在这里实现指标数据的处理逻辑
	return nil
}

// processLog 处理日志类型的数据
func (p *ProcessorCustom) processLog(log *models.Log) error {
	// 在这里实现日志数据的处理逻辑
	return nil
}

// Stop 停止处理器
func (p *ProcessorCustom) Stop() error {
	// 关闭各种客户端连接
	// if p.redisClient != nil {
	//     p.redisClient.Close()
	// }
	return nil
}

// Register the plugin
func init() {
	pipeline.Processors[pluginName] = func() pipeline.Processor {
		return &ProcessorCustom{
			IgnoreError: true,
		}
	}
}
