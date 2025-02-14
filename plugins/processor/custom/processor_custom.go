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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"github.com/alibaba/ilogtail/pkg/protocol"
)

type ProcessorCustom struct {
	URL         string // HTTP endpoint URL
	IgnoreError bool   // Whether to ignore processing errors

	context    pipeline.Context
	httpClient *http.Client
}

const pluginName = "processor_custom"

func (p *ProcessorCustom) Init(context pipeline.Context) error {
	logger.Info(p.context.GetRuntimeContext(), "this is", "Init")
	p.context = context
	p.httpClient = &http.Client{
		Timeout: time.Second * 10,
	}
	return nil
}

func (p *ProcessorCustom) Description() string {
	logger.Info(p.context.GetRuntimeContext(), "this is", "Description")
	return "custom processor that can handle any data format and do any processing"
}

func (p *ProcessorCustom) Process(in *models.PipelineGroupEvents, context pipeline.PipelineContext) {
	logger.Info(p.context.GetRuntimeContext(), "this is", "Process")
	if in == nil || len(in.Events) == 0 {
		return
	}

	for i := range in.Events {
		if err := p.processEvent(in, i); err != nil {
			logger.Warning(p.context.GetRuntimeContext(), "CUSTOM_PROCESSOR_ALARM", "process event error", err)
			if !p.IgnoreError {
				return
			}
		}
	}

	context.Collector().Collect(in.Group, in.Events...)
}

func (p *ProcessorCustom) processEvent(in *models.PipelineGroupEvents, i int) error {
	logger.Info(p.context.GetRuntimeContext(), "this is", "processEvent")
	switch e := in.Events[i].(type) {
	case models.ByteArray:
		respBody, err := p.processByteArray(e)
		if err != nil {
			return err
		}
		in.Events[i] = models.ByteArray(respBody)
		return nil
	case *models.Log:
		// TODO: 实现日志处理逻辑
		return nil
	case *models.Metric:
		// TODO: 实现指标处理逻辑
		return nil
	default:
		return fmt.Errorf("unsupported event type: %T", e)
	}
}

func (p *ProcessorCustom) processByteArray(data models.ByteArray) ([]byte, error) {
	logger.Info(p.context.GetRuntimeContext(), "this is", "processByteArray")
	logger.Info(p.context.GetRuntimeContext(), "request is", string(data))
	// 调用HTTP接口
	resp, err := p.httpClient.Post(p.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应
	return io.ReadAll(resp.Body)
}

func (p *ProcessorCustom) ProcessLogs(logArray []*protocol.Log) []*protocol.Log {
	logger.Info(p.context.GetRuntimeContext(), "this is", "ProcessLogs")
	return logArray
}

func (p *ProcessorCustom) Stop() error {
	logger.Info(p.context.GetRuntimeContext(), "this is", "Stop")
	return nil
}

func init() {
	logger.Info(context.Background(), "this is", "init")
	pipeline.Processors[pluginName] = func() pipeline.Processor {
		return &ProcessorCustom{
			IgnoreError: true,
		}
	}
}
