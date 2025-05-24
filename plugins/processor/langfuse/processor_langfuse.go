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

package langfuse

import (
	"fmt"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"github.com/alibaba/ilogtail/pkg/protocol"
	"github.com/alibaba/ilogtail/pkg/protocol/decoder/opentelemetry"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

// OtlpOutputFormat defines the output format for OTLP traces
type OtlpOutputFormat string

const (
	OtlpOutputFormatNone  OtlpOutputFormat = "none"  // No OTLP output
	OtlpOutputFormatProto OtlpOutputFormat = "proto" // Protobuf format
	OtlpOutputFormatJSON  OtlpOutputFormat = "json"  // JSON format
)

// ProcessorLangfuse converts JSON trace data to Langfuse-compatible OTLP format
type ProcessorLangfuse struct {
	ServiceName string           // Service name to add to resource attributes
	IgnoreError bool             // Whether to ignore processing errors
	OtlpFormat  OtlpOutputFormat // OTLP output format (none/proto/json)

	context pipeline.Context
}

const pluginName = "processor_langfuse"

func (p *ProcessorLangfuse) Init(context pipeline.Context) error {
	p.context = context

	// Set default values
	if p.ServiceName == "" {
		p.ServiceName = "loongcollector"
	}
	if p.OtlpFormat == "" {
		p.OtlpFormat = OtlpOutputFormatNone
	}

	return nil
}

func (p *ProcessorLangfuse) Description() string {
	return "processor that converts JSON trace data to Langfuse-compatible OTLP format"
}

func (p *ProcessorLangfuse) Process(in *models.PipelineGroupEvents, context pipeline.PipelineContext) {
	if in == nil || len(in.Events) == 0 {
		return
	}

	var convertedEvents []models.PipelineEvent
	for i := range in.Events {
		converted, err := p.convertEvent(in.Events[i], in.Group)
		if err != nil {
			logger.Warning(p.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "convert event error", err)
			if !p.IgnoreError {
				return
			}
			// Keep original event if error
			convertedEvents = append(convertedEvents, in.Events[i])
		} else if converted != nil {
			convertedEvents = append(convertedEvents, converted...)
		}
	}

	// Replace original events
	in.Events = convertedEvents

	// Log conversion results
	logger.Info(p.context.GetRuntimeContext(), "langfuse processor processed events", "count", len(convertedEvents))

	// Only call Collect if context is not nil
	if context != nil {
		context.Collector().Collect(in.Group, in.Events...)
	}
}

func (p *ProcessorLangfuse) convertEvent(event models.PipelineEvent, group *models.GroupInfo) ([]models.PipelineEvent, error) {
	switch e := event.(type) {
	case models.ByteArray:
		return p.convertByteArray(e, group)
	case *models.Log:
		return p.convertLog(e)
	default:
		return []models.PipelineEvent{event}, fmt.Errorf("unsupported event type: %T", e)
	}
}

func (p *ProcessorLangfuse) convertByteArray(data models.ByteArray, group *models.GroupInfo) ([]models.PipelineEvent, error) {
	var converter TraceConverter
	if group != nil && group.Metadata != nil {
		if v := group.Metadata.Get(models.KafkaMsgKey); v != "" {
			converter = GetTraceConverter(p.context, v)
			if converter == nil {
				logger.Error(p.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "no converter found for kafka message key", "key", v)
				return []models.PipelineEvent{data}, nil
			}
		} else {
			logger.Error(p.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "no kafka message key found in group metadata")
			return []models.PipelineEvent{data}, nil
		}
	} else {
		logger.Error(p.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "no group metadata found")
		return []models.PipelineEvent{data}, nil
	}

	traces, err := converter.Convert(data)
	if err != nil {
		return nil, fmt.Errorf("failed to convert trace data: %v", err)
	}

	for i := 0; i < traces.ResourceSpans().Len(); i++ {
		resourceSpans := traces.ResourceSpans().At(i)
		// Add service name and other resource attributes
		resourceAttrs := resourceSpans.Resource().Attributes()
		resourceAttrs.PutStr("serviceName", p.ServiceName)
		for j := 0; j < resourceSpans.ScopeSpans().Len(); j++ {
			scopeSpans := resourceSpans.ScopeSpans().At(j)
			scopeSpans.Scope().SetName("loongcollector")
			scopeSpans.Scope().SetVersion("1.0.0")
		}
	}

	// Handle OTLP output format
	request := ptraceotlp.NewExportRequestFromTraces(traces)
	var bytes []byte

	switch p.OtlpFormat {
	case OtlpOutputFormatNone:
		// Convert to PipelineGroupEvents
		groupEvents, err := opentelemetry.ConvertOtlpTracesToGroupEvents(traces)
		if err != nil || len(groupEvents) == 0 {
			return nil, fmt.Errorf("failed to convert OTLP trace to group events: %v", err)
		}
		return groupEvents[0].Events, nil
	case OtlpOutputFormatProto:
		bytes, err = request.MarshalProto()
	case OtlpOutputFormatJSON:
		bytes, err = request.MarshalJSON()
	default:
		return nil, fmt.Errorf("unsupported OTLP output format: %s", p.OtlpFormat)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal OTLP trace: %v", err)
	}
	return []models.PipelineEvent{models.NewByteArray(bytes)}, nil
}

func (p *ProcessorLangfuse) convertLog(log *models.Log) ([]models.PipelineEvent, error) {
	// TODO: Implement log conversion logic if needed
	return []models.PipelineEvent{log}, nil
}

func (p *ProcessorLangfuse) ProcessLogs(logArray []*protocol.Log) []*protocol.Log {
	return logArray
}

func (p *ProcessorLangfuse) Stop() error {
	return nil
}

func init() {
	pipeline.Processors[pluginName] = func() pipeline.Processor {
		return &ProcessorLangfuse{
			ServiceName: "loongcollector",
			IgnoreError: true,
			OtlpFormat:  OtlpOutputFormatNone,
		}
	}
}
