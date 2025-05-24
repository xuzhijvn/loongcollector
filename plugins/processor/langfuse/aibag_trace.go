package langfuse

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

type AiBagTraceConverter struct {
	context pipeline.Context
}

type AiBagTraceData struct {
	Attributes map[string]interface{} `json:"attributes"`
	StartTime  int64                  `json:"start_time"` //毫秒时间戳
	Context    map[string]interface{} `json:"context"`
	Name       string                 `json:"name"`
	EndTime    int64                  `json:"end_time"` //毫秒时间戳
	Status     interface{}            `json:"status"`
	Kind       string                 `json:"kind"`
}

func (a *AiBagTraceConverter) Convert(byteArray models.ByteArray) (ptrace.Traces, error) {
	traces := ptrace.NewTraces()
	resourceSpans := traces.ResourceSpans().AppendEmpty()
	resourceSpans.Resource().Attributes().PutStr("from", "ai-interface")
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()

	traceData := &AiBagTraceData{}
	err := json.Unmarshal(byteArray, &traceData)
	if err == nil {
		if err := a.addSpanFromTraceData(traceData, scopeSpans); err != nil {
			return traces, fmt.Errorf("failed to create span from JSON object: %v", err)
		}
	} else {
		var traceDataArray []AiBagTraceData
		if err := json.Unmarshal(byteArray, &traceDataArray); err != nil {
			return traces, fmt.Errorf("failed to parse input as JSON: %v", err)
		}
		for _, data := range traceDataArray {
			if err := a.addSpanFromTraceData(&data, scopeSpans); err != nil {
				logger.Warning(a.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "create span error", err)
				continue
			}
		}
	}
	return traces, nil
}

func (a *AiBagTraceConverter) addSpanFromTraceData(traceData *AiBagTraceData, scopeSpans ptrace.ScopeSpans) error {
	span := scopeSpans.Spans().AppendEmpty()
	// 设置 trace_id 和 span_id
	if traceData.Context != nil {
		if tid, ok := traceData.Context["trace_id"].(string); ok {
			traceID := strings.TrimPrefix(tid, "0x")
			traceID = strings.ReplaceAll(traceID, "-", "")
			if traceIDBytes, err := hexToTraceID(traceID); err == nil {
				span.SetTraceID(traceIDBytes)
			} else {
				logger.Error(a.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "invalid trace_id format", tid, err)
				return fmt.Errorf("invalid trace_id format: %s", tid)
			}
		} else {
			logger.Error(a.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "missing trace_id in context")
			return fmt.Errorf("missing trace_id in context")
		}

		if sid, ok := traceData.Context["span_id"].(string); ok {
			spanID := strings.TrimPrefix(sid, "0x")
			if spanIDBytes, err := hexToSpanID(spanID); err == nil {
				span.SetSpanID(spanIDBytes)
			} else {
				logger.Error(a.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "invalid span_id format", sid, err)
				return fmt.Errorf("invalid span_id format: %s", sid)
			}
		} else {
			logger.Error(a.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "missing span_id in context")
			return fmt.Errorf("missing span_id in context")
		}
	} else {
		logger.Error(a.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "missing context in trace data")
		return fmt.Errorf("missing context in trace data")
	}

	// 设置 name 和 kind
	span.SetName(traceData.Name)
	switch strings.ToUpper(traceData.Kind) {
	case "CLIENT", "SPAN_KIND_CLIENT", "SPANKIND.CLIENT":
		span.SetKind(ptrace.SpanKindClient)
	case "SERVER", "SPAN_KIND_SERVER", "SPANKIND.SERVER":
		span.SetKind(ptrace.SpanKindServer)
	case "PRODUCER", "SPAN_KIND_PRODUCER", "SPANKIND.PRODUCER":
		span.SetKind(ptrace.SpanKindProducer)
	case "CONSUMER", "SPAN_KIND_CONSUMER", "SPANKIND.CONSUMER":
		span.SetKind(ptrace.SpanKindConsumer)
	case "INTERNAL", "SPAN_KIND_INTERNAL", "SPANKIND.INTERNAL":
		span.SetKind(ptrace.SpanKindInternal)
	default:
		span.SetKind(ptrace.SpanKindUnspecified)
	}

	// 设置时间戳（毫秒转纳秒）
	span.SetStartTimestamp(pcommon.Timestamp(traceData.StartTime * 1_000_000))
	span.SetEndTimestamp(pcommon.Timestamp(traceData.EndTime * 1_000_000))

	// 设置属性
	if traceData.Attributes != nil {
		addAttributesToSpan(span.Attributes(), traceData.Attributes)
	}

	// 设置状态
	if traceData.Status != nil {
		if statusMap, ok := traceData.Status.(map[string]interface{}); ok {
			// If status is an object
			if statusCode, ok := statusMap["status_code"].(string); ok {
				if strings.ToUpper(statusCode) == "OK" {
					span.Status().SetCode(ptrace.StatusCodeOk)
				} else {
					span.Status().SetCode(ptrace.StatusCodeError)
				}
			}
		}
	} else {
		span.Status().SetCode(ptrace.StatusCodeOk)
	}
	return nil
}
