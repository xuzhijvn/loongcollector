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

type HiAgentTraceConverter struct {
	context pipeline.Context
}

type HiAgentTraceData struct {
	Attributes map[string]interface{} `json:"attributes"`
	Context    map[string]interface{} `json:"context"`
	EndTime    string                 `json:"end_time"`
	Events     []interface{}          `json:"events"`
	Kind       string                 `json:"kind"`
	Links      []interface{}          `json:"links"`
	Name       string                 `json:"name"`
	ParentID   string                 `json:"parent_id"`
	Resource   map[string]interface{} `json:"resource"`
	StartTime  string                 `json:"start_time"`
	Status     interface{}            `json:"status"`
}

func (h *HiAgentTraceConverter) Convert(byteArray models.ByteArray) (ptrace.Traces, error) {
	traces := ptrace.NewTraces()
	resourceSpans := traces.ResourceSpans().AppendEmpty()
	resourceSpans.Resource().Attributes().PutStr("from", "hiagent")
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()

	traceData := &HiAgentTraceData{}
	err := json.Unmarshal(byteArray, &traceData)
	if err == nil {
		if err := h.addSpanFromTraceData(traceData, scopeSpans); err != nil {
			return traces, fmt.Errorf("failed to create span from JSON object: %v", err)
		}
	} else {
		var traceDataArray []HiAgentTraceData
		if err := json.Unmarshal(byteArray, &traceDataArray); err != nil {
			return traces, fmt.Errorf("failed to parse input as JSON: %v", err)
		}

		for _, data := range traceDataArray {
			if err := h.addSpanFromTraceData(&data, scopeSpans); err != nil {
				logger.Warning(h.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "create span error", err)
				continue
			}
		}
	}
	return traces, nil
}

func (h *HiAgentTraceConverter) addSpanFromTraceData(traceData *HiAgentTraceData, scopeSpans ptrace.ScopeSpans) error {
	span := scopeSpans.Spans().AppendEmpty()

	// 1. Process basic fields
	// Parse trace_id, span_id, parent_id
	var traceID, spanID, parentID string

	// Get trace_id and span_id from Context
	if traceData.Context != nil {
		if tid, ok := traceData.Context["trace_id"].(string); ok {
			traceID = strings.TrimPrefix(tid, "0x")
		} else {
			logger.Error(h.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "missing trace_id in context")
			return fmt.Errorf("missing trace_id in context")
		}

		if sid, ok := traceData.Context["span_id"].(string); ok {
			spanID = strings.TrimPrefix(sid, "0x")
		} else {
			logger.Error(h.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "missing span_id in context")
			return fmt.Errorf("missing span_id in context")
		}
	} else {
		logger.Error(h.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "missing context in trace data")
		return fmt.Errorf("missing context in trace data")
	}

	// Get parent_id
	if traceData.ParentID != "" {
		parentID = strings.TrimPrefix(traceData.ParentID, "0x")
	}

	// Set span basic properties
	if traceIDBytes, err := hexToTraceID(traceID); err == nil {
		span.SetTraceID(traceIDBytes)
	} else {
		logger.Error(h.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "invalid trace_id format", traceID, err)
		return fmt.Errorf("invalid trace_id format: %s", traceID)
	}

	if spanIDBytes, err := hexToSpanID(spanID); err == nil {
		span.SetSpanID(spanIDBytes)
	} else {
		logger.Error(h.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "invalid span_id format", spanID, err)
		return fmt.Errorf("invalid span_id format: %s", spanID)
	}

	if parentID != "" {
		if parentIDBytes, err := hexToSpanID(parentID); err == nil {
			span.SetParentSpanID(parentIDBytes)
		} else {
			logger.Warning(h.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "invalid parent_id format", parentID, err)
		}
	}

	// Set name and type
	if traceData.Name != "" {
		span.SetName(traceData.Name)
	} else {
		span.SetName("unknown")
	}

	// Set Span kind
	if traceData.Kind != "" {
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
	}

	// Set timestamps
	startTimeNano := parseTimestamp(traceData.StartTime)
	endTimeNano := parseTimestamp(traceData.EndTime)

	// Ensure end time is greater than start time
	if endTimeNano <= startTimeNano {
		endTimeNano = startTimeNano + 1000000 // Add 1ms if no valid end time
	}

	span.SetStartTimestamp(pcommon.Timestamp(startTimeNano))
	span.SetEndTimestamp(pcommon.Timestamp(endTimeNano))

	// 2. Process attributes
	attributes := span.Attributes()
	if traceData.Attributes != nil {
		addAttributesToSpan(attributes, traceData.Attributes)

		// 3. Add Langfuse-specific attributes
		// These mappings are based on what Langfuse's OpenTelemetry consumer expects
		// Reference: https://langfuse.com/docs/opentelemetry/get-started

		// Model name mapping
		if model, ok := traceData.Attributes["model_name"].(string); ok {
			attributes.PutStr("gen_ai.request.model", model)
		} else if model, ok := traceData.Attributes["model"].(string); ok {
			attributes.PutStr("gen_ai.request.model", model)
		}

		// Input/output mapping
		if input, ok := traceData.Attributes["input"].(string); ok {
			attributes.PutStr("gen_ai.prompt", input)
		}

		if output, ok := traceData.Attributes["output"].(string); ok {
			attributes.PutStr("gen_ai.completion", output)
		}

		// Token usage mapping
		if inputTokens, ok := getTokenCount(traceData.Attributes, "input_tokens"); ok {
			attributes.PutInt("gen_ai.usage.prompt_tokens", inputTokens)
		}

		if outputTokens, ok := getTokenCount(traceData.Attributes, "output_tokens"); ok {
			attributes.PutInt("gen_ai.usage.completion_tokens", outputTokens)
		}

		// Latency mapping
		if latency, ok := getLatency(traceData.Attributes, "latency"); ok {
			attributes.PutDouble("gen_ai.latency_ms", latency)
		}

		// User ID and session ID mapping
		if userID, ok := traceData.Attributes["user_id"].(string); ok {
			attributes.PutStr("user.id", userID)
		}

		if convID, ok := traceData.Attributes["conversation_id"].(string); ok {
			attributes.PutStr("session.id", convID)
		}
	}

	// 4. Set status
	if traceData.Status != nil {
		// If status is a string
		if statusStr, ok := traceData.Status.(string); ok {
			if strings.ToUpper(statusStr) == "ERROR" {
				span.Status().SetCode(ptrace.StatusCodeError)
			} else {
				span.Status().SetCode(ptrace.StatusCodeOk)
			}
		} else if statusMap, ok := traceData.Status.(map[string]interface{}); ok {
			// If status is an object
			if statusCode, ok := statusMap["status_code"].(string); ok {
				if strings.ToUpper(statusCode) == "ERROR" {
					span.Status().SetCode(ptrace.StatusCodeError)
				} else {
					span.Status().SetCode(ptrace.StatusCodeOk)
				}
			}
		}
	} else {
		span.Status().SetCode(ptrace.StatusCodeOk)
	}

	return nil
}
