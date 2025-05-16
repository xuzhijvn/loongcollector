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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"github.com/alibaba/ilogtail/pkg/protocol"
	"github.com/alibaba/ilogtail/pkg/protocol/decoder/opentelemetry"
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

// TraceData represents the input JSON object structure
type TraceData struct {
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
		converted, err := p.convertEvent(in.Events[i])
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

func (p *ProcessorLangfuse) convertEvent(event models.PipelineEvent) ([]models.PipelineEvent, error) {
	switch e := event.(type) {
	case models.ByteArray:
		return p.convertByteArray(e)
	case *models.Log:
		return p.convertLog(e)
	default:
		return []models.PipelineEvent{event}, fmt.Errorf("unsupported event type: %T", e)
	}
}

func (p *ProcessorLangfuse) convertByteArray(data models.ByteArray) ([]models.PipelineEvent, error) {
	// Create OTLP Trace structure
	traces := ptrace.NewTraces()
	resourceSpans := traces.ResourceSpans().AppendEmpty()

	// Add service name and other resource attributes
	resourceAttrs := resourceSpans.Resource().Attributes()
	resourceAttrs.PutStr("service.name", p.ServiceName)

	// Create ScopeSpans
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()
	scopeSpans.Scope().SetName("loongcollector")
	scopeSpans.Scope().SetVersion("1.0.0")

	// Try to parse the JSON data
	var traceData TraceData
	err := json.Unmarshal(data, &traceData)
	if err == nil {
		// Convert object to Span
		if err := p.addSpanFromTraceData(traceData, scopeSpans); err != nil {
			return nil, fmt.Errorf("failed to create span from JSON object: %v", err)
		}
	} else {
		// Try to parse as JSON array
		var traceDataArray []TraceData
		if err := json.Unmarshal(data, &traceDataArray); err != nil {
			return nil, fmt.Errorf("failed to parse input as JSON: %v", err)
		}

		// Process each object in the array
		for _, traceData := range traceDataArray {
			if err := p.addSpanFromTraceData(traceData, scopeSpans); err != nil {
				logger.Warning(p.context.GetRuntimeContext(), "LANGFUSE_PROCESSOR_ALARM", "create span error", err)
				continue
			}
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

func (p *ProcessorLangfuse) addSpanFromTraceData(traceData TraceData, scopeSpans ptrace.ScopeSpans) error {
	span := scopeSpans.Spans().AppendEmpty()

	// 1. Process basic fields
	// Parse trace_id, span_id, parent_id
	var traceID, spanID, parentID string

	// Get trace_id and span_id from Context
	if traceData.Context != nil {
		if tid, ok := traceData.Context["trace_id"].(string); ok {
			traceID = strings.TrimPrefix(tid, "0x")
		}
		if sid, ok := traceData.Context["span_id"].(string); ok {
			spanID = strings.TrimPrefix(sid, "0x")
		}
	}

	// Get parent_id
	if traceData.ParentID != "" {
		parentID = strings.TrimPrefix(traceData.ParentID, "0x")
	}

	// Set span basic properties
	if traceIDBytes, err := hexToTraceID(traceID); err == nil {
		span.SetTraceID(pcommon.TraceID(traceIDBytes))
	}

	if spanIDBytes, err := hexToSpanID(spanID); err == nil {
		span.SetSpanID(pcommon.SpanID(spanIDBytes))
	}

	if parentIDBytes, err := hexToSpanID(parentID); err == nil && parentID != "" {
		span.SetParentSpanID(pcommon.SpanID(parentIDBytes))
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
		case "CLIENT", "SPAN_KIND_CLIENT":
			span.SetKind(ptrace.SpanKindClient)
		case "SERVER", "SPAN_KIND_SERVER":
			span.SetKind(ptrace.SpanKindServer)
		case "PRODUCER", "SPAN_KIND_PRODUCER":
			span.SetKind(ptrace.SpanKindProducer)
		case "CONSUMER", "SPAN_KIND_CONSUMER":
			span.SetKind(ptrace.SpanKindConsumer)
		case "INTERNAL", "SPAN_KIND_INTERNAL":
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

// Convert hex string to appropriate byte array based on specified length
func hexToTraceID(hexStr string) ([16]byte, error) {
	var result [16]byte

	if hexStr == "" {
		return result, nil
	}

	// Ensure string length is 32 (16 bytes)
	if len(hexStr) != 32 {
		hexStr = strings.Repeat("0", 32-len(hexStr)) + hexStr
	}

	// Parse byte by byte
	for i := 0; i < 16; i++ {
		start := i * 2
		end := start + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}

		b, err := strconv.ParseUint(hexStr[start:end], 16, 8)
		if err != nil {
			return result, err
		}

		result[i] = byte(b)
	}

	return result, nil
}

func hexToSpanID(hexStr string) ([8]byte, error) {
	var result [8]byte

	if hexStr == "" {
		return result, nil
	}

	// Ensure string length is 16 (8 bytes)
	if len(hexStr) != 16 {
		hexStr = strings.Repeat("0", 16-len(hexStr)) + hexStr
	}

	// Parse byte by byte
	for i := 0; i < 8; i++ {
		start := i * 2
		end := start + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}

		b, err := strconv.ParseUint(hexStr[start:end], 16, 8)
		if err != nil {
			return result, err
		}

		result[i] = byte(b)
	}

	return result, nil
}

// Parse timestamp string to nanosecond timestamp
func parseTimestamp(tsStr string) uint64 {
	if tsStr == "" {
		return uint64(time.Now().UnixNano())
	}

	// Try parsing RFC3339 format
	if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
		return uint64(t.UnixNano())
	}

	// Try parsing scientific notation format
	var ts float64
	if _, err := fmt.Sscanf(tsStr, "%e", &ts); err == nil {
		return uint64(ts)
	}

	// Try parsing integer format
	if ts, err := strconv.ParseUint(tsStr, 10, 64); err == nil {
		// Check if it's a second-level timestamp (less than 10^12)
		if ts < 1_000_000_000_000 {
			return ts * 1_000_000_000 // Convert to nanoseconds
		}
		return ts
	}

	// Default to current time
	return uint64(time.Now().UnixNano())
}

// Add attributes to Span
func addAttributesToSpan(attrs pcommon.Map, values map[string]interface{}) {
	for k, v := range values {
		switch val := v.(type) {
		case string:
			attrs.PutStr(k, val)
		case bool:
			attrs.PutBool(k, val)
		case int:
			attrs.PutInt(k, int64(val))
		case int64:
			attrs.PutInt(k, val)
		case float64:
			attrs.PutDouble(k, val)
		case map[string]interface{}:
			jsonBytes, _ := json.Marshal(val)
			attrs.PutStr(k, string(jsonBytes))
		case []interface{}:
			jsonBytes, _ := json.Marshal(val)
			attrs.PutStr(k, string(jsonBytes))
		default:
			attrs.PutStr(k, fmt.Sprintf("%v", val))
		}
	}
}

// Extract token count from attributes
func getTokenCount(attrs map[string]interface{}, key string) (int64, bool) {
	if val, ok := attrs[key]; ok {
		switch v := val.(type) {
		case float64:
			return int64(v), true
		case int:
			return int64(v), true
		case int64:
			return v, true
		case string:
			if count, err := strconv.ParseInt(v, 10, 64); err == nil {
				return count, true
			}
		}
	}
	return 0, false
}

// Extract latency from attributes
func getLatency(attrs map[string]interface{}, key string) (float64, bool) {
	if val, ok := attrs[key]; ok {
		switch v := val.(type) {
		case float64:
			return v, true
		case int:
			return float64(v), true
		case int64:
			return float64(v), true
		case string:
			if latency, err := strconv.ParseFloat(v, 64); err == nil {
				return latency, true
			}
		}
	}
	return 0, false
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
