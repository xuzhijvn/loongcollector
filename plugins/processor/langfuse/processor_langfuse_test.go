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
	"testing"

	"github.com/alibaba/ilogtail/pkg/helper"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"github.com/alibaba/ilogtail/plugins/test/mock"
)

func init() {
	logger.InitTestLogger(logger.OptionOpenMemoryReceiver)
}

func newProcessor() (*ProcessorLangfuse, error) {
	ctx := mock.NewEmptyContext("p", "l", "c")
	processor := &ProcessorLangfuse{
		ServiceName: "test-service",
		IgnoreError: true,
	}
	err := processor.Init(ctx)
	return processor, err
}

// Create test data for JSON array format
func createArrayTestData() string {
	testData := `[
	{
		"_id": "1",
		"attributes": {
			"model_name": "gpt-4",
			"input": "Hello",
			"output": "Hi there",
			"input_tokens": 5,
			"output_tokens": 10,
			"latency": 200.5,
			"user_id": "user123",
			"conversation_id": "conv456"
		},
		"context": {
			"trace_id": "1234567890abcdef1234567890abcdef",
			"span_id": "1234567890abcdef"
		},
		"end_time": "2021-10-11T12:34:14Z",
		"events": [],
		"kind": "CLIENT",
		"links": [],
		"name": "test_span",
		"parent_id": "",
		"resource": {},
		"start_time": "2021-10-11T12:34:13Z",
		"status": {
			"status_code": "OK"
		}
	}
]`
	return testData
}

// Create test data for JSON object format
func createObjectTestData() string {
	testData := `{
		"_id": "2",
		"attributes": {
			"model_name": "gpt-3.5-turbo",
			"input": "What is the capital of France?",
			"output": "The capital of France is Paris.",
			"input_tokens": 7,
			"output_tokens": 8,
			"latency": 150.75,
			"user_id": "user456",
			"conversation_id": "conv789"
		},
		"context": {
			"trace_id": "abcdef1234567890abcdef1234567890",
			"span_id": "abcdef1234567890"
		},
		"end_time": "2021-11-12T13:45:15Z",
		"events": [],
		"kind": "INTERNAL",
		"links": [],
		"name": "single_object_span",
		"parent_id": "",
		"resource": {},
		"start_time": "2021-11-12T13:45:14Z",
		"status": {
			"status_code": "OK"
		}
	}`
	return testData
}

// Create test data for JSON object format
func createAiInterfaceObjectTestData() string {
	testData := `{
    "attributes": {
      "message_id": "01JVXBKBYHDPTW5QBQ53XG4HPB",
      "session_id": "aiinterface-test01",
      "conversation_id": "aiinterface-test01",
      "app_id": "000104"
    },
    "start_time": 1747963195170,
    "context": {
      "trace_id": "aiinterface-trace-test",
      "span_id": "59fc3f8f-356e-4536-af9f-1a443a119a9b"
    },
    "name": "ai-interface-168.64.26.52_2_1",
    "end_time": 1747963195369,
    "status": {
      "status_code": "OK"
    },
    "kind": "aiinterfaceTrace"
  }`
	return testData
}

// Test processing JSON array format data
func TestProcessorLangfuse_ProcessArray(t *testing.T) {
	// Prepare test data
	testData := createArrayTestData()
	processor, err := newProcessor()
	require.NoError(t, err)

	// Create input events
	inputGroup := &models.PipelineGroupEvents{
		Group:  models.NewGroup(models.NewMetadata(), models.NewTags()),
		Events: []models.PipelineEvent{models.ByteArray(testData)},
	}

	// Create test context
	context := helper.NewObservePipelineContext(10)
	processor.Process(inputGroup, context)

	// Verify events have been converted
	require.NotNil(t, inputGroup)
	require.GreaterOrEqual(t, len(inputGroup.Events), 1)

	// Check if there's an event of the correct type
	var span *models.Span
	for _, event := range inputGroup.Events {
		if s, ok := event.(*models.Span); ok {
			span = s
			break
		}
	}

	// Verify span conversion was successful
	assert.NotNil(t, span, "There should be at least one span event")

	if span != nil {
		// Verify basic span properties
		assert.Equal(t, "test_span", span.Name)
		assert.NotEmpty(t, span.TraceID)
		assert.NotEmpty(t, span.SpanID)

		// Verify specific attributes have been correctly mapped
		assert.Equal(t, "gpt-4", span.Tags.Get("gen_ai.request.model"))
		assert.Equal(t, "Hello", span.Tags.Get("gen_ai.prompt"))
		assert.Equal(t, "Hi there", span.Tags.Get("gen_ai.completion"))
		assert.Equal(t, "user123", span.Tags.Get("user.id"))
		assert.Equal(t, "conv456", span.Tags.Get("session.id"))
	}
}

// Test processing JSON object format data
func TestProcessorLangfuse_ProcessObject(t *testing.T) {
	// Prepare test data
	testData := createObjectTestData()
	processor, err := newProcessor()
	require.NoError(t, err)

	// Create input events
	inputGroup := &models.PipelineGroupEvents{
		Group:  models.NewGroup(models.NewMetadata(), models.NewTags()),
		Events: []models.PipelineEvent{models.ByteArray(testData)},
	}
	inputGroup.Group.Metadata.Add(models.KafkaMsgKey, KafkaMsgKeyHiAgentTrace)
	context := helper.NewObservePipelineContext(10)
	// Create test context
	processor.Process(inputGroup, context)

	// Verify events have been converted
	require.NotNil(t, inputGroup)
	require.GreaterOrEqual(t, len(inputGroup.Events), 1)

	// Check if there's an event of the correct type
	var span *models.Span
	for _, event := range inputGroup.Events {
		if s, ok := event.(*models.Span); ok {
			span = s
			break
		}
	}

	// Verify span conversion was successful
	assert.NotNil(t, span, "There should be at least one span event")

	if span != nil {
		// Verify basic span properties
		assert.Equal(t, "single_object_span", span.Name)
		assert.NotEmpty(t, span.TraceID)
		assert.NotEmpty(t, span.SpanID)

		// Verify specific attributes have been correctly mapped
		assert.Equal(t, "gpt-3.5-turbo", span.Tags.Get("gen_ai.request.model"))
		assert.Equal(t, "What is the capital of France?", span.Tags.Get("gen_ai.prompt"))
		assert.Equal(t, "The capital of France is Paris.", span.Tags.Get("gen_ai.completion"))
		assert.Equal(t, "user456", span.Tags.Get("user.id"))
		assert.Equal(t, "conv789", span.Tags.Get("session.id"))
	}
}

func TestHexToTraceID(t *testing.T) {
	tests := []struct {
		name    string
		hexStr  string
		wantErr bool
	}{
		{
			name:    "valid 32 chars trace ID",
			hexStr:  "1234567890abcdef1234567890abcdef",
			wantErr: false,
		},
		{
			name:    "valid shorter trace ID (will be padded)",
			hexStr:  "1234567890abcdef",
			wantErr: false,
		},
		{
			name:    "empty trace ID",
			hexStr:  "",
			wantErr: false,
		},
		{
			name:    "invalid hex chars",
			hexStr:  "1234567890abcdefX234567890abcdef",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexToTraceID(tt.hexStr)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tt.hexStr != "" {
				assert.NotEqual(t, [16]byte{}, got)
			}
		})
	}
}

func TestHexToSpanID(t *testing.T) {
	tests := []struct {
		name    string
		hexStr  string
		wantErr bool
	}{
		{
			name:    "valid 16 chars span ID",
			hexStr:  "1234567890abcdef",
			wantErr: false,
		},
		{
			name:    "valid shorter span ID (will be padded)",
			hexStr:  "1234567890",
			wantErr: false,
		},
		{
			name:    "empty span ID",
			hexStr:  "",
			wantErr: false,
		},
		{
			name:    "invalid hex chars",
			hexStr:  "1234567890abcdeX",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexToSpanID(tt.hexStr)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if tt.hexStr != "" {
				assert.NotEqual(t, [8]byte{}, got)
			}
		})
	}
}

func TestDescription(t *testing.T) {
	processor, err := newProcessor()
	require.NoError(t, err)
	assert.Equal(t, processor.Description(), "processor that converts JSON trace data to Langfuse-compatible OTLP format")
}

func TestInit(t *testing.T) {
	p := pipeline.Processors[pluginName]()
	assert.Equal(t, "langfuse.ProcessorLangfuse", p.(*ProcessorLangfuse).String())
}

// String returns the string representation of the processor type (for testing)
func (p *ProcessorLangfuse) String() string {
	return "langfuse.ProcessorLangfuse"
}
