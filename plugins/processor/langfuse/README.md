# LangFuse处理器插件

## 简介

LangFuse处理器插件负责将JSON格式的追踪数据转换为Langfuse兼容的OpenTelemetry格式。Langfuse是一个专为LLM应用设计的观测工具，提供追踪、评估和监控功能。

该处理器既可以解析JSON数组格式的追踪数据，也支持单个JSON对象格式，并将其转换为Langfuse可识别的OTLP格式，以便进行LLM应用的监控和性能分析。

## 参数说明

参数 | 类型 | 是否必选 | 说明
--- | --- | --- | ---
ServiceName | String | 否 | 服务名称，将被添加到资源属性中，默认为"loongcollector"
IgnoreError | Boolean | 否 | 是否忽略处理错误，默认为true

## 样例

### 输入格式示例

#### JSON数组格式
```json
[
  {
    "_id": "9eDUaJQBVbNa3ZRbYAev",
    "attributes": {
      "model_name": "glm4-130b-chat",
      "input": "Hello",
      "output": "Hi there",
      "input_tokens": 5,
      "output_tokens": 10,
      "latency": 200.5,
      "user_id": "user123",
      "conversation_id": "conv456"
    },
    "context": {
      "span_id": "0xe25a125f37394d2a",
      "trace_id": "0xea8d9a2d2426986a4da353ebb3f7efda",
      "trace_state": "[]"
    },
    "end_time": "2025-01-15T07:18:53.596585Z",
    "events": [],
    "kind": "SpanKind.INTERNAL",
    "links": [],
    "name": "UserInput",
    "parent_id": "",
    "resource": {
      "attributes": {
        "service.name": "runtime-server"
      },
      "schema_url": ""
    },
    "start_time": "2025-01-15T07:18:17.714786Z",
    "status": {
      "status_code": "OK"
    }
  }
]
```

#### 单个JSON对象格式
```json
{
  "_id": "8-DUaJQBVbNa3ZRbYAev",
  "attributes": {
    "model_name": "glm4-130b-chat",
    "input": "用500字以内的文字表述指标如何变动、以及原因推测，给出具体的数据",
    "output": "根据历史对话中提供的数据，我将精准提取并分析昨日全渠道日活数据与近30日均值数据...",
    "input_tokens": 2461,
    "output_tokens": 610,
    "latency": 29746,
    "user_id": "8979",
    "conversation_id": "01JHMAFPCKXQP8P865DW34SQ6V"
  },
  "context": {
    "span_id": "0x2e3a27782d894cd4",
    "trace_id": "0xea8d9a2d2426986a4da353ebb3f7efda",
    "trace_state": "[]"
  },
  "end_time": "2025-01-15T07:18:47.505618Z",
  "events": [],
  "kind": "SpanKind.INTERNAL",
  "links": [],
  "name": "glm4-130b-chat",
  "parent_id": "0xe25a125f37394d2a",
  "resource": {
    "attributes": {
      "service.name": "runtime-server"
    },
    "schema_url": ""
  },
  "start_time": "2025-01-15T07:18:17.758620Z",
  "status": {
    "status_code": "OK"
  }
}
```

### 配置示例

```json
{
  "inputs": [
    {
      "type": "service_http",
      "detail": {
        "Address": "0.0.0.0:8080",
        "ReadTimeout": 10,
        "WriteTimeout": 10
      }
    }
  ],
  "processors": [
    {
      "type": "processor_langfuse",
      "detail": {
        "ServiceName": "my-llm-service",
        "IgnoreError": true
      }
    }
  ],
  "flushers": [
    {
      "type": "flusher_otlp",
      "detail": {
        "Traces": {
          "Endpoint": "langfuse.example.com:4317"
        }
      }
    }
  ]
}
```

## 工作原理

LangFuse处理器将执行以下步骤：

1. 尝试将输入解析为单个JSON对象或JSON数组
2. 创建OpenTelemetry Trace数据结构
3. 将JSON对象中的字段映射到OTLP Span中
4. 进行特定的字段转换，将LLM相关字段（如模型名称、输入/输出、token计数）映射到Langfuse期望的格式
5. 将处理后的数据转换为标准Span事件

## Langfuse字段映射

LangFuse处理器会执行以下字段映射：

* `model_name` -> `gen_ai.request.model`
* `input` -> `gen_ai.prompt`
* `output` -> `gen_ai.completion`
* `input_tokens` -> `gen_ai.usage.prompt_tokens`
* `output_tokens` -> `gen_ai.usage.completion_tokens`
* `latency` -> `gen_ai.latency_ms`
* `user_id` -> `user.id`
* `conversation_id` -> `session.id`

更多关于Langfuse的信息，请参考[Langfuse文档](https://langfuse.com/docs/opentelemetry/get-started)。 