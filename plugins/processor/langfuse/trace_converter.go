package langfuse

import (
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

type TraceConverter interface {
	Convert(byteArray models.ByteArray) (ptrace.Traces, error)
}

func GetTraceConverter(context pipeline.Context, kafkaMsgKey string) TraceConverter {
	switch kafkaMsgKey {
	case KafkaMsgKeyAiInterfaceTrace:
		return &AiBagTraceConverter{
			context: context,
		}
	case KafkaMsgKeyHiAgentTrace:
		fallthrough
	default:
		return &HiAgentTraceConverter{
			context: context,
		}
	}
}
