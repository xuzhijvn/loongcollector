package langfuse

import (
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace"
	ptraceotlp "go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/pkg/models"
	"github.com/alibaba/ilogtail/pkg/pipeline"
	"github.com/alibaba/ilogtail/pkg/pipeline/extensions"
	conv "github.com/alibaba/ilogtail/pkg/protocol/converter"
	httpflusher "github.com/alibaba/ilogtail/plugins/flusher/http"
)

type Mode string

const (
	ModeOTLP   Mode = "otlp"
	ModeIngest Mode = "ingest"
)

type FlusherLangfuse struct {
	Mode        Mode              `json:"Mode"`
	Endpoint    string            `json:"Endpoint"`
	Headers     map[string]string `json:"Headers"`
	Timeout     time.Duration     `json:"Timeout"`
	ContentType string            `json:"ContentType"`

	context     pipeline.Context
	converter   *conv.Converter
	FlusherHTTP *httpflusher.FlusherHTTP
}

func (f *FlusherLangfuse) Description() string {
	return "Langfuse flusher for both OTLP/HTTP and Ingestion API modes"
}

func (f *FlusherLangfuse) Init(ctx pipeline.Context) error {
	f.context = ctx
	if f.Endpoint == "" {
		return fmt.Errorf("langfuse flusher: endpoint is required")
	}
	if f.Timeout == 0 {
		f.Timeout = 30 * time.Second
	}
	if f.Mode == "" {
		f.Mode = ModeOTLP
	}
	if f.ContentType == "" {
		if f.Mode == ModeOTLP {
			f.ContentType = "application/x-protobuf"
		} else {
			f.ContentType = "application/json"
		}
	}

	f.FlusherHTTP = httpflusher.NewHTTPFlusher()
	f.FlusherHTTP.RemoteURL = f.Endpoint
	f.FlusherHTTP.Timeout = f.Timeout
	f.FlusherHTTP.Headers = f.Headers

	// 设置Encoder
	if f.Mode == ModeOTLP {
		encoderType := "ext_default_encoder"
		encoderOptions := map[string]interface{}{"Format": "otlp"}
		if f.ContentType == "application/json" {
			encoderOptions["Encoding"] = "json"
		} else {
			encoderOptions["Encoding"] = "protobuf"
		}
		f.FlusherHTTP.Encoder = &extensions.ExtensionConfig{
			Type:    encoderType,
			Options: encoderOptions,
		}
	} else {
		f.FlusherHTTP.Encoder = &extensions.ExtensionConfig{
			Type:    "ext_default_encoder",
			Options: map[string]interface{}{"Format": "json"},
		}
	}

	if err := f.FlusherHTTP.Init(ctx); err != nil {
		return fmt.Errorf("langfuse flusher: http flusher init failed: %v", err)
	}

	if f.Mode == ModeOTLP {
		var err error
		f.converter, err = conv.NewConverter(conv.ProtocolOtlpV1, conv.EncodingNone, nil, nil, ctx.GetPipelineScopeConfig())
		if err != nil {
			return fmt.Errorf("langfuse flusher: failed to create converter: %v", err)
		}
	}

	logger.Info(f.context.GetRuntimeContext(), "langfuse flusher init", "endpoint", f.Endpoint, "mode", f.Mode, "content_type", f.ContentType)
	return nil
}

func (f *FlusherLangfuse) Export(groupEventsArray []*models.PipelineGroupEvents, ctx pipeline.PipelineContext) error {
	switch f.Mode {
	case ModeOTLP:
		traces := ptrace.NewTraces()
		for _, group := range groupEventsArray {
			_, _, resourceTrace, err := conv.ConvertPipelineEventToOtlpEvent(f.converter, group)
			if err != nil {
				logger.Error(f.context.GetRuntimeContext(), "FLUSHER_LANGFUSE_OTLP_ALARM", "convert pipeline event fail", err)
				continue
			}
			if resourceTrace.ScopeSpans().Len() > 0 {
				newTrace := traces.ResourceSpans().AppendEmpty()
				resourceTrace.MoveTo(newTrace)
			}
		}
		if traces.ResourceSpans().Len() == 0 {
			return nil
		}
		// 组装为PipelineGroupEvents，交给FlusherHTTP处理
		req := ptraceotlp.NewExportRequestFromTraces(traces)
		tracesBytes, err := req.MarshalProto()
		if err != nil {
			logger.Error(f.context.GetRuntimeContext(), "FLUSHER_LANGFUSE_OTLP_ALARM", "marshal traces fail", err)
			return err
		}
		fakeGroup := &models.PipelineGroupEvents{
			Events: []models.PipelineEvent{models.ByteArray(tracesBytes)},
		}
		return f.FlusherHTTP.Export([]*models.PipelineGroupEvents{fakeGroup}, ctx)
	case ModeIngest:
		return f.FlusherHTTP.Export(groupEventsArray, ctx)
	default:
		return fmt.Errorf("unsupported langfuse flusher mode: %s", f.Mode)
	}
}

func (f *FlusherLangfuse) SetUrgent(flag bool) {
	if f.FlusherHTTP != nil {
		f.FlusherHTTP.SetUrgent(flag)
	}
}

func (f *FlusherLangfuse) IsReady(projectName string, logstoreName string, logstoreKey int64) bool {
	if f.FlusherHTTP != nil {
		return f.FlusherHTTP.IsReady(projectName, logstoreName, logstoreKey)
	}
	return false
}

func (f *FlusherLangfuse) Stop() error {
	if f.FlusherHTTP != nil {
		return f.FlusherHTTP.Stop()
	}
	return nil
}

func init() {
	pipeline.Flushers["flusher_langfuse"] = func() pipeline.Flusher {
		return &FlusherLangfuse{}
	}
}
