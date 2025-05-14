// Copyright 2024 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package log

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/alibaba/ilogtail/pkg/logger"
	"github.com/alibaba/ilogtail/test/config"
	"github.com/alibaba/ilogtail/test/engine/setup"
	"github.com/alibaba/ilogtail/test/engine/trigger"
)

func RegexSingle(ctx context.Context, totalLog int, path string, interval int) (context.Context, error) {
	return generate(ctx, "regex", path, totalLog, interval)
}

func RegexSingleGBK(ctx context.Context, totalLog int, path string, interval int) (context.Context, error) {
	return generate(ctx, "regexGBK", path, totalLog, interval)
}

func RegexMultiline(ctx context.Context, totalLog int, path string, interval int) (context.Context, error) {
	return generate(ctx, "regexMultiline", path, totalLog, interval)
}

func JSONSingle(ctx context.Context, totalLog int, path string, interval int) (context.Context, error) {
	return generate(ctx, "json", path, totalLog, interval)
}

func JSONMultiline(ctx context.Context, totalLog int, path string, interval int) (context.Context, error) {
	return generate(ctx, "jsonMultiline", path, totalLog, interval)
}

func Apsara(ctx context.Context, totalLog int, path string, interval int) (context.Context, error) {
	return generate(ctx, "apsara", path, totalLog, interval)
}

func DelimiterSingle(ctx context.Context, totalLog int, path string, interval int, delimiter, quote string) (context.Context, error) {
	return generate(ctx, "delimiter", path, totalLog, interval, "delimiter", delimiter, "quote", quote)
}

func DelimiterMultiline(ctx context.Context, totalLog int, path string, interval int, delimiter, quote string) (context.Context, error) {
	return generate(ctx, "delimiterMultiline", path, totalLog, interval, "delimiter", delimiter, "quote", quote)
}

func Nginx(ctx context.Context, rate, duration int, path string) (context.Context, error) {
	return generateBenchmark(ctx, "nginx", path, rate, duration)
}

func ChangeRotateInterval(ctx context.Context, interval int) (context.Context, error) {
	return context.WithValue(ctx, config.RotateIntervalKey, interval), nil
}

func generate(ctx context.Context, mode, path string, count, interval int, customKV ...string) (context.Context, error) {
	time.Sleep(3 * time.Second)
	customKVString := make(map[string]string)
	for i := 0; i < len(customKV); i += 2 {
		customKVString[customKV[i]] = customKV[i+1]
	}
	jsonStr, err := json.Marshal(customKVString)
	if err != nil {
		return ctx, err
	}
	rotateInterval := 30
	if ctx.Value(config.RotateIntervalKey) != nil {
		rotateInterval = ctx.Value(config.RotateIntervalKey).(int)
	}
	command := trigger.GetRunTriggerCommand("log", "file", "mode", mode, "path", path, "count", strconv.Itoa(count), "interval", strconv.Itoa(interval), "rotate", strconv.Itoa(rotateInterval), "custom", wrapperCustomArgs(string(jsonStr)))
	logger.Info(ctx, "Exec command", command)
	go func() {
		if _, err := setup.Env.ExecOnSource(ctx, command); err != nil {
			logger.Error(ctx, "EXEC_ALARM", "ExecOnSource failed", err.Error())
		}
	}()
	return ctx, nil
}

func generateBenchmark(ctx context.Context, mode, path string, rate, duration int, customKV ...string) (context.Context, error) {
	time.Sleep(3 * time.Second)
	customKVString := make(map[string]string)
	for i := 0; i < len(customKV); i += 2 {
		customKVString[customKV[i]] = customKV[i+1]
	}
	jsonStr, err := json.Marshal(customKVString)
	if err != nil {
		return ctx, err
	}
	command := trigger.GetRunTriggerCommand("log", "file_benchmark", "mode", mode, "path", path, "rate", strconv.Itoa(rate), "duration", strconv.Itoa(duration), "custom", wrapperCustomArgs(string(jsonStr)))
	go func() {
		if _, err := setup.Env.ExecOnSource(ctx, command); err != nil {
			logger.Error(ctx, "EXEC_ALARM", "ExecOnSource failed", err.Error())
		}
	}()
	return ctx, nil
}

func wrapperCustomArgs(customArgs string) string {
	customArgs = strings.ReplaceAll(customArgs, "\\", "\\\\")
	return "\"" + strings.ReplaceAll(customArgs, "\"", "\\\"") + "\""
}
