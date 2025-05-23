// Copyright 2021 iLogtail Authors
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

package pipeline

import "github.com/alibaba/ilogtail/pkg/selfmonitor"

// logtail plugin type define
const (
	MetricInputType  = iota
	ServiceInputType = iota
	FilterType       = iota
	ProcessorType    = iota
	AggregatorType   = iota
)

type PluginContext struct {
	ID           string
	Priority     int
	MetricRecord *selfmonitor.MetricsRecord
}

type PluginMeta struct {
	PluginID         string
	PluginType       string
	PluginTypeWithID string
}

type MetricCreator func() MetricInput

var MetricInputs = map[string]MetricCreator{}

func AddMetricCreator(name string, creator MetricCreator) {
	MetricInputs[name] = creator
}

type ServiceCreator func() ServiceInput

var ServiceInputs = map[string]ServiceCreator{}

func AddServiceCreator(name string, creator ServiceCreator) {
	ServiceInputs[name] = creator
}

type ProcessorCreator func() Processor

var Processors = map[string]ProcessorCreator{}

func AddProcessorCreator(name string, creator ProcessorCreator) {
	Processors[name] = creator
}

type AggregatorCreator func() Aggregator

var Aggregators = map[string]AggregatorCreator{}

func AddAggregatorCreator(name string, creator AggregatorCreator) {
	Aggregators[name] = creator
}

type FlusherCreator func() Flusher

var Flushers = map[string]FlusherCreator{}

func AddFlusherCreator(name string, creator FlusherCreator) {
	Flushers[name] = creator
}

type ExtensionCreator func() Extension

var Extensions = map[string]ExtensionCreator{}

func AddExtensionCreator(name string, creator ExtensionCreator) {
	Extensions[name] = creator
}

func GetPluginCommonLabels(context Context, pluginMeta *PluginMeta) []selfmonitor.LabelPair {
	labels := make([]selfmonitor.LabelPair, 0)
	labels = append(labels, selfmonitor.LabelPair{Key: selfmonitor.MetricLabelKeyMetricCategory, Value: selfmonitor.MetricLabelValueMetricCategoryPlugin})
	labels = append(labels, selfmonitor.LabelPair{Key: selfmonitor.MetricLabelKeyProject, Value: context.GetProject()})
	labels = append(labels, selfmonitor.LabelPair{Key: selfmonitor.MetricLabelKeyLogstore, Value: context.GetLogstore()})
	labels = append(labels, selfmonitor.LabelPair{Key: selfmonitor.MetricLabelKeyPipelineName, Value: context.GetConfigName()})

	if len(pluginMeta.PluginID) > 0 {
		labels = append(labels, selfmonitor.LabelPair{Key: selfmonitor.MetricLabelKeyPluginID, Value: pluginMeta.PluginID})
	}
	if len(pluginMeta.PluginType) > 0 {
		labels = append(labels, selfmonitor.LabelPair{Key: selfmonitor.MetricLabelKeyPluginType, Value: pluginMeta.PluginType})
	}
	return labels
}
