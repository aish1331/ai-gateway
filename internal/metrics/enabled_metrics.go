// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package metrics

import (
	"fmt"
	"slices"
	"strings"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// knownMetricNames lists every instrument registered by the external processor.
var knownMetricNames = []string{
	genaiMetricClientTokenUsage,
	genaiMetricServerRequestDuration,
	genaiMetricServerTimeToFirstToken,
	genaiMetricServerTimePerOutputToken,
	mcpRequestDuration,
	mcpMethodCount,
	mcpInitializationDuration,
	mcpCapabilitiesNegotiated,
	mpcProgressNotifications,
}

// ParseEnabledMetrics parses a comma-separated list of OpenTelemetry metric names, e.g.
// "gen_ai.client.token.usage,gen_ai.server.time_to_first_token". An empty string returns nil,
// which means all metrics are enabled.
func ParseEnabledMetrics(s string) ([]string, error) {
	var enabled []string
	for name := range strings.SplitSeq(s, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !slices.Contains(knownMetricNames, name) {
			return nil, fmt.Errorf("unknown metric %q, must be one of: %s", name, strings.Join(knownMetricNames, ", "))
		}
		if !slices.Contains(enabled, name) {
			enabled = append(enabled, name)
		}
	}
	return enabled, nil
}

// enabledMetricsView drops every instrument not in enabled. Dropped instruments keep no
// aggregation state, so recording to them costs nothing and they are absent from all readers.
func enabledMetricsView(enabled []string) sdkmetric.View {
	return func(inst sdkmetric.Instrument) (sdkmetric.Stream, bool) {
		if slices.Contains(enabled, inst.Name) {
			return sdkmetric.Stream{}, false
		}
		return sdkmetric.Stream{Aggregation: sdkmetric.AggregationDrop{}}, true
	}
}
