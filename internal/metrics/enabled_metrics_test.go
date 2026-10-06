// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package metrics

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	internaltesting "github.com/envoyproxy/ai-gateway/internal/testing"
)

func TestParseEnabledMetrics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		expect []string
		err    string
	}{
		{name: "empty", input: "", expect: nil},
		{name: "only separators", input: " , ,", expect: nil},
		{
			name:   "trims and dedupes",
			input:  " gen_ai.client.token.usage , gen_ai.server.time_to_first_token,gen_ai.client.token.usage",
			expect: []string{genaiMetricClientTokenUsage, genaiMetricServerTimeToFirstToken},
		},
		{name: "mcp", input: "mcp.request.duration", expect: []string{mcpRequestDuration}},
		{name: "prometheus name is rejected", input: "gen_ai_client_token_usage", err: `unknown metric "gen_ai_client_token_usage"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEnabledMetrics(tc.input)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect, got)
		})
	}
}

func TestNewMeterFromEnv_EnabledMetrics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled []string
		expect  []string
	}{
		{
			name: "all by default",
			expect: []string{
				genaiMetricClientTokenUsage, genaiMetricServerRequestDuration,
				genaiMetricServerTimeToFirstToken, genaiMetricServerTimePerOutputToken,
			},
		},
		{
			name:    "subset",
			enabled: []string{genaiMetricClientTokenUsage, genaiMetricServerTimeToFirstToken},
			expect:  []string{genaiMetricClientTokenUsage, genaiMetricServerTimeToFirstToken},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			internaltesting.ClearTestEnv(t)
			reader := sdkmetric.NewManualReader()
			meter, shutdown, err := NewMeterFromEnv(t.Context(), io.Discard, reader, tc.enabled)
			require.NoError(t, err)
			t.Cleanup(func() { _ = shutdown(context.Background()) })

			g := newGenAI(meter)
			g.tokenUsage.Record(t.Context(), 1)
			g.requestLatency.Record(t.Context(), 1)
			g.firstTokenLatency.Record(t.Context(), 1)
			g.outputTokenLatency.Record(t.Context(), 1)

			var rm metricdata.ResourceMetrics
			require.NoError(t, reader.Collect(t.Context(), &rm))
			var got []string
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					got = append(got, m.Name)
				}
			}
			require.ElementsMatch(t, tc.expect, got)
		})
	}
}
