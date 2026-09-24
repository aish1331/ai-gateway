// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extensionserver

import (
	"testing"

	egextension "github.com/envoyproxy/gateway/proto/extension"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	htomv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	httpconnectionmanagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/envoyproxy/ai-gateway/internal/internalapi"
)

func TestServer_createBackendListener(t *testing.T) {
	tests := []struct {
		name             string
		mcpHTTPFilters   []*httpconnectionmanagerv3.HttpFilter
		accessLogConfig  []*accesslogv3.AccessLog
		expectedListener *listenerv3.Listener
	}{
		{
			name:           "no filters",
			mcpHTTPFilters: nil,
			expectedListener: &listenerv3.Listener{
				Name: mcpBackendListenerName,
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Protocol: corev3.SocketAddress_TCP,
							Address:  "127.0.0.1",
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: internalapi.MCPBackendListenerPort,
							},
						},
					},
				},
			},
		},
		{
			name:           "no filters with access logs",
			mcpHTTPFilters: nil,
			accessLogConfig: []*accesslogv3.AccessLog{
				{Name: "accesslog1"},
				{Name: "accesslog2"},
			},
			expectedListener: &listenerv3.Listener{
				Name: mcpBackendListenerName,
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Protocol: corev3.SocketAddress_TCP,
							Address:  "127.0.0.1",
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: internalapi.MCPBackendListenerPort,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{log: testr.New(t)}
			listener, err := s.createBackendListener(tt.mcpHTTPFilters, tt.accessLogConfig)
			require.NoError(t, err)

			require.Equal(t, tt.expectedListener.Name, listener.Name)
			require.Equal(t, tt.expectedListener.Address.GetSocketAddress().Address, listener.Address.GetSocketAddress().Address)
			require.Equal(t, tt.expectedListener.Address.GetSocketAddress().GetPortValue(), listener.Address.GetSocketAddress().GetPortValue())
			require.Equal(t, tt.expectedListener.Address.GetSocketAddress().Protocol, listener.Address.GetSocketAddress().Protocol)

			hcm, _, err := findHCM(listener.FilterChains[0])
			require.NoError(t, err)
			require.True(t, hcm.GetSchemeHeaderTransformation().GetMatchUpstream(), "SchemeHeaderTransformation.MatchUpstream should be true")
			require.Len(t, hcm.AccessLog, len(tt.accessLogConfig))
			for i := range tt.accessLogConfig {
				require.Equal(t, tt.accessLogConfig[i].Name, hcm.AccessLog[i].Name)
			}
		})
	}
}

func TestServer_createRoutesForBackendListener(t *testing.T) {
	tests := []struct {
		name          string
		routes        []*routev3.RouteConfiguration
		expectedRoute *routev3.RouteConfiguration
	}{
		{
			name:          "empty",
			routes:        []*routev3.RouteConfiguration{},
			expectedRoute: nil,
		},
		{
			name: "no MCP routes",
			routes: []*routev3.RouteConfiguration{
				{
					VirtualHosts: []*routev3.VirtualHost{
						{
							Name:   "test-vh",
							Routes: []*routev3.Route{{Name: "normal"}},
						},
					},
				},
			},
			expectedRoute: nil,
		},
		{
			name: "with MCP routes",
			routes: []*routev3.RouteConfiguration{
				{
					VirtualHosts: []*routev3.VirtualHost{
						{
							Name:   "test-vh",
							Routes: []*routev3.Route{{Name: "normal"}},
						},
					},
				},
				{
					VirtualHosts: []*routev3.VirtualHost{
						{
							Name:    "mcp-vh",
							Domains: []string{"*"},
							Routes: []*routev3.Route{
								{
									Name: internalapi.MCPPerBackendRefHTTPRoutePrefix + "foo/rule/0",
									Action: &routev3.Route_Route{
										Route: &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_Cluster{}},
									},
								},
								{
									Name: internalapi.MCPPerBackendRefHTTPRoutePrefix + "bar/rule/1",
									Action: &routev3.Route_Route{
										Route: &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_Cluster{}},
									},
								},
							},
						},
					},
				},
			},
			expectedRoute: &routev3.RouteConfiguration{
				Name: "aigateway-mcp-backend-listener-route-config",
				VirtualHosts: []*routev3.VirtualHost{
					{
						Domains: []string{"*"},
						Name:    "aigateway-mcp-backend-listener-wildcard",
						Routes: []*routev3.Route{
							{Name: internalapi.MCPPerBackendRefHTTPRoutePrefix + "foo/rule/0", Action: &routev3.Route_Route{
								Route: &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_Cluster{}},
							}},
							{Name: internalapi.MCPPerBackendRefHTTPRoutePrefix + "bar/rule/1", Action: &routev3.Route_Route{
								Route: &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_Cluster{}},
							}},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{log: testr.New(t)}
			route := s.createRoutesForBackendListener(tt.routes)
			if tt.expectedRoute == nil {
				require.Nil(t, route)
			} else {
				require.Empty(t, cmp.Diff(tt.expectedRoute, route, protocmp.Transform()))
			}
		})
	}
}

// rewrittenMCPProxyCluster is what modifyMCPGatewayGeneratedCluster must leave behind: a static
// cluster pointing at the in-pod proxy on localhost.
func rewrittenMCPProxyCluster(name string) *clusterv3.Cluster {
	return &clusterv3.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
		ConnectTimeout:       &durationpb.Duration{Seconds: 10},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &corev3.Address{
										Address: &corev3.Address_SocketAddress{
											SocketAddress: &corev3.SocketAddress{
												Address:       "127.0.0.1",
												PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: internalapi.MCPProxyPort},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestServer_mcpProxyClusterNames(t *testing.T) {
	// Envoy Gateway serves the proxy Backend's IP endpoint over EDS, so the clusters carry no
	// address and the routes are the only place the proxy-bound rules can be recognized.
	routes := []*routev3.RouteConfiguration{
		{
			VirtualHosts: []*routev3.VirtualHost{
				{
					Name: "vh",
					Routes: []*routev3.Route{
						// The MCP endpoint and the protected resource metadata endpoint both
						// forward to the shared proxy Backend, on whichever rule index they land.
						forwardingMCPRoute(internalapi.MCPMainHTTPRoutePrefix+"foo/rule/0", "cluster/rule/0"),
						forwardingMCPRoute(internalapi.MCPMainHTTPRoutePrefix+"foo/rule/1", "cluster/rule/1"),
						// The remaining discovery documents are direct responses, so no cluster.
						{Name: internalapi.MCPMainHTTPRoutePrefix + "foo/rule/2", Action: &routev3.Route_DirectResponse{
							DirectResponse: &routev3.DirectResponseAction{Status: 200},
						}},
						// Not the main MCP HTTPRoute.
						forwardingMCPRoute(internalapi.MCPPerBackendRefHTTPRoutePrefix+"foo/rule/0", "cluster/backend"),
						forwardingMCPRoute("httproute/ns/user-route/rule/0", "cluster/user"),
					},
				},
			},
		},
	}

	require.Equal(t, map[string]bool{"cluster/rule/0": true, "cluster/rule/1": true}, mcpProxyClusterNames(routes))
}

func forwardingMCPRoute(name, cluster string) *routev3.Route {
	return &routev3.Route{
		Name: name,
		Action: &routev3.Route_Route{Route: &routev3.RouteAction{
			ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: cluster},
		}},
	}
}

func TestServer_modifyMCPGatewayGeneratedCluster(t *testing.T) {
	const (
		mcpRule0 = internalapi.MCPMainHTTPRoutePrefix + "foo-bar/rule/0"
		mcpRule1 = internalapi.MCPMainHTTPRoutePrefix + "foo-bar/rule/1"
	)
	// The OAuth metadata rule is not rule/0, and used to be left pointing at the unroutable
	// placeholder Backend, which made the metadata endpoint hang.
	clusters := []*clusterv3.Cluster{
		{Name: "normal-cluster"},
		{Name: mcpRule0},
		{Name: mcpRule1},
		{Name: internalapi.MCPPerBackendRefHTTPRoutePrefix + "foo-bar/rule/0"},
	}

	s := &Server{log: testr.New(t)}
	s.modifyMCPGatewayGeneratedCluster(clusters, map[string]bool{mcpRule0: true, mcpRule1: true})

	require.Empty(t, cmp.Diff([]*clusterv3.Cluster{
		{Name: "normal-cluster"},
		rewrittenMCPProxyCluster(mcpRule0),
		rewrittenMCPProxyCluster(mcpRule1),
		{Name: internalapi.MCPPerBackendRefHTTPRoutePrefix + "foo-bar/rule/0"},
	}, clusters, protocmp.Transform()))
}

func TestServer_isMCPBackendHTTPFilter(t *testing.T) {
	tests := []struct {
		name     string
		filter   *httpconnectionmanagerv3.HttpFilter
		expected bool
	}{
		{
			name:     "MCP backend filter",
			filter:   &httpconnectionmanagerv3.HttpFilter{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test"},
			expected: true,
		},
		{
			name:     "regular filter",
			filter:   &httpconnectionmanagerv3.HttpFilter{Name: "envoy.filters.http.router"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{log: testr.New(t)}
			result := s.isMCPBackendHTTPFilter(tt.filter)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestServer_maybeUpdateMCPRoutes(t *testing.T) {
	emptyConfig := &anypb.Any{TypeUrl: "type.googleapis.com/google.protobuf.Empty"}
	allAuthnFilters := func() map[string]*anypb.Any {
		return map[string]*anypb.Any{
			filterNameJWTAuthn:   emptyConfig,
			filterNameAPIKeyAuth: emptyConfig,
			filterNameExtAuth:    emptyConfig,
			"other-filter":       emptyConfig,
		}
	}
	// The header injection applied to every route that lands on the in-pod MCP proxy.
	proxyHeaders := []*corev3.HeaderValueOption{
		{
			AppendAction:   corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			KeepEmptyValue: true,
			Header: &corev3.HeaderValue{
				Key:   internalapi.MCPBackendSubsetHeader,
				Value: `%DYNAMIC_METADATA(["aigateway.envoy.io", "mcp_backend_subset"])%`,
			},
		},
	}
	route := func(name, path, cluster string) *routev3.Route {
		r := &routev3.Route{
			Name:                 name,
			Match:                &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Path{Path: path}},
			TypedPerFilterConfig: allAuthnFilters(),
		}
		if cluster != "" {
			r.Action = &routev3.Route_Route{Route: &routev3.RouteAction{
				ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: cluster},
			}}
		}
		return r
	}
	wrap := func(routes ...*routev3.Route) []*routev3.RouteConfiguration {
		return []*routev3.RouteConfiguration{{VirtualHosts: []*routev3.VirtualHost{{Name: "vh", Routes: routes}}}}
	}

	const (
		mcpCluster      = internalapi.MCPMainHTTPRoutePrefix + "foo/rule/0"
		metadataCluster = internalapi.MCPMainHTTPRoutePrefix + "foo/rule/1"
	)
	proxyClusters := map[string]bool{mcpCluster: true, metadataCluster: true}

	t.Run("keeps authn on the MCP rule and strips it from the well-known rules", func(t *testing.T) {
		mcp := route(internalapi.MCPMainHTTPRoutePrefix+"foo/rule/0", "/mcp", mcpCluster)
		metadata := route(internalapi.MCPMainHTTPRoutePrefix+"foo/rule/1", "/.well-known/oauth-protected-resource/mcp", metadataCluster)
		authServer := route(internalapi.MCPMainHTTPRoutePrefix+"foo/rule/2", "/.well-known/oauth-authorization-server/mcp", "")
		routes := wrap(mcp, metadata, authServer)

		s := &Server{log: testr.New(t)}
		s.maybeUpdateMCPRoutes(routes, proxyClusters)

		// The MCP endpoint is the protected one: authn stays, and the proxy gets the trusted
		// backend subset rendered into a header.
		require.Equal(t, allAuthnFilters(), mcp.TypedPerFilterConfig)
		require.Empty(t, cmp.Diff(proxyHeaders, mcp.RequestHeadersToAdd, protocmp.Transform()))

		// The metadata endpoint is served by the proxy too, but a client fetches it precisely
		// because it has no token yet, so it must not be behind authn.
		require.Equal(t, map[string]*anypb.Any{"other-filter": emptyConfig}, metadata.TypedPerFilterConfig)
		require.Empty(t, cmp.Diff(proxyHeaders, metadata.RequestHeadersToAdd, protocmp.Transform()))

		// The authorization server document is a direct response, so no proxy headers.
		require.Equal(t, map[string]*anypb.Any{"other-filter": emptyConfig}, authServer.TypedPerFilterConfig)
		require.Empty(t, authServer.RequestHeadersToAdd)
	})

	t.Run("keeps authn on an MCP rule served under an unrelated well-known path", func(t *testing.T) {
		// Only the OAuth discovery documents are public. An MCPRoute whose serving path happens
		// to sit under /.well-known/ is still MCP traffic and must stay authenticated.
		mcp := route(internalapi.MCPMainHTTPRoutePrefix+"foo/rule/0", "/.well-known/mcp", mcpCluster)
		routes := wrap(mcp)

		s := &Server{log: testr.New(t)}
		s.maybeUpdateMCPRoutes(routes, proxyClusters)

		require.Equal(t, allAuthnFilters(), mcp.TypedPerFilterConfig)
	})

	t.Run("ignores routes that are not MCP main routes", func(t *testing.T) {
		other := route("httproute/ns/user-route/rule/0", "/mcp", mcpCluster)
		routes := wrap(other)

		s := &Server{log: testr.New(t)}
		s.maybeUpdateMCPRoutes(routes, proxyClusters)

		require.Equal(t, allAuthnFilters(), other.TypedPerFilterConfig)
		require.Empty(t, other.RequestHeadersToAdd)
	})
}

func TestServer_extractMCPBackendFiltersFromMCPProxyListener(t *testing.T) {
	tests := []struct {
		name               string
		listeners          []*listenerv3.Listener
		expectedFilters    []*httpconnectionmanagerv3.HttpFilter
		expectedAccessLogs []*accesslogv3.AccessLog
	}{
		{
			name:               "no listeners",
			listeners:          []*listenerv3.Listener{},
			expectedFilters:    nil,
			expectedAccessLogs: nil,
		},
		{
			name: "listener with MCP backend filter without access logs",
			listeners: []*listenerv3.Listener{
				{
					Name: "test-listener",
					FilterChains: []*listenerv3.FilterChain{
						{
							Filters: []*listenerv3.Filter{
								{
									Name: wellknown.HTTPConnectionManager,
									ConfigType: &listenerv3.Filter_TypedConfig{
										TypedConfig: mustToAny(t, &httpconnectionmanagerv3.HttpConnectionManager{
											StatPrefix: "http",
											HttpFilters: []*httpconnectionmanagerv3.HttpFilter{
												{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter"},
												{Name: "envoy.filters.http.router"},
											},
										}),
									},
								},
							},
						},
					},
				},
			},
			expectedFilters: []*httpconnectionmanagerv3.HttpFilter{
				{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter"},
			},
		},
		{
			name: "listener with MCP backend filter with access logs",
			listeners: []*listenerv3.Listener{
				{
					Name: "test-listener1",
					FilterChains: []*listenerv3.FilterChain{
						{
							Filters: []*listenerv3.Filter{
								{
									Name: wellknown.HTTPConnectionManager,
									ConfigType: &listenerv3.Filter_TypedConfig{
										TypedConfig: mustToAny(t, &httpconnectionmanagerv3.HttpConnectionManager{
											StatPrefix: "http",
											HttpFilters: []*httpconnectionmanagerv3.HttpFilter{
												{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter"},
												{Name: "envoy.filters.http.router"},
											},
										}),
									},
								},
							},
						},
					},
				},
				{
					Name: "test-listener2",
					FilterChains: []*listenerv3.FilterChain{
						{
							Filters: []*listenerv3.Filter{
								{
									Name: wellknown.HTTPConnectionManager,
									ConfigType: &listenerv3.Filter_TypedConfig{
										TypedConfig: mustToAny(t, &httpconnectionmanagerv3.HttpConnectionManager{
											StatPrefix: "http",
											HttpFilters: []*httpconnectionmanagerv3.HttpFilter{
												{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter2"},
												{Name: "envoy.filters.http.router"},
											},
											AccessLog: []*accesslogv3.AccessLog{
												{Name: "listener2-accesslog1"},
												{Name: "listener2-accesslog2"},
											},
										}),
									},
								},
							},
						},
					},
				},
				{
					Name: "test-listener3",
					FilterChains: []*listenerv3.FilterChain{
						{
							Filters: []*listenerv3.Filter{
								{
									Name: wellknown.HTTPConnectionManager,
									ConfigType: &listenerv3.Filter_TypedConfig{
										TypedConfig: mustToAny(t, &httpconnectionmanagerv3.HttpConnectionManager{
											StatPrefix: "http",
											HttpFilters: []*httpconnectionmanagerv3.HttpFilter{
												{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter3"},
												{Name: "envoy.filters.http.router"},
											},
											AccessLog: []*accesslogv3.AccessLog{
												{Name: "listener3-accesslog1"},
												{Name: "listener3-accesslog2"},
											},
										}),
									},
								},
							},
						},
					},
				},
			},
			expectedFilters: []*httpconnectionmanagerv3.HttpFilter{
				{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter"},
				{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter2"},
				{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter3"},
			},
			expectedAccessLogs: []*accesslogv3.AccessLog{
				{Name: "listener3-accesslog1"},
				{Name: "listener3-accesslog2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{log: testr.New(t)}
			filters, accessLogConfigs, err := s.extractMCPBackendFiltersFromMCPProxyListener(tt.listeners)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(tt.expectedFilters, filters, protocmp.Transform()))
			require.Empty(t, cmp.Diff(tt.expectedAccessLogs, accessLogConfigs, protocmp.Transform()))
		})
	}
}

func TestServer_maybeGenerateResourcesForMCPGateway(t *testing.T) {
	tests := []struct {
		name          string
		req           *egextension.PostTranslateModifyRequest
		check         func(t *testing.T, req *egextension.PostTranslateModifyRequest)
		expectedError bool
	}{
		{
			name: "no listeners or routes",
			req: &egextension.PostTranslateModifyRequest{
				Listeners: []*listenerv3.Listener{},
				Routes:    []*routev3.RouteConfiguration{},
			},
			check: func(t *testing.T, req *egextension.PostTranslateModifyRequest) {
				require.Empty(t, req.Listeners)
				require.Empty(t, req.Routes)
			},
		},
		{
			name: "with MCP routes and listeners",
			req: &egextension.PostTranslateModifyRequest{
				Listeners: []*listenerv3.Listener{
					{
						Name: "test-listener",
						FilterChains: []*listenerv3.FilterChain{
							{
								Filters: []*listenerv3.Filter{
									{
										Name: wellknown.HTTPConnectionManager,
										ConfigType: &listenerv3.Filter_TypedConfig{
											TypedConfig: mustToAny(t, &httpconnectionmanagerv3.HttpConnectionManager{
												StatPrefix: "http",
												HttpFilters: []*httpconnectionmanagerv3.HttpFilter{
													{Name: internalapi.MCPPerBackendHTTPRouteFilterPrefix + "test-filter"},
													{Name: "envoy.filters.http.router"},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				Routes: []*routev3.RouteConfiguration{
					{
						VirtualHosts: []*routev3.VirtualHost{
							{
								Name:    "mcp-vh",
								Domains: []string{"*"},
								Routes: []*routev3.Route{
									{
										Name: internalapi.MCPPerBackendRefHTTPRoutePrefix + "foo/rule/0",
										Action: &routev3.Route_Route{
											Route: &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_Cluster{}},
										},
									},
									forwardingMCPRoute(internalapi.MCPMainHTTPRoutePrefix+"foo-bar/rule/0",
										internalapi.MCPMainHTTPRoutePrefix+"foo-bar/rule/0"),
								},
							},
						},
					},
				},
				Clusters: []*clusterv3.Cluster{
					{Name: internalapi.MCPMainHTTPRoutePrefix + "foo-bar/rule/0"},
				},
			},
			check: func(t *testing.T, req *egextension.PostTranslateModifyRequest) {
				require.Len(t, req.Listeners, 2)
				require.Equal(t, mcpBackendListenerName, req.Listeners[1].Name)

				require.Len(t, req.Routes, 2)
				require.Equal(t, "aigateway-mcp-backend-listener-route-config", req.Routes[1].Name)

				require.Len(t, req.Clusters, 1)
				require.Empty(t, cmp.Diff(rewrittenMCPProxyCluster(internalapi.MCPMainHTTPRoutePrefix+"foo-bar/rule/0"),
					req.Clusters[0], protocmp.Transform()))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{log: testr.New(t)}
			err := s.maybeGenerateResourcesForMCPGateway(tt.req)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.check(t, tt.req)
			}
		})
	}
}

// TestServer_createBackendListener_headerToMetadataRules pins the header_to_metadata rules the MCP
// backend listener is built with: a stable order, and Remove set only for the internal metadata
// headers that must not reach the upstream MCP server.
func TestServer_createBackendListener_headerToMetadataRules(t *testing.T) {
	s := &Server{log: testr.New(t)}

	type rule struct {
		header string
		key    string
		remove bool
	}
	rulesOf := func(t *testing.T) []rule {
		t.Helper()
		listener, err := s.createBackendListener(nil, nil)
		require.NoError(t, err)
		hcm, _, err := findHCM(listener.FilterChains[0])
		require.NoError(t, err)
		i, filter := findHeaderToMetadataFilter(hcm.HttpFilters)
		require.NotEqual(t, -1, i)
		cfg := &htomv3.Config{}
		require.NoError(t, filter.GetTypedConfig().UnmarshalTo(cfg))
		rules := make([]rule, 0, len(cfg.RequestRules))
		for _, r := range cfg.RequestRules {
			rules = append(rules, rule{r.GetHeader(), r.GetOnHeaderPresent().GetKey(), r.GetRemove()})
		}
		return rules
	}

	got := rulesOf(t)
	require.Equal(t, []rule{
		{"x-ai-eg-mcp-backend", "mcp_backend", false},
		{"x-ai-eg-mcp-metadata-method", "mcp_method", true},
		{"x-ai-eg-mcp-metadata-request-id", "mcp_request_id", true},
		{"x-ai-eg-mcp-metadata-resource-uri", "mcp_resource_uri", true},
		{"x-ai-eg-mcp-metadata-tool-name", "mcp_tool_name", true},
	}, got)

	// Ranging a map is randomized per-iteration, so an unsorted build would differ across calls. An
	// unstable order changes the serialized listener and makes Envoy drain it on every translation.
	for range 20 {
		require.Equal(t, got, rulesOf(t))
	}
}
