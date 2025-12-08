package models

import (
	"encoding/json"
	"time"

	"github.com/google/pprof/profile"
)

// StoredProfile represents a parsed pprof profile from a bundle.
type StoredProfile struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Path          string            `json:"path"`
	SampleTypes   []string          `json:"sampleTypes"`
	PeriodType    string            `json:"periodType"`
	PeriodUnit    string            `json:"periodUnit"`
	Duration      float64           `json:"durationSec"`
	SampleCount   int               `json:"sampleCount"`
	FunctionCount int               `json:"functionCount"`
	CreatedAt     time.Time         `json:"createdAt"`
	Bytes         []byte            `json:"-"`
	Profile       *profile.Profile  `json:"-"`
	Meta          map[string]string `json:"meta,omitempty"`
	BundleID      string            `json:"bundleId"`
	Group         string            `json:"group,omitempty"`
}

// Bundle represents a loaded support bundle.
type Bundle struct {
	ID                 string                `json:"id"`
	Name               string                `json:"name"`
	Created            time.Time             `json:"created"`
	Profiles           []*StoredProfile      `json:"profiles"`
	Warnings           []string              `json:"warnings,omitempty"`
	Path               string                `json:"path"`
	Metadata           *BundleMetadata       `json:"metadata,omitempty"`
	AgentLog           *BundleLog            `json:"agentLog,omitempty"`
	Prometheus         []*PrometheusSnapshot `json:"prometheus,omitempty"`
	PrometheusURL      string                `json:"prometheusUrl,omitempty"`
	PrometheusGraphURL string                `json:"prometheusGraphUrl,omitempty"`
	GrafanaURL         string                `json:"grafanaUrl,omitempty"`
	GrafanaFolderURL   string                `json:"grafanaFolderUrl,omitempty"`
}

// PrometheusSnapshot represents a prometheus metrics snapshot from a bundle.
type PrometheusSnapshot struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	Path      string    `json:"path"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
	Content   []byte    `json:"-"`
}

// BundleLog represents agent log file information.
type BundleLog struct {
	Path            string `json:"path"`
	Size            int64  `json:"size"`
	Lines           int    `json:"lines"`
	Truncated       bool   `json:"truncated"`
	HighlightedHTML string `json:"-"`
}

// BundleMetadata contains parsed metadata from a support bundle.
type BundleMetadata struct {
	DeploymentID      string          `json:"deploymentId,omitempty"`
	LicenseStatus     json.RawMessage `json:"licenseStatus,omitempty"`
	LicenseStatusRaw  string          `json:"licenseStatusRaw,omitempty"`
	LicenseValid      bool            `json:"licenseValid"`
	LicenseFound      bool            `json:"licenseFound"`
	TailnetBuildInfo  json.RawMessage `json:"tailnetBuildInfo,omitempty"`
	BuildInfo         json.RawMessage `json:"buildInfo,omitempty"`
	LicenseMatch      bool            `json:"licenseMatch"`
	LicenseMismatch   string          `json:"licenseMismatch,omitempty"`
	BuildInfoMatch    bool            `json:"buildInfoMatch"`
	BuildInfoMismatch string          `json:"buildInfoMismatch,omitempty"`
	Version           string          `json:"version,omitempty"`
	DashboardURL      string          `json:"dashboardUrl,omitempty"`
	HealthStatus      *HealthStatus   `json:"healthStatus,omitempty"`
	Network           *NetworkInfo    `json:"network,omitempty"`
}

// HealthStatus represents the overall health status from a bundle.
type HealthStatus struct {
	Healthy    bool              `json:"healthy"`
	Severity   string            `json:"severity"`
	Warnings   []string          `json:"warnings,omitempty"`
	Components []HealthComponent `json:"components,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
	Timestamp  *time.Time        `json:"timestamp,omitempty"`
}

// HealthComponent represents a single health check component.
type HealthComponent struct {
	Name      string   `json:"name"`
	Healthy   bool     `json:"healthy"`
	Severity  string   `json:"severity,omitempty"`
	Messages  []string `json:"messages,omitempty"`
	Dismissed bool     `json:"dismissed,omitempty"`
}

// NetworkInfo contains network diagnostic information.
type NetworkInfo struct {
	Health         *NetworkHealthSummary  `json:"health,omitempty"`
	Usage          *NetworkUsageSummary   `json:"usage,omitempty"`
	Severity       string                 `json:"severity,omitempty"`
	Warnings       []NetworkWarning       `json:"warnings,omitempty"`
	Errors         []string               `json:"errors,omitempty"`
	Regions        []NetworkRegionStatus  `json:"regions,omitempty"`
	Interfaces     []NetworkInterfaceInfo `json:"interfaces,omitempty"`
	HostnameSuffix string                 `json:"hostnameSuffix,omitempty"`
	NetcheckLogs   []string               `json:"netcheckLogs,omitempty"`
}

// NetworkWarning represents a warning from netcheck with code and message.
type NetworkWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NetworkHealthSummary provides a quick network health overview.
type NetworkHealthSummary struct {
	Healthy  bool   `json:"healthy"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message,omitempty"`
}

// NetworkUsageSummary describes network configuration and capabilities.
type NetworkUsageSummary struct {
	UsesSTUN                  *bool   `json:"usesStun,omitempty"`
	UsesEmbeddedDERP          *bool   `json:"usesEmbeddedDerp,omitempty"`
	EmbeddedDERPRegion        string  `json:"embeddedDerpRegion,omitempty"`
	PreferredDERP             string  `json:"preferredDerp,omitempty"`
	DirectConnectionsDisabled *bool   `json:"directConnectionsDisabled,omitempty"`
	ForceWebsockets           *bool   `json:"forceWebsockets,omitempty"`
	WorkspaceProxy            *bool   `json:"workspaceProxy,omitempty"`
	WorkspaceProxyReason      string  `json:"workspaceProxyReason,omitempty"`
	UDP                       *bool   `json:"udp,omitempty"`
	IPv4                      *bool   `json:"ipv4,omitempty"`
	IPv6                      *bool   `json:"ipv6,omitempty"`
	IPv4CanSend               *bool   `json:"ipv4CanSend,omitempty"`
	IPv6CanSend               *bool   `json:"ipv6CanSend,omitempty"`
	OSHasIPv6                 *bool   `json:"osHasIpv6,omitempty"`
	ICMPv4                    *bool   `json:"icmpv4,omitempty"`
	MappingVariesByDestIP     *bool   `json:"mappingVariesByDestIp,omitempty"`
	HairPinning               *bool   `json:"hairPinning,omitempty"`
	UPnP                      *bool   `json:"upnp,omitempty"`
	PMP                       *bool   `json:"pmp,omitempty"`
	PCP                       *bool   `json:"pcp,omitempty"`
	CaptivePortal             *string `json:"captivePortal,omitempty"`
	GlobalV4                  string  `json:"globalV4,omitempty"`
	GlobalV6                  string  `json:"globalV6,omitempty"`
}

// NetworkRegionStatus represents the status of a DERP region.
type NetworkRegionStatus struct {
	RegionID            int                 `json:"regionId,omitempty"`
	Code                string              `json:"code,omitempty"`
	Name                string              `json:"name,omitempty"`
	Healthy             bool                `json:"healthy"`
	Severity            string              `json:"severity,omitempty"`
	Warnings            []string            `json:"warnings,omitempty"`
	Errors              []string            `json:"errors,omitempty"`
	UsesWebsocket       *bool               `json:"usesWebsocket,omitempty"`
	CanExchangeMessages *bool               `json:"canExchangeMessages,omitempty"`
	EmbeddedRelay       bool                `json:"embeddedRelay"`
	LatencyMS           *float64            `json:"latencyMs,omitempty"`
	Nodes               []NetworkNodeStatus `json:"nodes,omitempty"`
}

// NetworkNodeStatus represents the status of a single node within a DERP region.
type NetworkNodeStatus struct {
	Name                string   `json:"name"`
	Healthy             bool     `json:"healthy"`
	Severity            string   `json:"severity,omitempty"`
	STUNOnly            bool     `json:"stunOnly,omitempty"`
	CanExchangeMessages bool     `json:"canExchangeMessages"`
	UsesWebsocket       bool     `json:"usesWebsocket"`
	LatencyMS           *float64 `json:"latencyMs,omitempty"`
	Error               *string  `json:"error,omitempty"`
	STUNError           *string  `json:"stunError,omitempty"`
}

// NetworkInterfaceInfo describes a network interface.
type NetworkInterfaceInfo struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses,omitempty"`
}

// LoadResult holds the result of loading a bundle.
type LoadResult struct {
	Bundle   *Bundle
	Warnings []string
	Error    error
}

// TimeSeriesPoint represents a point in a time series.
type TimeSeriesPoint struct {
	Timestamp time.Time        `json:"timestamp"`
	BundleID  string           `json:"bundleId"`
	ProfileID string           `json:"profileId"`
	Name      string           `json:"name"`
	Metrics   map[string]int64 `json:"metrics"`
}

// TopRow represents a row in the top functions view.
type TopRow struct {
	Func        string  `json:"func"`
	File        string  `json:"file"`
	Flat        int64   `json:"flat"`
	Cum         int64   `json:"cum"`
	FlatPercent float64 `json:"flatPct"`
	CumPercent  float64 `json:"cumPct"`
}

// FlameNode represents a node in a flame graph.
type FlameNode struct {
	Name     string                `json:"name"`
	Value    int64                 `json:"value"`
	Children []*FlameNode          `json:"children,omitempty"`
	ChildMap map[string]*FlameNode `json:"-"` // Fast lookup - exported for use
}

// GetChild returns or creates a child node with the given name.
func (n *FlameNode) GetChild(name string) *FlameNode {
	if n.ChildMap == nil {
		n.ChildMap = make(map[string]*FlameNode)
		for _, c := range n.Children {
			n.ChildMap[c.Name] = c
		}
	}

	if child, exists := n.ChildMap[name]; exists {
		return child
	}

	child := &FlameNode{Name: name}
	n.Children = append(n.Children, child)
	n.ChildMap[name] = child
	return child
}

// ComparisonResult holds the result of comparing two profiles.
type ComparisonResult struct {
	Profile1 string              `json:"profile1"`
	Profile2 string              `json:"profile2"`
	Diff     []ComparisonDiffRow `json:"diff"`
}

// ComparisonDiffRow represents a row in the comparison diff view.
type ComparisonDiffRow struct {
	Func     string  `json:"func"`
	Flat1    int64   `json:"flat1"`
	Flat2    int64   `json:"flat2"`
	FlatDiff int64   `json:"flatDiff"`
	PctDiff  float64 `json:"pctDiff"`
}

// FlameDiffNode represents a node in a differential flame graph.
type FlameDiffNode struct {
	Name     string                    `json:"name"`
	Value1   int64                     `json:"value1"`
	Value2   int64                     `json:"value2"`
	Diff     int64                     `json:"diff"`
	PctDiff  float64                   `json:"pctDiff"`
	Children []*FlameDiffNode          `json:"children,omitempty"`
	ChildMap map[string]*FlameDiffNode `json:"-"`
}

// GetChild returns or creates a child node with the given name.
func (n *FlameDiffNode) GetChild(name string) *FlameDiffNode {
	if n.ChildMap == nil {
		n.ChildMap = make(map[string]*FlameDiffNode)
		for _, c := range n.Children {
			n.ChildMap[c.Name] = c
		}
	}

	if child, exists := n.ChildMap[name]; exists {
		return child
	}

	child := &FlameDiffNode{Name: name}
	n.Children = append(n.Children, child)
	n.ChildMap[name] = child
	return child
}
