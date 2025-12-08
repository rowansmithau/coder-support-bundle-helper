package parser

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/util"
)

// ParseNetworkInfo parses network diagnostic information from the bundle.
func ParseNetworkInfo(zr *zip.Reader, metadata *models.BundleMetadata, warnings *[]string) {
	if metadata == nil {
		return
	}

	type connectionRegionMeta struct {
		Code     string
		Name     string
		Embedded bool
	}

	info := models.NetworkInfo{}
	warnSet := map[string]struct{}{}
	errSet := map[string]struct{}{}
	regionMetas := map[int]connectionRegionMeta{}
	dataFound := false

	// Parse connection_info.json
	if f := util.FindSibling(zr, "network/connection_info.json"); f != nil {
		if content, err := util.ReadZipFile(f); err == nil {
			var payload struct {
				DERPMap struct {
					HomeParams struct {
						RegionScore map[string]float64 `json:"regionScore"`
					} `json:"homeParams"`
					Regions map[string]struct {
						RegionID   int    `json:"regionID"`
						RegionCode string `json:"regionCode"`
						RegionName string `json:"regionName"`
						EmbeddedRelay bool `json:"embeddedRelay"`
					} `json:"regions"`
				} `json:"derpMap"`
				DisableDirectConnections bool `json:"disableDirectConnections"`
			}
			if err := json.Unmarshal(content, &payload); err != nil {
				*warnings = append(*warnings, fmt.Sprintf("network/connection_info.json parse error: %v", err))
			} else {
				dataFound = true
				if payload.DisableDirectConnections {
					t := true
					if info.Usage == nil {
						info.Usage = &models.NetworkUsageSummary{}
					}
					info.Usage.DirectConnectionsDisabled = &t
				}

				for _, r := range payload.DERPMap.Regions {
					regionMetas[r.RegionID] = connectionRegionMeta{
						Code:     r.RegionCode,
						Name:     r.RegionName,
						Embedded: r.EmbeddedRelay,
					}
					if r.EmbeddedRelay {
						if info.Usage == nil {
							info.Usage = &models.NetworkUsageSummary{}
						}
						t := true
						info.Usage.UsesEmbeddedDERP = &t
						info.Usage.EmbeddedDERPRegion = r.RegionName
					}
				}
			}
		}
	}

	// Parse netcheck.json
	if f := util.FindSibling(zr, "network/netcheck.json"); f != nil {
		if content, err := util.ReadZipFile(f); err == nil {
			// The netcheck.json has a wrapper structure with severity, warnings, regions, etc.
			// The actual netcheck data is nested under the "netcheck" key.
			type netcheckData struct {
				UDP                   bool               `json:"UDP"`
				IPv6                  bool               `json:"IPv6"`
				IPv4                  bool               `json:"IPv4"`
				IPv4CanSend           bool               `json:"IPv4CanSend"`
				IPv6CanSend           bool               `json:"IPv6CanSend"`
				OSHasIPv6             bool               `json:"OSHasIPv6"`
				ICMPv4                bool               `json:"ICMPv4"`
				MappingVariesByDestIP *bool              `json:"MappingVariesByDestIP"`
				HairPinning           *bool              `json:"HairPinning"`
				UPnP                  *bool              `json:"UPnP"`
				PMP                   *bool              `json:"PMP"`
				PCP                   *bool              `json:"PCP"`
				PreferredDERP         int                `json:"PreferredDERP"`
				RegionLatency         map[string]float64 `json:"RegionLatency"`
				RegionV4Latency       map[string]float64 `json:"RegionV4Latency"`
				RegionV6Latency       map[string]float64 `json:"RegionV6Latency"`
				GlobalV4              string             `json:"GlobalV4"`
				GlobalV6              string             `json:"GlobalV6"`
				CaptivePortal         *string            `json:"CaptivePortal"`
			}
			var wrapper struct {
				Severity    string                  `json:"severity"`
				Healthy     bool                    `json:"healthy"`
				Warnings    []models.NetworkWarning `json:"warnings"`
				NetcheckLogs []string               `json:"netcheck_logs"`
				Netcheck    *netcheckData           `json:"netcheck"`
				Regions     map[string]struct {
					Healthy     bool   `json:"healthy"`
					Severity    string `json:"severity"`
					Region      struct {
						RegionID      int    `json:"RegionID"`
						RegionCode    string `json:"RegionCode"`
						RegionName    string `json:"RegionName"`
						EmbeddedRelay bool   `json:"EmbeddedRelay"`
					} `json:"region"`
					NodeReports []struct {
						Healthy  bool    `json:"healthy"`
						Severity string  `json:"severity"`
						Error    *string `json:"error"`
						Node     struct {
							Name     string `json:"Name"`
							STUNOnly bool   `json:"STUNOnly"`
						} `json:"node"`
						CanExchangeMessages bool    `json:"can_exchange_messages"`
						RoundTripPingMS     float64 `json:"round_trip_ping_ms"`
						UsesWebsocket       bool    `json:"uses_websocket"`
						ClientLogs          [][]any `json:"client_logs"`
						STUN                struct {
							Enabled bool    `json:"Enabled"`
							CanSTUN bool    `json:"CanSTUN"`
							Error   *string `json:"Error"`
						} `json:"stun"`
					} `json:"node_reports"`
				} `json:"regions"`
			}
			if err := json.Unmarshal(content, &wrapper); err != nil {
				*warnings = append(*warnings, fmt.Sprintf("network/netcheck.json parse error: %v", err))
			} else {
				// Process top-level netcheck info (severity, warnings, regions)
				dataFound = true
				info.Severity = wrapper.Severity
				info.Warnings = wrapper.Warnings
				info.NetcheckLogs = wrapper.NetcheckLogs

				// Set health status from wrapper
				info.Health = &models.NetworkHealthSummary{
					Healthy:  wrapper.Healthy,
					Severity: wrapper.Severity,
				}

				// Track STUN success across all regions
				anySTUNSuccess := false
				anySTUNAttempt := false

				// Process regions from the wrapper
				for _, r := range wrapper.Regions {
					region := models.NetworkRegionStatus{
						RegionID:      r.Region.RegionID,
						Code:          r.Region.RegionCode,
						Name:          r.Region.RegionName,
						Healthy:       r.Healthy,
						Severity:      r.Severity,
						EmbeddedRelay: r.Region.EmbeddedRelay,
					}

					// Build node details and collect errors
					var regionErrors []string
					for _, nr := range r.NodeReports {
						node := models.NetworkNodeStatus{
							Name:                nr.Node.Name,
							Healthy:             nr.Healthy,
							Severity:            nr.Severity,
							STUNOnly:            nr.Node.STUNOnly,
							CanExchangeMessages: nr.CanExchangeMessages,
							UsesWebsocket:       nr.UsesWebsocket,
							Error:               nr.Error,
						}
						if nr.RoundTripPingMS > 0 {
							lat := nr.RoundTripPingMS
							node.LatencyMS = &lat
							if region.LatencyMS == nil || lat < *region.LatencyMS {
								region.LatencyMS = &lat
							}
						}
						// Track STUN status
						if nr.STUN.Enabled {
							anySTUNAttempt = true
							if nr.STUN.CanSTUN {
								anySTUNSuccess = true
							}
						}
						if nr.STUN.Error != nil && *nr.STUN.Error != "" {
							node.STUNError = nr.STUN.Error
							regionErrors = append(regionErrors, *nr.STUN.Error)
						}
						// Extract errors from client_logs
						for _, log := range nr.ClientLogs {
							if len(log) >= 2 {
								if msg, ok := log[1].(string); ok && strings.Contains(strings.ToLower(msg), "error") {
									if node.Error == nil {
										node.Error = &msg
									}
									errSet[msg] = struct{}{}
								}
							}
						}
						region.Nodes = append(region.Nodes, node)
						
						// Set region-level flags from first node
						if len(region.Nodes) == 1 {
							t := nr.UsesWebsocket
							region.UsesWebsocket = &t
							c := nr.CanExchangeMessages
							region.CanExchangeMessages = &c
						}
					}
					region.Errors = regionErrors

					// Store region metadata for later use
					regionMetas[r.Region.RegionID] = connectionRegionMeta{
						Code:     r.Region.RegionCode,
						Name:     r.Region.RegionName,
						Embedded: r.Region.EmbeddedRelay,
					}

					info.Regions = append(info.Regions, region)
				}

				// Set STUN connectivity status and add warning if failed
				if anySTUNAttempt {
					if info.Usage == nil {
						info.Usage = &models.NetworkUsageSummary{}
					}
					info.Usage.UsesSTUN = &anySTUNSuccess
					if !anySTUNSuccess {
						info.Warnings = append(info.Warnings, models.NetworkWarning{
							Code:    "",
							Message: "STUN probes did not succeed",
						})
					}
				}

				// Now process the nested netcheck data if present
				payload := wrapper.Netcheck
				if payload == nil {
					goto assignNetwork
				}
				dataFound = true
				if info.Usage == nil {
					info.Usage = &models.NetworkUsageSummary{}
				}
				info.Usage.UDP = &payload.UDP
				info.Usage.IPv4 = &payload.IPv4
				info.Usage.IPv6 = &payload.IPv6
				info.Usage.IPv4CanSend = &payload.IPv4CanSend
				info.Usage.IPv6CanSend = &payload.IPv6CanSend
				info.Usage.OSHasIPv6 = &payload.OSHasIPv6
				info.Usage.ICMPv4 = &payload.ICMPv4
				info.Usage.MappingVariesByDestIP = payload.MappingVariesByDestIP
				info.Usage.HairPinning = payload.HairPinning
				info.Usage.UPnP = payload.UPnP
				info.Usage.PMP = payload.PMP
				info.Usage.PCP = payload.PCP
				info.Usage.CaptivePortal = payload.CaptivePortal
				info.Usage.GlobalV4 = payload.GlobalV4
				info.Usage.GlobalV6 = payload.GlobalV6

				if payload.PreferredDERP > 0 {
					if meta, ok := regionMetas[payload.PreferredDERP]; ok {
						info.Usage.PreferredDERP = meta.Name
					} else {
						info.Usage.PreferredDERP = fmt.Sprintf("Region %d", payload.PreferredDERP)
					}
				}

				// Update existing regions with latency data from netcheck
				// (regions were already populated from wrapper.Regions)
				regionLatencies := map[int]float64{}
				for k, v := range payload.RegionLatency {
					if id, err := strconv.Atoi(k); err == nil {
						regionLatencies[id] = v / 1000000 // Convert from ns to ms
					}
				}

				// Update latency on existing regions
				for i := range info.Regions {
					if lat, ok := regionLatencies[info.Regions[i].RegionID]; ok {
						info.Regions[i].LatencyMS = &lat
					}
				}
			}
		}
	}

assignNetwork:
	// Parse derp_region_XX.json files
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "network/derp_region_") || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		content, err := util.ReadZipFile(f)
		if err != nil {
			continue
		}

		var payload struct {
			Healthy  bool   `json:"healthy"`
			Severity string `json:"severity"`
			Warnings []json.RawMessage `json:"warnings"`
			Error    *string `json:"error"`
			Region   struct {
				RegionID   int    `json:"regionID"`
				RegionCode string `json:"regionCode"`
				RegionName string `json:"regionName"`
				EmbeddedRelay bool `json:"embeddedRelay"`
			} `json:"region"`
			NodeReports []struct {
				Healthy        bool    `json:"healthy"`
				CanExchangeMessages bool `json:"canExchangeMessages"`
				UsesWebsocket  bool    `json:"usesWebsocket"`
				RoundTripPing  string  `json:"roundTripPing"`
				Error          *string `json:"error"`
			} `json:"node_reports"`
		}
		if err := json.Unmarshal(content, &payload); err != nil {
			continue
		}

		dataFound = true

		// Find or create region in info.Regions
		var region *models.NetworkRegionStatus
		for i := range info.Regions {
			if info.Regions[i].RegionID == payload.Region.RegionID {
				region = &info.Regions[i]
				break
			}
		}
		if region == nil {
			info.Regions = append(info.Regions, models.NetworkRegionStatus{
				RegionID: payload.Region.RegionID,
			})
			region = &info.Regions[len(info.Regions)-1]
		}

		region.Code = payload.Region.RegionCode
		region.Name = payload.Region.RegionName
		region.Healthy = payload.Healthy
		region.Severity = strings.ToLower(payload.Severity)
		region.EmbeddedRelay = payload.Region.EmbeddedRelay

		if payload.Error != nil && *payload.Error != "" {
			region.Errors = append(region.Errors, *payload.Error)
			errSet[*payload.Error] = struct{}{}
		}

		for _, warn := range payload.Warnings {
			var text string
			if err := json.Unmarshal(warn, &text); err == nil {
				region.Warnings = append(region.Warnings, text)
				warnSet[text] = struct{}{}
			}
		}

		for _, nr := range payload.NodeReports {
			if nr.CanExchangeMessages {
				t := true
				region.CanExchangeMessages = &t
			}
			if nr.UsesWebsocket {
				t := true
				region.UsesWebsocket = &t
			}
			if nr.Error != nil && *nr.Error != "" {
				region.Errors = append(region.Errors, *nr.Error)
				errSet[*nr.Error] = struct{}{}
			}
		}
	}

	// Parse interfaces.json
	if f := util.FindSibling(zr, "network/interfaces.json"); f != nil {
		if content, err := util.ReadZipFile(f); err == nil {
			var payload []struct {
				Name  string   `json:"name"`
				MTU   int      `json:"mtu"`
				Addrs []string `json:"addrs"`
			}
			if err := json.Unmarshal(content, &payload); err == nil {
				dataFound = true
				for _, iface := range payload {
					info.Interfaces = append(info.Interfaces, models.NetworkInterfaceInfo{
						Name:      iface.Name,
						MTU:       iface.MTU,
						Addresses: iface.Addrs,
					})
				}
			}
		}
	}

	// Sort results
	if len(info.Regions) > 0 {
		sort.Slice(info.Regions, func(i, j int) bool {
			return info.Regions[i].Name < info.Regions[j].Name
		})
	}

	if len(info.Interfaces) > 0 {
		sort.Slice(info.Interfaces, func(i, j int) bool {
			return info.Interfaces[i].Name < info.Interfaces[j].Name
		})
	}

	// warnSet is collected but no longer used since warnings come from netcheck.json directly
	if len(errSet) > 0 {
		info.Errors = make([]string, 0, len(errSet))
		for msg := range errSet {
			info.Errors = append(info.Errors, msg)
		}
		sort.Strings(info.Errors)
	}

	if dataFound || len(info.Warnings) > 0 || len(info.Errors) > 0 {
		metadata.Network = &info
	}
}
