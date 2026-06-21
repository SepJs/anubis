package baseline

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/SepJs/anubis/pkg/utils"
	"github.com/schollz/progressbar/v3"
)

// Metrics holds the baseline measurements
type Metrics struct {
	Target            string            `json:"target"`
	CapturedAt        time.Time         `json:"captured_at"`
	AvgResponseTimeMs float64           `json:"avg_response_time_ms"`
	MinResponseTimeMs float64           `json:"min_response_time_ms"`
	MaxResponseTimeMs float64           `json:"max_response_time_ms"`
	StatusCode        int               `json:"status_code"`
	ServerHeader      string            `json:"server_header,omitempty"`
	ContentType       string            `json:"content_type,omitempty"`
	OpenPortSample    []int             `json:"open_port_sample,omitempty"`
	ConnectionStable  bool              `json:"connection_stable"`
	TLSEnabled        bool              `json:"tls_enabled"`
	ResponseHeaders   map[string]string `json:"response_headers,omitempty"`
	Probes            int               `json:"probes"`
}

const probeCount = 5

// Collect performs the Level 0 baseline measurement
func Collect(target string, showProgress bool) (*Metrics, error) {
	cfg := utils.DefaultHTTPConfig()
	cfg.SkipVerify = true // baseline doesn't care about cert validity

	client, err := utils.BuildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("baseline: build client: %w", err)
	}

	metrics := &Metrics{
		Target:          target,
		CapturedAt:      time.Now(),
		ResponseHeaders: make(map[string]string),
		Probes:          probeCount,
	}

	var bar *progressbar.ProgressBar
	if showProgress {
		utils.LogInfo("Level 0 Baseline — establishing baseline metrics...")
		bar = progressbar.NewOptions(probeCount,
			progressbar.OptionSetDescription("Baseline"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "█",
				SaucerPadding: "░",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionSetWidth(30),
		)
	} else {
		// Silent spinner-style indicator
		fmt.Print("  Baseline: [")
	}

	var responseTimes []float64
	stableCount := 0

	for i := 0; i < probeCount; i++ {
		start := time.Now()
		resp, err := utils.DoRequest(client, http.MethodGet, target, nil, cfg)
		elapsed := time.Since(start).Milliseconds()

		if err == nil {
			responseTimes = append(responseTimes, float64(elapsed))
			metrics.StatusCode = resp.StatusCode
			if metrics.ServerHeader == "" {
				metrics.ServerHeader = resp.Header.Get("Server")
			}
			if metrics.ContentType == "" {
				metrics.ContentType = resp.Header.Get("Content-Type")
			}
			// Capture all response headers on first successful probe
			if i == 0 {
				for k, vv := range resp.Header {
					if len(vv) > 0 {
						metrics.ResponseHeaders[k] = vv[0]
					}
				}
			}
			utils.SafeClose(resp.Body)
			stableCount++
		}

		if showProgress && bar != nil {
			_ = bar.Add(1)
		} else {
			if i < probeCount-1 {
				fmt.Print("█")
			} else {
				fmt.Println("█]")
			}
		}

		time.Sleep(200 * time.Millisecond)
	}

	if showProgress {
		fmt.Println()
	}

	// Compute stats
	if len(responseTimes) > 0 {
		var sum, minT, maxT float64
		minT = responseTimes[0]
		maxT = responseTimes[0]
		for _, t := range responseTimes {
			sum += t
			if t < minT {
				minT = t
			}
			if t > maxT {
				maxT = t
			}
		}
		metrics.AvgResponseTimeMs = sum / float64(len(responseTimes))
		metrics.MinResponseTimeMs = minT
		metrics.MaxResponseTimeMs = maxT
	}

	metrics.ConnectionStable = stableCount >= (probeCount / 2)
	metrics.TLSEnabled = utils.IsHTTPS(target)

	return metrics, nil
}

// LoadFromFile loads a previously saved baseline from disk
func LoadFromFile(path string) (*Metrics, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: read file: %w", err)
	}
	var m Metrics
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("baseline: parse file: %w", err)
	}
	return &m, nil
}

// SaveToFile persists a baseline snapshot to disk
func SaveToFile(m *Metrics, path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Compare prints a human-readable comparison between two baselines
func Compare(baseline, current *Metrics) {
	utils.PrintSeparator()
	utils.PrintHeader("Level 0 Baseline Comparison")
	fmt.Printf("  Baseline captured:    %s\n", baseline.CapturedAt.Format(time.RFC1123))
	fmt.Printf("  Current scan:         %s\n", current.CapturedAt.Format(time.RFC1123))
	fmt.Printf("\n")
	fmt.Printf("  Avg response (base):  %.1f ms\n", baseline.AvgResponseTimeMs)
	fmt.Printf("  Avg response (now):   %.1f ms", current.AvgResponseTimeMs)
	delta := current.AvgResponseTimeMs - baseline.AvgResponseTimeMs
	if delta > 500 {
		fmt.Printf("  ⚠  +%.0f ms (significantly slower)\n", delta)
	} else if delta < -200 {
		fmt.Printf("  ✓  %.0f ms (faster)\n", delta)
	} else {
		fmt.Printf("  ≈  similar\n")
	}
	fmt.Printf("  Connection stable (base): %v\n", baseline.ConnectionStable)
	fmt.Printf("  Connection stable (now):  %v\n", current.ConnectionStable)
	if baseline.ServerHeader != current.ServerHeader {
		utils.LogWarn("Server header changed: %q → %q", baseline.ServerHeader, current.ServerHeader)
	}
	utils.PrintSeparator()
}
