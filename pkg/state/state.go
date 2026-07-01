// Package state manages scan checkpoint persistence for resume capability.
// It uses a JSON state file (.anubis.state) with atomic.Pointer-based
// lock-free concurrent access.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/SepJs/anubis/pkg/scanner"
)

const StateFile = ".anubis.state"

type CheckpointState struct {
	Target            string              `json:"target"`
	Level             scanner.ScanLevel   `json:"level"`
	Flags             scanner.ScanConfig  `json:"flags"`
	CompletedModules  []string            `json:"completed_modules"`
	RemainingModules  []string            `json:"remaining_modules"`
	Findings          []scanner.Finding   `json:"findings"`
	BaselineMetrics   interface{}         `json:"baseline_metrics,omitempty"`
	ScanStartTime     time.Time           `json:"scan_start_time"`
	ElapsedSeconds    float64             `json:"elapsed_seconds"`
	SavedAt           time.Time           `json:"saved_at"`
}

type AtomicState struct {
	ptr atomic.Pointer[CheckpointState]
}

func NewAtomicState() *AtomicState {
	return &AtomicState{}
}

func (as *AtomicState) Load() *CheckpointState {
	return as.ptr.Load()
}

func (as *AtomicState) Store(s *CheckpointState) {
	as.ptr.Store(s)
}

func Save(state *CheckpointState) error {
	state.SavedAt = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("state: marshal: %w", err)
	}
	if err := os.WriteFile(StateFile, data, 0600); err != nil {
		return fmt.Errorf("state: write: %w", err)
	}
	return nil
}

func Load() (*CheckpointState, error) {
	data, err := os.ReadFile(StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no checkpoint file found at %s", StateFile)
		}
		return nil, fmt.Errorf("state: read: %w", err)
	}
	var state CheckpointState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("state: parse: %w", err)
	}
	return &state, nil
}

func Exists() bool {
	_, err := os.Stat(StateFile)
	return err == nil
}

func Delete() {
	_ = os.Remove(StateFile)
}

func BuildInitial(cfg scanner.ScanConfig, moduleNames []string) *CheckpointState {
	return &CheckpointState{
		Target:           cfg.Target,
		Level:            cfg.Level,
		Flags:            cfg,
		RemainingModules: moduleNames,
		ScanStartTime:    time.Now(),
	}
}

func MarkModuleComplete(state *CheckpointState, moduleName string, findings []scanner.Finding) {
	state.CompletedModules = append(state.CompletedModules, moduleName)
	remaining := state.RemainingModules[:0]
	for _, m := range state.RemainingModules {
		if m != moduleName {
			remaining = append(remaining, m)
		}
	}
	state.RemainingModules = remaining
	state.Findings = append(state.Findings, findings...)
	state.ElapsedSeconds = time.Since(state.ScanStartTime).Seconds()
}
