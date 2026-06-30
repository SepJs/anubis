package heuristic

import (
	"math"
	"sync"

	"github.com/SepJs/anubis/pkg/scanner"
)

type HeuristicEngine struct {
	mu      sync.RWMutex
	rules   []HeuristicRule
	history map[string][]float64
}

type HeuristicRule struct {
	Name      string
	Weight    float64
	Condition func(finding scanner.Finding) bool
	AdjustFn  func(finding scanner.Finding) (float64, float64)
}

type HeuristicResult struct {
	Finding       scanner.Finding
	Likelihood    float64
	SeverityScore float64
	RiskScore     float64
	Explanation   string
}

func NewHeuristicEngine() *HeuristicEngine {
	he := &HeuristicEngine{
		rules:   make([]HeuristicRule, 0),
		history: make(map[string][]float64),
	}
	he.registerDefaultRules()
	return he
}

func (he *HeuristicEngine) registerDefaultRules() {
	he.rules = []HeuristicRule{
		{
			Name:   "evidence_strength",
			Weight: 0.25,
			Condition: func(f scanner.Finding) bool {
				return f.Evidence != ""
			},
			AdjustFn: func(f scanner.Finding) (float64, float64) {
				evLen := len(f.Evidence)
				likelihood := math.Min(float64(evLen)/200.0, 1.0)
				return likelihood, 0.0
			},
		},
		{
			Name:   "confidence_boost",
			Weight: 0.20,
			Condition: func(f scanner.Finding) bool {
				return f.Confidence == scanner.ConfidenceConfirmed
			},
			AdjustFn: func(f scanner.Finding) (float64, float64) {
				return 0.9, float64(severityWeight(f.Severity))
			},
		},
		{
			Name:   "cvss_correlation",
			Weight: 0.15,
			Condition: func(f scanner.Finding) bool {
				return f.CVSSScore > 0
			},
			AdjustFn: func(f scanner.Finding) (float64, float64) {
				likelihood := f.CVSSScore / 10.0
				return likelihood, f.CVSSScore
			},
		},
		{
			Name:   "owasp_reference",
			Weight: 0.10,
			Condition: func(f scanner.Finding) bool {
				return f.OWASPMapping != ""
			},
			AdjustFn: func(f scanner.Finding) (float64, float64) {
				return 0.6, 5.0
			},
		},
		{
			Name:   "remediation_available",
			Weight: 0.10,
			Condition: func(f scanner.Finding) bool {
				return f.Remediation != ""
			},
			AdjustFn: func(f scanner.Finding) (float64, float64) {
				return 0.5, 0.0
			},
		},
		{
			Name:   "module_specificity",
			Weight: 0.10,
			Condition: func(f scanner.Finding) bool {
				return f.Module == "sqli" || f.Module == "xss" || f.Module == "brute_force"
			},
			AdjustFn: func(f scanner.Finding) (float64, float64) {
				return 0.7, 6.5
			},
		},
		{
			Name:   "historical_pattern",
			Weight: 0.10,
			Condition: func(f scanner.Finding) bool {
				return true
			},
			AdjustFn: func(f scanner.Finding) (float64, float64) {
				he.mu.RLock()
				key := f.Module + ":" + f.Title
				scores := he.history[key]
				he.mu.RUnlock()
				if len(scores) > 0 {
					var avg float64
					for _, s := range scores {
						avg += s
					}
					avg /= float64(len(scores))
					return avg, avg * 10
				}
				return 0.5, 5.0
			},
		},
	}
}

func (he *HeuristicEngine) Analyze(finding scanner.Finding) HeuristicResult {
	result := HeuristicResult{
		Finding:       finding,
		Likelihood:    0.5,
		SeverityScore: float64(severityWeight(finding.Severity)),
	}

	var totalWeight float64
	var weightedLikelihood float64
	var weightedSeverity float64
	var explanations []string

	for _, rule := range he.rules {
		if !rule.Condition(finding) {
			continue
		}

		lBoost, sBoost := rule.AdjustFn(finding)
		weightedLikelihood += rule.Weight * lBoost
		weightedSeverity += rule.Weight * sBoost
		totalWeight += rule.Weight

		if lBoost > 0.5 || sBoost > 5.0 {
			explanations = append(explanations, rule.Name)
		}
	}

	if totalWeight > 0 {
		result.Likelihood = weightedLikelihood / totalWeight
		result.SeverityScore = weightedSeverity / totalWeight
	}

	if result.SeverityScore > 0 {
		result.RiskScore = result.Likelihood * (result.SeverityScore / 10.0) * 10
	}

	if len(explanations) > 0 {
		result.Explanation = "matched: " + joinStrings(explanations, ", ")
	}

	he.mu.Lock()
	key := finding.Module + ":" + finding.Title
	he.history[key] = append(he.history[key], result.Likelihood)
	if len(he.history[key]) > 100 {
		he.history[key] = he.history[key][len(he.history[key])-100:]
	}
	he.mu.Unlock()

	return result
}

func (he *HeuristicEngine) AnalyzeAll(findings []scanner.Finding) []HeuristicResult {
	results := make([]HeuristicResult, len(findings))
	for i, f := range findings {
		results[i] = he.Analyze(f)
	}
	return results
}

func (he *HeuristicEngine) AddRule(rule HeuristicRule) {
	he.mu.Lock()
	defer he.mu.Unlock()
	he.rules = append(he.rules, rule)
}

func severityWeight(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 10
	case scanner.SeverityHigh:
		return 7
	case scanner.SeverityMedium:
		return 5
	case scanner.SeverityLow:
		return 2
	case scanner.SeverityInfo:
		return 0
	default:
		return 0
	}
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}
	return result
}
