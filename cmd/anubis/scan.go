package main

import (
	bruteforce "github.com/innervoid/anubis/pkg/modules/brute_force"
	"github.com/innervoid/anubis/pkg/modules/dns"
	"github.com/innervoid/anubis/pkg/modules/fingerprint"
	"github.com/innervoid/anubis/pkg/modules/headers"
	"github.com/innervoid/anubis/pkg/modules/portscan"
	"github.com/innervoid/anubis/pkg/modules/sensitive"
	sslmod "github.com/innervoid/anubis/pkg/modules/ssl"
	"github.com/innervoid/anubis/pkg/modules/sqli"
	"github.com/innervoid/anubis/pkg/modules/xss"
	"github.com/innervoid/anubis/pkg/scanner"
)

func allModules() []scanner.Module {
	return []scanner.Module{
		portscan.New(),
		sslmod.New(),
		headers.New(),
		sensitive.New(),
		dns.New(),
		sqli.New(),
		xss.New(),
		bruteforce.New(),
		fingerprint.New(),
	}
}

func dispatchScan() error {
	cfg := buildConfig()
	if resume { return resumeScan(cfg) }
	if batch { return batchScan(cfg) }
	return runSingleScan(cfg)
}

func buildConfig() scanner.ScanConfig {
	return scanner.ScanConfig{
		Target:  target,
		Level:   scanner.ScanLevel(level),
		Threads: threads,
	}
}

func runSingleScan(cfg scanner.ScanConfig) error {
	engine := scanner.NewEngine(cfg, allModules())
	_, err := engine.Run()
	return err
}

func resumeScan(cfg scanner.ScanConfig) error { return nil }
func batchScan(cfg scanner.ScanConfig) error   { return nil }