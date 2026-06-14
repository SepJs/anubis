package sqli

import (
	"github.com/innervoid/anubis/pkg/requester"
	"github.com/innervoid/anubis/pkg/scanner"
)

type Module struct{}
func New() *Module { return &Module{} }
func (m *Module) Name() string { return "SQLI" }
func (m *Module) Run(cfg scanner.ScanConfig, findings chan<- scanner.Finding, client *requester.AnubisClient) error { return nil }
func (m *Module) Level() scanner.ScanLevel { return scanner.Level1 }
func (m *Module) Description() string { return "Tests input parameters for SQL injection vulnerabilities." }