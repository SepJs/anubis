// Package grpcapi provides a gRPC remote control interface for the Anubis
// scan engine, allowing remote scan initiation, status queries, and module
// listing over TLS with token authentication.
package grpcapi

type AnubisServiceServer struct {
	UnimplementedAnubisServiceServer
}

func (s *AnubisServiceServer) mustEmbedUnimplementedAnubisServiceServer() {}

type UnimplementedAnubisServiceServer struct{}

type AnubisServiceClient interface{}

type ScanRequest struct {
	Target   string      `json:"target"`
	Level    int32       `json:"level"`
	Config   *ScanConfig `json:"config,omitempty"`
	Sync     bool        `json:"sync"`
}

type ScanConfig struct {
	Threads       int32  `json:"threads,omitempty"`
	Timeout       int32  `json:"timeout,omitempty"`
	RateLimit     int32  `json:"rate_limit,omitempty"`
	DelayStrategy string `json:"delay_strategy,omitempty"`
	ProxyURL      string `json:"proxy_url,omitempty"`
	GhostMode     bool   `json:"ghost_mode,omitempty"`
	Ghost         bool   `json:"ghost,omitempty"`
}

type ScanResponse struct {
	ScanId    string `json:"scan_id"`
	Status    string `json:"status"`
	Target    string `json:"target"`
	Accepted  bool   `json:"accepted"`
	Timestamp int64  `json:"timestamp"`
	Error     string `json:"error,omitempty"`
}

type StatusRequest struct {
	ScanId string `json:"scan_id"`
}

type StatusResponse struct {
	ScanId      string  `json:"scan_id"`
	Status      string  `json:"status"`
	Progress    float64 `json:"progress"`
	Findings    int32   `json:"findings"`
	StartedAt   int64   `json:"started_at"`
	CompletedAt int64   `json:"completed_at,omitempty"`
	Error       string  `json:"error,omitempty"`
}

type ModuleRequest struct {
	Level int32 `json:"level,omitempty"`
}

type ModuleResponse struct {
	Modules []*ModuleInfo `json:"modules"`
}

type ModuleInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Level       int32  `json:"level"`
}

func RegisterAnubisServiceServer(s interface{}, server *AnubisServer) {}

type ServiceDesc struct {
	ServiceName string
	Methods     []struct {
		Name    string
		Handler interface{}
	}
}

var DefaultServiceDesc = ServiceDesc{
	ServiceName: "anubis.AnubisService",
}
