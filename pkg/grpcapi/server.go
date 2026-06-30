package grpcapi

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/SepJs/anubis/pkg/scanner"
)

type AnubisServer struct {
	engine    *scanner.Engine
	authToken string
	scanCh    chan *ScanRequest
}

func NewAnubisServer(authToken string) *AnubisServer {
	return &AnubisServer{
		authToken: authToken,
		scanCh:    make(chan *ScanRequest, 100),
	}
}

func (s *AnubisServer) authenticate(ctx context.Context) error {
	if s.authToken == "" {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return status.Error(codes.Unauthenticated, "missing auth token")
	}

	if tokens[0] != "Bearer "+s.authToken {
		return status.Error(codes.Unauthenticated, "invalid auth token")
	}

	return nil
}

func (s *AnubisServer) StartScan(ctx context.Context, req *ScanRequest) (*ScanResponse, error) {
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	resp := &ScanResponse{
		Status:    "queued",
		Target:    req.Target,
		Accepted:  true,
		Timestamp: time.Now().Unix(),
	}

	return resp, nil
}

func (s *AnubisServer) GetScanStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error) {
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	return &StatusResponse{
		ScanId:    req.ScanId,
		Status:    "running",
		Progress:  0.5,
		Findings:  0,
		StartedAt: time.Now().Unix(),
	}, nil
}

func (s *AnubisServer) ListModules(ctx context.Context, req *ModuleRequest) (*ModuleResponse, error) {
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	return &ModuleResponse{
		Modules: []*ModuleInfo{
			{Name: "portscan", Description: "TCP port scanning", Level: 1},
			{Name: "ssl", Description: "SSL/TLS analysis", Level: 1},
			{Name: "headers", Description: "HTTP security headers", Level: 1},
			{Name: "sensitive", Description: "Sensitive file discovery", Level: 1},
			{Name: "dns", Description: "DNS enumeration", Level: 2},
			{Name: "sqli", Description: "SQL injection testing", Level: 2},
			{Name: "xss", Description: "Cross-site scripting", Level: 2},
			{Name: "brute_force", Description: "Brute force credentials", Level: 2},
			{Name: "fingerprint", Description: "Stack fingerprinting", Level: 3},
			{Name: "discovery", Description: "Subdomain discovery", Level: 2},
		},
	}, nil
}

func StartGRPCServer(addr string, server *AnubisServer, tlsCert, tlsKey string) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("grpc: listen: %w", err)
	}

	var opts []grpc.ServerOption
	if tlsCert != "" && tlsKey != "" {
		creds, err := credentials.NewServerTLSFromFile(tlsCert, tlsKey)
		if err != nil {
			return nil, fmt.Errorf("grpc: tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	grpcServer := grpc.NewServer(opts...)
	RegisterAnubisServiceServer(grpcServer, server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	return grpcServer, nil
}
