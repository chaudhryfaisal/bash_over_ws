package server

import (
	"bash_over_ws/pkg/auth"
	"bash_over_ws/pkg/logging"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Config holds server configuration
type Config struct {
	Port      string
	AuthToken string
	SSLCert   string
	SSLKey    string
	SSLGenerate    bool
	LogLevel  string
}

// Server represents the WebSocket server
type Server struct {
	config    *Config
	logger    *logging.Logger
	validator *auth.TokenValidator
	sessions  *SessionManager
	server    *http.Server
	mu        sync.RWMutex
}

// New creates a new server instance
func New(config *Config) *Server {
	logger := logging.New(config.LogLevel).WithComponent("server")
	validator := auth.NewTokenValidator(config.AuthToken)
	sessions := NewSessionManager(logger)

	return &Server{
		config:    config,
		logger:    logger,
		validator: validator,
		sessions:  sessions,
	}
}

// Start starts the server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	
	// WebSocket endpoint
	mux.HandleFunc("/ws", s.validator.Middleware(s.handleWebSocket))
	
	// 404 for all other endpoints
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	})

	s.server = &http.Server{
		Addr:    ":" + s.config.Port,
		Handler: mux,
	}

	s.logger.Info("Starting server", "port", s.config.Port)

	// Start server with or without TLS
	if s.config.SSLCert != "" && s.config.SSLKey != "" {
		return s.startTLS()
	}

	// Check if we need to generate self-signed certificates
	if s.shouldGenerateSSL() {
		if err := s.generateSelfSignedCert(); err != nil {
			s.logger.Error("Failed to generate self-signed certificate", "error", err)
			return err
		}
		return s.startTLS()
	}

	return s.server.ListenAndServe()
}

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping server")
	
	// Close all sessions
	s.sessions.CloseAll()
	
	// Shutdown HTTP server
	return s.server.Shutdown(ctx)
}

// startTLS starts the server with TLS
func (s *Server) startTLS() error {
	s.logger.Info("Starting server with TLS", "cert", s.config.SSLCert, "key", s.config.SSLKey)
	return s.server.ListenAndServeTLS(s.config.SSLCert, s.config.SSLKey)
}

// shouldGenerateSSL determines if we should generate self-signed certificates
func (s *Server) shouldGenerateSSL() bool {
	// Generate if no cert/key specified but we want SSL
	return s.config.SSLCert == "" && s.config.SSLKey == "" && s.config.SSLGenerate
}

// generateSelfSignedCert generates a self-signed certificate for development
func (s *Server) generateSelfSignedCert() error {
	s.logger.Info("Generating self-signed certificate")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Bash Over WebSocket"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate
	certOut, err := os.Create("server.crt")
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create("server.key")
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Update config to use generated certificates
	s.config.SSLCert = "server.crt"
	s.config.SSLKey = "server.key"

	s.logger.Info("Self-signed certificate generated", "cert", s.config.SSLCert, "key", s.config.SSLKey)
	return nil
}
