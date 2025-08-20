package server

import (
	"bash_over_ws/pkg/auth"
	"bash_over_ws/pkg/logging"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Config holds server configuration
type Config struct {
	Port        string
	AuthToken   string
	SSLCert     string
	SSLKey      string
	SSLGenerate bool
	LogLevel    string
}

// Server represents the WebSocket server
type Server struct {
	config    *Config
	logger    *logging.Logger
	validator *auth.TokenValidator
	sessions  *SessionManager
	server    *http.Server
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

	mux.HandleFunc("/ws", s.validator.Middleware(s.handleWebSocket))
	mux.HandleFunc("/cmd", s.validator.Middleware(s.handleCommand))
	mux.HandleFunc("/proxy/", s.validator.Middleware(s.handleProxy))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"OK"}`))
	})
	// 404 for all other endpoints
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.logger.Info("404", "path", r.URL.Path)
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
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
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

// CommandRequest represents a command execution request
type CommandRequest struct {
	Command string `json:"command"`
	WorkDir string `json:"workdir,omitempty"`
	Timeout int    `json:"timeout,omitempty"` // timeout in seconds, default 300 (5 minutes)
}

// CommandResponse represents a command execution response
type CommandResponse struct {
	Success  bool   `json:"success"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code"`
	Duration string `json:"duration"`
	TimedOut bool   `json:"timed_out"`
}

// handleCommand handles command execution requests
func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	if req.Command == "" {
		http.Error(w, "Command is required", http.StatusBadRequest)
		return
	}

	// Set default timeout to 5 minutes if not specified
	timeout := time.Duration(req.Timeout) * time.Second
	if req.Timeout <= 0 {
		timeout = 5 * time.Minute
	}

	// Validate and set working directory
	workDir := ""
	if req.WorkDir != "" {
		// Make sure the working directory is relative and safe
		cleanPath := filepath.Clean(req.WorkDir)
		if filepath.IsAbs(cleanPath) || strings.Contains(cleanPath, "..") {
			http.Error(w, "Working directory must be relative and cannot contain '..'", http.StatusBadRequest)
			return
		}

		// Get current working directory (server directory)
		cwd, err := os.Getwd()
		if err != nil {
			s.logger.Error("Failed to get current working directory", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		workDir = filepath.Join(cwd, cleanPath)

		// Verify the directory exists
		if _, err := os.Stat(workDir); os.IsNotExist(err) {
			http.Error(w, "Working directory does not exist", http.StatusBadRequest)
			return
		}
	}

	s.logger.Info("Executing command", "command", req.Command, "workdir", workDir, "timeout", timeout)

	start := time.Now()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Parse command and arguments
	parts := strings.Fields(req.Command)
	if len(parts) == 0 {
		http.Error(w, "Invalid command", http.StatusBadRequest)
		return
	}

	// Create command
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	if workDir != "" {
		cmd.Dir = workDir
	}

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute command
	err := cmd.Run()
	duration := time.Since(start)

	// Prepare response
	response := CommandResponse{
		Success:  err == nil,
		Output:   stdout.String(),
		Duration: duration.String(),
		TimedOut: ctx.Err() == context.DeadlineExceeded,
	}

	if err != nil {
		response.Error = err.Error()
		if stderr.Len() > 0 {
			if response.Error != "" {
				response.Error += ": " + stderr.String()
			} else {
				response.Error = stderr.String()
			}
		}

		// Get exit code if available
		if exitError, ok := err.(*exec.ExitError); ok {
			response.ExitCode = exitError.ExitCode()
		} else {
			response.ExitCode = -1
		}
	}

	// If there's stderr output but no error, include it in the output
	if stderr.Len() > 0 && err == nil {
		if response.Output != "" {
			response.Output += "\n" + stderr.String()
		} else {
			response.Output = stderr.String()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode response", "error", err)
	}

	s.logger.Info("Command executed", "command", req.Command, "success", response.Success, "duration", duration)
}

// handleProxy handles proxy requests to localhost ports
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Extract port from URL path
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Port is required", http.StatusBadRequest)
		return
	}

	port := parts[0]
	targetPath := "/"
	if len(parts) > 1 {
		targetPath = "/" + parts[1]
	}

	// Check if this is a WebSocket upgrade request
	if isWebSocketRequest(r) {
		s.handleWebSocketProxy(w, r, port, targetPath)
		return
	}

	// Handle regular HTTP proxy
	s.handleHTTPProxy(w, r, port, targetPath)
}

// isWebSocketRequest checks if the request is a WebSocket upgrade request
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// handleHTTPProxy handles regular HTTP proxy requests
func (s *Server) handleHTTPProxy(w http.ResponseWriter, r *http.Request, port, targetPath string) {
	// Create target URL - just the base URL without the path
	target, err := url.Parse(fmt.Sprintf("http://localhost:%s", port))
	if err != nil {
		s.logger.Error("Failed to parse target URL", "error", err, "port", port, "path", targetPath)
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the proxy to handle errors gracefully
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s.logger.Error("Proxy error", "error", err, "target", target.String())
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
	}

	// Create a new request with the correct path
	originalPath := r.URL.Path
	r.URL.Host = target.Host
	r.URL.Scheme = target.Scheme
	r.URL.Path = targetPath
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = target.Host

	s.logger.Info("Proxying HTTP request", "target", fmt.Sprintf("%s%s", target.String(), targetPath), "method", r.Method, "originalPath", originalPath)
	proxy.ServeHTTP(w, r)
}

// handleWebSocketProxy handles WebSocket proxy requests
func (s *Server) handleWebSocketProxy(w http.ResponseWriter, r *http.Request, port, targetPath string) {
	// Create target URL for WebSocket
	targetURL := fmt.Sprintf("ws://localhost:%s%s", port, targetPath)

	s.logger.Info("Proxying WebSocket request", "target", targetURL)

	// Upgrade the client connection
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for proxy
		},
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("Failed to upgrade client connection", "error", err)
		return
	}
	defer clientConn.Close()

	// Connect to target WebSocket
	targetConn, _, err := websocket.DefaultDialer.Dial(targetURL, nil)
	if err != nil {
		s.logger.Error("Failed to connect to target WebSocket", "error", err, "target", targetURL)
		clientConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseServiceRestart, "Target service unavailable"))
		return
	}
	defer targetConn.Close()

	// Start bidirectional proxy
	done := make(chan struct{})

	// Client to target
	go func() {
		defer close(done)
		for {
			messageType, data, err := clientConn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					s.logger.Error("Error reading from client", "error", err)
				}
				return
			}

			if err := targetConn.WriteMessage(messageType, data); err != nil {
				s.logger.Error("Error writing to target", "error", err)
				return
			}
		}
	}()

	// Target to client
	go func() {
		for {
			messageType, data, err := targetConn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					s.logger.Error("Error reading from target", "error", err)
				}
				return
			}

			if err := clientConn.WriteMessage(messageType, data); err != nil {
				s.logger.Error("Error writing to client", "error", err)
				return
			}
		}
	}()

	// Wait for one of the connections to close
	<-done
	s.logger.Info("WebSocket proxy connection closed", "target", targetURL)
}
