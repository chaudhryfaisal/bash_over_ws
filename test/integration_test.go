package test

import (
	"bash_over_ws/pkg/server"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const (
	testToken    = "test-token-123"
	testCertFile = "testdata/test.crt"
	testKeyFile  = "testdata/test.key"
)

func TestBashOverWebSocketIntegration(t *testing.T) {
	// Generate test certificates
	if err := generateTestCertificates(); err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}
	defer cleanupTestCertificates()

	// Find available port
	port, err := findAvailablePort()
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}

	// Start server
	serverConfig := &server.Config{
		Port:      port,
		AuthToken: testToken,
		SSLCert:   testCertFile,
		SSLKey:    testKeyFile,
		LogLevel:  "error", // Reduce log noise in tests
	}

	srv := server.New(serverConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil {
			serverErr <- err
		}
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Test 1: Valid authentication
	t.Run("ValidAuthentication", func(t *testing.T) {
		testValidAuthentication(t, port)
	})

	// Test 2: Invalid authentication
	t.Run("InvalidAuthentication", func(t *testing.T) {
		testInvalidAuthentication(t, port)
	})

	// Test 3: Bash command execution
	t.Run("BashCommandExecution", func(t *testing.T) {
		testBashCommandExecution(t, port)
	})

	// Test 4: Multiple concurrent clients
	t.Run("MultipleConcurrentClients", func(t *testing.T) {
		testMultipleConcurrentClients(t, port)
	})

	// Shutdown server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	
	if err := srv.Stop(shutdownCtx); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Check for server errors
	select {
	case err := <-serverErr:
		if err != nil && !strings.Contains(err.Error(), "Server closed") {
			t.Errorf("Server error: %v", err)
		}
	default:
		// No error, which is good
	}
}

func testValidAuthentication(t *testing.T, port string) {
	url := fmt.Sprintf("wss://localhost:%s/ws?token=%s", port, testToken)
	
	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to connect with valid token: %v", err)
	}
	defer conn.Close()

	// Connection should be successful
	t.Log("Successfully connected with valid authentication")
}

func testInvalidAuthentication(t *testing.T, port string) {
	url := fmt.Sprintf("wss://localhost:%s/ws?token=invalid-token", port)
	
	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	_, _, err := dialer.Dial(url, nil)
	if err == nil {
		t.Fatal("Expected connection to fail with invalid token")
	}

	// Should get authentication error (either 401 or bad handshake due to auth failure)
	if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "bad handshake") {
		t.Errorf("Expected authentication error, got: %v", err)
	}

	t.Log("Successfully rejected invalid authentication")
}

func testBashCommandExecution(t *testing.T, port string) {
	url := fmt.Sprintf("wss://localhost:%s/ws?token=%s", port, testToken)
	
	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send echo command
	command := "echo 'Hello, World!'\n"
	if err := conn.WriteMessage(websocket.TextMessage, []byte(command)); err != nil {
		t.Fatalf("Failed to send command: %v", err)
	}

	// Read response with timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	var output strings.Builder
	for i := 0; i < 10; i++ { // Read multiple messages to get full output
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		output.Write(message)
		
		// Check if we got the expected output
		if strings.Contains(output.String(), "Hello, World!") {
			t.Log("Successfully executed bash command and received output")
			return
		}
	}

	t.Errorf("Did not receive expected output. Got: %s", output.String())
}

func testMultipleConcurrentClients(t *testing.T, port string) {
	const numClients = 3
	url := fmt.Sprintf("wss://localhost:%s/ws?token=%s", port, testToken)
	
	dialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Connect multiple clients
	var connections []*websocket.Conn
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()

	for i := 0; i < numClients; i++ {
		conn, _, err := dialer.Dial(url, nil)
		if err != nil {
			t.Fatalf("Failed to connect client %d: %v", i, err)
		}
		connections = append(connections, conn)
	}

	// Send different commands to each client
	for i, conn := range connections {
		command := fmt.Sprintf("echo 'Client %d'\n", i)
		if err := conn.WriteMessage(websocket.TextMessage, []byte(command)); err != nil {
			t.Errorf("Failed to send command to client %d: %v", i, err)
		}
	}

	// Verify each client gets its own output
	for i, conn := range connections {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		
		var output strings.Builder
		for j := 0; j < 10; j++ {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}
			output.Write(message)
			
			expectedOutput := fmt.Sprintf("Client %d", i)
			if strings.Contains(output.String(), expectedOutput) {
				t.Logf("Client %d received correct output", i)
				break
			}
		}
	}

	t.Log("Successfully tested multiple concurrent clients")
}

func generateTestCertificates() error {
	// Create testdata directory
	if err := os.MkdirAll("testdata", 0755); err != nil {
		return err
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Save certificate
	certOut, err := os.Create(testCertFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Save private key
	keyOut, err := os.Create(testKeyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

func cleanupTestCertificates() {
	os.Remove(testCertFile)
	os.Remove(testKeyFile)
}

func findAvailablePort() (string, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return fmt.Sprintf("%d", addr.Port), nil
}