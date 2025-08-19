package client

import (
	"bash_over_ws/pkg/logging"
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// Config holds client configuration
type Config struct {
	URL      string
	Token    string
	Insecure bool
	LogLevel string
}

// Client represents the WebSocket client
type Client struct {
	config *Config
	logger *logging.Logger
	conn   *websocket.Conn
	done   chan struct{}
}

// New creates a new client instance
func New(config *Config) *Client {
	logger := logging.New(config.LogLevel).WithComponent("client")
	
	return &Client{
		config: config,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Connect connects to the WebSocket server
func (c *Client) Connect() error {
	// Parse URL
	u, err := url.Parse(c.config.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Add token as query parameter if not already present
	if u.RawQuery == "" && c.config.Token != "" {
		q := u.Query()
		q.Set("token", c.config.Token)
		u.RawQuery = q.Encode()
	}

	// Configure WebSocket dialer
	dialer := websocket.DefaultDialer
	if c.config.Insecure {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		c.logger.Warn("SSL certificate verification disabled")
	}

	// Set authorization header if token provided and not in query
	headers := make(map[string][]string)
	if c.config.Token != "" && u.Query().Get("token") == "" {
		headers["Authorization"] = []string{"Bearer " + c.config.Token}
	}

	c.logger.Info("Connecting to server", "url", u.String())

	// Connect to WebSocket
	conn, _, err := dialer.Dial(u.String(), headers)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.conn = conn
	c.logger.Info("Connected to server")

	return nil
}

// Start starts the client terminal session
func (c *Client) Start() error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	// Set up terminal
	if err := c.setupTerminal(); err != nil {
		return fmt.Errorf("failed to setup terminal: %w", err)
	}

	// Set up signal handling for graceful shutdown
	c.setupSignalHandling()

	// Start I/O goroutines
	go c.handleTerminalToWebSocket()
	go c.handleWebSocketToTerminal()

	c.logger.Info("Terminal session started. Press Ctrl+C to exit.")

	// Wait for session to end
	<-c.done

	return nil
}

// Close closes the client connection
func (c *Client) Close() error {
	c.logger.Info("Closing connection")
	
	close(c.done)
	
	if c.conn != nil {
		return c.conn.Close()
	}
	
	return nil
}

// setupTerminal configures the terminal for raw mode
func (c *Client) setupTerminal() error {
	// Check if stdin is a terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		c.logger.Warn("stdin is not a terminal")
		return nil
	}

	// Set terminal to raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}

	// Restore terminal on exit
	go func() {
		<-c.done
		term.Restore(int(os.Stdin.Fd()), oldState)
	}()

	return nil
}

// setupSignalHandling sets up signal handling for graceful shutdown
func (c *Client) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		c.logger.Info("Received signal", "signal", sig.String())
		c.Close()
	}()
}

// handleTerminalToWebSocket handles input from terminal to WebSocket
func (c *Client) handleTerminalToWebSocket() {
	defer c.Close()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-c.done:
			return
		default:
			// Read from stdin
			n, err := os.Stdin.Read(buffer)
			if err != nil {
				c.logger.Error("Failed to read from stdin", "error", err)
				return
			}

			// Send to WebSocket
			if err := c.conn.WriteMessage(websocket.TextMessage, buffer[:n]); err != nil {
				c.logger.Error("Failed to write to WebSocket", "error", err)
				return
			}
		}
	}
}

// handleWebSocketToTerminal handles output from WebSocket to terminal
func (c *Client) handleWebSocketToTerminal() {
	defer c.Close()

	for {
		select {
		case <-c.done:
			return
		default:
			// Read from WebSocket
			messageType, data, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.logger.Error("WebSocket read error", "error", err)
				}
				return
			}

			// Only handle text messages
			if messageType == websocket.TextMessage {
				// Write to stdout
				if _, err := os.Stdout.Write(data); err != nil {
					c.logger.Error("Failed to write to stdout", "error", err)
					return
				}
			}
		}
	}
}