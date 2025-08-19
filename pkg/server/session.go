package server

import (
	"bash_over_ws/pkg/logging"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// Session represents a client session with a PTY
type Session struct {
	ID       string
	conn     *websocket.Conn
	pty      *os.File
	cmd      *exec.Cmd
	logger   *logging.Logger
	done     chan struct{}
	clientAddr string
}

// SessionManager manages multiple client sessions
type SessionManager struct {
	sessions map[string]*Session
	logger   *logging.Logger
	mu       sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager(logger *logging.Logger) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		logger:   logger.WithComponent("session_manager"),
	}
}

// CreateSession creates a new session for a WebSocket connection
func (sm *SessionManager) CreateSession(conn *websocket.Conn, clientAddr string) (*Session, error) {
	// Generate unique session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Create bash command
	cmd := exec.Command("/bin/bash")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	// Start PTY
	ptyFile, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start PTY: %w", err)
	}

	// Create session
	session := &Session{
		ID:         sessionID,
		conn:       conn,
		pty:        ptyFile,
		cmd:        cmd,
		logger:     sm.logger.WithSessionID(sessionID).WithClientAddr(clientAddr),
		done:       make(chan struct{}),
		clientAddr: clientAddr,
	}

	// Store session
	sm.mu.Lock()
	sm.sessions[sessionID] = session
	sm.mu.Unlock()

	sm.logger.Info("Session created", "session_id", sessionID, "client_addr", clientAddr)
	return session, nil
}

// RemoveSession removes a session from the manager
func (sm *SessionManager) RemoveSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		session.cleanup()
		delete(sm.sessions, sessionID)
		sm.logger.Info("Session removed", "session_id", sessionID)
	}
}

// CloseAll closes all active sessions
func (sm *SessionManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for sessionID, session := range sm.sessions {
		session.cleanup()
		delete(sm.sessions, sessionID)
	}
	sm.logger.Info("All sessions closed")
}

// Start starts the session and handles I/O between WebSocket and PTY
func (s *Session) Start() {
	defer s.cleanup()

	// Set up WebSocket close handler
	s.conn.SetCloseHandler(func(code int, text string) error {
		s.logger.Info("WebSocket connection closed by client", "code", code, "text", text)
		close(s.done)
		return nil
	})

	// Start goroutines for I/O
	go s.handleWebSocketToPTY()
	go s.handlePTYToWebSocket()

	// Wait for session to end
	<-s.done
}

// handleWebSocketToPTY handles input from WebSocket to PTY
func (s *Session) handleWebSocketToPTY() {
	defer func() {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}()

	for {
		select {
		case <-s.done:
			return
		default:
			// Read message from WebSocket
			messageType, data, err := s.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					s.logger.Error("WebSocket read error", "error", err)
				}
				return
			}

			// Only handle text messages
			if messageType == websocket.TextMessage {
				// Write to PTY
				if _, err := s.pty.Write(data); err != nil {
					s.logger.Error("Failed to write to PTY", "error", err)
					return
				}
			}
		}
	}
}

// handlePTYToWebSocket handles output from PTY to WebSocket
func (s *Session) handlePTYToWebSocket() {
	defer func() {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-s.done:
			return
		default:
			// Read from PTY
			n, err := s.pty.Read(buffer)
			if err != nil {
				if err != io.EOF {
					s.logger.Error("Failed to read from PTY", "error", err)
				}
				return
			}

			// Send to WebSocket
			if err := s.conn.WriteMessage(websocket.TextMessage, buffer[:n]); err != nil {
				s.logger.Error("Failed to write to WebSocket", "error", err)
				return
			}
		}
	}
}

// cleanup cleans up session resources
func (s *Session) cleanup() {
	s.logger.Info("Cleaning up session")

	// Close WebSocket connection
	if s.conn != nil {
		s.conn.Close()
	}

	// Close PTY
	if s.pty != nil {
		s.pty.Close()
	}

	// Terminate bash process
	if s.cmd != nil && s.cmd.Process != nil {
		// Send SIGTERM first
		if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			s.logger.Error("Failed to send SIGTERM", "error", err)
		}

		// Wait a bit, then force kill if necessary
		go func() {
			if err := s.cmd.Wait(); err != nil {
				s.logger.Debug("Process wait error", "error", err)
			}
		}()
	}
}

// generateSessionID generates a random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}