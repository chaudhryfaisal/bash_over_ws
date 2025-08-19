package server

import (
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow connections from any origin for simplicity
		// In production, you might want to restrict this
		return true
	},
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("Failed to upgrade connection", "error", err)
		return
	}

	// Create session for this connection
	session, err := s.sessions.CreateSession(conn, r.RemoteAddr)
	if err != nil {
		s.logger.Error("Failed to create session", "error", err, "client_addr", r.RemoteAddr)
		conn.Close()
		return
	}

	s.logger.Info("New WebSocket connection", "session_id", session.ID, "client_addr", r.RemoteAddr)

	// Start session (this will block until session ends)
	session.Start()

	s.logger.Info("WebSocket connection closed", "session_id", session.ID, "client_addr", r.RemoteAddr)
}