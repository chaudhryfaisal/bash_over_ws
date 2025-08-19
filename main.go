package main

import (
	"bash_over_ws/pkg/client"
	"bash_over_ws/pkg/server"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:     "bash_over_ws",
		Short:   "Bash over WebSocket - Remote terminal access",
		Version: version,
		Long: `A secure WebSocket-based remote terminal application that provides
bash access over encrypted connections with token-based authentication.`,
	}

	// Server command
	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start the WebSocket server",
		Long:  "Start the WebSocket server to accept client connections",
		RunE:  runServer,
	}

	// Client command
	var clientCmd = &cobra.Command{
		Use:   "client",
		Short: "Connect to a WebSocket server",
		Long:  "Connect to a WebSocket server and start a terminal session",
		RunE:  runClient,
	}

	// Client flags
	var (
		clientURL      string
		clientToken    string
		clientInsecure bool
		clientLogLevel string
	)

	clientCmd.Flags().StringVarP(&clientURL, "url", "u", "", "WebSocket server URL (required)")
	clientCmd.Flags().StringVarP(&clientToken, "token", "t", "", "Authentication token")
	clientCmd.Flags().BoolVar(&clientInsecure, "insecure", false, "Skip SSL certificate verification")
	clientCmd.Flags().StringVar(&clientLogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	clientCmd.MarkFlagRequired("url")

	// Server flags
	var serverLogLevel string
	serverCmd.Flags().StringVar(&serverLogLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	rootCmd.AddCommand(serverCmd, clientCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	// Get configuration from environment variables
	config := &server.Config{
		Port:        getEnvOrDefault("PORT", "8080"),
		AuthToken:   getEnvOrDefault("AUTH_TOKEN", ""),
		SSLCert:     getEnvOrDefault("SSL_CERT", ""),
		SSLKey:      getEnvOrDefault("SSL_KEY", ""),
		SSLGenerate: getEnvOrDefault("SSL_GENERATE", "false") == "true",
		LogLevel:    getEnvOrDefault("LOG_LEVEL", cmd.Flag("log-level").Value.String()),
	}

	// Validate required configuration
	if config.AuthToken == "" {
		return fmt.Errorf("AUTH_TOKEN environment variable is required")
	}

	// Create and start server
	srv := server.New(config)

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Printf("\nReceived signal: %v\n", sig)
		fmt.Println("Shutting down server...")

		// Give server 30 seconds to shutdown gracefully
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := srv.Stop(shutdownCtx); err != nil {
			fmt.Printf("Error during shutdown: %v\n", err)
		}
		cancel()
	}()

	// Start server
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func runClient(cmd *cobra.Command, args []string) error {
	// Get configuration from flags and environment
	config := &client.Config{
		URL:      cmd.Flag("url").Value.String(),
		Token:    getTokenFromFlagOrEnv(cmd.Flag("token").Value.String()),
		Insecure: cmd.Flag("insecure").Value.String() == "true",
		LogLevel: cmd.Flag("log-level").Value.String(),
	}

	// Validate required configuration
	if config.URL == "" {
		return fmt.Errorf("URL is required")
	}
	if config.Token == "" {
		return fmt.Errorf("authentication token is required (use --token flag or AUTH_TOKEN environment variable)")
	}

	// Create and connect client
	c := client.New(config)

	if err := c.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer c.Close()

	// Start terminal session
	if err := c.Start(); err != nil {
		return fmt.Errorf("session error: %w", err)
	}

	return nil
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getTokenFromFlagOrEnv gets token from flag or environment variable
func getTokenFromFlagOrEnv(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("AUTH_TOKEN")
}
