# Bash Over WebSocket

A secure WebSocket-based remote terminal application that provides bash access over encrypted connections with token-based authentication.

## Features

- **Single Binary**: Both client and server functionality in one executable
- **Token Authentication**: Simple static token-based authentication
- **SSL/TLS Support**: Secure communication with automatic certificate generation
- **Multiple Clients**: Support for concurrent client sessions with isolated bash environments
- **Production Ready**: Structured logging, graceful shutdown, and proper error handling
- **Cross Platform**: Works on Linux, macOS, and Windows (where bash is available)

## Installation

### Build from Source

```bash
git clone <repository-url>
cd bash_over_ws
go build -o bash_over_ws
```

### Download Binary

Download the latest release from the releases page.

## Usage

### Server Mode

Start the WebSocket server to accept client connections:

```bash
# Basic server (HTTP)
AUTH_TOKEN=your-secret-token PORT=8080 ./bash_over_ws server

# Server with SSL/TLS (auto-generated certificates)
AUTH_TOKEN=your-secret-token PORT=8443 ./bash_over_ws server

# Server with custom SSL certificates
AUTH_TOKEN=your-secret-token PORT=8443 SSL_CERT=server.crt SSL_KEY=server.key ./bash_over_ws server

# Server with debug logging
AUTH_TOKEN=your-secret-token PORT=8080 LOG_LEVEL=debug ./bash_over_ws server
```

### Client Mode

Connect to a WebSocket server and start a terminal session:

```bash
# Connect to HTTP server
./bash_over_ws client --url ws://localhost:8080/ws --token your-secret-token

# Connect to HTTPS server (with SSL verification)
./bash_over_ws client --url wss://localhost:8443/ws --token your-secret-token

# Connect to HTTPS server (skip SSL verification for self-signed certificates)
./bash_over_ws client --url wss://localhost:8443/ws --token your-secret-token --insecure

# Connect with token from environment variable
AUTH_TOKEN=your-secret-token ./bash_over_ws client --url wss://localhost:8443/ws

# Connect with debug logging
./bash_over_ws client --url ws://localhost:8080/ws --token your-secret-token --log-level debug
```

## Configuration

### Environment Variables

#### Server Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AUTH_TOKEN` | Authentication token for client connections | - | Yes |
| `PORT` | Server listening port | `8080` | No |
| `SSL_CERT` | Path to SSL certificate file | - | No |
| `SSL_KEY` | Path to SSL private key file | - | No |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` | No |

#### Client Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AUTH_TOKEN` | Authentication token (if not provided via --token flag) | - | Yes |

### Command Line Flags

#### Server Flags

```bash
./bash_over_ws server --help
```

- `--log-level`: Set logging level (debug, info, warn, error)

#### Client Flags

```bash
./bash_over_ws client --help
```

- `--url, -u`: WebSocket server URL (required)
- `--token, -t`: Authentication token
- `--insecure`: Skip SSL certificate verification
- `--log-level`: Set logging level (debug, info, warn, error)

## Authentication

The application supports token-based authentication using a simple static token. The token can be provided in two ways:

1. **Query Parameter**: `ws://server:port/ws?token=your-token`
2. **Authorization Header**: `Authorization: Bearer your-token`

The client automatically uses the query parameter method by default.

## SSL/TLS Support

### Automatic Certificate Generation

If no SSL certificate files are specified, the server will automatically generate self-signed certificates for development use. These certificates are valid for 1 year and include `localhost` and `127.0.0.1`.

### Custom Certificates

For production use, provide your own SSL certificates:

```bash
SSL_CERT=/path/to/certificate.crt SSL_KEY=/path/to/private.key ./bash_over_ws server
```

### Client SSL Verification

By default, the client verifies SSL certificates. For development with self-signed certificates, use the `--insecure` flag:

```bash
./bash_over_ws client --url wss://localhost:8443/ws --token your-token --insecure
```

## Security Considerations

1. **Use Strong Tokens**: Generate cryptographically secure random tokens for production
2. **Use SSL/TLS**: Always use encrypted connections in production environments
3. **Network Security**: Restrict network access to the server port using firewalls
4. **Token Rotation**: Regularly rotate authentication tokens
5. **Logging**: Monitor server logs for suspicious activity

## Examples

### Development Setup

1. Start server with auto-generated SSL certificates:
```bash
AUTH_TOKEN=dev-token-123 PORT=8443 ./bash_over_ws server
```

2. Connect client (in another terminal):
```bash
./bash_over_ws client --url wss://localhost:8443/ws --token dev-token-123 --insecure
```

### Production Setup

1. Generate or obtain SSL certificates
2. Start server:
```bash
AUTH_TOKEN=prod-secure-token PORT=443 SSL_CERT=/etc/ssl/server.crt SSL_KEY=/etc/ssl/server.key ./bash_over_ws server
```

3. Connect client:
```bash
./bash_over_ws client --url wss://your-server.com/ws --token prod-secure-token
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure the server is running and the port is correct
2. **Authentication Failed**: Verify the token matches between client and server
3. **SSL Certificate Errors**: Use `--insecure` flag for self-signed certificates
4. **Permission Denied**: Ensure the user has permission to execute bash

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
# Server
LOG_LEVEL=debug AUTH_TOKEN=token ./bash_over_ws server

# Client
./bash_over_ws client --url ws://localhost:8080/ws --token token --log-level debug
```

## Testing

Run the integration tests:

```bash
go test ./test -v
```

The tests verify:
- Authentication (valid and invalid tokens)
- Bash command execution
- Multiple concurrent client sessions
- SSL certificate handling

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]