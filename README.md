# LogWisp

LogWisp is a lightweight log streaming and viewing system written in Go. It provides real-time log monitoring capabilities with a focus on reliability and simplicity.

This program is in early development. Features or the whole program may break or behave unexpectedly. Use/reference at your own risk.

## Key Features

### Core Functionality

- Dual operation modes: Service for log collection and streaming, Viewer for log consumption
- Real-time log streaming using Server-Sent Events (SSE)
- Support for both JSON structured logs (slog) and plain text logs
- Directory and file monitoring with pattern matching
- Basic authentication and TLS support
- Rate limiting with per-client tracking


### Reliability & Performance
- Automatic reconnection with exponential backoff
- Connection pooling and management
- Client inactivity detection
- Configurable buffer sizes for streaming
- Heartbeat mechanism to maintain connections
- File rotation handling


### Monitoring & Management
- Monitor multiple log files and directories
- Per-target pattern configuration
- Configurable rate limits and timeouts
- Connection and resource cleanup
- Comprehensive logging and statistics

### Easy to Use
- Simple TOML configuration
- Basic authentication support
- Minimal dependencies
- Clean shutdown handling
- Interactive viewer with basic commands

## Quick Start

1. [placeholder] Create a configuration file (logwisp.toml):
```toml

mode = "service"  # or "viewer"
port = 9090


[logger]
level = "INFO"
directory = "/var/log/logwisp"


[monitor.paths.app1]
path = "/var/log/myapp"
pattern = "*.log"
is_file = false


[security]
auth_enabled = true
auth_username = "admin"
auth_password = "secret"
```


2. Run in service mode:

logwisp -config /path/to/logwisp.toml


3. Run in viewer mode:

logwisp -config /path/to/logwisp.toml -view



## Configuration

[placeholder]


## Building

Requires Go 1.23 or later.

Use "build.sh" to build.


## License

BSD-3