#!/bin/bash
set -e

# cyNetMapper Docker Entrypoint Script
# This script handles container initialization and command execution

# Default configuration
CONFIG_DIR="/app/config"
DATA_DIR="/app/data"
DEFAULT_CONFIG="$CONFIG_DIR/default.toml"

# Function to print usage
show_usage() {
    echo "cyNetMapper Docker Container"
    echo ""
    echo "Usage:"
    echo "  docker run cynetmapper [OPTIONS] [TARGETS]"
    echo ""
    echo "Examples:"
    echo "  # Show help"
    echo "  docker run cynetmapper --help"
    echo ""
    echo "  # Basic scan"
    echo "  docker run cynetmapper 192.168.1.0/24"
    echo ""
    echo "  # Scan with custom config"
    echo "  docker run -v /path/to/config:/app/config cynetmapper --config /app/config/custom.toml 10.0.0.0/8"
    echo ""
    echo "  # Save results to host"
    echo "  docker run -v /path/to/results:/app/data cynetmapper --output /app/data/scan.json 192.168.1.1"
    echo ""
    echo "  # Use cyndiff tool"
    echo "  docker run -v /path/to/scans:/app/data cynetmapper cyndiff /app/data/scan1.json /app/data/scan2.json"
}

# Function to initialize configuration
init_config() {
    if [ ! -f "$DEFAULT_CONFIG" ]; then
        echo "Creating default configuration..."
        mkdir -p "$CONFIG_DIR"
        cat > "$DEFAULT_CONFIG" << 'EOF'
# cyNetMapper Default Configuration

[scanning]
# Default scan timing (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)
timing = 3

# Maximum concurrent hosts to scan
max_concurrent_hosts = 100

# Maximum concurrent ports per host
max_concurrent_ports = 1000

# Default ports to scan (common ports)
default_ports = [
    22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
]

[discovery]
# Enable host discovery
enable_ping = true
enable_arp = true
enable_dns = true

# DNS settings
dns_timeout = 5000  # milliseconds
reverse_dns = true

[output]
# Default output format
format = "json"

# Include timing information
include_timing = true

# Include host discovery details
include_discovery = true

[logging]
# Log level: error, warn, info, debug, trace
level = "info"

# Log to file
log_to_file = false
log_file = "/app/data/cynetmapper.log"
EOF
    fi
}

# Function to check if running as root (for capabilities)
check_capabilities() {
    if [ "$(id -u)" = "0" ]; then
        echo "Warning: Running as root. Consider using --user flag for better security."
    fi
    
    # Check if we have necessary capabilities for raw sockets
    if ! capsh --print | grep -q "cap_net_raw"; then
        echo "Warning: Missing CAP_NET_RAW capability. Some scan types may not work."
        echo "Run with: docker run --cap-add=NET_RAW cynetmapper"
    fi
}

# Function to handle signals
handle_signal() {
    echo "Received signal, shutting down gracefully..."
    # Kill any running cynetmapper processes
    pkill -f cynetmapper || true
    exit 0
}

# Set up signal handlers
trap handle_signal SIGTERM SIGINT

# Initialize
echo "Starting cyNetMapper container..."
init_config
check_capabilities

# Ensure data directory exists
mkdir -p "$DATA_DIR"

# Handle special cases
case "$1" in
    "--help" | "-h" | "help")
        show_usage
        cynetmapper --help
        exit 0
        ;;
    "--version" | "-v" | "version")
        cynetmapper --version
        exit 0
        ;;
    "cyndiff")
        # Run cyndiff tool
        shift
        exec cyndiff "$@"
        ;;
    "bash" | "sh")
        # Interactive shell for debugging
        exec "$@"
        ;;
    "")
        # No arguments provided
        show_usage
        exit 1
        ;;
esac

# Default: run cynetmapper with provided arguments
echo "Executing: cynetmapper $*"
exec cynetmapper "$@"