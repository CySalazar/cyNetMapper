#!/bin/bash
# cyNetMapper Lab Testing Script
# This script tests the Docker lab environment and validates service connectivity

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Lab network configuration
LAB_NETWORK="172.20.0.0/16"
LAB_SUBNET="172.20.0"

# Service endpoints to test
declare -A SERVICES=(
    ["nginx-web"]="172.20.0.10:80"
    ["nginx-ssl"]="172.20.0.10:443"
    ["apache-web"]="172.20.0.11:80"
    ["mysql-db"]="172.20.0.20:3306"
    ["postgres-db"]="172.20.0.21:5432"
    ["ssh-server"]="172.20.0.30:2222"
    ["ftp-server"]="172.20.0.31:21"
    ["dns-server"]="172.20.0.40:53"
    ["smtp-server"]="172.20.0.50:1025"
    ["redis-cache"]="172.20.0.60:6379"
    ["dvwa"]="172.20.0.70:80"
)

# Expected service banners/responses
declare -A EXPECTED_BANNERS=(
    ["nginx-web"]="nginx"
    ["apache-web"]="Apache"
    ["mysql-db"]="mysql"
    ["postgres-db"]="PostgreSQL"
    ["ssh-server"]="SSH"
    ["ftp-server"]="FTP"
    ["smtp-server"]="SMTP"
    ["redis-cache"]="redis"
)

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    log_info "Checking Docker availability..."
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log_success "Docker is available"
}

check_compose() {
    log_info "Checking Docker Compose availability..."
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available"
        exit 1
    fi
    
    log_success "Docker Compose is available"
}

start_lab() {
    log_info "Starting cyNetMapper lab environment..."
    
    cd "$(dirname "$0")"
    
    # Use docker compose (newer) or docker-compose (legacy)
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi
    
    $COMPOSE_CMD -f docker-compose.lab.yml up -d
    
    log_info "Waiting for services to start..."
    sleep 30
    
    log_success "Lab environment started"
}

stop_lab() {
    log_info "Stopping cyNetMapper lab environment..."
    
    cd "$(dirname "$0")"
    
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi
    
    $COMPOSE_CMD -f docker-compose.lab.yml down
    
    log_success "Lab environment stopped"
}

test_port_connectivity() {
    local service_name="$1"
    local endpoint="$2"
    local ip=$(echo "$endpoint" | cut -d':' -f1)
    local port=$(echo "$endpoint" | cut -d':' -f2)
    
    log_info "Testing connectivity to $service_name ($endpoint)..."
    
    if timeout 5 bash -c "</dev/tcp/$ip/$port"; then
        log_success "$service_name is reachable on port $port"
        return 0
    else
        log_error "$service_name is not reachable on port $port"
        return 1
    fi
}

test_http_service() {
    local service_name="$1"
    local ip="$2"
    local port="$3"
    local protocol="${4:-http}"
    
    log_info "Testing HTTP service $service_name..."
    
    local url="$protocol://$ip:$port/"
    local response=$(curl -s -m 10 -w "%{http_code}" -o /dev/null "$url" 2>/dev/null || echo "000")
    
    if [[ "$response" =~ ^[2-3][0-9][0-9]$ ]]; then
        log_success "$service_name HTTP service is responding (HTTP $response)"
        return 0
    else
        log_error "$service_name HTTP service is not responding properly (HTTP $response)"
        return 1
    fi
}

test_dns_service() {
    log_info "Testing DNS service..."
    
    # Test DNS resolution
    if nslookup nginx.lab.local 172.20.0.40 &> /dev/null; then
        log_success "DNS service is resolving lab.local domains"
        return 0
    else
        log_error "DNS service is not resolving lab.local domains"
        return 1
    fi
}

run_cynetmapper_scan() {
    log_info "Running cyNetMapper scan against lab environment..."
    
    # Check if cynetmapper binary exists in the scanner container
    if docker exec lab-scanner which cynetmapper &> /dev/null; then
        log_info "Running basic network scan..."
        
        # Run a basic scan of the lab network
        docker exec lab-scanner cynetmapper \
            --targets "$LAB_NETWORK" \
            --output-format json \
            --output-file /app/data/lab-scan-results.json \
            --discovery-method ping \
            --port-scan-method tcp-connect \
            --ports 21,22,23,25,53,80,110,143,443,993,995,1025,2222,3306,5432,6379,8080,8081,8082 \
            --timeout 5000 \
            --max-retries 2 \
            --verbose
        
        if [ $? -eq 0 ]; then
            log_success "cyNetMapper scan completed successfully"
            
            # Show scan results summary
            if [ -f "results/lab-scan-results.json" ]; then
                log_info "Scan results saved to results/lab-scan-results.json"
                
                # Use cyndiff to analyze results if available
                if docker exec lab-scanner which cyndiff &> /dev/null; then
                    log_info "Generating scan summary with cyndiff..."
                    docker exec lab-scanner cyndiff \
                        --source /app/data/lab-scan-results.json \
                        --format text \
                        --summary
                fi
            fi
            
            return 0
        else
            log_error "cyNetMapper scan failed"
            return 1
        fi
    else
        log_warning "cyNetMapper binary not found in scanner container"
        return 1
    fi
}

generate_test_report() {
    local total_tests="$1"
    local passed_tests="$2"
    local failed_tests="$3"
    
    log_info "Generating test report..."
    
    cat > "results/lab-test-report.txt" << EOF
cyNetMapper Lab Test Report
==========================
Generated: $(date)

Test Summary:
- Total Tests: $total_tests
- Passed: $passed_tests
- Failed: $failed_tests
- Success Rate: $(( passed_tests * 100 / total_tests ))%

Lab Network: $LAB_NETWORK
Test Duration: $(date)

Service Status:
EOF
    
    for service in "${!SERVICES[@]}"; do
        echo "- $service: ${SERVICE_STATUS[$service]:-UNKNOWN}" >> "results/lab-test-report.txt"
    done
    
    log_success "Test report saved to results/lab-test-report.txt"
}

main() {
    local command="${1:-test}"
    
    case "$command" in
        "start")
            check_docker
            check_compose
            start_lab
            ;;
        "stop")
            check_docker
            check_compose
            stop_lab
            ;;
        "test")
            check_docker
            
            # Create results directory
            mkdir -p results
            
            log_info "Starting cyNetMapper lab connectivity tests..."
            
            local total_tests=0
            local passed_tests=0
            local failed_tests=0
            declare -A SERVICE_STATUS
            
            # Test basic port connectivity
            for service in "${!SERVICES[@]}"; do
                endpoint="${SERVICES[$service]}"
                total_tests=$((total_tests + 1))
                
                if test_port_connectivity "$service" "$endpoint"; then
                    passed_tests=$((passed_tests + 1))
                    SERVICE_STATUS["$service"]="PASS"
                else
                    failed_tests=$((failed_tests + 1))
                    SERVICE_STATUS["$service"]="FAIL"
                fi
            done
            
            # Test HTTP services specifically
            total_tests=$((total_tests + 1))
            if test_http_service "nginx-web" "172.20.0.10" "80"; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            
            total_tests=$((total_tests + 1))
            if test_http_service "nginx-ssl" "172.20.0.10" "443" "https"; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            
            total_tests=$((total_tests + 1))
            if test_http_service "apache-web" "172.20.0.11" "80"; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            
            # Test DNS service
            total_tests=$((total_tests + 1))
            if test_dns_service; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            
            # Run cyNetMapper scan
            total_tests=$((total_tests + 1))
            if run_cynetmapper_scan; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
            
            # Generate test report
            generate_test_report "$total_tests" "$passed_tests" "$failed_tests"
            
            log_info "Test Summary: $passed_tests/$total_tests tests passed"
            
            if [ "$failed_tests" -eq 0 ]; then
                log_success "All tests passed! Lab environment is ready for cyNetMapper testing."
                exit 0
            else
                log_error "$failed_tests tests failed. Please check the lab environment."
                exit 1
            fi
            ;;
        "scan")
            run_cynetmapper_scan
            ;;
        "help")
            echo "Usage: $0 [start|stop|test|scan|help]"
            echo ""
            echo "Commands:"
            echo "  start  - Start the lab environment"
            echo "  stop   - Stop the lab environment"
            echo "  test   - Run connectivity tests"
            echo "  scan   - Run cyNetMapper scan"
            echo "  help   - Show this help message"
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"