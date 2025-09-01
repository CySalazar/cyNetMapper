# cyNetMapper Docker Lab

This directory contains a complete Docker-based testing laboratory for cyNetMapper, providing a controlled network environment with various services for comprehensive scanning and testing.

## Overview

The lab environment includes:

- **Web Services**: Nginx (HTTP/HTTPS), Apache HTTP Server
- **Database Services**: MySQL, PostgreSQL
- **Network Services**: SSH, FTP, DNS (CoreDNS), SMTP (MailHog)
- **Cache Services**: Redis
- **Security Testing**: DVWA (Damn Vulnerable Web Application)
- **Network Tools**: NetShoot container for debugging
- **Scanner**: cyNetMapper container with scanning capabilities

## Network Architecture

```
Lab Network: 172.20.0.0/16
├── 172.20.0.10  - nginx-web (HTTP:80, HTTPS:443)
├── 172.20.0.11  - apache-web (HTTP:80)
├── 172.20.0.20  - mysql-db (MySQL:3306)
├── 172.20.0.21  - postgres-db (PostgreSQL:5432)
├── 172.20.0.30  - ssh-server (SSH:2222)
├── 172.20.0.31  - ftp-server (FTP:21, Passive:30000-30009)
├── 172.20.0.40  - dns-server (DNS:53)
├── 172.20.0.50  - smtp-server (SMTP:1025, Web UI:8025)
├── 172.20.0.60  - redis-cache (Redis:6379)
├── 172.20.0.70  - dvwa (HTTP:80)
├── 172.20.0.100 - nettools (debugging)
└── 172.20.0.200 - cynetmapper (scanner)
```

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+ (or docker-compose 1.29+)
- At least 4GB RAM available for containers
- Ports 21, 53, 80, 443, 1025, 2222, 3306, 5432, 6379, 8025, 8080-8082 available on host

### Starting the Lab

```bash
# Start all services
./test-lab.sh start

# Or manually with docker-compose
docker-compose -f docker-compose.lab.yml up -d
```

### Running Tests

```bash
# Run connectivity tests
./test-lab.sh test

# Run cyNetMapper scan
./test-lab.sh scan
```

### Stopping the Lab

```bash
# Stop all services
./test-lab.sh stop

# Or manually
docker-compose -f docker-compose.lab.yml down
```

## Service Details

### Web Services

#### Nginx (172.20.0.10)
- **HTTP**: Port 80
- **HTTPS**: Port 443 (self-signed certificate)
- **Features**: Custom headers, API endpoints, status codes
- **Test URLs**:
  - `http://172.20.0.10/` - Main page
  - `http://172.20.0.10/api/` - JSON API
  - `http://172.20.0.10/health` - Health check
  - `https://172.20.0.10/ssl-info` - SSL information

#### Apache (172.20.0.11)
- **HTTP**: Port 80
- **Features**: Server status, custom headers
- **Test URLs**:
  - `http://172.20.0.11/` - Main page
  - `http://172.20.0.11/server-status` - Server status
  - `http://172.20.0.11/server-info` - Server information

### Database Services

#### MySQL (172.20.0.20:3306)
- **Credentials**: `testuser:testpass`
- **Database**: `testdb`
- **Root Password**: `testpass123`

#### PostgreSQL (172.20.0.21:5432)
- **Credentials**: `testuser:testpass`
- **Database**: `testdb`

### Network Services

#### SSH Server (172.20.0.30:2222)
- **Credentials**: `testuser:testpass123`
- **Features**: Password authentication enabled

#### FTP Server (172.20.0.31:21)
- **Credentials**: `testuser:testpass123`
- **Passive Ports**: 30000-30009

#### DNS Server (172.20.0.40:53)
- **Zone**: `lab.local`
- **Features**: Forward/reverse DNS, SRV records
- **Test**: `nslookup nginx.lab.local 172.20.0.40`

#### SMTP Server (172.20.0.50)
- **SMTP**: Port 1025
- **Web UI**: Port 8025 (MailHog interface)

### Cache Services

#### Redis (172.20.0.60:6379)
- **Password**: `testpass123`
- **Test**: `redis-cli -h 172.20.0.60 -a testpass123 ping`

### Security Testing

#### DVWA (172.20.0.70:80)
- **Purpose**: Vulnerable web application for security testing
- **Access**: `http://172.20.0.70/`

## Testing with cyNetMapper

### Basic Network Scan

```bash
# Enter the scanner container
docker exec -it lab-scanner bash

# Run a comprehensive scan
cynetmapper \
  --targets 172.20.0.0/16 \
  --output-format json \
  --output-file /app/data/lab-scan.json \
  --discovery-method ping \
  --port-scan-method tcp-connect \
  --ports 21,22,23,25,53,80,110,143,443,993,995,1025,2222,3306,5432,6379,8080,8081,8082 \
  --timeout 5000 \
  --max-retries 2 \
  --verbose
```

### Service Detection

```bash
# Scan with service detection
cynetmapper \
  --targets 172.20.0.10-172.20.0.70 \
  --service-detection \
  --banner-grab \
  --output-format nmap-xml \
  --output-file /app/data/services.xml
```

### Comparing Scan Results

```bash
# Generate baseline scan
cynetmapper --targets 172.20.0.0/16 --output-file baseline.json

# Run second scan after changes
cynetmapper --targets 172.20.0.0/16 --output-file current.json

# Compare results
cyndiff --source baseline.json --target current.json --format html --output diff-report.html
```

## Golden Fixtures

The lab is designed to provide consistent, reproducible results for testing. Expected scan results:

### Expected Open Ports

| Service | IP | Ports | Protocol |
|---------|----|---------|---------|
| nginx | 172.20.0.10 | 80, 443 | TCP |
| apache | 172.20.0.11 | 80 | TCP |
| mysql | 172.20.0.20 | 3306 | TCP |
| postgres | 172.20.0.21 | 5432 | TCP |
| ssh | 172.20.0.30 | 2222 | TCP |
| ftp | 172.20.0.31 | 21 | TCP |
| dns | 172.20.0.40 | 53 | TCP/UDP |
| smtp | 172.20.0.50 | 1025, 8025 | TCP |
| redis | 172.20.0.60 | 6379 | TCP |
| dvwa | 172.20.0.70 | 80 | TCP |

### Expected Service Banners

- **HTTP Services**: Should return custom `X-Lab-Server` and `X-Scan-Test` headers
- **SSH**: OpenSSH banner
- **FTP**: Pure-FTPd banner
- **MySQL**: MySQL version string
- **PostgreSQL**: PostgreSQL version string
- **Redis**: Redis PONG response

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Ensure host ports are not in use
   ```bash
   netstat -tulpn | grep -E ':(21|53|80|443|1025|2222|3306|5432|6379|8025|8080|8081|8082)\s'
   ```

2. **DNS Resolution**: Check if local DNS conflicts with port 53
   ```bash
   sudo lsof -i :53
   ```

3. **Container Health**: Check container status
   ```bash
   docker-compose -f docker-compose.lab.yml ps
   docker-compose -f docker-compose.lab.yml logs [service-name]
   ```

4. **Network Connectivity**: Test from nettools container
   ```bash
   docker exec -it lab-nettools bash
   nmap -sT 172.20.0.10-70
   ```

### Performance Tuning

- **Memory**: Increase Docker memory limit if containers are killed
- **CPU**: Adjust container CPU limits in docker-compose.lab.yml
- **Network**: Use host networking for better performance (less isolation)

## Security Considerations

⚠️ **Warning**: This lab environment contains intentionally vulnerable services and should only be used in isolated environments.

- Do not expose lab services to public networks
- Use only for testing and development
- Reset credentials and configurations for production use
- The DVWA container contains known vulnerabilities

## Contributing

To add new services to the lab:

1. Add service definition to `docker-compose.lab.yml`
2. Assign static IP in the 172.20.0.0/16 range
3. Update DNS records in `lab-configs/zones/`
4. Add service tests to `test-lab.sh`
5. Update this README with service details

## Files Structure

```
docker/
├── docker-compose.lab.yml    # Main lab composition
├── test-lab.sh               # Testing and management script
├── entrypoint.sh             # Container entrypoint
├── lab-configs/              # Service configurations
│   ├── nginx.conf           # Nginx configuration
│   ├── httpd.conf           # Apache configuration
│   ├── Corefile             # CoreDNS configuration
│   ├── ssl/                 # SSL certificates
│   │   ├── server.crt
│   │   └── server.key
│   └── zones/               # DNS zone files
│       ├── lab.local.zone
│       └── 172.20.0.zone
└── results/                  # Test results and scan outputs
```

## License

This lab environment is part of the cyNetMapper project and follows the same license terms.