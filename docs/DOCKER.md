# 🐳 Docker Deployment Guide

## Tóm Tắt

Docker image **KHÔNG bao gồm** folder `parsers/data/` vì:
- ✅ GeoIP databases quá lớn (~100MB)
- ✅ Dễ update databases mà không rebuild image
- ✅ Giữ image size nhỏ
- ✅ `.dockerignore` ignore `*.mmdb` files

**Giải pháp:** Mount folder `parsers/data/` từ host vào container qua volume.

---

## 📋 Yêu Cầu Trước Khi Chạy

### 1. Chuẩn Bị Data Files

```bash
# Tạo folder structure
mkdir -p parsers/data/geoip
mkdir -p parsers/data/attack_intel

# Download GeoIP databases
# Tải từ: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# Đặt vào parsers/data/geoip/:
# - GeoLite2-City.mmdb
# - GeoLite2-ASN.mmdb

# Attack intelligence files (đã có sẵn)
# parsers/data/attack_intel/mitre_attack.json
# parsers/data/attack_intel/owasp_mapping.json
# parsers/data/attack_intel/attack_intelligence.json
```

### 2. Cấu Hình Environment

```bash
# Copy .env.example
cp .env.example .env

# Chỉnh sửa .env - Thêm Gemini API key
nano .env
```

**Tối thiểu cần:**
```bash
GEMINI_ENABLED=true
GEMINI_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Loki connection (nếu dùng)
LOKI_ENABLED=true
LOKI_URL=http://loki:3100
```

---

## 🚀 Build & Run

### Method 1: Docker Compose (Khuyến nghị)

```bash
# Build image
docker-compose build

# Run container (detached)
docker-compose up -d

# View logs
docker-compose logs -f log-parser

# Stop
docker-compose down
```

### Method 2: Docker Build Manual

```bash
# Build image
docker build -t pbl6-enricher:latest .

# Run container
docker run -d \
  --name pbl6-enricher \
  -p 5000:5000 \
  -v $(pwd)/parsers/data:/app/parsers/data:ro \
  -v $(pwd)/logs:/app/logs \
  --env-file .env \
  pbl6-enricher:latest

# View logs
docker logs -f pbl6-enricher

# Stop
docker stop pbl6-enricher
docker rm pbl6-enricher
```

---

## 📂 Volume Mounts Explained

```yaml
volumes:
  # Logs - Read/Write
  - ./logs:/app/logs
  
  # Data - Read Only (GeoIP + Attack Intel)
  - ./parsers/data:/app/parsers/data:ro
```

**Tại sao `:ro` (read-only)?**
- Container chỉ cần đọc databases
- Bảo vệ data khỏi bị thay đổi từ container
- Best practice cho data files

---

## 🔍 Verify Deployment

### 1. Check Container Status

```bash
docker-compose ps
```

**Output mong đợi:**
```
NAME              STATUS         PORTS
log-parser        Up 2 minutes   0.0.0.0:5000->5000/tcp
```

### 2. Check Health

```bash
curl http://localhost:5000/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 123.45
}
```

### 3. Check Logs

```bash
docker-compose logs -f log-parser
```

**Logs mong đợi:**
```
✅ GeoIP enricher initialized
✅ Threat Intel enricher initialized
✅ Attack DB enricher initialized
✅ Google Gemini analyzer initialized
   Model: gemini-2.5-flash (FREE)
 * Running on http://0.0.0.0:5000
```

### 4. Verify Data Mounts

```bash
# Exec vào container
docker exec -it log-parser bash

# Kiểm tra files
ls -la /app/parsers/data/geoip/
# Expected:
# GeoLite2-City.mmdb
# GeoLite2-ASN.mmdb

ls -la /app/parsers/data/attack_intel/
# Expected:
# mitre_attack.json
# owasp_mapping.json
# attack_intelligence.json

# Exit
exit
```

---

## 🐛 Troubleshooting

### Container Không Start

```bash
# Xem logs chi tiết
docker-compose logs log-parser

# Common issues:
# 1. Port 5000 đã được dùng
# 2. .env file không tồn tại
# 3. Data files không tìm thấy
```

### GeoIP Database Not Found

**Lỗi:**
```
FileNotFoundError: GeoLite2-City.mmdb not found
```

**Fix:**
```bash
# 1. Kiểm tra files exist trên host
ls -la parsers/data/geoip/

# 2. Kiểm tra mount trong container
docker exec -it log-parser ls -la /app/parsers/data/geoip/

# 3. Nếu không có, tải lại databases
# https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

# 4. Restart container
docker-compose restart log-parser
```

### Gemini API Not Working

**Lỗi:**
```
ERROR: Gemini API key not valid
```

**Fix:**
```bash
# 1. Kiểm tra .env
cat .env | grep GEMINI

# 2. Test từ container
docker exec -it log-parser python scripts/quick_test_gemini.py

# 3. Nếu lỗi, update .env và restart
docker-compose restart log-parser
```

### Permission Denied (Logs)

**Lỗi:**
```
PermissionError: [Errno 13] Permission denied: '/app/logs/app.log'
```

**Fix:**
```bash
# Thay đổi ownership của logs folder
sudo chown -R 1000:1000 logs/

# Hoặc chmod
chmod -R 755 logs/

# Restart
docker-compose restart log-parser
```

---

## 📊 Resource Limits

**Mặc định trong docker-compose.yml:**

```yaml
resources:
  limits:
    cpus: '1.0'      # Max 1 CPU core
    memory: 1G       # Max 1GB RAM
  reservations:
    cpus: '0.3'      # Min 0.3 CPU
    memory: 512M     # Min 512MB RAM
```

**Điều chỉnh theo nhu cầu:**
```bash
# Edit docker-compose.yml
nano docker-compose.yml

# Thay đổi giá trị limits/reservations
# Sau đó rebuild
docker-compose up -d --force-recreate
```

---

## 🔄 Update & Maintenance

### Update Code

```bash
# Pull latest code
git pull origin main

# Rebuild image
docker-compose build

# Restart với image mới
docker-compose up -d
```

### Update GeoIP Databases

```bash
# Download new databases
# Đặt vào parsers/data/geoip/

# Restart container (mount mới tự động load)
docker-compose restart log-parser
```

### Update Gemini API Key

```bash
# Update .env
nano .env

# Restart
docker-compose restart log-parser
```

### View Container Stats

```bash
# Real-time stats
docker stats log-parser

# Detailed info
docker inspect log-parser
```

---

## 🌐 Network Configuration

**Kết nối vào existing network:**

```yaml
networks:
  monitoring:
    external: true
    name: monitoring_default  # Loki/Grafana network
```

**Nếu cần đổi network:**
```bash
# 1. List networks
docker network ls

# 2. Update docker-compose.yml
nano docker-compose.yml

# 3. Restart
docker-compose up -d
```

---

## 📝 Best Practices

### 1. Data Management
- ✅ Luôn mount `parsers/data` as volume
- ✅ Không bao gồm data trong image
- ✅ Backup GeoIP databases định kỳ

### 2. Logs Management
- ✅ Mount logs folder để persist logs
- ✅ Rotate logs định kỳ
- ✅ Monitor log size

### 3. Security
- ✅ Không commit `.env` vào git
- ✅ Use read-only mounts cho data
- ✅ Run as non-root user (appuser)
- ✅ Limit resources

### 4. Updates
- ✅ Update GeoIP databases hàng tháng
- ✅ Rebuild image khi có code changes
- ✅ Monitor Gemini API usage

---

## 📚 References

- [Dockerfile](../Dockerfile)
- [docker-compose.yml](../docker-compose.yml)
- [.dockerignore](../.dockerignore)
- [Main Setup Guide](SETUP.md)

---

**Need help?** Check [SETUP.md](SETUP.md#troubleshooting) or open an issue!
