# 🚀 Hướng Dẫn Cài Đặt - PBL6 Log Enricher

**Phiên bản:** 1.0.0  
**Tác giả:** tanbrando  
**Ngày cập nhật:** 10/11/2025

---

## 📋 Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Yêu Cầu Hệ Thống](#yêu-cầu-hệ-thống)
3. [Cài Đặt Nhanh](#cài-đặt-nhanh)
4. [Cấu Hình Chi Tiết](#cấu-hình-chi-tiết)
5. [Google Gemini AI Setup](#google-gemini-ai-setup)
6. [Chạy Ứng Dụng](#chạy-ứng-dụng)
7. [Docker Deployment](#docker-deployment)
8. [Grafana Integration](#grafana-integration)
9. [API Endpoints](#api-endpoints)
10. [Troubleshooting](#troubleshooting)

---

## 🎯 Tổng Quan

**PBL6 Log Enricher** là hệ thống phân tích và làm giàu log bảo mật cho SOC (Security Operations Center):

### Tính Năng Chính

- 🔍 **4 Log Parsers**: ModSecurity, Suricata, Zeek, UFW
- 🌍 **Multi-layer Enrichment**: 
  - GeoIP (MaxMind GeoLite2)
  - Threat Intelligence (AbuseIPDB, VirusTotal)
  - Attack Database (MITRE ATT&CK, OWASP)
  - User-Agent parsing
- 🤖 **AI Analysis**: Google Gemini 2.5 Flash (FREE)
- 🔗 **40+ REST API Endpoints**
- 📊 **Grafana Time Range Support**
- 🐳 **Docker Ready**

---

## 💻 Yêu Cầu Hệ Thống

### Phần Mềm

- Python 3.11+
- pip (Python package manager)
- Git
- Docker & Docker Compose (cho production)

### Phần Cứng (Khuyến nghị)

- **CPU**: 2 cores+
- **RAM**: 4GB+ (8GB cho production)
- **Disk**: 2GB+ (cho GeoIP databases và logs)

### Hệ Điều Hành

- ✅ Linux (Ubuntu 20.04+, Debian 11+)
- ✅ macOS (11+)
- ✅ Windows 10/11 (với WSL2)

---

## ⚡ Cài Đặt Nhanh

### 1. Clone Repository

```bash
git clone https://github.com/tanbrando/pbl6-enricher.git
cd pbl6-enricher
```

### 2. Tạo Virtual Environment

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

### 3. Cài Đặt Dependencies

```bash
pip install -r requirements.txt
```

### 4. Copy File Cấu Hình

```bash
cp .env.example .env
```

### 5. Tải GeoIP Databases

```bash
# Download GeoLite2 databases (free)
# Đặt vào: parsers/data/geoip/
# - GeoLite2-City.mmdb
# - GeoLite2-ASN.mmdb
```

**Tải từ:** https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

### 6. Cấu Hình Gemini API (FREE)

Xem chi tiết: [Google Gemini AI Setup](#google-gemini-ai-setup)

### 7. Chạy Ứng Dụng

```bash
python parsers/unified/app.py
```

Server sẽ chạy tại: `http://localhost:5000`

---

## ⚙️ Cấu Hình Chi Tiết

### File `.env`

```bash
# ============================================================
# FLASK SETTINGS
# ============================================================
FLASK_ENV=development
FLASK_DEBUG=True
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# ============================================================
# LOGGING
# ============================================================
LOG_LEVEL=INFO
LOG_FILE=logs/enricher.log

# ============================================================
# GEOIP SETTINGS
# ============================================================
GEOIP_ENABLED=True
GEOIP_CITY_DB=parsers/data/geoip/GeoLite2-City.mmdb
GEOIP_ASN_DB=parsers/data/geoip/GeoLite2-ASN.mmdb

# ============================================================
# THREAT INTELLIGENCE
# ============================================================
THREAT_INTEL_ENABLED=True

# AbuseIPDB (Free tier: 1000 requests/day)
ABUSEIPDB_ENABLED=True
ABUSEIPDB_API_KEY=your-abuseipdb-api-key-here
ABUSEIPDB_MIN_CONFIDENCE=75

# VirusTotal (Free tier: 500 requests/day)
VIRUSTOTAL_ENABLED=False
VIRUSTOTAL_API_KEY=your-virustotal-api-key-here

# ============================================================
# ATTACK DATABASE
# ============================================================
ATTACK_DB_ENABLED=True
ATTACK_DB_PATH=parsers/data/attack_intel/

# MITRE ATT&CK
MITRE_ATTACK_FILE=mitre_attack.json

# OWASP Top 10
OWASP_MAPPING_FILE=owasp_mapping.json

# ============================================================
# AI ANALYSIS - GOOGLE GEMINI (FREE!)
# ============================================================
GEMINI_ENABLED=True
GEMINI_API_KEY=your-gemini-api-key-here

# AI Settings
AI_PROVIDER=gemini
AI_TEMPERATURE=0.3
AI_MAX_TOKENS=2000
AI_TIMEOUT=30

# ============================================================
# LOKI INTEGRATION (Optional)
# ============================================================
LOKI_ENABLED=False
LOKI_URL=http://localhost:3100
LOKI_USERNAME=
LOKI_PASSWORD=

# ============================================================
# GRAFANA INTEGRATION
# ============================================================
# Time range format: ISO8601 or Unix timestamp
DEFAULT_TIME_RANGE=1h
```

---

## 🤖 Google Gemini AI Setup

### Tại Sao Chọn Gemini?

✅ **Hoàn Toàn MIỄN PHÍ**  
✅ Không cần thẻ tín dụng  
✅ Model mới nhất (Gemini 2.5 Flash)  
✅ Giới hạn hào phóng:
   - 15 requests/phút
   - 1 triệu tokens/phút  
   - 1500 requests/ngày

### Bước 1: Lấy API Key (5 phút)

1. **Truy cập Google AI Studio:**
   ```
   https://aistudio.google.com/apikey
   ```

2. **Đăng nhập** bằng Google Account

3. **Tạo API Key:**
   - Click "Create API Key"
   - Chọn "Create API key in new project" hoặc chọn project có sẵn
   - Copy API key (format: `AIza...`)

4. **Lưu API Key vào `.env`:**
   ```bash
   GEMINI_ENABLED=True
   GEMINI_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ```

### Bước 2: Test API Key

```bash
python scripts/quick_test_gemini.py
```

**Output mong đợi:**
```
🔑 Testing Gemini API...
   API Key: AIzaSyXXXX...XXXX

✅ Gemini is working!
Response: Xin chào!

🧪 Testing JSON response...
JSON Response: {"status": "ok", "message": "test"}

✅ All tests passed!
```

### Bước 3: Test Full Integration

```bash
python scripts/test_analyzer.py
```

### Models Được Sử Dụng

Hệ thống tự động chọn model theo thứ tự:

1. ✅ **gemini-2.5-flash** (Primary - Latest stable, Nov 2025)
2. ✅ **gemini-2.0-flash-exp** (Fallback - Experimental)
3. ✅ **gemini-2.0-flash** (Fallback - Stable 2.0)
4. ✅ **gemini-flash-latest** (Fallback - Latest alias)

### Free Tier Limits

| Metric | Limit |
|--------|-------|
| Requests/phút | 15 |
| Tokens/phút | 1,000,000 |
| Requests/ngày | 1,500 |

**Đủ cho:** Hầu hết use cases SOC, demo, development, testing

---

## 🏃 Chạy Ứng Dụng

### Development Mode

```bash
# Activate venv
source venv/bin/activate  # Linux/Mac
# hoặc
venv\Scripts\activate     # Windows

# Run
python parsers/unified/app.py
```

### Production Mode

```bash
# Với Gunicorn (Linux/Mac)
gunicorn -w 4 -b 0.0.0.0:5000 parsers.unified.app:app

# Hoặc dùng Docker (khuyến nghị)
docker-compose up -d
```

### Health Check

```bash
curl http://localhost:5000/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 123.45,
  "parsers": ["modsec", "suricata", "zeek", "ufw"],
  "enrichers": ["geoip", "threat_intel", "attack_db", "ai_analyzer"]
}
```

---

## 🐳 Docker Deployment

### File Cấu Hình

**`docker-compose.yml`**

```yaml
services:
  enricher:
    build: .
    container_name: pbl6-enricher
    ports:
      - "5000:5000"
    env_file:
      - .env
    volumes:
      - ./parsers/data:/app/parsers/data:ro
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Build & Run

```bash
# Build image
docker-compose build

# Run container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Dockerfile Highlights

```dockerfile
FROM python:3.11-slim

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . /app
WORKDIR /app

# Non-root user
USER appuser

# Expose port
EXPOSE 5000

# Run
CMD ["python", "parsers/unified/app.py"]
```

---

## 📊 Grafana Integration

### Cài Đặt Data Source

1. **Thêm JSON API Data Source** trong Grafana
2. **URL:** `http://localhost:5000`
3. **Headers:** (nếu có authentication)

### Example Queries

**ModSecurity - GeoIP:**
```
/modsec/transaction/${transaction_id}/geoip?start=${__from}&end=${__to}
```

**Suricata - Threat Intel:**
```
/suricata/flow/${flow_id}/threat-intel?start=${__from}&end=${__to}
```

**Zeek - AI Analysis:**
```
/zeek/notice/${notice_id}/ai-analyze?start=${__from}&end=${__to}
```

### Dashboard Template

Import dashboard từ: `grafana-dashboards/enricher-overview.json`

---

## 🔗 API Endpoints

### ModSecurity (14 endpoints)

```
GET  /modsec/parse                          # Parse raw log
GET  /modsec/transaction/{id}               # Get transaction
GET  /modsec/transaction/{id}/geoip         # GeoIP enrichment
GET  /modsec/transaction/{id}/threat-intel  # Threat intel
GET  /modsec/transaction/{id}/attack-intel  # Attack DB
GET  /modsec/transaction/{id}/user-agent    # User-Agent
GET  /modsec/transaction/{id}/ai-analyze    # AI analysis
POST /modsec/enrich                         # Bulk enrich
```

### Suricata (10 endpoints)

```
GET  /suricata/parse                    # Parse raw log
GET  /suricata/flow/{id}                # Get flow
GET  /suricata/flow/{id}/geoip          # GeoIP
GET  /suricata/flow/{id}/threat-intel   # Threat intel
GET  /suricata/flow/{id}/attack-intel   # Attack DB
GET  /suricata/flow/{id}/ai-analyze     # AI analysis
POST /suricata/enrich                   # Bulk enrich
```

### Zeek (10 endpoints)

```
GET  /zeek/parse                      # Parse raw log
GET  /zeek/notice/{id}                # Get notice
GET  /zeek/notice/{id}/geoip          # GeoIP
GET  /zeek/notice/{id}/threat-intel   # Threat intel
GET  /zeek/notice/{id}/attack-intel   # Attack DB
GET  /zeek/notice/{id}/ai-analyze     # AI analysis
POST /zeek/enrich                     # Bulk enrich
```

### UFW (6 endpoints)

```
GET  /ufw/parse               # Parse raw log
GET  /ufw/event/{id}          # Get event
GET  /ufw/event/{id}/geoip    # GeoIP
POST /ufw/enrich              # Bulk enrich
```

### System (4 endpoints)

```
GET  /health      # Health check
GET  /metrics     # Prometheus metrics
GET  /version     # API version
GET  /docs        # API documentation
```

**Total:** 44 endpoints

---

## 🔧 Troubleshooting

### Lỗi Thường Gặp

#### 1. GeoIP Database Not Found

**Lỗi:**
```
FileNotFoundError: GeoLite2-City.mmdb not found
```

**Giải pháp:**
```bash
# Tải GeoLite2 databases
wget https://git.io/GeoLite2-City.mmdb
wget https://git.io/GeoLite2-ASN.mmdb

# Di chuyển vào đúng folder
mv GeoLite2-*.mmdb parsers/data/geoip/
```

#### 2. Gemini API Key Invalid

**Lỗi:**
```
ERROR: Gemini API key not valid
```

**Giải pháp:**
1. Kiểm tra API key trong `.env`
2. Đảm bảo format đúng: `AIza...`
3. Test lại: `python scripts/quick_test_gemini.py`
4. Tạo key mới tại: https://aistudio.google.com/apikey

#### 3. Gemini Empty Response

**Lỗi:**
```
ERROR: Empty response from Gemini API
```

**Nguyên nhân:**
- Rate limit exceeded (15 RPM)
- Safety filters blocked response
- Network timeout

**Giải pháp:**
```bash
# Check logs
tail -f logs/enricher.log

# Test with simple prompt
python scripts/quick_test_gemini.py

# Increase timeout in .env
AI_TIMEOUT=60
```

#### 4. Port Already in Use

**Lỗi:**
```
OSError: [Errno 48] Address already in use
```

**Giải pháp:**
```bash
# Linux/Mac - Kill process on port 5000
lsof -ti:5000 | xargs kill -9

# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Hoặc đổi port trong .env
FLASK_PORT=5001
```

#### 5. Import Error

**Lỗi:**
```
ModuleNotFoundError: No module named 'google.genai'
```

**Giải pháp:**
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Hoặc cài riêng
pip install google-genai
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Run with verbose output
python parsers/unified/app.py --debug
```

### Logs Location

```
logs/
├── enricher.log          # Main application log
├── error.log             # Error log only
└── access.log            # HTTP access log
```

---

## 📚 Tài Liệu Tham Khảo

### Dự Án
- [README.md](../README.md) - Tổng quan dự án
- [API Documentation](http://localhost:5000/docs) - Swagger/OpenAPI

### External APIs
- [Google Gemini API](https://ai.google.dev/gemini-api/docs)
- [MaxMind GeoIP](https://dev.maxmind.com/geoip/docs)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)

### Tools
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Docker Documentation](https://docs.docker.com/)
- [Grafana Documentation](https://grafana.com/docs/)

---

## 🤝 Hỗ Trợ

### GitHub Issues
Báo lỗi hoặc đề xuất tính năng: https://github.com/tanbrando/pbl6-enricher/issues

### Email
Technical support: tanbrando@example.com

---

## 📝 License

MIT License - Copyright (c) 2025 tanbrando

---

**Happy Enriching! 🚀**
