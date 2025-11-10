# 🔍 PBL6 Log Enricher# Unified Log Parser API



> **Hệ thống phân tích và làm giàu log bảo mật cho SOC với AI (Google Gemini FREE)****Author:** tanbrando  

**Date:** 2025-01-08 03:08:52 UTC  

![Version](https://img.shields.io/badge/version-1.0.0-blue)**Version:** 1.0.0

![Python](https://img.shields.io/badge/python-3.11+-green)

![License](https://img.shields.io/badge/license-MIT-orange)## Features

![AI](https://img.shields.io/badge/AI-Gemini_2.5_Flash-purple)

- 🔍 **4 Log Parsers** (ModSecurity, Suricata, Zeek, UFW)

---- 🌍 **Multi-layer Enrichment** (GeoIP, Threat Intel, Attack DB)

- 🤖 **AI Analysis** (Google Gemini 2.0 Flash **FREE** + Azure OpenAI)

## ✨ Tính Năng Chính- 🔗 **40+ REST API Endpoints**

- 📊 **Grafana Time Range Support**

### 🔍 Log Parsing- 🐳 **Docker Production Ready**

- **ModSecurity** - Web Application Firewall logs

- **Suricata** - Network IDS/IPS logs  ## 🆕 NEW: FREE AI Analysis with Google Gemini!

- **Zeek** - Network monitoring logs

- **UFW** - Ubuntu firewall logsThis project now supports **Google Gemini 2.0 Flash** - completely **FREE** AI-powered security analysis!



### 🌍 Multi-layer Enrichment✅ No credit card required  

- **GeoIP** - Vị trí địa lý (MaxMind GeoLite2)✅ Generous free limits (15 RPM, 1M TPM, 1500 RPD)  

- **Threat Intelligence** - AbuseIPDB, VirusTotal✅ Latest AI model  

- **Attack Database** - MITRE ATT&CK, OWASP Top 10✅ Easy 5-minute setup  

- **User-Agent** - Browser/Device fingerprinting

**[📖 Read the Gemini Setup Guide →](docs/GEMINI_SETUP.md)**
### 🤖 AI Security Analysis (FREE!)
- **Google Gemini 2.5 Flash** - Latest FREE AI model
- Phân tích tấn công tự động
- Đánh giá mức độ nguy hiểm
- Đề xuất biện pháp xử lý
- Mapping MITRE ATT&CK techniques

### 🔗 API & Integration
- **44 REST API endpoints**
- Grafana time range support
- Prometheus metrics
- Swagger/OpenAPI documentation

### 🐳 Production Ready
- Docker & Docker Compose
- Health checks
- Structured logging
- Error handling

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
# Clone repository
git clone https://github.com/tanbrando/pbl6-enricher.git
cd pbl6-enricher

# Tạo virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# hoặc: venv\Scripts\activate  # Windows

# Cài đặt dependencies
pip install -r requirements.txt
```

### 2. Cấu Hình

```bash
# Copy file cấu hình mẫu
cp .env.example .env

# Chỉnh sửa .env - Thêm API keys
nano .env
```

**Tối thiểu cần:**
```bash
# Google Gemini API (FREE - 5 phút setup)
GEMINI_ENABLED=True
GEMINI_API_KEY=AIza...  # Lấy tại: https://aistudio.google.com/apikey
```

### 3. Tải GeoIP Databases

```bash
# Tạo thư mục
mkdir -p parsers/data/geoip

# Tải databases (hoặc download thủ công từ MaxMind)
# Đặt 2 files này vào parsers/data/geoip/:
# - GeoLite2-City.mmdb
# - GeoLite2-ASN.mmdb
```

**Download:** https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

### 4. Chạy

```bash
python parsers/unified/app.py
```

Server chạy tại: **http://localhost:5000**

### 5. Test

```bash
# Health check
curl http://localhost:5000/health

# Test Gemini AI
python scripts/quick_test_gemini.py
```

---

## 📖 Documentation

### 📚 Hướng Dẫn Đầy Đủ
👉 **[docs/SETUP.md](docs/SETUP.md)** - Setup guide chi tiết (Vietnamese)

### 🤖 Google Gemini Setup
👉 **[5 phút setup AI miễn phí](#google-gemini-setup-5-phút)**

### 🔗 API Reference
- [API Endpoints](#api-endpoints)
- [Swagger UI](http://localhost:5000/docs)

### 🐳 Deployment
- [Docker Setup](#docker-setup)
- [Production Guide](docs/SETUP.md#docker-deployment)

---

## 🤖 Google Gemini Setup (5 phút)

### Tại Sao Gemini?

✅ **100% MIỄN PHÍ** - Không cần thẻ tín dụng  
✅ **Latest AI** - Gemini 2.5 Flash (Nov 2025)  
✅ **Generous Limits** - 15 RPM, 1M TPM, 1500 RPD  
✅ **Easy Setup** - Chỉ 3 bước

### Bước 1: Lấy API Key

1. Truy cập: https://aistudio.google.com/apikey
2. Đăng nhập Google Account
3. Click "Create API Key"
4. Copy API key (format: `AIza...`)

### Bước 2: Cấu Hình

```bash
# Thêm vào file .env
GEMINI_ENABLED=True
GEMINI_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Bước 3: Test

```bash
python scripts/quick_test_gemini.py
```

**Output mong đợi:**
```
✅ Gemini is working!
Response: Xin chào!
✅ All tests passed!
```

**Done! 🎉** Bạn đã có AI analysis miễn phí!

---

## 📊 API Endpoints

### ModSecurity (14 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/modsec/transaction/{id}/geoip` | GeoIP enrichment |
| GET | `/modsec/transaction/{id}/threat-intel` | Threat intelligence |
| GET | `/modsec/transaction/{id}/attack-intel` | Attack database |
| GET | `/modsec/transaction/{id}/user-agent` | User-Agent parsing |
| GET | `/modsec/transaction/{id}/ai-analyze` | **AI analysis** 🤖 |

### Suricata (10 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/suricata/flow/{id}/geoip` | GeoIP enrichment |
| GET | `/suricata/flow/{id}/threat-intel` | Threat intelligence |
| GET | `/suricata/flow/{id}/attack-intel` | Attack database |
| GET | `/suricata/flow/{id}/ai-analyze` | **AI analysis** 🤖 |

### Zeek (10 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/zeek/notice/{id}/geoip` | GeoIP enrichment |
| GET | `/zeek/notice/{id}/threat-intel` | Threat intelligence |
| GET | `/zeek/notice/{id}/attack-intel` | Attack database |
| GET | `/zeek/notice/{id}/ai-analyze` | **AI analysis** 🤖 |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |
| GET | `/docs` | Swagger UI |

**Total: 44 endpoints**

---

## 🐳 Docker Setup

### Quick Start

```bash
# Build & Run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  enricher:
    build: .
    ports:
      - "5000:5000"
    env_file:
      - .env
    volumes:
      - ./parsers/data:/app/parsers/data:ro
      - ./logs:/app/logs
    restart: unless-stopped
```

---

## 📈 Example Usage

### 1. Parse ModSecurity Log

```bash
curl -X POST http://localhost:5000/modsec/parse \
  -H "Content-Type: application/json" \
  -d '{
    "log": "[2025-01-08 10:00:00] [123] 192.168.1.100 POST /login ..."
  }'
```

### 2. Get GeoIP Enrichment

```bash
curl http://localhost:5000/modsec/transaction/123/geoip
```

**Response:**
```json
{
  "transaction_id": "123",
  "geoip": {
    "ip": "192.168.1.100",
    "country": "Vietnam",
    "city": "Hanoi",
    "latitude": 21.0285,
    "longitude": 105.8542
  }
}
```

### 3. AI Security Analysis 🤖

```bash
curl http://localhost:5000/modsec/transaction/123/ai-analyze
```

**Response:**
```json
{
  "summary": "SQL Injection attack detected from Vietnam IP",
  "threat_level": "Critical",
  "confidence": 95,
  "attack_narrative": "Attacker attempted SQL injection...",
  "recommendations": {
    "immediate": ["Block source IP", "Review logs"],
    "short_term": ["Update WAF rules"],
    "long_term": ["Security training"]
  },
  "mitre_attack_techniques": ["T1190", "T1059"],
  "ai_provider": "Google Gemini",
  "ai_model": "gemini-2.5-flash"
}
```

---

## 🛠️ Development

### Project Structure

```
pbl6-enricher/
├── parsers/
│   ├── data/                  # Data files
│   │   ├── geoip/            # GeoIP databases
│   │   └── attack_intel/     # MITRE, OWASP data
│   └── unified/              # Main application
│       ├── app.py            # Flask app
│       ├── routes/           # API routes
│       ├── services/         # Business logic
│       ├── enrichers/        # Enrichment modules
│       └── ai/               # AI analyzers
├── shared/                    # Shared utilities
├── scripts/                   # Helper scripts
├── docs/                      # Documentation
├── logs/                      # Log files
├── requirements.txt          # Python dependencies
├── Dockerfile                # Docker image
├── docker-compose.yml        # Docker compose
└── .env.example              # Environment template
```

### Running Tests

```bash
# Test Gemini integration
python scripts/quick_test_gemini.py

# Test AI analyzer
python scripts/test_analyzer.py

# Test complex analysis
python scripts/test_complex_analysis.py
```

---

## 🔧 Troubleshooting

### Common Issues

**Q: GeoIP database not found**
```bash
# Download from MaxMind
# Place files in: parsers/data/geoip/
# - GeoLite2-City.mmdb
# - GeoLite2-ASN.mmdb
```

**Q: Gemini API key invalid**
```bash
# Get new key: https://aistudio.google.com/apikey
# Update .env: GEMINI_API_KEY=AIza...
# Test: python scripts/quick_test_gemini.py
```

**Q: Empty response from Gemini**
```bash
# Check rate limits (15 RPM)
# Increase timeout in .env: AI_TIMEOUT=60
# Check logs: tail -f logs/enricher.log
```

**Q: Port already in use**
```bash
# Change port in .env
FLASK_PORT=5001

# Or kill process
lsof -ti:5000 | xargs kill -9  # Mac/Linux
```

👉 **Xem thêm:** [docs/SETUP.md](docs/SETUP.md#troubleshooting)

---

## 📝 License

MIT License - Copyright (c) 2025 tanbrando

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

---

## 📧 Contact

- **Author:** tanbrando
- **Email:** tanbrando@example.com
- **GitHub:** https://github.com/tanbrando/pbl6-enricher

---

## 🌟 Acknowledgments

- **Google Gemini** - Free AI API
- **MaxMind** - GeoIP databases
- **MITRE** - ATT&CK framework
- **OWASP** - Security knowledge base

---

**Built with ❤️ for SOC teams**

**Happy Log Enriching! 🚀**
