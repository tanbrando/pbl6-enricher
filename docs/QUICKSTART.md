# ⚡ Quick Start Guide - PBL6 Log Enricher

**Thời gian cài đặt:** 10 phút  
**Yêu cầu:** Python 3.11+, Git

---

## 🚀 Bước 1: Clone & Cài Đặt (2 phút)

```bash
# Clone repository
git clone https://github.com/tanbrando/pbl6-enricher.git
cd pbl6-enricher

# Tạo virtual environment
python -m venv venv

# Activate venv
source venv/bin/activate  # Linux/Mac
# hoặc
venv\Scripts\activate     # Windows

# Cài dependencies
pip install -r requirements.txt
```

---

## 🔧 Bước 2: Cấu Hình (3 phút)

### 2.1 Copy Environment File

```bash
cp .env.example .env
```

### 2.2 Lấy Gemini API Key (FREE)

1. **Truy cập:** https://aistudio.google.com/apikey
2. **Đăng nhập** Google Account
3. **Click** "Create API Key"
4. **Copy** API key (bắt đầu với `AIza...`)

### 2.3 Cập Nhật .env

```bash
# Mở file .env
nano .env  # hoặc notepad .env

# Thêm Gemini API key
GEMINI_ENABLED=True
GEMINI_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**Lưu file!**

---

## 📦 Bước 3: Tải GeoIP Databases (3 phút)

### 3.1 Tạo Thư Mục

```bash
mkdir -p parsers/data/geoip
```

### 3.2 Download Databases

**Tải từ MaxMind:** https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Cần 2 files:
- `GeoLite2-City.mmdb`
- `GeoLite2-ASN.mmdb`

### 3.3 Đặt Vào Thư Mục

```bash
# Di chuyển files vào
mv ~/Downloads/GeoLite2-*.mmdb parsers/data/geoip/
```

---

## ▶️ Bước 4: Chạy (1 phút)

```bash
python parsers/unified/app.py
```

**Output mong đợi:**
```
 * Running on http://0.0.0.0:5000
✅ Google Gemini analyzer initialized
   Model: gemini-2.5-flash (FREE)
```

---

## ✅ Bước 5: Test (1 phút)

### Test Health

```bash
curl http://localhost:5000/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

### Test Gemini AI

```bash
python scripts/quick_test_gemini.py
```

**Response:**
```
✅ Gemini is working!
Response: Xin chào!
✅ All tests passed!
```

---

## 🎉 Done!

Server đang chạy tại: **http://localhost:5000**

### Next Steps

1. **Xem API docs:** http://localhost:5000/docs
2. **Test endpoints:** Xem [README.md](../README.md#api-endpoints)
3. **Setup Grafana:** Xem [SETUP.md](SETUP.md#grafana-integration)

---

## 🔧 Troubleshooting

### Port đã được sử dụng

```bash
# Đổi port trong .env
FLASK_PORT=5001

# Hoặc kill process
lsof -ti:5000 | xargs kill -9  # Mac/Linux
```

### GeoIP không tìm thấy

```bash
# Kiểm tra files
ls -la parsers/data/geoip/

# Phải có:
# GeoLite2-City.mmdb
# GeoLite2-ASN.mmdb
```

### Gemini API lỗi

```bash
# Test API key
python scripts/quick_test_gemini.py

# Nếu lỗi, lấy key mới:
# https://aistudio.google.com/apikey
```

---

## 📚 Tài Liệu

- **Full Setup Guide:** [SETUP.md](SETUP.md)
- **API Reference:** [README.md](../README.md#api-endpoints)
- **Docker Guide:** [SETUP.md](SETUP.md#docker-deployment)

---

**Questions?** Check [SETUP.md](SETUP.md#troubleshooting) or open an issue!
