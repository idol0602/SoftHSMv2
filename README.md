# Universal Cloud SoftHSMv2 Cryptographic Microservice
### *Dịch vụ Bảo mật Phần cứng Ảo (Cloud HSM as a Service) Dùng Chung Đa Dự Án*

---

Dự án cung cấp một microservice độc lập đóng gói phần cứng bảo mật ảo **SoftHSMv2** (chuẩn **PKCS#11**) kết hợp với **FastAPI** và **PyKCS11**. Dịch vụ được thiết kế theo kiến trúc **Cloud HSM as a Service**, sẵn sàng phục vụ đồng thời cho **nhiều dự án khác nhau** (Fintech, Hợp đồng điện tử, Hóa đơn điện tử, Đấu giá & Bỏ phiếu kín, Xác thực Webhook, Tokenization thẻ,...) mà không bị bó hẹp trong bất kỳ một bài toán đơn lẻ nào.

---

## 📑 Mục lục
1. [Khả năng tái sử dụng đa dự án (Multi-Tenant & Use Cases)](#1-khả-năng-tái-sử-dụng-đa-dự-án-multi-tenant--use-cases)
2. [Cấu trúc thư mục dự án](#2-cấu-trúc-thư-mục-dự-án)
3. [Biến môi trường cấu hình](#3-biến-môi-trường-cấu-hình)
4. [Hướng dẫn chạy cục bộ với Docker](#4-hướng-dẫn-chạy-cục-bộ-với-docker)
5. [Tài liệu API & Hướng dẫn kiểm thử cURL](#5-tài-liệu-api--hướng-dẫn-kiểm-thử-curl)
6. [Hướng dẫn Deploy lên Cloud PaaS (Render / Koyeb)](#6-hướng-dẫn-deploy-lên-cloud-paas-render--koyeb)
7. [Giải pháp Cronjob giữ Server Render luôn thức 24/7 (Anti-Sleep)](#7-giải-pháp-cronjob-giữ-server-render-luôn-thức-247-anti-sleep)
8. [Khuyến nghị an toàn bảo mật](#8-khuyến-nghị-an-toàn-bảo-mật)

---

## 1. Khả năng tái sử dụng đa dự án (Multi-Tenant & Use Cases)

Microservice này hoạt động như một **Trung tâm Quản lý Mật mã & Khóa bảo mật tập trung** (Centralized KMS / HSM) cho toàn bộ hạ tầng backend của bạn:

```
                      ┌──────────────────────────────────────┐
                      │    Các Dự Án / Microservices Gọi API │
                      └──────────────────┬───────────────────┘
                                         │
        ┌───────────────────┬────────────┴────────┬──────────────────┐
        ▼                   ▼                     ▼                  ▼
┌───────────────┐   ┌───────────────┐     ┌───────────────┐   ┌───────────────┐
│  Dự án 1:     │   │  Dự án 2:     │     │  Dự án 3:     │   │  Dự án 4:     │
│  e-Contract & │   │  Đấu Giá &    │     │  Fintech &    │   │  Hệ Thống IoT │
│  Hóa Đơn Điện │   │  Bỏ Phiếu Kín │     │  Thanh Toán   │   │  & mTLS /     │
│  Tử           │   │  (Sealed-Bid) │     │  (PCI-DSS PII)│   │  Webhooks     │
└───────┬───────┘   └───────┬───────┘     └───────┬───────┘   └───────┬───────┘
        │                   │                     │                   │
        │ [X-API-Key: A]    │ [X-API-Key: B]      │ [X-API-Key: C]    │ [X-API-Key: D]
        ▼                   ▼                     ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              UNIVERSAL SOFTHSMV2 REST API (Port 8080)                       │
│  - Namespace Key Isolation (`invoice:*`, `auction:*`, `payment:*`,...)      │
│  - Multi-API Key Authentication                                             │
│  - Thread-Safe PKCS#11 Engine                                               │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 BẢO VỆ PHẦN CỨNG ẢO (SoftHSMv2 PKCS#11)                    │
│   Private Key luôn được niêm phong: CKA_SENSITIVE=True, CKA_EXTRACTABLE=False │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Các kịch bản ứng dụng thực tế:

| Lĩnh vực / Dự án | Nhu cầu bảo mật | Endpoint sử dụng |
|---|---|---|
| **Hợp đồng điện tử & e-Invoice** | Ký số hóa đơn, văn bản pháp lý, biên bản thỏa thuận bằng khóa RSA 2048/3072 hoặc ECDSA | `POST /api/v1/hsm/sign`<br>`POST /api/v1/hsm/verify` |
| **Đấu giá & Bỏ phiếu kín** | Niêm phong giá thầu, phiếu bầu bằng Public Key; chỉ giải mã công bố khi hết giờ | `POST /api/v1/hsm/encrypt`<br>`POST /api/v1/hsm/decrypt` |
| **Fintech & Cổng thanh toán** | Tokenization dữ liệu thẻ (PAN), số tài khoản, dữ liệu định danh cá nhân (PII / CCCD) | `POST /api/v1/hsm/encrypt`<br>`POST /api/v1/hsm/decrypt` |
| **Xác thực Webhook & Microservices** | Ký số chuỗi băm (HMAC/Digital Signature) bảo vệ request giữa các service nội bộ | `POST /api/v1/hsm/sign`<br>`POST /api/v1/hsm/verify` |
| **IoT & Thiết bị ngoại vi** | Cấp phát Public Key cho thiết bị để xác thực phiên kết nối mTLS an toàn | `GET /api/v1/hsm/public-key/{key_label}` |

### Cơ chế phân quyền & Cách ly giữa các dự án:
1. **Namespace Key Label**:
   - Dự án Hóa đơn đặt nhãn: `invoice:2026-master`
   - Dự án Đấu giá đặt nhãn: `auction:session-9988`
   - Dự án Fintech đặt nhãn: `fintech:card-enc-rsa`
   - Cho phép lọc danh sách theo tiền tố: `GET /api/v1/hsm/keys?prefix=invoice:`
2. **Hỗ trợ Multi-API Key**:
   - Biến môi trường `API_KEYS` cho phép khai báo danh sách nhiều khóa bí mật: `API_KEYS=key_duan1,key_duan2,key_duan3`. Mỗi dự án chỉ cần cầm đúng API Key của mình.

---

## 2. Cấu trúc thư mục dự án

```
.
├── .github/
│   └── workflows/
│       └── keep_alive.yml      # Cronjob tự động ping server Render mỗi 10 phút chống Sleep
├── Dockerfile                  # Container Debian Bookworm + SoftHSM2 + PyKCS11 tối ưu kích thước
├── docker-compose.yml          # Chạy local với persistent volume cho token SoftHSM
├── render.yaml                 # Blueprint Render tự động deploy 1-click
├── entrypoint.sh               # Shell script tự khởi tạo token và slot khi khởi động
├── softhsm2.conf               # Cấu hình lưu trữ token SoftHSMv2 vào /var/lib/softhsm/tokens
├── requirements.txt            # FastAPI, Uvicorn, PyKCS11, Cryptography
├── .env.example                # File mẫu biến môi trường
├── .dockerignore               # Bỏ qua file rác khi build image
├── README.md                   # Tài liệu hướng dẫn chi tiết
└── app/
    ├── __init__.py
    ├── config.py               # Quản lý cấu hình Settings & Multi-API Key
    ├── auth.py                 # Xác thực X-API-Key chống Timing Attack (secrets.compare_digest)
    ├── schemas.py              # Pydantic models chuẩn cho mọi nghiệp vụ mật mã
    ├── hsm.py                  # Module lõi PKCS#11 (Thread-Lock RLock an toàn đa luồng)
    └── main.py                 # REST API Router (Quản lý khóa, Mã hóa, Ký số)
```

---

## 3. Biến môi trường cấu hình

| Tên biến | Giá trị mặc định | Giải thích |
|---|---|---|
| `API_KEY` | `crypto-hsm-super-secret-key-change-me` | Khóa API chính dùng cho header `X-API-Key` |
| `API_KEYS` | *(Tùy chọn)* | Danh sách nhiều API Key phân tách bằng dấu phẩy để cấp cho các dự án khác nhau |
| `HSM_TOKEN_LABEL` | `DefaultCryptoToken` | Nhãn của Token lưu trữ khóa trong SoftHSMv2 |
| `HSM_PIN` | `1234` | User PIN để đăng nhập mở Session ký và giải mã (4-255 ký tự) |
| `HSM_SO_PIN` | `12345678` | Security Officer PIN dùng khi khởi tạo hoặc reset Token |
| `SOFTHSM2_CONF` | `/etc/softhsm2.conf` | Đường dẫn file cấu hình SoftHSMv2 |
| `HSM_LIB_PATH` | `/usr/lib/softhsm/libsofthsm2.so` | Đường dẫn file thư viện PKCS#11 (.so) |
| `PORT` | `8080` | Cổng HTTP lắng nghe (Render/Koyeb tự động inject) |
| `HOST` | `0.0.0.0` | Địa chỉ mạng lắng nghe |
| `LOG_LEVEL` | `INFO` | Mức log: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## 4. Hướng dẫn chạy cục bộ với Docker

### Cách 1: Sử dụng Docker Compose (Khuyên dùng)
Volume `softhsm_tokens` đã cấu hình sẵn để dữ liệu khóa không bị mất khi container restart:

```bash
# 1. Khởi động background
docker compose up -d --build

# 2. Xem logs kiểm tra token
docker compose logs -f

# 3. Dừng container
docker compose down
```

### Cách 2: Sử dụng Docker CLI thủ công

```bash
docker build -t universal-softhsm-api:2.0.0 .

docker volume create softhsm_master_tokens

docker run -d \
  --name universal-softhsm \
  -p 8080:8080 \
  -e API_KEY="my-super-secret-key" \
  -e HSM_PIN="1234" \
  -e HSM_SO_PIN="12345678" \
  -v softhsm_master_tokens:/var/lib/softhsm/tokens \
  universal-softhsm-api:2.0.0
```

Truy cập Swagger UI tài liệu trực quan tại: **`http://localhost:8080/docs`**

---

## 5. Tài liệu API & Hướng dẫn kiểm thử cURL

Thiết lập biến môi trường terminal để test:

```bash
export API_URL="http://localhost:8080"
export API_KEY="crypto-hsm-super-secret-key-change-me"
```

---

### 5.1. System Healthcheck (`GET /health`)
Endpoint công khai không yêu cầu API Key:

```bash
curl -X GET "$API_URL/health"
```

---

### 5.2. Quản lý vòng đời cặp khóa (Key Lifecycle Management)

#### A. Sinh cặp khóa RSA (dùng cho Hóa đơn / Đấu giá / Mã hóa):
```bash
curl -X POST "$API_URL/api/v1/hsm/generate-keypair" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_label": "invoice:master-rsa-2026",
    "key_type": "RSA",
    "key_size": 2048
  }'
```

#### B. Sinh cặp khóa ECDSA (secp256r1) cho ký nhanh & mTLS:
```bash
curl -X POST "$API_URL/api/v1/hsm/generate-keypair" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_label": "contract:signer-ecdsa",
    "key_type": "ECDSA",
    "curve": "secp256r1"
  }'
```

#### C. Liệt kê toàn bộ khóa trong HSM (có hỗ trợ lọc theo tiền tố dự án):
```bash
# Liệt kê tất cả các khóa
curl -X GET "$API_URL/api/v1/hsm/keys" \
  -H "X-API-Key: $API_KEY"

# Chỉ liệt kê các khóa thuộc dự án 'invoice:'
curl -X GET "$API_URL/api/v1/hsm/keys?prefix=invoice:" \
  -H "X-API-Key: $API_KEY"
```

#### D. Xem chi tiết thuộc tính của một khóa (`GET /api/v1/hsm/keys/{key_label}`):
```bash
curl -X GET "$API_URL/api/v1/hsm/keys/invoice:master-rsa-2026" \
  -H "X-API-Key: $API_KEY"
```

#### E. Xuất Public Key chuẩn PEM (`GET /api/v1/hsm/public-key/{key_label}`):
```bash
curl -X GET "$API_URL/api/v1/hsm/public-key/invoice:master-rsa-2026" \
  -H "X-API-Key: $API_KEY"
```

#### F. Xóa cặp khóa khỏi Token (`DELETE /api/v1/hsm/keys/{key_label}`):
```bash
curl -X DELETE "$API_URL/api/v1/hsm/keys/invoice:master-rsa-2026" \
  -H "X-API-Key: $API_KEY"
```

---

### 5.3. Mã hóa & Giải mã (Encryption & Decryption)

#### Mã hóa dữ liệu / Niêm phong thông tin nhạy cảm (`POST /api/v1/hsm/encrypt`):
```bash
curl -X POST "$API_URL/api/v1/hsm/encrypt" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_label": "invoice:master-rsa-2026",
    "plaintext": "DỮ LIỆU BÍ MẬT HOẶC MỨC GIÁ NIÊM PHONG",
    "mechanism": "RSA_PKCS1"
  }'
```

#### Giải mã dữ liệu bằng Private Key bảo vệ trong HSM (`POST /api/v1/hsm/decrypt`):
```bash
curl -X POST "$API_URL/api/v1/hsm/decrypt" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_label": "invoice:master-rsa-2026",
    "ciphertext_base64": "<DÁN_CHUỖI_CIPHERTEXT_BASE64_Ở_BƯỚC_TRÊN>",
    "mechanism": "RSA_PKCS1",
    "return_as_string": true
  }'
```

---

### 5.4. Ký số & Xác thực chữ ký số (Digital Signatures & Verification)

#### Ký số hợp đồng / hóa đơn / chuỗi băm giao dịch (`POST /api/v1/hsm/sign`):
```bash
curl -X POST "$API_URL/api/v1/hsm/sign" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_label": "invoice:master-rsa-2026",
    "data": "HÓA ĐƠN ĐIỆN TỬ SỐ 001 - TỔNG TIỀN: 50.000.000 VND - NGÀY 2026-10-20",
    "is_prehashed": false,
    "mechanism": "AUTO"
  }'
```

#### Xác thực chữ ký số bằng Public Key (`POST /api/v1/hsm/verify`):
```bash
curl -X POST "$API_URL/api/v1/hsm/verify" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_label": "invoice:master-rsa-2026",
    "data": "HÓA ĐƠN ĐIỆN TỬ SỐ 001 - TỔNG TIỀN: 50.000.000 VND - NGÀY 2026-10-20",
    "signature_base64": "<DÁN_CHUỖI_SIGNATURE_BASE64_Ở_BƯỚC_TRÊN>",
    "is_prehashed": false,
    "mechanism": "AUTO"
  }'
```

---

## 6. Hướng dẫn Deploy lên Cloud PaaS (Render / Koyeb)

### 6.1. Triển khai lên Koyeb (Có hỗ trợ Persistent Volume)
1. Push mã nguồn lên GitHub.
2. Tại [Koyeb Console](https://app.koyeb.com/) -> Bấm **Create Service** -> Chọn GitHub repo -> Build type: **Dockerfile**.
3. **Cấu hình Volumes**: Chọn **Add Volume**, Mount Path: `/var/lib/softhsm/tokens` (dung lượng 1GB).
4. Cấu hình biến môi trường: `API_KEY`, `API_KEYS`, `HSM_PIN`, `HSM_SO_PIN`, `PORT=8080`.
5. Health Check Path: `/health`. Bấm **Deploy**.

---

### 6.2. Triển khai lên Render

#### Cách 1: Triển khai 1-Click bằng Blueprint
1. Tại [Render Dashboard](https://dashboard.render.com/) -> Bấm **New +** -> Chọn **Blueprint**.
2. Chọn repository này. Render sẽ tự động đọc file [render.yaml](file:///d:/PersonalProject/TrustSim/SoftHSMv2/render.yaml) và khởi tạo Web Service.

#### Cách 2: Triển khai thủ công
1. Tạo **Web Service** -> Chọn Docker environment.
2. Cấu hình Health Check Path: `/health`.
3. Thêm các biến môi trường: `API_KEY`, `HSM_PIN`, `HSM_SO_PIN`, `HSM_TOKEN_LABEL`.

> **Lưu ý về Render Free Tier**: Sau 15 phút không có request, Render sẽ đưa container vào trạng thái ngủ (Sleep Mode), gây độ trễ Cold Start từ 40-60 giây ở lượt gọi tiếp theo. Hãy thiết lập Cronjob Anti-Sleep theo hướng dẫn bên dưới.

---

## 7. Giải pháp Cronjob giữ Server Render luôn thức 24/7 (Anti-Sleep)

### Cách 1: Sử dụng UptimeRobot (Khuyên dùng - 2 phút cài đặt)
1. Đăng ký tài khoản miễn phí tại [https://uptimerobot.com/](https://uptimerobot.com/).
2. Bấm **+ Add New Monitor**:
   - **Type**: `HTTP(s)`
   - **Name**: `Universal SoftHSM KeepAlive`
   - **URL**: `https://<ten-app-cua-ban>.onrender.com/health`
   - **Monitoring Interval**: `5 minutes` (nhỏ hơn ngưỡng 15 phút của Render).
3. Bấm **Create Monitor**. Server sẽ được ping liên tục và **không bao giờ ngủ**.

---

### Cách 2: Sử dụng GitHub Actions Workflow có sẵn trong Repo
Workflow [.github/workflows/keep_alive.yml](file:///d:/PersonalProject/TrustSim/SoftHSMv2/.github/workflows/keep_alive.yml) đã được cấu hình chạy định kỳ `*/10 * * * *`:
1. Vào GitHub repo của bạn -> **Settings** -> **Secrets and variables** -> **Actions**.
2. Thêm Secret:
   - **Name**: `RENDER_SERVICE_URL`
   - **Value**: `https://<ten-app>.onrender.com` (không có dấu `/` ở cuối).
3. GitHub Actions sẽ tự động kích hoạt ping nền mỗi 10 phút.

---

### Cách 3: Đặt Crontab trên VPS riêng của bất kỳ microservice nào khác
```bash
crontab -e
# Thêm dòng sau:
*/10 * * * * curl -s -f https://<ten-app>.onrender.com/health > /dev/null 2>&1
```

---

## 8. Khuyến nghị an toàn bảo mật

1. **Bảo mật SO PIN & User PIN**: Tuyệt đối không commit mã PIN thực tế lên Git. Sử dụng Secret Manager của Cloud PaaS để inject.
2. **Cách ly khóa theo Namespace**: Thống nhất tiền tố nhãn khóa giữa các team (ví dụ: `du_an_a:key_name`, `du_an_b:key_name`).
3. **Phân quyền API Key**: Sử dụng biến `API_KEYS` để cấp riêng từng key cho từng microservice gọi vào.
4. **Sao lưu dữ liệu Token**: Định kỳ backup thư mục `/var/lib/softhsm/tokens` lên Cloud Object Storage có mã hóa KMS.
