# ==============================================================================
# DOCKERFILE: Microservice SoftHSMv2 REST API cho Hệ sinh thái Đấu Giá SIM
# Tối ưu hóa kích thước image và độ an toàn cho Cloud PaaS (Render / Koyeb)
# ==============================================================================

FROM python:3.11-slim

# Thiết lập biến môi trường chuẩn của Python và hệ thống
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOFTHSM2_CONF=/etc/softhsm2.conf \
    PORT=8080 \
    HOST=0.0.0.0

# 1. Cài đặt SoftHSM2, công cụ quản trị OpenSC và các thư viện biên dịch PyKCS11
RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    opensc \
    libsofthsm2 \
    gcc \
    g++ \
    swig \
    python3-dev \
    libpcsclite-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2. Tạo thư mục làm việc và thư mục lưu trữ token SoftHSM
WORKDIR /app
RUN mkdir -p /var/lib/softhsm/tokens /usr/lib/softhsm && \
    chmod 700 /var/lib/softhsm/tokens

# 3. Sao chép và cài đặt các phụ thuộc Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4. Gỡ bỏ các công cụ build không cần thiết sau khi đã compile xong PyKCS11
RUN apt-get purge -y --auto-remove gcc g++ swig python3-dev && \
    rm -rf /var/lib/apt/lists/*

# 5. Sao chép file cấu hình SoftHSMv2 và mã nguồn
COPY softhsm2.conf /etc/softhsm2.conf
COPY entrypoint.sh /entrypoint.sh
COPY app/ ./app/

# Chuyển đổi định dạng ngắt dòng (CRLF sang LF) đề phòng build trên Windows
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

# Cổng mặc định
EXPOSE 8080

# Thiết lập Healthcheck kiểm tra định kỳ
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/health || exit 1

# Khởi chạy qua entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
