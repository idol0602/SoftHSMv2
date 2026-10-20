#!/bin/bash
set -e

# ==============================================================================
# ENTRYPOINT SCRIPT: Khởi tạo và kiểm tra SoftHSMv2 trước khi chạy FastAPI Server
# ==============================================================================

echo "=========================================================="
echo "🚀 Khởi động Universal SoftHSMv2 Crypto Microservice"
echo "=========================================================="

# 1. Cấu hình biến môi trường mặc định nếu chưa có
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/softhsm2.conf}"
TOKEN_LABEL="${HSM_TOKEN_LABEL:-DefaultCryptoToken}"
SO_PIN="${HSM_SO_PIN:-12345678}"
USER_PIN="${HSM_PIN:-1234}"
PORT="${PORT:-8080}"
HOST="${HOST:-0.0.0.0}"

echo "⚙️  File cấu hình SoftHSM: $SOFTHSM2_CONF"
echo "⚙️  Nhãn Token mục tiêu:   $TOKEN_LABEL"
echo "⚙️  Cổng lắng nghe:       $PORT"

# 2. Đảm bảo thư mục lưu trữ Token tồn tại và có quyền truy cập
mkdir -p /var/lib/softhsm/tokens
chmod 700 /var/lib/softhsm/tokens

# 3. Tạo symlink chuẩn cho thư viện libsofthsm2.so nếu cần
if [ ! -f /usr/lib/softhsm/libsofthsm2.so ]; then
    mkdir -p /usr/lib/softhsm
    FOUND_LIB=$(find /usr/lib -name "libsofthsm2.so" 2>/dev/null | head -n 1)
    if [ -n "$FOUND_LIB" ]; then
        echo "🔗 Đang tạo symlink từ $FOUND_LIB -> /usr/lib/softhsm/libsofthsm2.so"
        ln -sf "$FOUND_LIB" /usr/lib/softhsm/libsofthsm2.so
    else
        echo "⚠️  Cảnh báo: Không tìm thấy file libsofthsm2.so trong /usr/lib"
    fi
fi

# 4. Tự động kiểm tra và phục hồi Token từ Cloud Storage (Supabase) nếu có
echo "☁️  Kiểm tra và phục hồi Token từ Cloud Storage (Supabase)..."
python -m app.backup restore || true

# 5. Kiểm tra xem Token với nhãn $TOKEN_LABEL đã được khởi tạo hay chưa
echo "🔍 Kiểm tra trạng thái Slot và Token..."
if softhsm2-util --show-slots | grep -q "Label: *$TOKEN_LABEL"; then
    echo "✅ Token '$TOKEN_LABEL' đã tồn tại và sẵn sàng hoạt động."
else
    echo "📦 Token '$TOKEN_LABEL' chưa tồn tại. Đang tiến hành khởi tạo token mới..."
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN"
    echo "✅ Đã khởi tạo thành công token '$TOKEN_LABEL' với User PIN và SO PIN cấu hình."
    
    echo "☁️  Tạo bản sao lưu khởi tạo lên Cloud Storage (Supabase)..."
    python -m app.backup backup || true
fi

# Hiển thị thông tin slot hiện tại
echo "----------------------------------------------------------"
softhsm2-util --show-slots
echo "----------------------------------------------------------"

# 5. Khởi động Web Server FastAPI qua Uvicorn
echo "🔥 Đang khởi động FastAPI Uvicorn Server trên ${HOST}:${PORT}..."
exec uvicorn app.main:app --host "$HOST" --port "$PORT" --workers 1 --log-level info
