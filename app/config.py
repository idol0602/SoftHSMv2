import os
from pathlib import Path
from typing import Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Cấu hình toàn hệ thống thông qua biến môi trường.
    Hỗ trợ load từ file .env hoặc env variables do Docker/Koyeb/Render inject.
    """
    # Khóa API để bảo vệ các endpoint nghiệp vụ (hỗ trợ 1 khóa hoặc danh sách nhiều khóa phân tách bằng dấu phẩy)
    API_KEY: str = "crypto-hsm-super-secret-key-change-me"
    API_KEYS: Optional[str] = None  # Ví dụ: "project_a_key,project_b_key,project_c_key"

    # Đường dẫn file cấu hình SoftHSMv2
    SOFTHSM2_CONF: str = "/etc/softhsm2.conf"

    # Đường dẫn file thư viện PKCS#11 (.so)
    HSM_LIB_PATH: str = "/usr/lib/softhsm/libsofthsm2.so"

    # Nhãn của Token lưu trữ khóa dùng chung
    HSM_TOKEN_LABEL: str = "DefaultCryptoToken"

    # Mã PIN người dùng (User PIN) để truy cập Token
    HSM_PIN: str = "1234"

    # Mã PIN quản trị (Security Officer PIN)
    HSM_SO_PIN: str = "12345678"

    # Cấu hình mạng máy chủ
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    LOG_LEVEL: str = "INFO"

    # Đường dẫn thư mục lưu trữ Token SoftHSM
    HSM_TOKEN_DIR: str = "/var/lib/softhsm/tokens"

    # Cấu hình Sao lưu tự động lên Supabase Storage (Bảo toàn dữ liệu trên Cloud PaaS / Render)
    ENABLE_CLOUD_BACKUP: bool = True
    SUPABASE_URL: Optional[str] = "https://legpvxckbitwatyeiiqb.supabase.co"
    SUPABASE_KEY: Optional[str] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxlZ3B2eGNrYml0d2F0eWVpaXFiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc4OTk2NDEsImV4cCI6MjEwMzQ3NTY0MX0.yHqHznFPgWBSNcofxtD2SI9-19sUmZj4nX1AsvWFZ84"
    SUPABASE_BUCKET: str = "pdf-files"
    SUPABASE_BACKUP_PATH: str = "backups/softhsm_tokens.tar.gz"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def get_valid_api_keys(self) -> list[str]:
        """Lấy danh sách tất cả các API Key hợp lệ (hỗ trợ nhiều dự án dùng chung)"""
        keys = set()
        if self.API_KEY:
            keys.add(self.API_KEY.strip())
        if self.API_KEYS:
            for k in self.API_KEYS.split(","):
                k = k.strip()
                if k:
                    keys.add(k)
        return list(keys)

    def resolve_hsm_lib_path(self) -> str:
        """
        Tự động kiểm tra và giải quyết đường dẫn thư viện SoftHSMv2 theo kiến trúc CPU.
        """
        candidates = [
            self.HSM_LIB_PATH,
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        # Nếu không tìm thấy, trả về giá trị mặc định để PyKCS11 thử tải
        return self.HSM_LIB_PATH


settings = Settings()
