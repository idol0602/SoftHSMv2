import secrets
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from app.config import settings

# Khai báo Header authentication chuẩn X-API-Key
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    Middleware xác thực API Key từ HTTP Header.
    Sử dụng secrets.compare_digest để ngăn chặn triệt để tấn công kênh phụ đo thời gian (Timing Attack).
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header 'X-API-Key' bị thiếu. Vui lòng cung cấp khóa API hợp lệ.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # So sánh an toàn chống timing attack với toàn bộ danh sách API key được cấp quyền
    valid_keys = settings.get_valid_api_keys()
    is_valid = any(secrets.compare_digest(api_key, vk) for vk in valid_keys)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key không chính xác hoặc không có quyền truy cập HSM.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key
