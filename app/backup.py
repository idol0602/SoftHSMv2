"""
Module sao lưu và phục hồi dữ liệu Token SoftHSMv2 lên Cloud Storage (Supabase Storage).
Giải quyết triệt để vấn đề mất khóa trên Render Free Tier do ổ cứng tạm thời (Ephemeral Filesystem).
"""

import io
import os
import sys
import tarfile
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import Tuple

from app.config import settings

logger = logging.getLogger("backup")


def _get_supabase_headers() -> dict:
    return {
        "Authorization": f"Bearer {settings.SUPABASE_KEY}",
        "apikey": settings.SUPABASE_KEY or "",
    }


def backup_tokens_to_supabase() -> Tuple[bool, str]:
    """
    Nén toàn bộ thư mục Token SoftHSMv2 (/var/lib/softhsm/tokens) thành file tar.gz
    và upload lên Supabase Storage với cơ chế upsert ghi đè.
    """
    if not settings.ENABLE_CLOUD_BACKUP:
        return False, "Cloud backup đang bị tắt (ENABLE_CLOUD_BACKUP=False)."

    if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
        msg = "Chưa cấu hình SUPABASE_URL hoặc SUPABASE_KEY. Bỏ qua sao lưu."
        logger.warning(msg)
        return False, msg

    token_dir = Path(settings.HSM_TOKEN_DIR)
    if not token_dir.exists():
        msg = f"Thư mục token '{token_dir}' không tồn tại."
        logger.warning(msg)
        return False, msg

    token_files = list(token_dir.glob("**/*"))
    if not token_files:
        msg = f"Thư mục token '{token_dir}' đang trống, không có dữ liệu để sao lưu."
        logger.info(msg)
        return False, msg

    try:
        # Nén thư mục token vào in-memory BytesIO
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            for item in token_dir.iterdir():
                tar.add(str(item), arcname=item.name)

        tar_bytes = tar_buffer.getvalue()
        tar_size_kb = len(tar_bytes) / 1024

        logger.info(
            "Đang tải bản sao lưu Token (%d files, %.2f KB) lên Supabase Bucket '%s/%s'...",
            len(token_files),
            tar_size_kb,
            settings.SUPABASE_BUCKET,
            settings.SUPABASE_BACKUP_PATH,
        )

        upload_url = (
            f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1/object/"
            f"{settings.SUPABASE_BUCKET}/{settings.SUPABASE_BACKUP_PATH.lstrip('/')}"
        )

        headers = _get_supabase_headers()
        headers.update({
            "Content-Type": "application/gzip",
            "x-upsert": "true",
        })

        req = urllib.request.Request(upload_url, data=tar_bytes, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 201):
                msg = f"Sao lưu thành công Token lên Supabase Storage ({tar_size_kb:.2f} KB)."
                logger.info("✅ %s", msg)
                return True, msg
            else:
                msg = f"Supabase phản hồi status code: {resp.status}"
                logger.warning(msg)
                return False, msg

    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        msg = f"Lỗi HTTP khi tải backup lên Supabase [{e.code}]: {err_body}"
        logger.error(msg)
        return False, msg
    except Exception as e:
        msg = f"Lỗi không xác định khi sao lưu token: {str(e)}"
        logger.error(msg, exc_info=True)
        return False, msg


def restore_tokens_from_supabase() -> Tuple[bool, str]:
    """
    Tải bản sao lưu tar.gz từ Supabase Storage và giải nén vào /var/lib/softhsm/tokens.
    Chỉ thực hiện nếu thư mục token đang trống hoặc bị thiếu slot.
    """
    if not settings.ENABLE_CLOUD_BACKUP:
        return False, "Cloud backup đang bị tắt (ENABLE_CLOUD_BACKUP=False)."

    if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
        msg = "Chưa cấu hình SUPABASE_URL hoặc SUPABASE_KEY. Bỏ qua phục hồi."
        logger.warning(msg)
        return False, msg

    token_dir = Path(settings.HSM_TOKEN_DIR)
    token_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(token_dir), 0o700)
    except Exception:
        pass

    download_url = (
        f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1/object/"
        f"{settings.SUPABASE_BUCKET}/{settings.SUPABASE_BACKUP_PATH.lstrip('/')}"
    )

    try:
        logger.info(
            "Đang kiểm tra và tải bản sao lưu Token từ Supabase Bucket '%s/%s'...",
            settings.SUPABASE_BUCKET,
            settings.SUPABASE_BACKUP_PATH,
        )

        headers = _get_supabase_headers()
        req = urllib.request.Request(download_url, headers=headers, method="GET")

        with urllib.request.urlopen(req, timeout=30) as resp:
            tar_bytes = resp.read()

        if not tar_bytes or len(tar_bytes) < 10:
            msg = "File sao lưu tải về rỗng hoặc không hợp lệ."
            logger.warning(msg)
            return False, msg

        tar_buffer = io.BytesIO(tar_bytes)
        restored_count = 0
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            tar.extractall(path=str(token_dir))
            restored_count = len(tar.getmembers())

        # Thiết lập quyền bảo mật chuẩn cho thư mục và các file token
        try:
            os.chmod(str(token_dir), 0o700)
            for f in token_dir.glob("**/*"):
                if f.is_file():
                    os.chmod(str(f), 0o600)
        except Exception:
            pass

        msg = f"Đã phục hồi thành công {restored_count} tệp tin Token từ Cloud Storage vào '{token_dir}'."
        logger.info("✅ %s", msg)
        return True, msg

    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        if e.code == 404 or "not_found" in err_body or "NoSuchKey" in err_body:
            msg = "Chưa có bản sao lưu nào trên Supabase Storage (Lần đầu khởi tạo)."
            logger.info("ℹ️ %s", msg)
            return False, msg
        msg = f"Lỗi HTTP khi tải bản sao lưu từ Supabase [{e.code}]: {err_body}"
        logger.warning(msg)
        return False, msg
    except Exception as e:
        msg = f"Lỗi không xác định khi phục hồi token: {str(e)}"
        logger.error(msg, exc_info=True)
        return False, msg


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"

    if cmd == "restore":
        success, message = restore_tokens_from_supabase()
        print(f"[{'SUCCESS' if success else 'SKIPPED'}] {message}")
        sys.exit(0 if success else 1)
    elif cmd == "backup":
        success, message = backup_tokens_to_supabase()
        print(f"[{'SUCCESS' if success else 'FAILED'}] {message}")
        sys.exit(0 if success else 1)
    else:
        print("Sử dụng: python -m app.backup [restore|backup]")
        sys.exit(0)
