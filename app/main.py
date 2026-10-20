import base64
import logging
from contextlib import asynccontextmanager
from typing import Annotated, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.auth import verify_api_key
from app.hsm import (
    HSMService,
    HSMServiceException,
    HSMKeyNotFoundException,
    HSMKeyAlreadyExistsException,
)
from app.schemas import (
    HealthResponse,
    GenerateKeyPairRequest,
    GenerateKeyPairResponse,
    KeyListResponse,
    KeySummary,
    DeleteKeyResponse,
    EncryptRequest,
    EncryptResponse,
    DecryptRequest,
    DecryptResponse,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
    PublicKeyResponse,
)

logger = logging.getLogger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Vòng đời khởi động ứng dụng: Kiểm tra kết nối SoftHSMv2"""
    logger.info("=== Khởi động Universal SoftHSMv2 REST API Microservice ===")
    hsm = HSMService.get_instance()
    health = hsm.check_health()
    logger.info("Trạng thái Token ban đầu: %s", health)
    yield
    logger.info("=== Dừng Universal SoftHSMv2 REST API Microservice ===")


app = FastAPI(
    title="Universal Cloud SoftHSMv2 Cryptographic Microservice",
    description=(
        "Microservice độc lập đóng gói phần cứng bảo mật ảo (SoftHSMv2 PKCS#11) đa năng. "
        "Sử dụng cho nhiều hệ thống/dự án khác nhau: Ký số Hợp đồng/Hóa đơn điện tử (e-Contract/e-Invoice), "
        "Niêm phong dữ liệu & Bỏ phiếu kín/Đấu giá, Tokenization thông tin thẻ/tài khoản Fintech, "
        "Xác thực Webhook và quản lý khóa mật mã tập trung."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Cấu hình CORS để cho phép tích hợp với Frontend & API Gateways của nhiều dự án
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Xử lý Exception tập trung
# ---------------------------------------------------------------------------
@app.exception_handler(HSMKeyNotFoundException)
async def handle_key_not_found(request, exc: HSMKeyNotFoundException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": "KeyNotFound", "message": str(exc)},
    )


@app.exception_handler(HSMKeyAlreadyExistsException)
async def handle_key_exists(request, exc: HSMKeyAlreadyExistsException):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"error": "KeyAlreadyExists", "message": str(exc)},
    )


@app.exception_handler(HSMServiceException)
async def handle_hsm_error(request, exc: HSMServiceException):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "HSMInternalError", "message": str(exc)},
    )


@app.exception_handler(Exception)
async def handle_unexpected_exception(request, exc: Exception):
    logger.error("Lỗi không mong muốn: %s", str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": type(exc).__name__, "message": str(exc)},
    )


# ---------------------------------------------------------------------------
# 1. System Healthcheck (Public - Dùng cho Monitor / Cloud PaaS Ping)
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Kiểm tra trạng thái Service và Slot/Token SoftHSMv2",
    tags=["System"],
)
async def health_check():
    """
    Endpoint kiểm tra trạng thái hoạt động:
    - Thư viện PKCS#11 (.so) đã nạp thành công chưa.
    - Slot ID và thông tin chi tiết của Hardware Security Token.
    """
    hsm = HSMService.get_instance()
    info = hsm.check_health()
    return info


# ---------------------------------------------------------------------------
# 2. Key Management (Quản lý vòng đời cặp khóa: Sinh, Liệt kê, Xem chi tiết, Xóa)
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/hsm/generate-keypair",
    response_model=GenerateKeyPairResponse,
    summary="Sinh cặp khóa RSA/ECDSA lưu trong Token",
    tags=["Key Management"],
)
async def generate_keypair(
    payload: GenerateKeyPairRequest,
    _: Annotated[str, Depends(verify_api_key)],
):
    """
    Tạo một cặp khóa mới lưu vĩnh viễn trong Token SoftHSMv2.
    - Khóa riêng (Private Key) được bảo vệ trong HSM, cấm trích xuất.
    - Hỗ trợ phân vùng namespace cho nhiều dự án qua nhãn (vd: `crm:signing-key`, `auction:session-01`).
    """
    hsm = HSMService.get_instance()
    key_type, pub_pem = hsm.generate_keypair(
        key_label=payload.key_label,
        key_type=payload.key_type.value,
        key_size=payload.key_size,
        curve=payload.curve or "secp256r1",
    )
    return GenerateKeyPairResponse(
        success=True,
        message=f"Đã sinh thành công cặp khóa {key_type} với nhãn '{payload.key_label}'.",
        key_label=payload.key_label,
        key_type=key_type,
        public_key_pem=pub_pem,
    )


@app.get(
    "/api/v1/hsm/keys",
    response_model=KeyListResponse,
    summary="Liệt kê danh sách các khóa trong Token",
    tags=["Key Management"],
)
async def list_keys(
    _: Annotated[str, Depends(verify_api_key)],
    prefix: Optional[str] = Query(
        None,
        description="Lọc các khóa theo tiền tố namespace của dự án (ví dụ: 'ecommerce:', 'invoice:', 'auction:')",
    ),
):
    """
    Lấy danh sách tất cả các cặp khóa đang được quản lý trong Token SoftHSM.
    Cho phép lọc theo tiền tố dự án để đảm bảo tính độc lập và cách ly.
    """
    hsm = HSMService.get_instance()
    keys_raw = hsm.list_keys(prefix=prefix)
    summaries = [KeySummary(**k) for k in keys_raw]
    return KeyListResponse(
        total=len(summaries),
        keys=summaries,
    )


@app.get(
    "/api/v1/hsm/keys/{key_label}",
    response_model=KeySummary,
    summary="Xem chi tiết thuộc tính và tính năng của khóa",
    tags=["Key Management"],
)
async def get_key_details(
    key_label: str,
    _: Annotated[str, Depends(verify_api_key)],
):
    """Lấy thông tin chi tiết thuật toán, độ dài và các cờ quyền năng của khóa."""
    hsm = HSMService.get_instance()
    info = hsm.get_key_info(key_label)
    return KeySummary(**info)


@app.get(
    "/api/v1/hsm/public-key/{key_label}",
    response_model=PublicKeyResponse,
    summary="Lấy Public Key định dạng PEM theo nhãn",
    tags=["Key Management"],
)
async def get_public_key(
    key_label: str,
    _: Annotated[str, Depends(verify_api_key)],
):
    """
    Xuất Public Key định dạng chuẩn PEM X.509 để chia sẻ cho các client/dự án
    dùng để mã hóa dữ liệu hoặc đối soát chữ ký số.
    """
    hsm = HSMService.get_instance()
    key_type, pub_pem = hsm.get_public_key_pem(key_label)
    return PublicKeyResponse(
        key_label=key_label,
        key_type=key_type,
        public_key_pem=pub_pem,
    )


@app.delete(
    "/api/v1/hsm/keys/{key_label}",
    response_model=DeleteKeyResponse,
    summary="Xóa vĩnh viễn cặp khóa khỏi Token",
    tags=["Key Management"],
)
async def delete_keypair(
    key_label: str,
    _: Annotated[str, Depends(verify_api_key)],
):
    """Hủy bỏ và giải phóng vĩnh viễn cặp khóa trong Token theo nhãn chỉ định."""
    hsm = HSMService.get_instance()
    deleted_count = hsm.delete_keypair(key_label)
    return DeleteKeyResponse(
        success=True,
        key_label=key_label,
        message=f"Đã xóa thành công cặp khóa '{key_label}' khỏi Token SoftHSM.",
        deleted_objects_count=deleted_count,
    )


# ---------------------------------------------------------------------------
# 3. Encryption & Decryption (Mã hóa và giải mã dữ liệu bảo mật)
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/hsm/encrypt",
    response_model=EncryptResponse,
    summary="Mã hóa dữ liệu / Niêm phong thông tin nhạy cảm",
    tags=["Encryption & Decryption"],
)
async def encrypt_data(
    payload: EncryptRequest,
    _: Annotated[str, Depends(verify_api_key)],
):
    """
    Mã hóa chuỗi dữ liệu nhạy cảm bằng Public Key trong HSM:
    - Tiếp nhận plaintext UTF-8 hoặc chuỗi nhị phân Base64.
    - Hỗ trợ RSA PKCS#1 v1.5 hoặc RSA OAEP với SHA-256 MGF1.
    - Ứng dụng: Niêm phong giá thầu, mã hóa trường PII, bỏ phiếu kín, thông tin thẻ/tài khoản.
    """
    if payload.plaintext is not None:
        raw_data = payload.plaintext.encode("utf-8")
    elif payload.data_base64 is not None:
        try:
            raw_data = base64.b64decode(payload.data_base64)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Dữ liệu 'data_base64' không hợp lệ: {str(e)}",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bắt buộc phải cung cấp một trong hai trường: 'plaintext' hoặc 'data_base64'.",
        )

    hsm = HSMService.get_instance()
    ciphertext = hsm.encrypt(
        key_label=payload.key_label,
        data=raw_data,
        mechanism_type=payload.mechanism.value,
    )

    return EncryptResponse(
        success=True,
        key_label=payload.key_label,
        ciphertext_base64=base64.b64encode(ciphertext).decode("utf-8"),
        mechanism=payload.mechanism.value,
    )


@app.post(
    "/api/v1/hsm/decrypt",
    response_model=DecryptResponse,
    summary="Giải mã dữ liệu bảo mật bằng Private Key",
    tags=["Encryption & Decryption"],
)
async def decrypt_data(
    payload: DecryptRequest,
    _: Annotated[str, Depends(verify_api_key)],
):
    """
    Giải mã dữ liệu bằng Private Key bảo vệ trong Token:
    - Thao tác giải mã diễn ra hoàn toàn bên trong ranh giới bảo mật của HSM.
    - Khóa riêng không bao giờ rời khỏi bộ nhớ an toàn.
    """
    try:
        cipher_bytes = base64.b64decode(payload.ciphertext_base64)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Trường 'ciphertext_base64' không đúng định dạng Base64: {str(e)}",
        )

    hsm = HSMService.get_instance()
    plaintext_bytes = hsm.decrypt(
        key_label=payload.key_label,
        ciphertext=cipher_bytes,
        mechanism_type=payload.mechanism.value,
    )

    result_str = None
    if payload.return_as_string:
        try:
            result_str = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            result_str = None

    return DecryptResponse(
        success=True,
        key_label=payload.key_label,
        plaintext=result_str,
        data_base64=base64.b64encode(plaintext_bytes).decode("utf-8"),
    )


# ---------------------------------------------------------------------------
# 4. Digital Signatures & Verification (Ký số và xác thực chữ ký số)
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/hsm/sign",
    response_model=SignResponse,
    summary="Ký số văn bản / Hợp đồng / Hóa đơn / Chuỗi băm giao dịch",
    tags=["Digital Signatures & Verification"],
)
async def sign_data(
    payload: SignRequest,
    _: Annotated[str, Depends(verify_api_key)],
):
    """
    Tạo chữ ký số điện tử bằng Private Key trong HSM:
    - Hỗ trợ ký trên toàn văn bản hoặc ký trên giá trị băm (Hash SHA-256).
    - Hỗ trợ thuật toán RSA (PKCS#1 v1.5 + SHA-256) hoặc ECDSA.
    - Ứng dụng: Ký số Hóa đơn điện tử, Hợp đồng kinh tế, Xác thực Webhook, Token xác thực phiên.
    """
    if payload.data is not None:
        raw_data = payload.data.encode("utf-8")
    elif payload.data_base64 is not None:
        try:
            raw_data = base64.b64decode(payload.data_base64)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Dữ liệu 'data_base64' không hợp lệ: {str(e)}",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bắt buộc phải cung cấp 'data' hoặc 'data_base64'.",
        )

    hsm = HSMService.get_instance()
    signature_bytes, mech_used = hsm.sign(
        key_label=payload.key_label,
        data=raw_data,
        is_prehashed=payload.is_prehashed,
        mechanism_type=payload.mechanism.value,
    )

    return SignResponse(
        success=True,
        key_label=payload.key_label,
        signature_base64=base64.b64encode(signature_bytes).decode("utf-8"),
        mechanism=mech_used,
    )


@app.post(
    "/api/v1/hsm/verify",
    response_model=VerifyResponse,
    summary="Xác thực chữ ký số bằng Public Key",
    tags=["Digital Signatures & Verification"],
)
async def verify_signature(
    payload: VerifyRequest,
    _: Annotated[str, Depends(verify_api_key)],
):
    """
    Kiểm tra tính toàn vẹn và nguồn gốc của dữ liệu:
    - Đối chiếu văn bản gốc và chữ ký số được cấp bởi Token.
    - Đảm bảo dữ liệu không bị sửa đổi bởi bên thứ ba (Chống chối bỏ).
    """
    if payload.data is not None:
        raw_data = payload.data.encode("utf-8")
    elif payload.data_base64 is not None:
        try:
            raw_data = base64.b64decode(payload.data_base64)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Dữ liệu 'data_base64' không hợp lệ: {str(e)}",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bắt buộc phải cung cấp 'data' hoặc 'data_base64'.",
        )

    try:
        sig_bytes = base64.b64decode(payload.signature_base64)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Chữ ký 'signature_base64' không đúng định dạng Base64: {str(e)}",
        )

    hsm = HSMService.get_instance()
    is_valid = hsm.verify(
        key_label=payload.key_label,
        data=raw_data,
        signature=sig_bytes,
        is_prehashed=payload.is_prehashed,
        mechanism_type=payload.mechanism.value,
    )

    msg = "Chữ ký số hợp lệ và toàn vẹn." if is_valid else "Chữ ký số KHÔNG hợp lệ hoặc văn bản đã bị sửa đổi."
    return VerifyResponse(
        valid=is_valid,
        key_label=payload.key_label,
        message=msg,
    )
