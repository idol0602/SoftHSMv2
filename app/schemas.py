from enum import Enum
from typing import Optional, Any, Dict, List
from pydantic import BaseModel, Field, field_validator


class KeyTypeEnum(str, Enum):
    RSA = "RSA"
    ECDSA = "ECDSA"


class RsaEncryptMechanismEnum(str, Enum):
    RSA_PKCS1 = "RSA_PKCS1"
    RSA_PKCS_OAEP = "RSA_PKCS_OAEP"


class SignMechanismEnum(str, Enum):
    AUTO = "AUTO"
    SHA256_RSA_PKCS = "SHA256_RSA_PKCS"
    ECDSA_SHA256 = "ECDSA_SHA256"


# ---------------------------------------------------------------------------
# 1. Health Models
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = Field(..., description="Trạng thái dịch vụ (healthy, degraded, error)")
    hsm_library: str = Field(..., description="Đường dẫn file thư viện PKCS#11 đang nạp")
    token_label: str = Field(..., description="Nhãn token đang kết nối")
    slot_id: Optional[int] = Field(None, description="ID của slot chứa token")
    token_initialized: bool = Field(..., description="Trạng thái khởi tạo của token")
    timestamp: str = Field(..., description="Thời gian kiểm tra ISO 8601")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Chi tiết phần cứng ảo/slot PKCS#11")


# ---------------------------------------------------------------------------
# 2. Key Management Models (Sinh khóa, Liệt kê, Chi tiết, Xóa khóa)
# ---------------------------------------------------------------------------
class GenerateKeyPairRequest(BaseModel):
    key_label: str = Field(
        ...,
        min_length=3,
        max_length=64,
        description="Định danh nhãn cặp khóa (hỗ trợ phân vùng namespace theo dự án, ví dụ: 'app-ecommerce:payment-key', 'contract-service:master-rsa', 'auction:session-01')",
        examples=["project-alpha:signing-key"]
    )
    key_type: KeyTypeEnum = Field(
        default=KeyTypeEnum.RSA,
        description="Loại thuật toán khóa: RSA hoặc ECDSA"
    )
    key_size: int = Field(
        default=2048,
        description="Độ dài khóa RSA (2048, 3072, 4096). Bỏ qua nếu là ECDSA."
    )
    curve: Optional[str] = Field(
        default="secp256r1",
        description="Tên đường cong Elliptic Curve nếu key_type là ECDSA (secp256r1, prime256v1, secp256k1)"
    )

    @field_validator("key_size")
    def validate_rsa_key_size(cls, v):
        valid_sizes = [2048, 3072, 4096]
        if v not in valid_sizes:
            raise ValueError(f"Độ dài khóa RSA không hợp lệ. Chỉ chấp nhận một trong các giá trị: {valid_sizes}")
        return v


class GenerateKeyPairResponse(BaseModel):
    success: bool
    message: str
    key_label: str
    key_type: str
    public_key_pem: Optional[str] = Field(None, description="Khóa công khai ở định dạng chuẩn PEM X.509 SubjectPublicKeyInfo")


class KeySummary(BaseModel):
    key_label: str = Field(..., description="Nhãn định danh của khóa")
    key_type: str = Field(..., description="Thuật toán khóa (RSA hoặc ECDSA)")
    key_size: Optional[int] = Field(None, description="Độ dài khóa tính theo bits (với RSA)")
    has_public_key: bool = Field(True, description="Có khóa công khai trong token hay không")
    has_private_key: bool = Field(True, description="Có khóa riêng tư trong token hay không")
    can_encrypt: bool = Field(False, description="Khóa hỗ trợ mã hóa")
    can_decrypt: bool = Field(False, description="Khóa hỗ trợ giải mã")
    can_sign: bool = Field(False, description="Khóa hỗ trợ ký số")
    can_verify: bool = Field(False, description="Khóa hỗ trợ xác thực chữ ký")


class KeyListResponse(BaseModel):
    total: int = Field(..., description="Tổng số khóa tìm thấy")
    keys: List[KeySummary] = Field(..., description="Danh sách các khóa")


class DeleteKeyResponse(BaseModel):
    success: bool
    key_label: str
    message: str
    deleted_objects_count: int = Field(..., description="Số đối tượng PKCS#11 (public/private) đã được xóa")


# ---------------------------------------------------------------------------
# 3. Encryption (Mã hóa dữ liệu / Niêm phong dữ liệu nhạy cảm) Models
# ---------------------------------------------------------------------------
class EncryptRequest(BaseModel):
    key_label: str = Field(..., description="Nhãn của khóa công khai dùng để mã hóa")
    plaintext: Optional[str] = Field(
        None,
        description="Dữ liệu văn bản hoặc chuỗi JSON cần mã hóa (UTF-8)",
        examples=['{"user_id": "U123", "secret_payload": "CONFIDENTIAL_DATA"}']
    )
    data_base64: Optional[str] = Field(
        None,
        description="Dữ liệu nhị phân tùy ý đã mã hóa Base64 (dùng nếu không truyền plaintext)"
    )
    mechanism: RsaEncryptMechanismEnum = Field(
        default=RsaEncryptMechanismEnum.RSA_PKCS1,
        description="Cơ chế đệm mã hóa RSA: RSA_PKCS1 (PKCS#1 v1.5) hoặc RSA_PKCS_OAEP (SHA-256 MGF1)"
    )


class EncryptResponse(BaseModel):
    success: bool
    key_label: str
    ciphertext_base64: str = Field(..., description="Bản mã dữ liệu ở định dạng Base64")
    mechanism: str


# ---------------------------------------------------------------------------
# 4. Decryption (Giải mã dữ liệu bảo mật) Models
# ---------------------------------------------------------------------------
class DecryptRequest(BaseModel):
    key_label: str = Field(..., description="Nhãn của khóa riêng trong HSM dùng để giải mã")
    ciphertext_base64: str = Field(..., description="Bản mã Base64 cần giải mã")
    mechanism: RsaEncryptMechanismEnum = Field(
        default=RsaEncryptMechanismEnum.RSA_PKCS1,
        description="Cơ chế đệm mã hóa đã dùng khi mã hóa"
    )
    return_as_string: bool = Field(
        default=True,
        description="Nếu True sẽ decode kết quả ra UTF-8 string; nếu False sẽ giữ nguyên nhị phân Base64"
    )


class DecryptResponse(BaseModel):
    success: bool
    key_label: str
    plaintext: Optional[str] = Field(None, description="Dữ liệu gốc giải mã dưới dạng chuỗi UTF-8")
    data_base64: Optional[str] = Field(None, description="Dữ liệu gốc dưới dạng Base64")


# ---------------------------------------------------------------------------
# 5. Sign (Ký số hợp đồng / Hóa đơn điện tử / Giao dịch) Models
# ---------------------------------------------------------------------------
class SignRequest(BaseModel):
    key_label: str = Field(..., description="Nhãn của khóa riêng trong HSM dùng để tạo chữ ký số")
    data: Optional[str] = Field(
        None,
        description="Nội dung văn bản, hợp đồng, hóa đơn điện tử hoặc payload giao dịch cần ký (chuỗi UTF-8)",
        examples=["HỢP ĐỒNG KINH TẾ SỐ #HD-2026-001..."]
    )
    data_base64: Optional[str] = Field(
        None,
        description="Dữ liệu nhị phân hoặc chuỗi băm (hash) cần ký dưới dạng Base64"
    )
    is_prehashed: bool = Field(
        default=False,
        description="Đặt True nếu data_base64 truyền vào đã là giá trị băm SHA-256 (32 bytes)"
    )
    mechanism: SignMechanismEnum = Field(
        default=SignMechanismEnum.AUTO,
        description="Cơ chế ký: AUTO, SHA256_RSA_PKCS hoặc ECDSA_SHA256"
    )


class SignResponse(BaseModel):
    success: bool
    key_label: str
    signature_base64: str = Field(..., description="Chữ ký số điện tử tạo bởi HSM ở định dạng Base64")
    mechanism: str


# ---------------------------------------------------------------------------
# 6. Verify (Xác thực chữ ký số) Models
# ---------------------------------------------------------------------------
class VerifyRequest(BaseModel):
    key_label: str = Field(..., description="Nhãn của khóa công khai dùng để xác thực")
    data: Optional[str] = Field(
        None,
        description="Nội dung văn bản, hợp đồng hoặc payload gốc cần đối soát (UTF-8)"
    )
    data_base64: Optional[str] = Field(
        None,
        description="Dữ liệu gốc hoặc chuỗi băm dạng Base64"
    )
    signature_base64: str = Field(..., description="Chữ ký số cần kiểm tra dạng Base64")
    is_prehashed: bool = Field(
        default=False,
        description="Đặt True nếu data_base64 truyền vào đã là giá trị băm SHA-256"
    )
    mechanism: SignMechanismEnum = Field(
        default=SignMechanismEnum.AUTO,
        description="Cơ chế kiểm tra chữ ký"
    )


class VerifyResponse(BaseModel):
    valid: bool = Field(..., description="Kết quả xác thực: True nếu hợp lệ, False nếu văn bản bị sửa đổi hoặc sai khóa")
    key_label: str
    message: str


# ---------------------------------------------------------------------------
# 7. Public Key Export Model
# ---------------------------------------------------------------------------
class PublicKeyResponse(BaseModel):
    key_label: str
    key_type: str
    public_key_pem: str = Field(..., description="Khóa công khai ở chuẩn PEM PKIX/X.509 SubjectPublicKeyInfo")
