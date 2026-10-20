import hashlib
import logging
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List

import PyKCS11
from PyKCS11.LowLevel import CKR_OK
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from app.config import settings

logger = logging.getLogger("hsm_service")
logging.basicConfig(level=settings.LOG_LEVEL)

# OID DER Encoded Constants cho Elliptic Curve
OID_SECP256R1_DER = bytes([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
OID_SECP256K1_DER = bytes([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A])

# ASN.1 DigestInfo prefix cho SHA-256 (dùng khi ký dữ liệu đã băm sẵn qua CKM_RSA_PKCS)
SHA256_DIGEST_INFO_PREFIX = bytes([
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
])


class HSMServiceException(Exception):
    """Lỗi nghiệp vụ của HSM Wrapper"""
    pass


class HSMKeyNotFoundException(HSMServiceException):
    """Không tìm thấy khóa theo nhãn chỉ định"""
    pass


class HSMKeyAlreadyExistsException(HSMServiceException):
    """Khóa với nhãn chỉ định đã tồn tại trong Token"""
    pass


class HSMService:
    """
    Quản lý kết nối và thao tác mật mã với SoftHSMv2 qua thư viện PKCS#11.
    Sử dụng Thread Lock để đảm bảo an toàn tuyệt đối khi xử lý nhiều request đồng thời.
    """
    _instance: Optional["HSMService"] = None
    _lock = threading.RLock()

    def __init__(self):
        self.lib_path = settings.resolve_hsm_lib_path()
        self.token_label = settings.HSM_TOKEN_LABEL
        self.pin = settings.HSM_PIN
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self._is_loaded = False
        self._slot_id: Optional[int] = None
        self._init_library()

    @classmethod
    def get_instance(cls) -> "HSMService":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _init_library(self):
        """Khởi tạo và nạp thư viện libsofthsm2.so"""
        try:
            logger.info("Đang nạp thư viện PKCS#11 từ: %s", self.lib_path)
            self.pkcs11.load(self.lib_path)
            self._is_loaded = True
            self._refresh_slot()
            logger.info("Nạp thư viện SoftHSMv2 thành công. Token slot ID: %s", self._slot_id)
        except Exception as e:
            logger.error("Không thể nạp thư viện SoftHSMv2: %s", str(e), exc_info=True)
            self._is_loaded = False

    def _refresh_slot(self) -> Optional[int]:
        """Tìm slot chứa token tương ứng với nhãn HSM_TOKEN_LABEL"""
        if not self._is_loaded:
            return None

        try:
            slots = self.pkcs11.getSlotList(tokenPresent=True)
            for slot in slots:
                try:
                    info = self.pkcs11.getTokenInfo(slot)
                    label = info.label.strip()
                    if label == self.token_label:
                        self._slot_id = slot
                        return slot
                except Exception:
                    continue
        except Exception as e:
            logger.warning("Lỗi khi quét danh sách slot: %s", str(e))

        return None

    @contextmanager
    def get_session(self, rw: bool = True, login: bool = True):
        """
        Context Manager mở session an toàn và tự động đóng/đăng xuất khi kết thúc.
        Sử dụng Thread Lock để ngăn ngừa xung đột trạng thái PKCS#11 ở tầng C.
        """
        with self._lock:
            if not self._is_loaded:
                self._init_library()
                if not self._is_loaded:
                    raise HSMServiceException("Thư viện SoftHSMv2 chưa được nạp hoặc đường dẫn không đúng.")

            slot = self._slot_id or self._refresh_slot()
            if slot is None:
                raise HSMServiceException(
                    f"Không tìm thấy slot chứa Token có nhãn '{self.token_label}'. "
                    f"Vui lòng kiểm tra script khởi tạo SoftHSM."
                )

            flags = PyKCS11.CKF_SERIAL_SESSION
            if rw:
                flags |= PyKCS11.CKF_RW_SESSION

            session = None
            try:
                session = self.pkcs11.openSession(slot, flags)
                if login:
                    session.login(self.pin)
                yield session
            except PyKCS11.PyKCS11Error as pe:
                logger.error("Lỗi PyKCS11 trong session: %s", str(pe))
                raise HSMServiceException(f"Lỗi phần cứng mã hóa SoftHSMv2: {str(pe)}") from pe
            finally:
                if session is not None:
                    try:
                        if login:
                            session.logout()
                    except Exception:
                        pass
                    try:
                        session.closeSession()
                    except Exception:
                        pass

    def check_health(self) -> Dict[str, Any]:
        """Kiểm tra sức khỏe của dịch vụ và trạng thái Token SoftHSMv2"""
        with self._lock:
            status = "healthy"
            slot = self._slot_id or self._refresh_slot()
            token_initialized = slot is not None
            details: Dict[str, Any] = {}

            if not self._is_loaded or slot is None:
                status = "unhealthy"

            if slot is not None:
                try:
                    token_info = self.pkcs11.getTokenInfo(slot)
                    details = {
                        "label": token_info.label.strip(),
                        "manufacturerID": token_info.manufacturerID.strip(),
                        "model": token_info.model.strip(),
                        "serialNumber": token_info.serialNumber.strip(),
                        "hardwareVersion": f"{token_info.hardwareVersion.major}.{token_info.hardwareVersion.minor}",
                        "firmwareVersion": f"{token_info.firmwareVersion.major}.{token_info.firmwareVersion.minor}",
                    }
                except Exception as e:
                    status = "degraded"
                    details["error"] = str(e)

            return {
                "status": status,
                "hsm_library": self.lib_path,
                "token_label": self.token_label,
                "slot_id": slot,
                "token_initialized": token_initialized,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": details,
            }

    def _find_key_objects(
        self, session, key_label: str, key_class: Optional[int] = None
    ) -> List[Any]:
        """Tìm các đối tượng khóa trong token theo nhãn và loại khóa"""
        template = [(PyKCS11.CKA_LABEL, key_label)]
        if key_class is not None:
            template.append((PyKCS11.CKA_CLASS, key_class))
        return session.findObjects(template)

    def list_keys(self, prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Liệt kê tất cả các khóa lưu trong Token.
        Hỗ trợ lọc theo tiền tố (namespace) để tách biệt nhiều dự án (vd: prefix="crm:").
        """
        with self.get_session(rw=False, login=True) as session:
            pub_keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])
            priv_keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])

            keys_map: Dict[str, Dict[str, Any]] = {}

            for pub in pub_keys:
                try:
                    attrs = session.getAttributeValue(pub, [
                        PyKCS11.CKA_LABEL,
                        PyKCS11.CKA_KEY_TYPE,
                        PyKCS11.CKA_ENCRYPT,
                        PyKCS11.CKA_VERIFY,
                    ])
                    label = attrs[0]
                    if not label:
                        continue
                    if prefix and not label.startswith(prefix):
                        continue

                    key_type_val = attrs[1]
                    key_type = "RSA" if key_type_val == PyKCS11.CKK_RSA else ("ECDSA" if key_type_val == PyKCS11.CKK_ECDSA else "UNKNOWN")

                    key_size = None
                    if key_type == "RSA":
                        try:
                            mod_attrs = session.getAttributeValue(pub, [PyKCS11.CKA_MODULUS_BITS])
                            key_size = mod_attrs[0]
                        except Exception:
                            pass

                    keys_map[label] = {
                        "key_label": label,
                        "key_type": key_type,
                        "key_size": key_size,
                        "has_public_key": True,
                        "has_private_key": False,
                        "can_encrypt": bool(attrs[2]),
                        "can_verify": bool(attrs[3]),
                        "can_decrypt": False,
                        "can_sign": False,
                    }
                except Exception:
                    continue

            for priv in priv_keys:
                try:
                    attrs = session.getAttributeValue(priv, [
                        PyKCS11.CKA_LABEL,
                        PyKCS11.CKA_KEY_TYPE,
                        PyKCS11.CKA_DECRYPT,
                        PyKCS11.CKA_SIGN,
                    ])
                    label = attrs[0]
                    if not label:
                        continue
                    if prefix and not label.startswith(prefix):
                        continue

                    if label in keys_map:
                        keys_map[label]["has_private_key"] = True
                        keys_map[label]["can_decrypt"] = bool(attrs[2])
                        keys_map[label]["can_sign"] = bool(attrs[3])
                    else:
                        key_type_val = attrs[1]
                        key_type = "RSA" if key_type_val == PyKCS11.CKK_RSA else ("ECDSA" if key_type_val == PyKCS11.CKK_ECDSA else "UNKNOWN")
                        keys_map[label] = {
                            "key_label": label,
                            "key_type": key_type,
                            "key_size": None,
                            "has_public_key": False,
                            "has_private_key": True,
                            "can_encrypt": False,
                            "can_verify": False,
                            "can_decrypt": bool(attrs[2]),
                            "can_sign": bool(attrs[3]),
                        }
                except Exception:
                    continue

            return list(keys_map.values())

    def get_key_info(self, key_label: str) -> Dict[str, Any]:
        """Lấy thông tin chi tiết và tính năng của một khóa cụ thể"""
        keys = self.list_keys()
        for k in keys:
            if k["key_label"] == key_label:
                return k
        raise HSMKeyNotFoundException(f"Không tìm thấy khóa với nhãn '{key_label}'.")

    def delete_keypair(self, key_label: str) -> int:
        """
        Xóa vĩnh viễn cặp khóa (Public & Private) trong Token theo nhãn chỉ định.
        Trả về số đối tượng đã bị xóa.
        """
        with self.get_session(rw=True, login=True) as session:
            objects = self._find_key_objects(session, key_label)
            if not objects:
                raise HSMKeyNotFoundException(f"Không tìm thấy khóa với nhãn '{key_label}' để xóa.")

            deleted_count = 0
            for obj in objects:
                try:
                    session.destroyObject(obj)
                    deleted_count += 1
                except PyKCS11.PyKCS11Error as pe:
                    logger.warning("Không thể xóa đối tượng khóa %s: %s", key_label, str(pe))

            return deleted_count

    # -----------------------------------------------------------------------
    # 1. Sinh cặp khóa RSA / ECDSA
    # -----------------------------------------------------------------------
    def generate_keypair(
        self, key_label: str, key_type: str = "RSA", key_size: int = 2048, curve: str = "secp256r1"
    ) -> Tuple[str, Optional[str]]:
        """
        Sinh cặp khóa bảo mật (RSA hoặc ECDSA) lưu trữ vĩnh viễn trong Token SoftHSM.
        Khóa riêng (Private Key) được đánh dấu CKA_SENSITIVE=True, CKA_EXTRACTABLE=False.
        """
        with self.get_session(rw=True, login=True) as session:
            # Kiểm tra xem nhãn khóa đã tồn tại hay chưa
            existing = self._find_key_objects(session, key_label)
            if existing:
                raise HSMKeyAlreadyExistsException(f"Khóa với nhãn '{key_label}' đã tồn tại trong token.")

            if key_type.upper() == "RSA":
                # Template khóa công khai RSA
                pub_template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                    (PyKCS11.CKA_LABEL, key_label),
                    (PyKCS11.CKA_ENCRYPT, True),
                    (PyKCS11.CKA_VERIFY, True),
                    (PyKCS11.CKA_WRAP, True),
                    (PyKCS11.CKA_TOKEN, True),
                    (PyKCS11.CKA_MODULUS_BITS, key_size),
                    (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),  # 65537
                ]

                # Template khóa riêng tư RSA (Không cho trích xuất ra ngoài)
                priv_template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                    (PyKCS11.CKA_LABEL, key_label),
                    (PyKCS11.CKA_DECRYPT, True),
                    (PyKCS11.CKA_SIGN, True),
                    (PyKCS11.CKA_UNWRAP, True),
                    (PyKCS11.CKA_TOKEN, True),
                    (PyKCS11.CKA_PRIVATE, True),
                    (PyKCS11.CKA_SENSITIVE, True),
                    (PyKCS11.CKA_EXTRACTABLE, False),
                ]

                pub_key, _ = session.generateKeyPair(
                    pub_template, priv_template, PyKCS11.CKM_RSA_PKCS_KEY_PAIR_GEN
                )
                pem_str = self._rsa_pub_to_pem(session, pub_key)
                return "RSA", pem_str

            elif key_type.upper() == "ECDSA":
                curve_lower = curve.lower()
                if "k1" in curve_lower:
                    oid_bytes = OID_SECP256K1_DER
                else:
                    oid_bytes = OID_SECP256R1_DER

                pub_template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                    (PyKCS11.CKA_LABEL, key_label),
                    (PyKCS11.CKA_VERIFY, True),
                    (PyKCS11.CKA_TOKEN, True),
                    (PyKCS11.CKA_EC_PARAMS, list(oid_bytes)),
                ]

                priv_template = [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                    (PyKCS11.CKA_LABEL, key_label),
                    (PyKCS11.CKA_SIGN, True),
                    (PyKCS11.CKA_TOKEN, True),
                    (PyKCS11.CKA_PRIVATE, True),
                    (PyKCS11.CKA_SENSITIVE, True),
                    (PyKCS11.CKA_EXTRACTABLE, False),
                ]

                pub_key, _ = session.generateKeyPair(
                    pub_template, priv_template, PyKCS11.CKM_EC_KEY_PAIR_GEN
                )
                pem_str = self._ec_pub_to_pem(session, pub_key, curve_lower)
                return "ECDSA", pem_str

            else:
                raise HSMServiceException(f"Loại thuật toán khóa '{key_type}' không được hỗ trợ (chỉ RSA hoặc ECDSA).")

    # -----------------------------------------------------------------------
    # 2. Xuất Public Key PEM
    # -----------------------------------------------------------------------
    def get_public_key_pem(self, key_label: str) -> Tuple[str, str]:
        """Đọc và xuất Public Key lưu trong Token ra định dạng chuẩn PEM X.509"""
        with self.get_session(rw=False, login=True) as session:
            keys = self._find_key_objects(session, key_label, PyKCS11.CKO_PUBLIC_KEY)
            if not keys:
                raise HSMKeyNotFoundException(f"Không tìm thấy Public Key với nhãn '{key_label}'.")

            pub_obj = keys[0]
            attrs = session.getAttributeValue(pub_obj, [PyKCS11.CKA_KEY_TYPE])
            key_type_val = attrs[0]

            if key_type_val == PyKCS11.CKK_RSA:
                pem = self._rsa_pub_to_pem(session, pub_obj)
                return "RSA", pem
            elif key_type_val == PyKCS11.CKK_ECDSA:
                pem = self._ec_pub_to_pem(session, pub_obj, "secp256r1")
                return "ECDSA", pem
            else:
                raise HSMServiceException(f"Khóa loại ID {key_type_val} không hỗ trợ xuất PEM.")

    def _rsa_pub_to_pem(self, session, pub_obj) -> str:
        """Chuyển đổi RSA Public Key trong PKCS#11 sang chuỗi PEM"""
        attrs = session.getAttributeValue(
            pub_obj, [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT]
        )
        modulus_bytes = bytes(attrs[0])
        exponent_bytes = bytes(attrs[1])

        n = int.from_bytes(modulus_bytes, byteorder="big")
        e = int.from_bytes(exponent_bytes, byteorder="big")

        public_numbers = rsa.RSAPublicNumbers(e, n)
        pub_key = public_numbers.public_key()
        pem_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    def _ec_pub_to_pem(self, session, pub_obj, curve_name: str) -> str:
        """Chuyển đổi EC Public Key trong PKCS#11 sang chuỗi PEM"""
        attrs = session.getAttributeValue(pub_obj, [PyKCS11.CKA_EC_POINT])
        point_raw = bytes(attrs[0])

        # SoftHSMv2 trả về EC Point bọc trong ASN.1 OCTET STRING (Tag 0x04)
        if point_raw.startswith(b"\x04") and len(point_raw) > 2 and point_raw[1] == len(point_raw) - 2:
            point_data = point_raw[2:]
        else:
            point_data = point_raw

        chosen_curve = ec.SECP256K1() if "k1" in curve_name else ec.SECP256R1()
        ec_key = ec.EllipticCurvePublicKey.from_encoded_point(chosen_curve, point_data)
        pem_bytes = ec_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    # -----------------------------------------------------------------------
    # 3. Mã hóa (Niêm phong giá thầu)
    # -----------------------------------------------------------------------
    def encrypt(
        self, key_label: str, data: bytes, mechanism_type: str = "RSA_PKCS1"
    ) -> bytes:
        """
        Niêm phong (mã hóa) dữ liệu giá thầu bằng Public Key.
        Hỗ trợ RSA PKCS#1 v1.5 hoặc RSA OAEP với SHA-256.
        """
        with self.get_session(rw=False, login=True) as session:
            keys = self._find_key_objects(session, key_label, PyKCS11.CKO_PUBLIC_KEY)
            if not keys:
                raise HSMKeyNotFoundException(f"Không tìm thấy Public Key '{key_label}' để mã hóa.")

            pub_obj = keys[0]

            if mechanism_type == "RSA_PKCS_OAEP":
                oaep_params = PyKCS11.CK_RSA_PKCS_OAEP_PARAMS(
                    PyKCS11.CKM_SHA256,
                    PyKCS11.CKG_MGF1_SHA256,
                    PyKCS11.CKZ_DATA_SPECIFIED,
                    None,
                )
                mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_OAEP, oaep_params)
            else:
                mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)

            ciphertext_list = session.encrypt(pub_obj, list(data), mechanism)
            return bytes(ciphertext_list)

    # -----------------------------------------------------------------------
    # 4. Giải mã (Mở niêm phong giá thầu)
    # -----------------------------------------------------------------------
    def decrypt(
        self, key_label: str, ciphertext: bytes, mechanism_type: str = "RSA_PKCS1"
    ) -> bytes:
        """
        Mở niêm phong (giải mã) giá thầu khi phiên kết thúc bằng Private Key trong HSM.
        Khóa riêng không bao giờ rời khỏi môi trường bảo vệ của HSM.
        """
        with self.get_session(rw=False, login=True) as session:
            keys = self._find_key_objects(session, key_label, PyKCS11.CKO_PRIVATE_KEY)
            if not keys:
                raise HSMKeyNotFoundException(f"Không tìm thấy Private Key '{key_label}' để giải mã.")

            priv_obj = keys[0]

            if mechanism_type == "RSA_PKCS_OAEP":
                oaep_params = PyKCS11.CK_RSA_PKCS_OAEP_PARAMS(
                    PyKCS11.CKM_SHA256,
                    PyKCS11.CKG_MGF1_SHA256,
                    PyKCS11.CKZ_DATA_SPECIFIED,
                    None,
                )
                mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_OAEP, oaep_params)
            else:
                mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)

            plaintext_list = session.decrypt(priv_obj, list(ciphertext), mechanism)
            return bytes(plaintext_list)

    # -----------------------------------------------------------------------
    # 5. Ký số (Hợp đồng / Giao dịch chuyển nhượng SIM)
    # -----------------------------------------------------------------------
    def sign(
        self,
        key_label: str,
        data: bytes,
        is_prehashed: bool = False,
        mechanism_type: str = "AUTO",
    ) -> Tuple[bytes, str]:
        """
        Ký số văn bản hoặc chuỗi băm hợp đồng chuyển nhượng SIM bằng Private Key trong Token.
        """
        with self.get_session(rw=False, login=True) as session:
            keys = self._find_key_objects(session, key_label, PyKCS11.CKO_PRIVATE_KEY)
            if not keys:
                raise HSMKeyNotFoundException(f"Không tìm thấy Private Key '{key_label}' để ký số.")

            priv_obj = keys[0]
            attrs = session.getAttributeValue(priv_obj, [PyKCS11.CKA_KEY_TYPE])
            key_type_val = attrs[0]

            if key_type_val == PyKCS11.CKK_RSA:
                if is_prehashed:
                    # Nếu đã là SHA-256 hash (32 bytes), gắn tiền tố DigestInfo và ký qua CKM_RSA_PKCS
                    if len(data) != 32:
                        raise HSMServiceException("Dữ liệu băm SHA-256 phải đúng chính xác 32 bytes.")
                    tbs = SHA256_DIGEST_INFO_PREFIX + data
                    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
                    mech_name = "SHA256_RSA_PKCS"
                else:
                    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
                    tbs = data
                    mech_name = "SHA256_RSA_PKCS"

                signature_list = session.sign(priv_obj, list(tbs), mechanism)
                return bytes(signature_list), mech_name

            elif key_type_val == PyKCS11.CKK_ECDSA:
                # Với ECDSA trong PKCS#11, ký trên chuỗi băm 32 bytes
                if not is_prehashed:
                    digest = hashlib.sha256(data).digest()
                else:
                    digest = data
                    if len(digest) != 32:
                        raise HSMServiceException("Dữ liệu băm SHA-256 cho ECDSA phải có độ dài 32 bytes.")

                mechanism = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)
                signature_list = session.sign(priv_obj, list(digest), mechanism)
                return bytes(signature_list), "ECDSA_SHA256"

            else:
                raise HSMServiceException(f"Thuật toán khóa ID {key_type_val} không hỗ trợ ký số.")

    # -----------------------------------------------------------------------
    # 6. Xác thực chữ ký số (Verify)
    # -----------------------------------------------------------------------
    def verify(
        self,
        key_label: str,
        data: bytes,
        signature: bytes,
        is_prehashed: bool = False,
        mechanism_type: str = "AUTO",
    ) -> bool:
        """
        Xác thực chữ ký số bằng Public Key trong HSM.
        Trả về True nếu chữ ký hợp lệ, False nếu không hợp lệ hoặc dữ liệu bị sửa đổi.
        """
        with self.get_session(rw=False, login=True) as session:
            keys = self._find_key_objects(session, key_label, PyKCS11.CKO_PUBLIC_KEY)
            if not keys:
                raise HSMKeyNotFoundException(f"Không tìm thấy Public Key '{key_label}' để xác thực.")

            pub_obj = keys[0]
            attrs = session.getAttributeValue(pub_obj, [PyKCS11.CKA_KEY_TYPE])
            key_type_val = attrs[0]

            try:
                if key_type_val == PyKCS11.CKK_RSA:
                    if is_prehashed:
                        if len(data) != 32:
                            raise HSMServiceException("Dữ liệu băm SHA-256 phải đúng chính xác 32 bytes.")
                        tbv = SHA256_DIGEST_INFO_PREFIX + data
                        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
                    else:
                        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
                        tbv = data

                    session.verify(pub_obj, list(tbv), list(signature), mechanism)
                    return True

                elif key_type_val == PyKCS11.CKK_ECDSA:
                    if not is_prehashed:
                        digest = hashlib.sha256(data).digest()
                    else:
                        digest = data
                        if len(digest) != 32:
                            raise HSMServiceException("Dữ liệu băm cho ECDSA phải có độ dài 32 bytes.")

                    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)
                    session.verify(pub_obj, list(digest), list(signature), mechanism)
                    return True

                else:
                    raise HSMServiceException(f"Thuật toán khóa ID {key_type_val} không hỗ trợ xác thực.")

            except PyKCS11.PyKCS11Error as pe:
                # Nếu mã lỗi là CKR_SIGNATURE_INVALID nghĩa là chữ ký không khớp dữ liệu
                logger.warning("Chữ ký số không khớp hoặc không hợp lệ: %s", str(pe))
                return False
