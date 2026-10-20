# Hướng Dẫn Tích Hợp Backend với Universal SoftHSMv2 Microservice
### *Developer Integration Guide: Digital Signatures, Encryption, Decryption & Key Management*

Tài liệu này hướng dẫn các kỹ sư Backend tích hợp hệ thống phần mềm của mình (Node.js, Python, Go, Java, C#,...) với **Universal Cloud SoftHSMv2 Microservice**.

---

## 📑 Mục lục
1. [Thông số kết nối & Xác thực](#1-thông-số-kết-nối--xác-thực)
2. [Chiến lược định danh khóa (Key Namespace Convention)](#2-chiến-lược-định-danh-khóa-key-namespace-convention)
3. [Client SDK Wrapper mẫu (Node.js, Python, Golang, C# .NET)](#3-client-sdk-wrapper-mẫu)
   - [3.1. Node.js / TypeScript (Native Fetch)](#31-nodejs--typescript-native-fetch)
   - [3.2. Python (Requests / Httpx)](#32-python-requests)
   - [3.3. Golang (net/http)](#33-golang-nethttp)
   - [3.4. C# / .NET 8 (HttpClient & Strongly Typed SDK)](#34-c--net-8-httpclient--strongly-typed-sdk)
4. [Các kịch bản nghiệp vụ thực tế (Integration Recipes)](#4-các-kịch-bản-nghiệp-vụ-thực-tế-integration-recipes)
   - [Kịch bản 1: Niêm phong và Mở niêm phong giá thầu / Dữ liệu bí mật](#kịch-bản-1-niêm-phong-và-mở-niêm-phong-giá-thầu--dữ-liệu-bí-mật)
   - [Kịch bản 2: Ký số Hợp đồng điện tử & Hóa đơn (e-Contract / e-Invoice)](#kịch-bản-2-ký-số-hợp-đồng-điện-tử--hóa-đơn-e-contract--e-invoice)
   - [Kịch bản 3: Mã hóa Envelope phía Client với Public Key PEM](#kịch-bản-3-mã-hóa-envelope-phía-client-với-public-key-pem)
   - [Kịch bản 4: Xác thực chữ ký số & Chống chối bỏ](#kịch-bản-4-xác-thực-chữ-ký-số--chống-chối-bỏ)
5. [Bảng mã lỗi & Xử lý sự cố (Error Handling & Resilience)](#5-bảng-mã-lỗi--xử-lý-sự-cố-error-handling--resilience)
6. [Checklist an toàn khi lên Production](#6-checklist-an-toàn-khi-lên-production)

---

## 1. Thông số kết nối & Xác thực

### 1.1. Cấu hình môi trường trong Backend của bạn
Trong file `.env` hoặc Secret Manager của ứng dụng backend, cấu hình 2 biến sau:

```env
# Địa chỉ URL của SoftHSM Microservice
HSM_BASE_URL=https://universal-crypto-softhsm.onrender.com

# API Key được cấp quyền truy cập
HSM_API_KEY=crypto-hsm-super-secret-key-change-me
```

### 1.2. HTTP Headers bắt buộc cho mọi Request
Mọi yêu cầu gửi tới các endpoint `/api/v1/hsm/*` đều phải đính kèm Header:

```http
Content-Type: application/json
X-API-Key: <GIÁ_TRỊ_HSM_API_KEY>
```

> **Ghi chú**: Endpoint `/health` là endpoint công khai, không yêu cầu header `X-API-Key`.

---

## 2. Chiến lược định danh khóa (Key Namespace Convention)

Do service này được dùng chung cho nhiều dự án/microservices, backend của bạn **phải tuân thủ quy tắc tiền tố (prefix)** để không bị trùng lặp khóa:

### Cú pháp chuẩn:
```text
<tên_dự_án>:<phân_hệ_hoặc_module>:<tên_định_danh_khóa>
```

### Ví dụ thực tế:
- **Sàn Đấu Giá**: `auction:session-2026:sim-0988888888`
- **Hợp Đồng Điện Tử**: `contract:estate:contract-hd-9921`
- **Hóa Đơn Điện Tử**: `invoice:einvoice:master-rsa-2026`
- **Fintech / Ngân Hàng**: `fintech:tokenization:card-pan-rsa`

### Lợi ích:
Khi bạn gọi `GET /api/v1/hsm/keys?prefix=auction:`, hệ thống chỉ trả về danh sách các khóa thuộc dự án của bạn, đảm bảo tính cách ly tuyệt đối.

---

## 3. Client SDK Wrapper mẫu

### 3.1. Node.js / TypeScript (Native Fetch)

Lưu file thành `hsm-client.ts` hoặc `hsm-client.js`:

```typescript
export interface KeySummary {
  key_label: string;
  key_type: string;
  key_size?: number;
  has_public_key: boolean;
  has_private_key: boolean;
  can_encrypt: boolean;
  can_decrypt: boolean;
  can_sign: boolean;
  can_verify: boolean;
}

export class HsmClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl = process.env.HSM_BASE_URL, apiKey = process.env.HSM_API_KEY) {
    if (!baseUrl || !apiKey) {
      throw new Error("HSM_BASE_URL and HSM_API_KEY must be provided");
    }
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers = {
      "Content-Type": "application/json",
      "X-API-Key": this.apiKey,
      ...options.headers,
    };

    const response = await fetch(url, { ...options, headers });
    if (!response.ok) {
      const errBody = await response.text();
      throw new Error(`HSM Error [${response.status}] ${response.statusText}: ${errBody}`);
    }
    return response.json() as Promise<T>;
  }

  /** Kiểm tra trạng thái kết nối HSM */
  async health(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/health`);
    return res.json();
  }

  /** Sinh cặp khóa mới */
  async generateKeyPair(
    keyLabel: string,
    keyType: "RSA" | "ECDSA" = "RSA",
    keySize = 2048,
    curve = "secp256r1"
  ): Promise<{ success: boolean; key_label: string; public_key_pem: string }> {
    return this.request("/api/v1/hsm/generate-keypair", {
      method: "POST",
      body: JSON.stringify({ key_label: keyLabel, key_type: keyType, key_size: keySize, curve }),
    });
  }

  /** Lấy Public Key định dạng PEM */
  async getPublicKey(keyLabel: string): Promise<string> {
    const res = await this.request<{ public_key_pem: string }>(`/api/v1/hsm/public-key/${encodeURIComponent(keyLabel)}`);
    return res.public_key_pem;
  }

  /** Liệt kê danh sách khóa (hỗ trợ lọc theo tiền tố dự án) */
  async listKeys(prefix?: string): Promise<KeySummary[]> {
    const query = prefix ? `?prefix=${encodeURIComponent(prefix)}` : "";
    const res = await this.request<{ total: number; keys: KeySummary[] }>(`/api/v1/hsm/keys${query}`);
    return res.keys;
  }

  /** Mã hóa (Niêm phong dữ liệu) */
  async encrypt(keyLabel: string, plaintext: string, mechanism: "RSA_PKCS1" | "RSA_PKCS_OAEP" = "RSA_PKCS1"): Promise<string> {
    const res = await this.request<{ ciphertext_base64: string }>("/api/v1/hsm/encrypt", {
      method: "POST",
      body: JSON.stringify({ key_label: keyLabel, plaintext, mechanism }),
    });
    return res.ciphertext_base64;
  }

  /** Giải mã (Mở niêm phong dữ liệu) */
  async decrypt(keyLabel: string, ciphertextBase64: string, mechanism: "RSA_PKCS1" | "RSA_PKCS_OAEP" = "RSA_PKCS1"): Promise<string> {
    const res = await this.request<{ plaintext: string }>("/api/v1/hsm/decrypt", {
      method: "POST",
      body: JSON.stringify({ key_label: keyLabel, ciphertext_base64: ciphertextBase64, mechanism, return_as_string: true }),
    });
    return res.plaintext;
  }

  /** Ký số văn bản / payload giao dịch */
  async sign(keyLabel: string, data: string, isPrehashed = false): Promise<string> {
    const res = await this.request<{ signature_base64: string }>("/api/v1/hsm/sign", {
      method: "POST",
      body: JSON.stringify({ key_label: keyLabel, data, is_prehashed: isPrehashed, mechanism: "AUTO" }),
    });
    return res.signature_base64;
  }

  /** Xác thực chữ ký số */
  async verify(keyLabel: string, data: string, signatureBase64: string, isPrehashed = false): Promise<boolean> {
    const res = await this.request<{ valid: boolean }>("/api/v1/hsm/verify", {
      method: "POST",
      body: JSON.stringify({ key_label: keyLabel, data, signature_base64: signatureBase64, is_prehashed: isPrehashed, mechanism: "AUTO" }),
    });
    return res.valid;
  }

  /** Xóa cặp khóa */
  async deleteKey(keyLabel: string): Promise<boolean> {
    const res = await this.request<{ success: boolean }>(`/api/v1/hsm/keys/${encodeURIComponent(keyLabel)}`, {
      method: "DELETE",
    });
    return res.success;
  }
}
```

---

### 3.2. Python (Requests)

Lưu file thành `hsm_client.py`:

```python
import os
import requests
from typing import Optional, Dict, Any, List

class HsmClient:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or os.getenv("HSM_BASE_URL", "https://universal-crypto-softhsm.onrender.com")).rstrip("/")
        self.api_key = api_key or os.getenv("HSM_API_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "X-API-Key": self.api_key
        })

    def check_health(self) -> Dict[str, Any]:
        resp = requests.get(f"{self.base_url}/health", timeout=10)
        resp.raise_for_status()
        return resp.json()

    def generate_keypair(self, key_label: str, key_type: str = "RSA", key_size: int = 2048, curve: str = "secp256r1") -> Dict[str, Any]:
        resp = self.session.post(f"{self.base_url}/api/v1/hsm/generate-keypair", json={
            "key_label": key_label,
            "key_type": key_type,
            "key_size": key_size,
            "curve": curve
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def encrypt(self, key_label: str, plaintext: str, mechanism: str = "RSA_PKCS1") -> str:
        resp = self.session.post(f"{self.base_url}/api/v1/hsm/encrypt", json={
            "key_label": key_label,
            "plaintext": plaintext,
            "mechanism": mechanism
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()["ciphertext_base64"]

    def decrypt(self, key_label: str, ciphertext_base64: str, mechanism: str = "RSA_PKCS1") -> str:
        resp = self.session.post(f"{self.base_url}/api/v1/hsm/decrypt", json={
            "key_label": key_label,
            "ciphertext_base64": ciphertext_base64,
            "mechanism": mechanism,
            "return_as_string": True
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()["plaintext"]

    def sign(self, key_label: str, data: str) -> str:
        resp = self.session.post(f"{self.base_url}/api/v1/hsm/sign", json={
            "key_label": key_label,
            "data": data,
            "mechanism": "AUTO"
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()["signature_base64"]

    def verify(self, key_label: str, data: str, signature_base64: str) -> bool:
        resp = self.session.post(f"{self.base_url}/api/v1/hsm/verify", json={
            "key_label": key_label,
            "data": data,
            "signature_base64": signature_base64,
            "mechanism": "AUTO"
        }, timeout=15)
        resp.raise_for_status()
        return resp.json()["valid"]
```

---

### 3.3. Golang (net/http)

```go
package hsm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type HSMClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

func NewHSMClient(baseURL, apiKey string) *HSMClient {
	return &HSMClient{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *HSMClient) Sign(keyLabel, data string) (string, error) {
	payload := map[string]interface{}{
		"key_label": keyLabel,
		"data":      data,
		"mechanism": "AUTO",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", c.BaseURL+"/api/v1/hsm/sign", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HSM error status: %d", resp.StatusCode)
	}

	var res struct {
		SignatureBase64 string `json:"signature_base64"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	return res.SignatureBase64, nil
}
```

---

### 3.4. C# / .NET 8 (HttpClient & Strongly Typed SDK)

Lưu file thành `SoftHsmClient.cs` (Dùng cho ASP.NET Core Web API):

```csharp
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace TrustSimBackend.Infrastructure.Services.Hsm;

public class SoftHsmClient
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    public SoftHsmClient(HttpClient httpClient, string baseUrl, string apiKey)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
        _apiKey = apiKey;
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string path, object? body = null)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Add("X-API-Key", _apiKey);
        if (body != null)
        {
            req.Content = JsonContent.Create(body);
        }
        return req;
    }

    /// <summary>Sinh cặp khóa ECDSA (secp256r1) hoặc RSA</summary>
    public async Task<GenerateKeyResult> GenerateKeyPairAsync(
        string keyLabel, 
        string keyType = "ECDSA", 
        int keySize = 2048, 
        string curve = "secp256r1", 
        CancellationToken ct = default)
    {
        var req = CreateRequest(HttpMethod.Post, "api/v1/hsm/generate-keypair", new {
            key_label = keyLabel,
            key_type = keyType,
            key_size = keySize,
            curve = curve
        });
        using var res = await _httpClient.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        return (await res.Content.ReadFromJsonAsync<GenerateKeyResult>(cancellationToken: ct))!;
    }

    /// <summary>Ký số trên chuỗi băm Hex SHA-256 (64 ký tự hex) cho Sổ cái / Hợp đồng</summary>
    public async Task<string> SignHashHexAsync(string keyLabel, string hashHex, CancellationToken ct = default)
    {
        var req = CreateRequest(HttpMethod.Post, "api/v1/hsm/sign", new {
            key_label = keyLabel,
            data_hex = hashHex,
            is_prehashed = true,
            mechanism = "AUTO"
        });
        using var res = await _httpClient.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        var data = await res.Content.ReadFromJsonAsync<SignResult>(cancellationToken: ct);
        return data!.SignatureBase64;
    }

    /// <summary>Xác thực chữ ký số từ xa qua SoftHSM</summary>
    public async Task<bool> VerifySignatureAsync(
        string keyLabel, 
        string hashHex, 
        string signatureBase64, 
        CancellationToken ct = default)
    {
        var req = CreateRequest(HttpMethod.Post, "api/v1/hsm/verify", new {
            key_label = keyLabel,
            data_hex = hashHex,
            signature_base64 = signatureBase64,
            is_prehashed = true,
            mechanism = "AUTO"
        });
        using var res = await _httpClient.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        var data = await res.Content.ReadFromJsonAsync<VerifyResult>(cancellationToken: ct);
        return data!.Valid;
    }

    /// <summary>Lấy Public Key chuẩn PEM (Hỗ trợ Cache-Control)</summary>
    public async Task<string> GetPublicKeyPemAsync(string keyLabel, CancellationToken ct = default)
    {
        var req = CreateRequest(HttpMethod.Get, $"api/v1/hsm/public-key/{Uri.EscapeDataString(keyLabel)}");
        using var res = await _httpClient.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();
        var data = await res.Content.ReadFromJsonAsync<PublicKeyResult>(cancellationToken: ct);
        return data!.PublicKeyPem;
    }
}

public record GenerateKeyResult(
    [property: JsonPropertyName("success")] bool Success,
    [property: JsonPropertyName("key_label")] string KeyLabel,
    [property: JsonPropertyName("public_key_pem")] string PublicKeyPem);

public record SignResult(
    [property: JsonPropertyName("success")] bool Success,
    [property: JsonPropertyName("signature_base64")] string SignatureBase64);

public record VerifyResult(
    [property: JsonPropertyName("valid")] bool Valid);

public record PublicKeyResult(
    [property: JsonPropertyName("public_key_pem")] string PublicKeyPem);
```

---

## 4. Các kịch bản nghiệp vụ thực tế (Integration Recipes)

### Kịch bản 1: Niêm phong và Mở niêm phong giá thầu / Dữ liệu bí mật
*(Sealed-Bid Auction / Secret Voting / Sensitive PII)*

```
[Bắt đầu phiên] ──► Gọi HSM sinh khóa phiên: `auction:session-001:rsa`
                          │
[Người dùng đặt giá] ──► Gọi HSM Encrypt(`auction:session-001:rsa`, giá_thầu)
                          │ Lưu ciphertext_base64 vào MySQL/PostgreSQL
                          │ (Không ai đọc trộm được mức giá kể cả DBA)
                          ▼
[Hết giờ đấu giá] ──► Lấy ciphertext_base64 từ DB
                          │ Gọi HSM Decrypt(`auction:session-001:rsa`, ciphertext_base64)
                          ▼
               Công bố mức giá & xác định người thắng
```

#### Code Node.js minh họa:
```typescript
import { HsmClient } from "./hsm-client";

const hsm = new HsmClient();

// 1. Khi phiên mở: Tạo cặp khóa cho phiên đấu giá
async function onAuctionStart(sessionId: string) {
  const keyLabel = `auction:session-${sessionId}:key`;
  const key = await hsm.generateKeyPair(keyLabel, "RSA", 2048);
  console.log(`Đã tạo khóa phiên: ${key.key_label}`);
}

// 2. Khi người dùng đặt giá: Niêm phong giá thầu
async function placeSealedBid(sessionId: string, userId: string, amountVnd: number) {
  const keyLabel = `auction:session-${sessionId}:key`;
  const bidPayload = JSON.stringify({ userId, amountVnd, timestamp: new Date() });

  // Mã hóa với HSM
  const encryptedBid = await hsm.encrypt(keyLabel, bidPayload, "RSA_PKCS1");

  // Lưu encryptedBid vào database của bạn
  // await db.bids.create({ sessionId, encryptedData: encryptedBid });
  return encryptedBid;
}

// 3. Khi phiên kết thúc: Mở niêm phong
async function onAuctionEnd(sessionId: string, encryptedBids: string[]) {
  const keyLabel = `auction:session-${sessionId}:key`;
  const decryptedBids = [];

  for (const cipher of encryptedBids) {
    const rawJson = await hsm.decrypt(keyLabel, cipher);
    decryptedBids.push(JSON.parse(rawJson));
  }

  // Sắp xếp tìm người trả giá cao nhất
  decryptedBids.sort((a, b) => b.amountVnd - a.amountVnd);
  return decryptedBids[0]; // Người chiến thắng
}
```

---

### Kịch bản 2: Ký số Hợp đồng điện tử & Hóa đơn (e-Contract / e-Invoice)

```typescript
// Ký hợp đồng mua bán chuyển nhượng
async function signContract(contractId: string, contractContent: string) {
  const masterSignerKey = "contract:company:master-signing-key";

  // Gọi HSM để ký số
  const signatureBase64 = await hsm.sign(masterSignerKey, contractContent);

  // Lưu hợp đồng kèm chữ ký vào Database
  const savedContract = {
    contractId,
    content: contractContent,
    signature: signatureBase64,
    signedAt: new Date().toISOString(),
  };

  return savedContract;
}
```

---

### Kịch bản 3: Mã hóa Envelope phía Client với Public Key PEM

Nếu bạn muốn Client (trình duyệt Web hoặc ứng dụng Mobile Flutter/React Native) **tự mã hóa dữ liệu ngay trên thiết bị người dùng** trước khi gửi lên Backend:

1. **Backend** gọi HSM để lấy Public Key:
   ```typescript
   const pubKeyPem = await hsm.getPublicKey("auction:session-001:key");
   ```
2. **Backend trả `pubKeyPem` về cho Mobile/Web app**.
3. **Frontend mã hóa dữ liệu** bằng thư viện chuẩn (như `node-forge`, `jsencrypt` hoặc `Web Crypto API`).
4. **Backend nhận ciphertext gửi lên** -> chuyển thẳng tới endpoint `/api/v1/hsm/decrypt` để giải mã an toàn.

---

### Kịch bản 4: Xác thực chữ ký số & Chống chối bỏ

Khi đối tác hoặc bên thứ ba cần đối soát tính toàn vẹn của hợp đồng/giao dịch:

```typescript
async function verifyContractIntegrity(contractContent: string, signatureBase64: string): Promise<boolean> {
  const keyLabel = "contract:company:master-signing-key";

  const isValid = await hsm.verify(keyLabel, contractContent, signatureBase64);

  if (isValid) {
    console.log("✅ Hợp đồng hoàn toàn nguyên bản, chữ ký số chuẩn xác.");
  } else {
    console.warn("❌ CẢNH BÁO: Hợp đồng đã bị chỉnh sửa hoặc sai chữ ký!");
  }

  return isValid;
}
```

---

## 5. Bảng mã lỗi & Xử lý sự cố (Error Handling & Resilience)

| Mã lỗi HTTP | Tên lỗi | Nguyên nhân | Cách xử lý trong Backend |
|:---:|---|---|---|
| `401` | `Unauthorized` | Thiếu hoặc sai header `X-API-Key` | Kiểm tra lại biến `HSM_API_KEY` trong file `.env` |
| `404` | `KeyNotFound` | Không tìm thấy `key_label` chỉ định | Kiểm tra lại chính tả của nhãn khóa hoặc gọi `generateKeyPair` trước |
| `409` | `KeyAlreadyExists` | Cặp khóa với `key_label` này đã tồn tại | Tránh gọi sinh lại khóa trùng nhãn; hoặc xóa khóa cũ trước |
| `422` | `Unprocessable Entity` | Sai định dạng body JSON hoặc thiếu trường | Kiểm tra Pydantic payload |
| `500` | `HSMInternalError` | Lỗi tầng phần cứng ảo PKCS#11 | Xem chi tiết thông điệp `message` trả về từ JSON |

### Xử lý Cold Start khi deploy trên Cloud PaaS (Render Free Tier):
Nếu bạn chưa cấu hình Keep-Alive Cronjob, lượt gọi đầu tiên sau 15 phút không hoạt động có thể mất **40 - 50 giây**.
Backend của bạn nên thiết lập **Timeout tối thiểu 60 giây** và cơ chế **Retry (Thử lại 2 lần)**:

```typescript
// Cấu hình Timeout trong Axios
const client = axios.create({
  baseURL: process.env.HSM_BASE_URL,
  timeout: 60000, // 60s để vượt qua Cold Start
  headers: { "X-API-Key": process.env.HSM_API_KEY }
});
```

---

## 6. Checklist an toàn khi lên Production

- [ ] **Không hardcode API Key**: Luôn nạp `HSM_API_KEY` từ Environment Variables hoặc AWS Secrets Manager / GCP Secret Manager / Vault.
- [ ] **Sử dụng HTTPS**: Tuyệt đối không kết nối qua HTTP không mã hóa ở môi trường Production.
- [ ] **Chuẩn hóa Namespace Khóa**: Mọi team/module phải tuân thủ tiền tố `<du_an>:<module>:<key_id>`.
- [ ] **Giữ server luôn thức**: Cài đặt UptimeRobot ping `GET /health` mỗi 5 phút để loại bỏ 100% thời gian chờ Cold Start.
- [ ] **Định kỳ sao lưu dữ liệu Token**: Đảm bảo thư mục volume lưu trữ `/var/lib/softhsm/tokens` trên cloud được backup định kỳ.
