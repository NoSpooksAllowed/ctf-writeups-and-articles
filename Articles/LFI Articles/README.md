# LFI Series

LFI / File Inclusion articles, based on the HTB Academy *File Inclusions* module and own lab logs.

- [Article — LFI: from theory to RCE](Articles/LFI%20Articles/Article%201/Article%201.md) — full walkthrough of the HTB Final Assessment: `str_replace` bypass, php.ini recon, include vs read, double URL-encoding, upload → predictable md5 name → webshell RCE.
- [Article 2 — php://filter in depth](Articles/LFI%20Articles/Article%202/Article%202.md) — wrapper mechanics, source-code disclosure, and LFI → RCE via PHP filter chains with `allow_url_include=Off` (THM Team lab).
