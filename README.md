# CTF Writeups & Articles

A collection of penetration testing writeups and security articles, built on lab-based walkthroughs.

**[Articles](Articles/)** — theory-then-practice series:

- [LFI](Articles/LFI%20Articles/) — File Inclusion: `str_replace` bypasses, php://filter mechanics, filter chains, LFI → RCE.
- [JWT](Articles/JWT%20Articles/) — JSON Web Tokens: fundamentals, weak-secret brute-forcing, header-parameter injection, algorithm confusion.

**[CTF](CTF/)** — box walkthroughs:

- [TryHackMe — Include](CTF/Include/include.thm.en.md) — two web apps, one chain: Mass Assignment → SSRF on the Node.js portal leaks creds for the SysMon PHP app, then LFI + SSH log poisoning via paramiko → webshell → RCE.

---

*More articles and writeups will be added as time goes on.*
