# CTF Writeups

Walkthroughs of CTF boxes and labs (TryHackMe, Hack The Box, etc.), written up from raw session logs: recon → foothold → flag, with the dead ends left in.

- [TryHackMe — Include](CTF/Include/include.thm.en.md) — two web apps, one chain: Mass Assignment → SSRF on the Node.js portal leaks creds for the SysMon PHP app, then LFI + SSH log poisoning via paramiko → webshell → RCE.
