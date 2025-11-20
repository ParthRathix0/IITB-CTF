# IITB CTF 2025 — Writeups

Solutions and detailed writeups for challenges solved during **TrustCTF 2025** (IITB CTF).

---

## Quick Overview

### Cryptography
- **[NOOb Randomness](./NOOb_Randomness.md)** — Known-plaintext attack on a weak byte-wide LCG stream cipher

### Reverse Engineering  
- **[GOREY](./GOREY.md)** — Go binary maze solver with non-standard movement (±2 steps)

### API Security
- **[Secure API](./Secure_API.md)** — HTTP Parameter Pollution exploit to bypass authorization and access admin balance

### Data Privacy
- **[Breached](./Breached.md)** — Database enumeration and HMAC-based flag recovery from breached admin account

---

## Tools Used

- **Ghidra** — Binary decompilation and reverse engineering
- **Python 3** — Scripting, cryptanalysis, maze solving (BFS), CSV parsing, HTTP requests, HMAC computation
- **curl** — API testing, exploitation, and database downloads
- **strings** — Binary analysis and maze data extraction
- **bash/sed/grep** — Input formatting, text processing, and automation scripting

---

## License

See [LICENSE](./LICENSE) for details.
