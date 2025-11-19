
# NOOb Randomness — writeup

**Challenge:** NOOb_Randomness  
**CTF:** TrustCTF  
**Category:** Cryptography
**Flag:** `trustctf{y0u_d0nt_3v3n_n33d_2_b_sm4rt_4_th15}`


---

## Summary

This challenge implements a very small stream cipher-esque mask using a byte-wide linear recurrence of the form

s_{n+1} = (A * s_n + C) mod 256

The program masks plaintexts by XORing each plaintext byte with the generated keystream bytes. We are given:

- a known plaintext `msg1` and its ciphertext `ct1` (hex printed by the challenge)
- a second ciphertext `ct2` (of unknown plaintext)
- the target ciphertext `ct3` containing the flag, masked with the same keystream

Because the keystream is byte-wide and the recurrence is linear modulo 256, a short known-plaintext attack recovers the LCG constants A, C and the initial seed. Once recovered we reconstruct the keystream and recover the flag by XOR.

---

## Recon / Observations

- The provided program `challenge.py` uses a helper (`secret.get_secret_material()`) to obtain `msg1, msg2, flag, A, C, SEED` and prints:
  - `PLAIN1_HEX` (known plaintext)
  - `CIPH1_HEX`, `CIPH2_HEX`, `CIPH3_HEX` (ciphertexts)
- The mask implementation (from `challenge.py`) is:

```py
def _step(x, y, z):
	return (x * z + y) & 0xFF

def _mask_bytes(payload: bytes, x: int, y: int, seed: int) -> bytes:
	s = seed & 0xFF
	out = bytearray()
	for b in payload:
		s = _step(x, y, s)
		out.append(b ^ s)
	return bytes(out)
```

The recurrence is therefore s_{n+1} = (A * s_n + C) mod 256 (A and C are small integers in 0..255).

Key point: because the keystream depends only on the previous keystream byte (and A,C), and we know the keystream for the first N bytes (from known plaintext), we can recover A and C by solving the linear equations modulo 256.

---

## Math / Attack Idea

Let ks[n] be the keystream byte applied to plaintext byte n so that

ct[n] = pt[n] ^ ks[n]

From known plaintext and ciphertext we compute ks[n] = pt[n] ^ ct[n]. The recurrence is:

ks[n+1] = (A * ks[n] + C) mod 256

Thus, for three consecutive keystream bytes ks[i-1], ks[i], ks[i+1], we have

ks[i+1] = A * ks[i] + C  (mod 256)
ks[i]   = A * ks[i-1] + C  (mod 256)

Subtracting these two equations gives

(ks[i+1] - ks[i]) = A * (ks[i] - ks[i-1])  (mod 256)

So if d1 = (ks[i] - ks[i-1]) mod 256 and d2 = (ks[i+1] - ks[i]) mod 256 and d1 is invertible mod 256 (i.e. odd), then

A = d2 * d1^{-1} (mod 256)

Then C = ks[i] - A * ks[i-1] (mod 256).

Because multiplication modulo 256 is invertible only for odd d1, we scan through indices until we find a triple with invertible d1.

Once A and C are known, the seed is simply ks[0] (the first keystream value), and we can regenerate the keystream to decrypt `ct3`.

---

## Implementation (how I solved it)

1. Run the provided program (or use the provided `output.txt`) to copy the hex strings for `PLAIN1_HEX`, `CIPH1_HEX`, and `CIPH3_HEX`.

2. Compute the keystream bytes for the prefix: `ks = [p ^ c for p,c in zip(msg1, ct1)]`.

3. Find an index `i` such that `d1 = ks[i] - ks[i-1]` is odd (invertible mod 256). Compute A and C as described above.

4. Regenerate keystream starting from `seed = ks[0]` using `s = (A * s + C) % 256` and XOR with `ct3` to get the flag.

### Reference solver (the challenge bundle included a working `solve.py`)

The core of the solver (trimmed) is:

```py
ks = [m ^ c for m, c in zip(msg1, ct1)]

def inv_mod_256(a):
	if a % 2 == 0:
		return None
	for x in range(256):
		if (a * x) % 256 == 1:
			return x
	return None

# find A,C
for i in range(1, len(ks)-1):
	d1 = (ks[i] - ks[i-1]) % 256
	d2 = (ks[i+1] - ks[i]) % 256
	inv = inv_mod_256(d1)
	if inv is None: continue
	A = (d2 * inv) % 256
	C = (ks[i] - A * ks[i-1]) % 256
	break

seed = ks[0]

# regenerate keystream for ct3 length
s = seed
keystream = []
for _ in range(len(ct3)):
	s = (A * s + C) % 256
	keystream.append(s)

flag = bytes(c ^ k for c,k in zip(ct3, keystream))
print(flag)
```

The repository already included `solve.py` with the exact approach above; it uses the printed hex strings from the challenge output.

---

## Reproduction steps

If you have the `output.txt` from the challenge (already included in this repo), run the provided `solve.py`:

```bash
cd noob_crypto
python3 solve.py
```


## Results

Using the supplied `output.txt` constants and the `solve.py` script, the A, C, and seed can be recovered and the flag extracted. The supplied `solve.py` prints the final `FLAG` when run with the bundled hex strings.

---

## Notes and mitigations

- The generator is a linear recurrence modulo 256 (a tiny LCG-like PRNG) operating over a single byte. It's insecure when used directly as a keystream for XOR.
- Known-plaintext attacks fully recover the parameters A and C (when an invertible difference exists) because the recurrence is low-entropy and linear.
- Use a cryptographically secure PRNG or a proper stream cipher (e.g. ChaCha20) for masking.

---
