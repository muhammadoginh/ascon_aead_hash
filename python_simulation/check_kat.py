#!/usr/bin/env python3
"""Verify python_simulation/ascon.py against official NIST SP 800-232 known-answer tests.

AEAD vectors: ascon-c/crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt (Count 1, 2, 34, 35)
Hash vectors: ascon-c/crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt (Count 1, 2, 9, 17)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ascon  # noqa: E402

KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
NONCE = bytes.fromhex("101112131415161718191A1B1C1D1E1F")

# (plaintext, associated data, ciphertext||tag)
AEAD_KATS = [
    ("", "", "4F9C278211BEC9316BF68F46EE8B2EC6"),
    ("", "30", "CCCB674FE18A09A285D6AB11B35675C0"),
    ("20", "", "E8DD576ABA1CD3E6FC704DE02AEDB79588"),
    ("20", "30", "962B8016836C75A7D86866588CA245D886"),
]

# (message, digest)
HASH_KATS = [
    ("", "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2"),
    ("00", "0728621035AF3ED2BCA03BF6FDE900F9456F5330E4B5EE23E7F6A1E70291BC80"),
    ("0001020304050607", "B88E497AE8E6FB641B87EF622EB8F2FCA0ED95383F7FFEBE167ACF1099BA764F"),
    ("000102030405060708090A0B0C0D0E0F", "3158C1940A2FBADBD68AB661777859B94A689E4EFC375911467ADDD641835C38"),
]


def main() -> int:
    failures = 0
    for pt_hex, ad_hex, ct_hex in AEAD_KATS:
        pt, ad, ct = bytes.fromhex(pt_hex), bytes.fromhex(ad_hex), bytes.fromhex(ct_hex)
        got = ascon.ascon_encrypt(KEY, NONCE, ad, pt)
        dec = ascon.ascon_decrypt(KEY, NONCE, ad, ct)
        status = "PASS" if (got == ct and dec == pt) else "FAIL"
        failures += status == "FAIL"
        print(f"AEAD128 pt={pt_hex or '-':>3} ad={ad_hex or '-':>3}  {got.hex().upper()}  {status}")
    for msg_hex, md_hex in HASH_KATS:
        got = ascon.ascon_hash(bytes.fromhex(msg_hex))
        status = "PASS" if got.hex().upper() == md_hex else "FAIL"
        failures += status == "FAIL"
        print(f"Hash256 msg={msg_hex or '-':>32}  {got.hex().upper()}  {status}")
    print("ALL KATS PASS" if failures == 0 else f"{failures} KAT FAILURES")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
