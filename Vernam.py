import sys

def E(key: bytes, msg: bytes) -> bytes:
    """Vernam XOR: ciphertext = key XOR message (key must be >= message)."""
    if len(key) < len(msg):
        raise ValueError("Key must be at least as long as the message")
    ba = bytearray(len(msg))
    for i in range(len(msg)):
        ba[i] = key[i] ^ msg[i]
    return bytes(ba)

# --- Convenience wrappers ---

def vernam_bytes(key: bytes, msg: bytes) -> bytes:
    """Alias for E(), kept for clarity when working at byte-level."""
    return E(key, msg)

def vernam(key_str: str, msg_str: str, encoding: str = "utf-8") -> bytes:
    """
    Vernam on strings: encode to bytes, XOR, return ciphertext bytes.
    Note: ciphertext is arbitrary bytes, not valid UTF-8 text.
    """
    k = key_str.encode(encoding)
    m = msg_str.encode(encoding)
    return vernam_bytes(k, m)

# --- CLI demo ---

if __name__ == "__main__":
    print("\n** Vernam cipher, extended version.")
    print("** Input is read as UTF-8 and converted to bytes.\n")

    key_str = input("=> Enter the cipher key (string) : ")
    msg_str = input("=> Enter the plaintext message : ")

    k = key_str.encode("utf-8")
    m = msg_str.encode("utf-8")

    if len(k) < len(m):
        print("The key must be at least as long as the message!", file=sys.stderr)
        sys.exit(1)

    # Encrypt
    c = E(k, m)

    print("\n== k (bytes):", k)
    print("== m (bytes):", m)
    print("== c (bytes):", c)
    print("== c (hex)  :", c.hex())

    # Decrypt demo: XOR again with same key
    m2 = E(k, c)
    print("== m' (bytes after decrypt):", m2)
    print("== m' (utf-8)              :", m2.decode('utf-8', errors='replace'))

    # Roundtrip check
    if m2 == m:
        print("\nRoundtrip successful ✅ (decrypted plaintext matches original)")
    else:
        print("\nRoundtrip FAILED ❌")
