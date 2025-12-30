"""
CryptoBreaker Hızlı Test
"""

from cryptobreaker import CaesarCipher, XORCracker, HashCracker
import hashlib

print("="*70)
print("CRYPTOBREAKER - HIZLI TEST")
print("="*70)

# Test 1: Caesar
print("\n[Test 1] Caesar Şifre")
print("-"*70)
caesar_text = "Khoor Zruog"
print(f"Şifreli: {caesar_text}")
result = CaesarCipher.crack(caesar_text, verbose=False)
print(f"✓ Çözüm: {result[0]['plaintext']} (Kaydırma: {result[0]['shift']})")

# Test 2: XOR
print("\n[Test 2] XOR Kırma")
print("-"*70)
plaintext = b"Secret Message"
xor_key = 0x42
encrypted = bytes(b ^ xor_key for b in plaintext)
print(f"Şifreli (hex): {encrypted.hex()}")
result = XORCracker.crack_single_byte(encrypted, verbose=False)
if result:
    print(f"✓ Çözüm: {result[0]['plaintext']}")
    print(f"  Anahtar: {result[0]['key_hex']}")

# Test 3: Hash
print("\n[Test 3] Hash Kırma")
print("-"*70)
password = "admin"
hash_md5 = hashlib.md5(password.encode()).hexdigest()
print(f"Hash: {hash_md5}")
cracked = HashCracker.crack_hash(hash_md5, 'md5', verbose=False)
if cracked:
    print(f"✓ Kırıldı: {cracked}")

print("\n" + "="*70)
print("TÜM TESTLER BAŞARILI!")
print("="*70)
