"""
CryptoBreaker Kullanım Örnekleri
Çeşitli şifreleme algoritmalarını kırma örnekleri
"""

from cryptobreaker import (
    CaesarCipher, VigenereCipher, SubstitutionCipher,
    XORCracker, HashCracker, ECBDetector
)
import hashlib


def demo_caesar():
    """Caesar şifre kırma örneği"""
    print("\n" + "="*70)
    print("ÖRNEK 1: CAESAR ŞİFRE KIRMA")
    print("="*70)
    
    # Şifreli metin (kaydırma: 3)
    ciphertext = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
    
    print(f"\nŞifreli Metin: {ciphertext}")
    print("\n[*] Kırılıyor...")
    
    results = CaesarCipher.crack(ciphertext)
    
    print(f"\n✓ En Olası Çözüm:")
    print(f"  Düz Metin: {results[0]['plaintext']}")
    print(f"  Kaydırma: {results[0]['shift']}")


def demo_vigenere():
    """Vigenère şifre kırma örneği"""
    print("\n" + "="*70)
    print("ÖRNEK 2: VIGENÈRE ŞİFRE KIRMA")
    print("="*70)
    
    # Vigenère ile şifrelenmiş metin (anahtar: "KEY")
    ciphertext = """
    RIJVSUYVJN IBXKRKDVYXC TYEURBSXKDSYXC KXN KXKVICSC YP MVIZDY KBQYVSDRWC
    """
    
    print(f"\nŞifreli Metin: {ciphertext[:100]}...")
    print("\n[*] Kırılıyor (Kasiski yöntemi)...")
    
    results = VigenereCipher.crack(ciphertext)
    
    print(f"\n✓ Sonuç:")
    print(f"  Anahtar: {results[0]['key']}")
    print(f"  Düz Metin: {results[0]['plaintext'][:100]}...")


def demo_substitution():
    """Substitution şifre kırma örneği"""
    print("\n" + "="*70)
    print("ÖRNEK 3: SUBSTITUTION ŞİFRE KIRMA")
    print("="*70)
    
    ciphertext = """
    Kgy jfaqc pxdtb udh nfzem dsyx kgy vwol mdm.
    Kgy uasy qdxm du w myaqyk zymmwmy.
    """
    
    print(f"\nŞifreli Metin: {ciphertext}")
    print("\n[*] Frekans analizi yapılıyor...")
    
    result = SubstitutionCipher.crack(ciphertext, language='english')
    
    print(f"\n✓ Tahmin Edilen Metin:")
    print(f"  {result['plaintext'][:150]}...")
    print(f"\n⚠ Manuel düzeltme gerekebilir!")


def demo_xor_single():
    """Tek byte XOR kırma örneği"""
    print("\n" + "="*70)
    print("ÖRNEK 4: XOR KIRMA (Tek Byte)")
    print("="*70)
    
    # Gizli mesaj
    plaintext = b"The secret key is hidden in the encrypted data!"
    xor_key = 0x5A  # Tek byte anahtar
    
    # XOR ile şifrele
    ciphertext = bytes(b ^ xor_key for b in plaintext)
    
    print(f"\nŞifreli Veri (hex): {ciphertext.hex()}")
    print(f"Gerçek Anahtar: {hex(xor_key)} (gizli)")
    print("\n[*] Brute force ile kırılıyor...")
    
    results = XORCracker.crack_single_byte(ciphertext)
    
    if results:
        print(f"\n✓ BAŞARILI!")
        print(f"  Bulunan Anahtar: {results[0]['key_hex']}")
        print(f"  Düz Metin: {results[0]['plaintext']}")


def demo_xor_repeating():
    """Tekrarlayan anahtar XOR kırma örneği"""
    print("\n" + "="*70)
    print("ÖRNEK 5: XOR KIRMA (Tekrarlayan Anahtar)")
    print("="*70)
    
    # Uzun mesaj
    plaintext = b"""
    Cryptography is the practice and study of techniques for secure communication
    in the presence of adversarial behavior. It is about constructing and analyzing
    protocols that prevent third parties or the public from reading private messages.
    """
    
    xor_key = b"SECRET"  # Tekrarlayan anahtar
    
    # XOR ile şifrele
    ciphertext = bytes(plaintext[i] ^ xor_key[i % len(xor_key)] 
                      for i in range(len(plaintext)))
    
    print(f"\nŞifreli Veri Boyutu: {len(ciphertext)} byte")
    print(f"Gerçek Anahtar: {xor_key.decode()} (gizli)")
    print("\n[*] Hamming distance analizi ile kırılıyor...")
    
    results = XORCracker.crack_repeating_key(ciphertext)
    
    if results:
        print(f"\n✓ BAŞARILI!")
        print(f"  Bulunan Anahtar: {results[0]['key']}")


def demo_hash_cracking():
    """Hash kırma örneği"""
    print("\n" + "="*70)
    print("ÖRNEK 6: HASH KIRMA (MD5)")
    print("="*70)
    
    # Zayıf parola
    password = "password123"
    hash_md5 = hashlib.md5(password.encode()).hexdigest()
    
    print(f"\nHedef Hash (MD5): {hash_md5}")
    print(f"Gerçek Parola: {password} (gizli)")
    print("\n[*] Dictionary attack başlatılıyor...")
    
    cracked = HashCracker.crack_hash(hash_md5, hash_type='md5')
    
    if cracked:
        print(f"\n✓ BAŞARILI!")
        print(f"  Kırılan Parola: {cracked}")
    else:
        print(f"\n✗ Wordlist'te bulunamadı")


def demo_ecb_detection():
    """ECB mode tespiti örneği"""
    print("\n" + "="*70)
    print("ÖRNEK 7: ECB MODE TESPİTİ")
    print("="*70)
    
    # Tekrarlayan bloklar içeren sahte şifreli veri
    block1 = bytes.fromhex("0123456789abcdef0123456789abcdef")
    block2 = bytes.fromhex("fedcba9876543210fedcba9876543210")
    block3 = bytes.fromhex("0123456789abcdef0123456789abcdef")  # Tekrar!
    
    ciphertext = block1 + block2 + block3
    
    print(f"\nŞifreli Veri (hex): {ciphertext.hex()}")
    print("\n[*] ECB analizi yapılıyor...")
    
    result = ECBDetector.detect_ecb(ciphertext, block_size=16)
    
    if result['is_ecb']:
        print(f"\n✗ GÜVENLİK AÇIĞI!")
        print(f"  ECB modu tespit edildi")
        print(f"  Tekrarlayan blok sayısı: {len(result['repeated_blocks'])}")


def demo_advanced_xor():
    """Gelişmiş XOR analizi"""
    print("\n" + "="*70)
    print("ÖRNEK 8: GELİŞMİŞ XOR ANALİZİ")
    print("="*70)
    
    # Gerçek dünya örneği: Base64 + XOR
    import base64
    
    plaintext = b"This is a confidential document with sensitive information."
    key = b"K3Y"
    
    # XOR şifreleme
    encrypted = bytes(plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext)))
    
    # Base64 encode (yaygın kullanım)
    encoded = base64.b64encode(encrypted).decode()
    
    print(f"\nBase64 Encoded Şifreli: {encoded}")
    print(f"Gerçek Anahtar: {key.decode()} (gizli)")
    
    # Decode ve kır
    print("\n[*] Base64 decode ediliyor...")
    decoded = base64.b64decode(encoded)
    
    print("[*] XOR kırılıyor...")
    results = XORCracker.crack_repeating_key(decoded, max_key_length=10)
    
    if results:
        print(f"\n✓ BAŞARILI!")
        print(f"  Bulunan Anahtar: {results[0]['key']}")
        print(f"  Düz Metin: {results[0]['plaintext']}")


def demo_multi_hash():
    """Çoklu hash kırma"""
    print("\n" + "="*70)
    print("ÖRNEK 9: ÇOKLU HASH KIRMA")
    print("="*70)
    
    # Farklı hash tipleri
    password = "admin"
    
    hashes = {
        'MD5': hashlib.md5(password.encode()).hexdigest(),
        'SHA1': hashlib.sha1(password.encode()).hexdigest(),
        'SHA256': hashlib.sha256(password.encode()).hexdigest()
    }
    
    print(f"\nHedef Hashler:")
    for hash_type, hash_value in hashes.items():
        print(f"  {hash_type}: {hash_value}")
    
    print(f"\n[*] Tüm hashler kırılıyor...")
    
    for hash_type, hash_value in hashes.items():
        print(f"\n[*] {hash_type} kırılıyor...")
        cracked = HashCracker.crack_hash(
            hash_value, 
            hash_type=hash_type.lower(),
            verbose=False
        )
        
        if cracked:
            print(f"  ✓ Kırıldı: {cracked}")
        else:
            print(f"  ✗ Bulunamadı")


def interactive_mode():
    """İnteraktif mod"""
    print("\n" + "="*70)
    print("İNTERAKTİF MOD")
    print("="*70)
    
    print("\nHangi şifre türünü kırmak istiyorsunuz?")
    print("1. Caesar Şifre")
    print("2. Vigenère Şifre")
    print("3. XOR (Tek Byte)")
    print("4. XOR (Tekrarlayan Anahtar)")
    print("5. Hash (MD5/SHA1/SHA256)")
    print("6. ECB Tespiti")
    print("0. Çıkış")
    
    choice = input("\nSeçiminiz (0-6): ").strip()
    
    if choice == '1':
        ciphertext = input("\nŞifreli metni girin: ")
        CaesarCipher.crack(ciphertext)
    
    elif choice == '2':
        ciphertext = input("\nŞifreli metni girin: ")
        VigenereCipher.crack(ciphertext)
    
    elif choice == '3':
        hex_input = input("\nŞifreli veriyi hex formatında girin: ")
        try:
            ciphertext = bytes.fromhex(hex_input)
            XORCracker.crack_single_byte(ciphertext)
        except ValueError:
            print("✗ Geçersiz hex formatı!")
    
    elif choice == '4':
        hex_input = input("\nŞifreli veriyi hex formatında girin: ")
        try:
            ciphertext = bytes.fromhex(hex_input)
            XORCracker.crack_repeating_key(ciphertext)
        except ValueError:
            print("✗ Geçersiz hex formatı!")
    
    elif choice == '5':
        hash_value = input("\nHash değerini girin: ")
        hash_type = input("Hash tipi (md5/sha1/sha256): ").lower()
        HashCracker.crack_hash(hash_value, hash_type)
    
    elif choice == '6':
        hex_input = input("\nŞifreli veriyi hex formatında girin: ")
        try:
            ciphertext = bytes.fromhex(hex_input)
            ECBDetector.detect_ecb(ciphertext)
        except ValueError:
            print("✗ Geçersiz hex formatı!")


def main():
    """Ana menü"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 10 + "CRYPTOBREAKER - Kullanım Örnekleri" + " " * 23 + "║")
    print("╚" + "=" * 68 + "╝")
    
    print("\n[*] Tüm örnekleri çalıştırmak için ENTER'a basın")
    print("[*] İnteraktif mod için 'i' yazın")
    print("[*] Çıkmak için 'q' yazın")
    
    choice = input("\nSeçiminiz: ").strip().lower()
    
    if choice == 'q':
        return
    elif choice == 'i':
        interactive_mode()
    else:
        # Tüm örnekleri çalıştır
        demo_caesar()
        input("\n[Enter] Devam...")
        
        demo_vigenere()
        input("\n[Enter] Devam...")
        
        demo_substitution()
        input("\n[Enter] Devam...")
        
        demo_xor_single()
        input("\n[Enter] Devam...")
        
        demo_xor_repeating()
        input("\n[Enter] Devam...")
        
        demo_hash_cracking()
        input("\n[Enter] Devam...")
        
        demo_ecb_detection()
        input("\n[Enter] Devam...")
        
        demo_advanced_xor()
        input("\n[Enter] Devam...")
        
        demo_multi_hash()
        
        print("\n" + "="*70)
        print("TÜM ÖRNEKLER TAMAMLANDI!")
        print("="*70)


if __name__ == "__main__":
    main()
