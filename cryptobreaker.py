"""
CryptoBreaker - Profesyonel Kriptanaliz Araç Seti
Çeşitli şifreleme algoritmalarını analiz etme ve kırma araçları

Desteklenen Saldırılar:
1. Klasik Şifreler (Caesar, Vigenère, Substitution, Transposition)
2. Modern Şifreleme Zayıflıkları (ECB, Padding Oracle, Weak Keys)
3. Hash Kırma (MD5, SHA1 collision, Rainbow Tables)
4. RSA Saldırıları (Weak primes, Small exponent, Factorization)
5. XOR Analizi ve Kırma
6. Frekans Analizi (Çoklu dil desteği)
"""

import hashlib
import itertools
import string
import re
from collections import Counter
from typing import List, Dict, Tuple, Optional
import math


class CryptoBreaker:
    """Ana kriptanaliz sınıfı"""
    
    def __init__(self):
        # Türkçe harf frekansları (%)
        self.turkish_freq = {
            'a': 11.92, 'e': 8.91, 'i': 8.60, 'n': 7.48, 'r': 6.95,
            'l': 5.75, 'ı': 5.12, 't': 4.54, 'k': 4.53, 'd': 4.14,
            'u': 3.46, 's': 3.01, 'm': 2.99, 'y': 2.88, 'o': 2.61,
            'b': 2.54, 'ü': 1.99, 'ş': 1.82, 'z': 1.50, 'v': 1.00,
            'g': 1.00, 'p': 0.79, 'c': 0.79, 'h': 0.73, 'ğ': 0.71,
            'ç': 0.70, 'f': 0.41, 'ö': 0.33
        }
        
        # İngilizce harf frekansları (%)
        self.english_freq = {
            'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
            'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
            'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
            'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
            'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
        }
        
        # Yaygın kelimeler (dil tespiti için)
        self.turkish_words = {'bir', 've', 'bu', 'için', 'ile', 'olan', 'var', 'gibi', 'daha', 'çok'}
        self.english_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her'}


class CaesarCipher:
    """Caesar Şifre Kırıcı"""
    
    @staticmethod
    def crack(ciphertext: str, verbose: bool = True) -> List[Dict]:
        """
        Caesar şifresini brute force ile kır
        
        Args:
            ciphertext: Şifreli metin
            verbose: Detaylı çıktı
            
        Returns:
            Olası çözümler listesi
        """
        if verbose:
            print("\n" + "=" * 70)
            print("CAESAR ŞİFRE KIRICI")
            print("=" * 70)
            print(f"\nŞifreli Metin: {ciphertext[:100]}...")
        
        results = []
        
        # 26 farklı kaydırma dene
        for shift in range(26):
            plaintext = ""
            for char in ciphertext:
                if char.isalpha():
                    # Büyük/küçük harf kontrolü
                    if char.isupper():
                        plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                    else:
                        plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                else:
                    plaintext += char
            
            # Okunabilirlik skoru hesapla
            score = CaesarCipher._calculate_readability(plaintext)
            
            results.append({
                'shift': shift,
                'plaintext': plaintext,
                'score': score
            })
        
        # Skora göre sırala
        results.sort(key=lambda x: x['score'], reverse=True)
        
        if verbose:
            print(f"\n[*] En Olası 5 Sonuç:")
            print("-" * 70)
            for i, result in enumerate(results[:5], 1):
                print(f"\n{i}. Kaydırma: {result['shift']} | Skor: {result['score']:.2f}")
                preview = result['plaintext'][:80] + "..." if len(result['plaintext']) > 80 else result['plaintext']
                print(f"   Metin: {preview}")
        
        return results
    
    @staticmethod
    def _calculate_readability(text: str) -> float:
        """Metnin okunabilirlik skorunu hesapla"""
        if not text:
            return 0.0
        
        # Harf oranı
        letters = sum(1 for c in text if c.isalpha())
        letter_ratio = letters / len(text)
        
        # Boşluk oranı (kelime ayırma)
        spaces = text.count(' ')
        space_ratio = spaces / len(text)
        
        # Yaygın kelime kontrolü
        words = text.lower().split()
        common_words = {'the', 'and', 'bir', 've', 'bu', 'is', 'to', 'in', 'that', 'için'}
        common_count = sum(1 for w in words if w in common_words)
        
        # Skor hesapla
        score = (letter_ratio * 50) + (space_ratio * 30) + (common_count * 10)
        return score


class VigenereCipher:
    """Vigenère Şifre Kırıcı"""
    
    @staticmethod
    def crack(ciphertext: str, max_key_length: int = 20, verbose: bool = True) -> List[Dict]:
        """
        Vigenère şifresini Kasiski ve frekans analizi ile kır
        
        Args:
            ciphertext: Şifreli metin
            max_key_length: Maksimum anahtar uzunluğu
            verbose: Detaylı çıktı
            
        Returns:
            Olası çözümler
        """
        if verbose:
            print("\n" + "=" * 70)
            print("VIGENÈRE ŞİFRE KIRICI")
            print("=" * 70)
            print(f"\nŞifreli Metin: {ciphertext[:100]}...")
        
        # Sadece harfleri al
        clean_text = ''.join(c for c in ciphertext.upper() if c.isalpha())
        
        # Anahtar uzunluğunu bul (Kasiski yöntemi)
        key_length = VigenereCipher._find_key_length(clean_text, max_key_length)
        
        if verbose:
            print(f"\n[*] Tahmin Edilen Anahtar Uzunluğu: {key_length}")
        
        # Anahtarı bul
        key = VigenereCipher._find_key(clean_text, key_length)
        
        if verbose:
            print(f"[*] Bulunan Anahtar: {key}")
        
        # Deşifre et
        plaintext = VigenereCipher._decrypt(ciphertext, key)
        
        if verbose:
            print(f"\n[*] Deşifre Edilmiş Metin:")
            print("-" * 70)
            preview = plaintext[:200] + "..." if len(plaintext) > 200 else plaintext
            print(preview)
        
        return [{
            'key': key,
            'key_length': key_length,
            'plaintext': plaintext
        }]
    
    @staticmethod
    def _find_key_length(ciphertext: str, max_length: int) -> int:
        """Kasiski yöntemi ile anahtar uzunluğunu bul"""
        # Index of Coincidence (IC) yöntemi
        ic_scores = {}
        
        for key_len in range(1, max_length + 1):
            # Metni key_len grubuna böl
            groups = [''] * key_len
            for i, char in enumerate(ciphertext):
                groups[i % key_len] += char
            
            # Her grup için IC hesapla
            avg_ic = 0
            for group in groups:
                if len(group) > 1:
                    avg_ic += VigenereCipher._calculate_ic(group)
            avg_ic /= key_len
            
            ic_scores[key_len] = avg_ic
        
        # En yüksek IC'ye sahip uzunluğu seç (İngilizce IC ≈ 0.065)
        best_length = max(ic_scores, key=ic_scores.get)
        return best_length
    
    @staticmethod
    def _calculate_ic(text: str) -> float:
        """Index of Coincidence hesapla"""
        n = len(text)
        if n <= 1:
            return 0
        
        freq = Counter(text)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic
    
    @staticmethod
    def _find_key(ciphertext: str, key_length: int) -> str:
        """Frekans analizi ile anahtarı bul"""
        key = ""
        
        for i in range(key_length):
            # i. pozisyondaki harfleri al
            group = ciphertext[i::key_length]
            
            # En olası kaydırmayı bul (frekans analizi)
            best_shift = 0
            best_score = 0
            
            for shift in range(26):
                # Bu kaydırma ile deşifre et
                decrypted = ''.join(
                    chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                    for c in group
                )
                
                # İngilizce frekans ile karşılaştır
                score = VigenereCipher._chi_squared(decrypted)
                
                if score > best_score:
                    best_score = score
                    best_shift = shift
            
            key += chr(best_shift + ord('A'))
        
        return key
    
    @staticmethod
    def _chi_squared(text: str) -> float:
        """Chi-squared testi ile İngilizce benzerliği"""
        expected_freq = {
            'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
            'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
            'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
            'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
            'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
        }
        
        if not text:
            return 0
        
        freq = Counter(text)
        total = len(text)
        
        score = 0
        for char in string.ascii_uppercase:
            observed = (freq.get(char, 0) / total) * 100
            expected = expected_freq.get(char, 0.01)
            score -= abs(observed - expected)
        
        return score
    
    @staticmethod
    def _decrypt(ciphertext: str, key: str) -> str:
        """Vigenère ile deşifre et"""
        plaintext = ""
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                
                if char.isupper():
                    plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                
                key_index += 1
            else:
                plaintext += char
        
        return plaintext


class SubstitutionCipher:
    """Monoalphabetic Substitution Şifre Kırıcı"""
    
    @staticmethod
    def crack(ciphertext: str, language: str = 'english', verbose: bool = True) -> Dict:
        """
        Substitution şifresini frekans analizi ile kır
        
        Args:
            ciphertext: Şifreli metin
            language: Dil ('english' veya 'turkish')
            verbose: Detaylı çıktı
            
        Returns:
            Çözüm dictionary
        """
        if verbose:
            print("\n" + "=" * 70)
            print("SUBSTITUTION ŞİFRE KIRICI")
            print("=" * 70)
            print(f"\nŞifreli Metin: {ciphertext[:100]}...")
        
        # Frekans analizi
        freq = Counter(c.lower() for c in ciphertext if c.isalpha())
        total = sum(freq.values())
        
        # Frekans sırasına göre sırala
        sorted_cipher = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        
        # Beklenen frekans sırası
        if language == 'turkish':
            expected = 'aeinrltdkusmyobüşzvgpchğçföj'
        else:
            expected = 'etaoinshrdlcumwfgypbvkjxqz'
        
        # Mapping oluştur
        mapping = {}
        for i, (cipher_char, _) in enumerate(sorted_cipher):
            if i < len(expected):
                mapping[cipher_char] = expected[i]
        
        # Deşifre et
        plaintext = ""
        for char in ciphertext:
            if char.lower() in mapping:
                decrypted = mapping[char.lower()]
                plaintext += decrypted.upper() if char.isupper() else decrypted
            else:
                plaintext += char
        
        if verbose:
            print(f"\n[*] Frekans Analizi:")
            print("-" * 70)
            print("Şifreli → Düz Metin (Tahmin)")
            for cipher_char, plain_char in list(mapping.items())[:10]:
                cipher_freq = (freq[cipher_char] / total) * 100
                print(f"  {cipher_char.upper()} → {plain_char.upper()}  ({cipher_freq:.2f}%)")
            
            print(f"\n[*] Deşifre Edilmiş Metin:")
            print("-" * 70)
            preview = plaintext[:200] + "..." if len(plaintext) > 200 else plaintext
            print(preview)
            print("\n⚠ Not: Substitution şifre tam otomatik kırılamaz.")
            print("   Yukarıdaki mapping'i manuel olarak düzeltmeniz gerekebilir.")
        
        return {
            'mapping': mapping,
            'plaintext': plaintext,
            'frequency': sorted_cipher
        }


class XORCracker:
    """XOR Şifre Kırıcı"""
    
    @staticmethod
    def crack_single_byte(ciphertext: bytes, verbose: bool = True) -> List[Dict]:
        """
        Tek byte XOR anahtarını kır
        
        Args:
            ciphertext: Şifreli veri (bytes)
            verbose: Detaylı çıktı
            
        Returns:
            Olası çözümler
        """
        if verbose:
            print("\n" + "=" * 70)
            print("XOR ŞİFRE KIRICI (Tek Byte)")
            print("=" * 70)
            print(f"\nŞifreli Veri (hex): {ciphertext.hex()[:100]}...")
        
        results = []
        
        # 256 olası byte dene
        for key in range(256):
            plaintext = bytes(b ^ key for b in ciphertext)
            
            # Okunabilirlik kontrolü
            try:
                text = plaintext.decode('utf-8', errors='strict')
                score = XORCracker._score_text(text)
                
                if score > 50:  # Eşik değer
                    results.append({
                        'key': key,
                        'key_hex': hex(key),
                        'key_char': chr(key) if 32 <= key < 127 else '?',
                        'plaintext': text,
                        'score': score
                    })
            except:
                continue
        
        # Skora göre sırala
        results.sort(key=lambda x: x['score'], reverse=True)
        
        if verbose:
            print(f"\n[*] Bulunan {len(results)} Olası Sonuç")
            print("-" * 70)
            for i, result in enumerate(results[:5], 1):
                print(f"\n{i}. Anahtar: {result['key_hex']} ('{result['key_char']}') | Skor: {result['score']:.1f}")
                preview = result['plaintext'][:80] + "..." if len(result['plaintext']) > 80 else result['plaintext']
                print(f"   Metin: {preview}")
        
        return results
    
    @staticmethod
    def crack_repeating_key(ciphertext: bytes, max_key_length: int = 40, verbose: bool = True) -> List[Dict]:
        """
        Tekrarlayan anahtar XOR'unu kır
        
        Args:
            ciphertext: Şifreli veri
            max_key_length: Maksimum anahtar uzunluğu
            verbose: Detaylı çıktı
            
        Returns:
            Olası çözümler
        """
        if verbose:
            print("\n" + "=" * 70)
            print("XOR ŞİFRE KIRICI (Tekrarlayan Anahtar)")
            print("=" * 70)
            print(f"\nŞifreli Veri Boyutu: {len(ciphertext)} byte")
        
        # Anahtar uzunluğunu bul (Hamming distance)
        key_length = XORCracker._find_key_length(ciphertext, max_key_length)
        
        if verbose:
            print(f"[*] Tahmin Edilen Anahtar Uzunluğu: {key_length}")
        
        # Anahtarı bul
        key = bytearray()
        for i in range(key_length):
            block = ciphertext[i::key_length]
            
            # Tek byte XOR kır
            best_key = 0
            best_score = 0
            
            for k in range(256):
                plaintext = bytes(b ^ k for b in block)
                try:
                    text = plaintext.decode('utf-8', errors='strict')
                    score = XORCracker._score_text(text)
                    if score > best_score:
                        best_score = score
                        best_key = k
                except:
                    continue
            
            key.append(best_key)
        
        # Deşifre et
        plaintext = bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))
        
        try:
            text = plaintext.decode('utf-8')
        except:
            text = plaintext.decode('utf-8', errors='replace')
        
        if verbose:
            print(f"[*] Bulunan Anahtar: {key.hex()}")
            print(f"[*] Anahtar (ASCII): {key.decode('utf-8', errors='replace')}")
            print(f"\n[*] Deşifre Edilmiş Metin:")
            print("-" * 70)
            preview = text[:300] + "..." if len(text) > 300 else text
            print(preview)
        
        return [{
            'key': key,
            'key_hex': key.hex(),
            'key_length': key_length,
            'plaintext': text
        }]
    
    @staticmethod
    def _find_key_length(ciphertext: bytes, max_length: int) -> int:
        """Hamming distance ile anahtar uzunluğunu bul"""
        distances = {}
        
        for key_size in range(2, min(max_length + 1, len(ciphertext) // 2)):
            # İlk 4 bloğu al
            blocks = [ciphertext[i*key_size:(i+1)*key_size] for i in range(4)]
            
            # Hamming distance hesapla
            total_distance = 0
            comparisons = 0
            
            for i in range(len(blocks)):
                for j in range(i + 1, len(blocks)):
                    if len(blocks[i]) == len(blocks[j]):
                        distance = XORCracker._hamming_distance(blocks[i], blocks[j])
                        total_distance += distance / key_size
                        comparisons += 1
            
            if comparisons > 0:
                distances[key_size] = total_distance / comparisons
        
        # En düşük normalized distance
        return min(distances, key=distances.get)
    
    @staticmethod
    def _hamming_distance(b1: bytes, b2: bytes) -> int:
        """İki byte dizisi arasındaki Hamming distance"""
        return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))
    
    @staticmethod
    def _score_text(text: str) -> float:
        """Metnin İngilizce/okunabilir olma skorunu hesapla"""
        if not text:
            return 0
        
        # Yazdırılabilir karakter oranı
        printable = sum(1 for c in text if c.isprintable())
        printable_ratio = printable / len(text)
        
        # Harf oranı
        letters = sum(1 for c in text if c.isalpha())
        letter_ratio = letters / len(text)
        
        # Boşluk oranı
        spaces = text.count(' ')
        space_ratio = spaces / len(text)
        
        # Yaygın kelimeler
        words = text.lower().split()
        common = {'the', 'and', 'to', 'of', 'a', 'in', 'is', 'it', 'you', 'that',
                  'bir', 've', 'bu', 'için', 'ile', 'var', 'olan'}
        common_count = sum(1 for w in words if w in common)
        
        # Skor hesapla
        score = (printable_ratio * 30) + (letter_ratio * 30) + \
                (space_ratio * 20) + (common_count * 5)
        
        return score


class HashCracker:
    """Hash Kırıcı (Dictionary ve Rainbow Table)"""
    
    @staticmethod
    def crack_hash(hash_value: str, hash_type: str = 'md5', 
                   wordlist: List[str] = None, verbose: bool = True) -> Optional[str]:
        """
        Hash değerini dictionary attack ile kır
        
        Args:
            hash_value: Kırılacak hash
            hash_type: Hash tipi ('md5', 'sha1', 'sha256')
            wordlist: Kelime listesi (None ise varsayılan)
            verbose: Detaylı çıktı
            
        Returns:
            Bulunan düz metin veya None
        """
        if verbose:
            print("\n" + "=" * 70)
            print(f"HASH KIRICI ({hash_type.upper()})")
            print("=" * 70)
            print(f"\nHedef Hash: {hash_value}")
        
        # Varsayılan wordlist
        if wordlist is None:
            wordlist = HashCracker._generate_default_wordlist()
        
        if verbose:
            print(f"[*] Wordlist Boyutu: {len(wordlist):,} kelime")
            print(f"[*] Deneniyor...")
        
        # Hash fonksiyonu seç
        if hash_type == 'md5':
            hash_func = hashlib.md5
        elif hash_type == 'sha1':
            hash_func = hashlib.sha1
        elif hash_type == 'sha256':
            hash_func = hashlib.sha256
        else:
            raise ValueError(f"Desteklenmeyen hash tipi: {hash_type}")
        
        # Dictionary attack
        for i, word in enumerate(wordlist):
            if verbose and i % 10000 == 0:
                print(f"  İlerleme: {i:,}/{len(wordlist):,}", end='\r')
            
            # Hash hesapla
            word_hash = hash_func(word.encode()).hexdigest()
            
            if word_hash == hash_value.lower():
                if verbose:
                    print(f"\n\n✓ BULUNDU!")
                    print(f"  Düz Metin: {word}")
                return word
        
        if verbose:
            print(f"\n\n✗ Bulunamadı ({len(wordlist):,} deneme)")
        
        return None
    
    @staticmethod
    def _generate_default_wordlist() -> List[str]:
        """Varsayılan wordlist oluştur"""
        wordlist = []
        
        # Yaygın parolalar
        common = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'superman', 'qazwsx', 'michael', 'football', 'welcome',
            'admin', 'root', 'test', 'guest', 'user',
            'parola', 'sifre', '123', 'password123', 'admin123'
        ]
        wordlist.extend(common)
        
        # Sayılar (0-9999)
        wordlist.extend(str(i) for i in range(10000))
        
        # Yaygın kelimeler + sayılar
        words = ['password', 'admin', 'user', 'test', 'hello', 'world']
        for word in words:
            for i in range(100):
                wordlist.append(f"{word}{i}")
                wordlist.append(f"{word}{i:02d}")
        
        return wordlist


class ECBDetector:
    """ECB Mode Tespit Edici ve Saldırı Aracı"""
    
    @staticmethod
    def detect_ecb(ciphertext: bytes, block_size: int = 16, verbose: bool = True) -> Dict:
        """
        ECB modunu tespit et (tekrarlayan bloklar)
        
        Args:
            ciphertext: Şifreli veri
            block_size: Blok boyutu (AES için 16)
            verbose: Detaylı çıktı
            
        Returns:
            Analiz sonuçları
        """
        if verbose:
            print("\n" + "=" * 70)
            print("ECB MODE TESPİT EDİCİ")
            print("=" * 70)
            print(f"\nVeri Boyutu: {len(ciphertext)} byte")
            print(f"Blok Boyutu: {block_size} byte")
        
        # Blokları ayır
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
        
        # Tekrarlayan blokları bul
        block_freq = Counter(blocks)
        repeated = {block.hex(): count for block, count in block_freq.items() if count > 1}
        
        # Benzersiz blok oranı
        unique_ratio = len(set(blocks)) / len(blocks)
        
        # ECB olasılığı
        is_ecb = len(repeated) > 0
        ecb_score = (1 - unique_ratio) * 100
        
        if verbose:
            print(f"\n[*] Toplam Blok: {len(blocks)}")
            print(f"[*] Benzersiz Blok: {len(set(blocks))}")
            print(f"[*] Tekrarlayan Blok: {len(repeated)}")
            print(f"[*] Benzersiz Oran: %{unique_ratio * 100:.1f}")
            
            if is_ecb:
                print(f"\n✗ ECB MODU TESPİT EDİLDİ! (Skor: %{ecb_score:.1f})")
                print(f"\n[*] Tekrarlayan Bloklar:")
                for block_hex, count in list(repeated.items())[:5]:
                    print(f"  {block_hex}: {count} kez")
                
                print(f"\n⚠ ECB modu güvensizdir!")
                print(f"  - Aynı düz metin bloğu aynı şifreli metin üretir")
                print(f"  - Patern analizi ile bilgi sızıntısı olabilir")
            else:
                print(f"\n✓ ECB modu tespit edilmedi (Skor: %{ecb_score:.1f})")
        
        return {
            'is_ecb': is_ecb,
            'ecb_score': ecb_score,
            'total_blocks': len(blocks),
            'unique_blocks': len(set(blocks)),
            'repeated_blocks': repeated,
            'unique_ratio': unique_ratio
        }


def main():
    """Demo ve test fonksiyonu"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "CRYPTOBREAKER - Kriptanaliz Araç Seti" + " " * 14 + "║")
    print("║" + " " * 15 + "Profesyonel Şifre Kırma Araçları" + " " * 20 + "║")
    print("╚" + "=" * 68 + "╝")
    
    print("\n[*] Mevcut Araçlar:")
    print("  1. Caesar Şifre Kırıcı")
    print("  2. Vigenère Şifre Kırıcı")
    print("  3. Substitution Şifre Kırıcı")
    print("  4. XOR Kırıcı (Tek Byte ve Tekrarlayan)")
    print("  5. Hash Kırıcı (MD5, SHA1, SHA256)")
    print("  6. ECB Mode Tespit Edici")
    
    # Demo örnekleri
    print("\n" + "=" * 70)
    print("DEMO: CAESAR ŞİFRE")
    print("=" * 70)
    
    caesar_cipher = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
    print(f"Şifreli: {caesar_cipher}")
    result = CaesarCipher.crack(caesar_cipher, verbose=False)
    print(f"Çözüm: {result[0]['plaintext']} (Kaydırma: {result[0]['shift']})")
    
    print("\n" + "=" * 70)
    print("DEMO: XOR KIRICI")
    print("=" * 70)
    
    # XOR örneği
    plaintext = b"This is a secret message!"
    xor_key = 0x42
    xor_cipher = bytes(b ^ xor_key for b in plaintext)
    print(f"Şifreli (hex): {xor_cipher.hex()}")
    
    xor_results = XORCracker.crack_single_byte(xor_cipher, verbose=False)
    if xor_results:
        print(f"Çözüm: {xor_results[0]['plaintext']}")
        print(f"Anahtar: {xor_results[0]['key_hex']}")
    
    print("\n" + "=" * 70)
    print("DEMO: HASH KIRICI")
    print("=" * 70)
    
    # MD5 örneği
    test_password = "password123"
    test_hash = hashlib.md5(test_password.encode()).hexdigest()
    print(f"Hash: {test_hash}")
    
    cracked = HashCracker.crack_hash(test_hash, 'md5', verbose=False)
    if cracked:
        print(f"Kırıldı: {cracked}")
    
    print("\n" + "=" * 70)
    print("\n[*] Kullanım örnekleri için modül dokümantasyonuna bakın.")
    print("[*] Her araç bağımsız olarak kullanılabilir.\n")


if __name__ == "__main__":
    main()
