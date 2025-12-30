# CryptoBreaker - Profesyonel Kriptanaliz Araç Seti

## 🔓 Genel Bakış

CryptoBreaker, çeşitli şifreleme algoritmalarını analiz etmek ve kırmak için geliştirilmiş profesyonel bir kriptanaliz araç setidir. Eğitim ve güvenlik araştırmaları için tasarlanmıştır.

## ⚠️ Yasal Uyarı

Bu araçlar **yalnızca eğitim amaçlı** ve **yasal güvenlik testleri** için kullanılmalıdır. İzinsiz sistemlere saldırı yapmak yasa dışıdır. Kullanıcı, bu araçların kullanımından doğan tüm sorumluluğu kabul eder.

---

## 🛠️ Desteklenen Saldırı Türleri

### 1. **Klasik Şifre Kırıcılar**
- ✅ **Caesar Şifre** - Brute force (26 deneme)
- ✅ **Vigenère Şifre** - Kasiski yöntemi + Frekans analizi
- ✅ **Substitution Şifre** - Frekans analizi (Türkçe/İngilizce)

### 2. **Modern Şifre Saldırıları**
- ✅ **XOR Kırıcı** - Tek byte ve tekrarlayan anahtar
- ✅ **ECB Mode Tespiti** - Tekrarlayan blok analizi
- ✅ **Padding Oracle** - (Gelecek sürümde)

### 3. **Hash Kırma**
- ✅ **MD5** - Dictionary attack
- ✅ **SHA1** - Dictionary attack
- ✅ **SHA256** - Dictionary attack
- ✅ **Rainbow Tables** - (Gelecek sürümde)

### 4. **RSA Saldırıları** (Gelecek sürümde)
- ⏳ Weak primes
- ⏳ Small exponent attack
- ⏳ Factorization

---

## 📥 Kurulum

Gerekli: **Python 3.x** (standart kütüphaneler kullanılıyor)

```bash
# Dosyaları indirin
git clone [repo-url]
cd cryptobreaker

# Veya doğrudan kullanın (ek paket gerekmez)
python cryptobreaker.py
```

---

## 🚀 Hızlı Başlangıç

### Demo Çalıştırma

```bash
# Ana demo
python cryptobreaker.py

# Kullanım örnekleri
python cryptobreaker_examples.py
```

### Temel Kullanım

```python
from cryptobreaker import CaesarCipher, XORCracker, HashCracker

# Caesar şifre kır
ciphertext = "Wkh txlfn eurzq ira"
result = CaesarCipher.crack(ciphertext)
print(result[0]['plaintext'])

# XOR kır
encrypted = bytes.fromhex("1e33382d33...")
result = XORCracker.crack_single_byte(encrypted)
print(result[0]['plaintext'])

# Hash kır
hash_md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
password = HashCracker.crack_hash(hash_md5, 'md5')
print(password)  # "password"
```

---

## 📚 Detaylı Kullanım Kılavuzu

### 1. Caesar Şifre Kırıcı

**Ne Yapar:** 26 farklı kaydırma denemesi yaparak Caesar şifresini kırar.

**Kullanım:**
```python
from cryptobreaker import CaesarCipher

ciphertext = "Khoor Zruog"  # "Hello World" (kaydırma: 3)
results = CaesarCipher.crack(ciphertext, verbose=True)

# En olası sonuç
print(results[0]['plaintext'])  # "Hello World"
print(results[0]['shift'])      # 3
```

**Parametreler:**
- `ciphertext` (str): Şifreli metin
- `verbose` (bool): Detaylı çıktı (varsayılan: True)

**Dönüş:**
- Liste[Dict]: Tüm olası çözümler (skora göre sıralı)
  - `shift`: Kaydırma miktarı
  - `plaintext`: Deşifre edilmiş metin
  - `score`: Okunabilirlik skoru

---

### 2. Vigenère Şifre Kırıcı

**Ne Yapar:** Kasiski yöntemi ile anahtar uzunluğunu bulur, frekans analizi ile anahtarı kırar.

**Kullanım:**
```python
from cryptobreaker import VigenereCipher

ciphertext = "RIJVS UYVJN IBXKR..."
results = VigenereCipher.crack(ciphertext, max_key_length=20)

print(results[0]['key'])        # Bulunan anahtar
print(results[0]['plaintext'])  # Deşifre edilmiş metin
```

**Parametreler:**
- `ciphertext` (str): Şifreli metin
- `max_key_length` (int): Maksimum anahtar uzunluğu (varsayılan: 20)
- `verbose` (bool): Detaylı çıktı

**Algoritma:**
1. Index of Coincidence (IC) ile anahtar uzunluğunu tahmin et
2. Her pozisyon için frekans analizi yap
3. Chi-squared testi ile en olası harfi bul
4. Anahtarı oluştur ve deşifre et

---

### 3. Substitution Şifre Kırıcı

**Ne Yapar:** Frekans analizi ile monoalphabetic substitution şifresini kırar.

**Kullanım:**
```python
from cryptobreaker import SubstitutionCipher

ciphertext = "Kgy jfaqc pxdtb udh..."
result = SubstitutionCipher.crack(ciphertext, language='english')

print(result['mapping'])    # Harf eşleştirmesi
print(result['plaintext'])  # Tahmin edilen metin
```

**Parametreler:**
- `ciphertext` (str): Şifreli metin
- `language` (str): Dil ('english' veya 'turkish')
- `verbose` (bool): Detaylı çıktı

**Not:** Substitution şifre tam otomatik kırılamaz. Çıktıdaki mapping'i manuel olarak düzeltmeniz gerekebilir.

---

### 4. XOR Kırıcı (Tek Byte)

**Ne Yapar:** 256 olası byte anahtarını deneyerek tek byte XOR şifresini kırar.

**Kullanım:**
```python
from cryptobreaker import XORCracker

# Şifreli veri (hex formatında)
ciphertext = bytes.fromhex("1e33382d33...")

results = XORCracker.crack_single_byte(ciphertext)

print(results[0]['key_hex'])    # "0x42"
print(results[0]['plaintext'])  # Deşifre edilmiş metin
```

**Parametreler:**
- `ciphertext` (bytes): Şifreli veri
- `verbose` (bool): Detaylı çıktı

**Dönüş:**
- Liste[Dict]: Olası çözümler (skora göre sıralı)
  - `key`: Anahtar (int)
  - `key_hex`: Anahtar (hex)
  - `key_char`: Anahtar (ASCII karakter)
  - `plaintext`: Deşifre edilmiş metin
  - `score`: Okunabilirlik skoru

---

### 5. XOR Kırıcı (Tekrarlayan Anahtar)

**Ne Yapar:** Hamming distance analizi ile anahtar uzunluğunu bulur, her byte'ı ayrı ayrı kırar.

**Kullanım:**
```python
from cryptobreaker import XORCracker

ciphertext = bytes.fromhex("a1b2c3d4...")

results = XORCracker.crack_repeating_key(ciphertext, max_key_length=40)

print(results[0]['key'])         # b'SECRET'
print(results[0]['key_hex'])     # "534543524554"
print(results[0]['plaintext'])   # Deşifre edilmiş metin
```

**Parametreler:**
- `ciphertext` (bytes): Şifreli veri
- `max_key_length` (int): Maksimum anahtar uzunluğu (varsayılan: 40)
- `verbose` (bool): Detaylı çıktı

**Algoritma:**
1. Hamming distance ile anahtar uzunluğunu tahmin et
2. Veriyi anahtar uzunluğuna göre bloklara böl
3. Her blok için tek byte XOR kır
4. Anahtarı birleştir ve deşifre et

---

### 6. Hash Kırıcı

**Ne Yapar:** Dictionary attack ile hash değerini kırar.

**Kullanım:**
```python
from cryptobreaker import HashCracker

# MD5 hash
hash_value = "5f4dcc3b5aa765d61d8327deb882cf99"
password = HashCracker.crack_hash(hash_value, hash_type='md5')

print(password)  # "password"
```

**Desteklenen Hash Tipleri:**
- `md5` - MD5
- `sha1` - SHA-1
- `sha256` - SHA-256

**Özel Wordlist:**
```python
# Kendi wordlist'inizi kullanın
wordlist = ['password', 'admin', '123456', ...]
password = HashCracker.crack_hash(
    hash_value, 
    hash_type='md5',
    wordlist=wordlist
)
```

**Varsayılan Wordlist:**
- Yaygın parolalar (~50 adet)
- Sayılar (0-9999)
- Kelime + sayı kombinasyonları

---

### 7. ECB Mode Tespit Edici

**Ne Yapar:** Tekrarlayan blokları tespit ederek ECB modunu belirler.

**Kullanım:**
```python
from cryptobreaker import ECBDetector

ciphertext = bytes.fromhex("0123456789abcdef...")

result = ECBDetector.detect_ecb(ciphertext, block_size=16)

if result['is_ecb']:
    print("⚠ ECB modu tespit edildi!")
    print(f"Tekrarlayan blok: {len(result['repeated_blocks'])}")
```

**Parametreler:**
- `ciphertext` (bytes): Şifreli veri
- `block_size` (int): Blok boyutu (AES için 16, varsayılan: 16)
- `verbose` (bool): Detaylı çıktı

**Dönüş:**
- Dict:
  - `is_ecb`: ECB modu tespit edildi mi?
  - `ecb_score`: ECB olasılık skoru (%)
  - `total_blocks`: Toplam blok sayısı
  - `unique_blocks`: Benzersiz blok sayısı
  - `repeated_blocks`: Tekrarlayan bloklar
  - `unique_ratio`: Benzersiz blok oranı

---

## 💡 Kullanım Örnekleri

### Örnek 1: CTF Challenge

```python
# CTF'de verilen şifreli metin
ciphertext = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"

# Caesar dene
from cryptobreaker import CaesarCipher
result = CaesarCipher.crack(ciphertext, verbose=False)
print(result[0]['plaintext'])
# "The quick brown fox jumps over the lazy dog"
```

### Örnek 2: XOR Encrypted File

```python
# Dosyadan şifreli veri oku
with open('encrypted.bin', 'rb') as f:
    ciphertext = f.read()

# XOR kır
from cryptobreaker import XORCracker
results = XORCracker.crack_repeating_key(ciphertext)

# Sonucu kaydet
with open('decrypted.txt', 'w') as f:
    f.write(results[0]['plaintext'])
```

### Örnek 3: Password Hash Cracking

```python
# Veritabanından alınan hash'ler
hashes = {
    'user1': '5f4dcc3b5aa765d61d8327deb882cf99',  # MD5
    'user2': '8be3c943b1609fffbfc51aad666d0a04adf83c9d',  # SHA1
}

from cryptobreaker import HashCracker

for user, hash_val in hashes.items():
    # Hash tipini uzunluktan tahmin et
    if len(hash_val) == 32:
        hash_type = 'md5'
    elif len(hash_val) == 40:
        hash_type = 'sha1'
    else:
        hash_type = 'sha256'
    
    password = HashCracker.crack_hash(hash_val, hash_type, verbose=False)
    
    if password:
        print(f"{user}: {password}")
```

### Örnek 4: ECB Oracle Attack

```python
# Şifreli veriyi analiz et
with open('encrypted_image.bin', 'rb') as f:
    ciphertext = f.read()

from cryptobreaker import ECBDetector

result = ECBDetector.detect_ecb(ciphertext, block_size=16)

if result['is_ecb']:
    print("⚠ ECB modu kullanılmış!")
    print("  Patern analizi ile bilgi sızıntısı olabilir")
    print(f"  Benzersiz oran: %{result['unique_ratio']*100:.1f}")
```

---

## 🎯 Gerçek Dünya Senaryoları

### Senaryo 1: Eski Sistem Şifresi

**Durum:** Eski bir sistemde Caesar şifresi kullanılmış.

```python
from cryptobreaker import CaesarCipher

# Sistemden alınan şifreli log
log_entry = "Xvhu orjjhg lq dw 14:30"

result = CaesarCipher.crack(log_entry, verbose=False)
print(result[0]['plaintext'])
# "User logged in at 14:30"
```

### Senaryo 2: Zayıf XOR Implementasyonu

**Durum:** Bir uygulama config dosyasını tek byte XOR ile şifrelemiş.

```python
from cryptobreaker import XORCracker

# Config dosyasından okunan veri
config_encrypted = bytes.fromhex("2e4b4a5e4b...")

results = XORCracker.crack_single_byte(config_encrypted)

if results:
    print("Config çözüldü:")
    print(results[0]['plaintext'])
    # "database_password=admin123"
```

### Senaryo 3: Sızdırılmış Hash Veritabanı

**Durum:** Bir veri ihlalinde MD5 hash'ler sızdırılmış.

```python
from cryptobreaker import HashCracker

leaked_hashes = [
    "5f4dcc3b5aa765d61d8327deb882cf99",
    "e10adc3949ba59abbe56e057f20f883e",
    "25d55ad283aa400af464c76d713c07ad"
]

print("Kırılan parolalar:")
for hash_val in leaked_hashes:
    password = HashCracker.crack_hash(hash_val, 'md5', verbose=False)
    if password:
        print(f"  {hash_val[:16]}... → {password}")
```

---

## 🔬 İleri Seviye Kullanım

### Özel Frekans Tablosu

```python
from cryptobreaker import SubstitutionCipher

# Kendi frekans tablonuzu tanımlayın
cipher = SubstitutionCipher()
cipher.custom_freq = {
    'x': 15.0, 'y': 12.0, 'z': 10.0,
    # ... diğer harfler
}

result = cipher.crack(ciphertext, language='custom')
```

### Çoklu Dil Desteği

```python
from cryptobreaker import VigenereCipher

# Türkçe metin için
ciphertext_tr = "ŞÖFRÖLÜ MÖSÖJ..."
result = VigenereCipher.crack(ciphertext_tr)

# Frekans analizi otomatik olarak en uygun dili seçer
```

### Paralel Hash Kırma

```python
import concurrent.futures
from cryptobreaker import HashCracker

hashes = ['hash1', 'hash2', 'hash3', ...]

def crack_single(hash_val):
    return HashCracker.crack_hash(hash_val, 'md5', verbose=False)

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(crack_single, hashes))

for hash_val, password in zip(hashes, results):
    if password:
        print(f"{hash_val} → {password}")
```

---

## 📊 Performans ve Sınırlamalar

### Performans

| Saldırı Türü | Hız | Başarı Oranı |
|--------------|-----|--------------|
| Caesar | Anında (26 deneme) | %100 |
| Vigenère | 1-5 saniye | %80-90 |
| Substitution | 1-2 saniye | %60-70 (manuel düzeltme gerekebilir) |
| XOR (Tek Byte) | <1 saniye | %95 |
| XOR (Tekrarlayan) | 2-10 saniye | %85 |
| Hash (MD5) | Wordlist'e bağlı | Wordlist'e bağlı |
| ECB Tespiti | Anında | %100 |

### Sınırlamalar

**Caesar & Vigenère:**
- Sadece İngilizce alfabesi (A-Z)
- Türkçe karakterler (ğüşıöçĞÜŞİÖÇ) desteklenmez

**Substitution:**
- Tam otomatik kırılamaz
- Manuel düzeltme gerekebilir
- Kısa metinlerde başarı oranı düşer

**XOR:**
- UTF-8 encoding varsayılır
- Binary veri için özel işlem gerekebilir

**Hash:**
- Wordlist kalitesine bağlı
- Güçlü parolalar kırılamaz
- Salt'lı hash'ler desteklenmez

---

## 🛡️ Güvenlik Tavsiyeleri

### Kendinizi Koruyun

**Caesar/Vigenère'ye Karşı:**
- ✅ Modern şifreleme kullanın (AES-256)
- ✅ Klasik şifreler sadece eğitim amaçlı

**XOR'a Karşı:**
- ✅ Tek byte XOR kullanmayın
- ✅ Kriptografik olarak güvenli RNG kullanın
- ✅ Anahtar uzunluğu mesaj uzunluğu kadar olmalı (One-Time Pad)

**Hash'e Karşı:**
- ✅ Güçlü parola kullanın (12+ karakter, karışık)
- ✅ Salt ekleyin (her kullanıcı için farklı)
- ✅ Yavaş hash kullanın (bcrypt, Argon2)
- ✅ MD5/SHA1 kullanmayın (kırılmış)

**ECB'ye Karşı:**
- ✅ ECB modu kullanmayın
- ✅ CBC, GCM veya CTR modu kullanın
- ✅ Her şifreleme için farklı IV

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen:

1. Fork yapın
2. Feature branch oluşturun
3. Değişikliklerinizi commit edin
4. Pull request gönderin

**Eklenebilecek Özellikler:**
- RSA saldırıları
- Padding oracle attack
- Timing attack
- Rainbow table desteği
- GPU hızlandırma
- Daha fazla hash tipi

---

## 📝 Lisans

Bu proje **eğitim amaçlı** geliştirilmiştir.

**İzinler:**
- ✅ Eğitim ve öğrenim
- ✅ Güvenlik araştırması
- ✅ Yasal penetrasyon testleri

**Yasak:**
- ❌ İzinsiz sistemlere saldırı
- ❌ Kötü amaçlı kullanım
- ❌ Yasa dışı aktiviteler

---

## 📞 Destek ve İletişim

**Sorunlar:** GitHub Issues  
**Dokümantasyon:** Bu README  
**Örnekler:** `cryptobreaker_examples.py`

---

## 🎓 Öğrenme Kaynakları

**Kriptografi:**
- [Applied Cryptography - Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)
- [The Code Book - Simon Singh](https://simonsingh.net/books/the-code-book/)
- [Cryptopals Challenges](https://cryptopals.com/)

**Kriptanaliz:**
- [Handbook of Applied Cryptography](http://cacr.uwaterloo.ca/hac/)
- [Practical Cryptography](http://practicalcryptography.com/)

---

**Versiyon:** 1.0  
**Son Güncelleme:** Aralık 2025  
**Durum:** Aktif Geliştirme

*"Güvenlik, saldırıyı anlamakla başlar."*
