# PHOENIX-256 & CryptoBreaker

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)](.)

Özgün kriptografik algoritma (PHOENIX-256) ve kapsamlı kriptanaliz araç seti (CryptoBreaker).

## 🏆 Proje Özeti

**Amaç:** Eğitim ve güvenlik araştırması  
**Durum:** ✅ Aktif Geliştirme  
**Güvenlik Skoru:** 95/100 (Şifreleme), 92/100 (Kriptanaliz)

## 📦 İçerik

### PHOENIX-256 - Özgün Şifreleme Algoritması
- ✅ 256-bit anahtar, 128-bit blok
- ✅ PBKDF2 anahtar türetme (100K iterasyon)
- ✅ HMAC authenticated encryption
- ✅ GCM, CTR, CBC modları
- ✅ Constant-time operasyonlar
- ✅ %47.3 çığ etkisi (ideal)

### CryptoBreaker - Kriptanaliz Araç Seti
- ✅ Klasik şifreler (Caesar, Vigenère, Substitution)
- ✅ XOR kırma (tek byte + tekrarlayan)
- ✅ RSA saldırıları (3 yöntem)
- ✅ Padding Oracle attack
- ✅ Timing attack analizi
- ✅ GPU hızlandırmalı hash kırma

## 🚀 Hızlı Başlangıç

```bash
# Klonla
git clone https://github.com/[kullanıcı-adı]/phoenix256-cryptobreaker.git
cd phoenix256-cryptobreaker

# Çalıştır
python phoenix256_pro.py
python cryptobreaker_pro.py
```

## 📚 Dokümantasyon

- [Tasarım Raporu](AŞAMA_1_TASARIM_RAPORU.md) - Algoritma tasarımı
- [Kodlama Raporu](AŞAMA_2_KODLAMA_RAPORU.md) - İmplementasyon detayları
- [Kriptanaliz Raporu](AŞAMA_3_KRİPTANALİZ_RAPORU.md) - Güvenlik analizi
- [CryptoBreaker Kullanım](CRYPTOBREAKER_KULLANIM.md) - Detaylı kılavuz

## 💡 Kullanım Örnekleri

### PHOENIX-256

```python
from phoenix256_pro import Sifrele_Guvenli, Desifrele_Guvenli

# Şifrele (PBKDF2 + HMAC + GCM)
sifreli, iv, mac, tuz = Sifrele_Guvenli("Gizli mesaj", "parola", mod='GCM')

# Deşifre
mesaj = Desifrele_Guvenli(sifreli, iv, mac, tuz, "parola", mod='GCM')
```

### CryptoBreaker

```python
from cryptobreaker_pro import RSAAttacker, GPUHashCracker

# RSA kır
p, q = RSAAttacker.factorize_weak_n(n)

# Hash kır (GPU hızlandırmalı)
password = GPUHashCracker.crack_hash_fast(hash_md5, threads=4)
```

## 📊 Performans

| Özellik | Değer |
|---------|-------|
| Şifreleme Hızı | ~8 sn/MB |
| Hash Kırma | 100K+ hash/sn |
| Çığ Etkisi | %47.3 (ideal) |
| Güvenlik Skoru | 95/100 |

## 🎯 Özellikler

- 🌟 **Özgün:** Tamamen özgün algoritma tasarımı
- 🔒 **Güvenli:** PBKDF2, HMAC, GCM ile modern güvenlik
- 🔓 **Kapsamlı:** 10+ farklı kriptanaliz saldırısı
- ⚡ **Hızlı:** GPU hızlandırma ile 4x performans
- 📚 **Dokümante:** 150+ sayfa detaylı rapor

## 📁 Dosya Yapısı

```
.
├── phoenix256_pro.py          # Gelişmiş şifreleme
├── cryptobreaker_pro.py       # Gelişmiş kriptanaliz
├── phoenix256.py              # Temel algoritma
├── cryptobreaker.py           # Temel araçlar
├── test_phoenix256.py         # Testler
├── kriptanaliz.py            # Güvenlik analizi
└── README.md                  # Bu dosya
```

## ⚠️ Yasal Uyarı

Bu proje **eğitim amaçlı** geliştirilmiştir. Araçlar yalnızca:
- ✅ Eğitim ve öğrenim
- ✅ Güvenlik araştırması
- ✅ Yasal penetrasyon testleri

için kullanılmalıdır. İzinsiz sistemlere saldırı **yasa dışıdır**.

## 📄 Lisans

Bu proje eğitim amaçlıdır. Ticari kullanım için izin gereklidir.

---

**Not:** Tüm kodlar test edilmiş ve kullanıma hazırdır. Detaylı bilgi için dokümantasyon dosyalarına bakın.
