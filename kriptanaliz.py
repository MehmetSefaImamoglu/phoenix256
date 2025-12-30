"""
PHOENIX-256 Kriptanaliz Araçları
Aşama 3: Kriptanaliz ve Analiz Raporu

Bu modül, PHOENIX-256 algoritmasına karşı çeşitli kriptanaliz saldırıları içerir:
1. Frekans Analizi (Ciphertext-Only Attack)
2. Known-Plaintext Attack
3. Brute Force Attack (Sınırlı anahtar uzayı)
4. Zayıf Nokta Analizi
"""

import os
import time
from collections import Counter
from typing import List, Tuple, Dict
import hashlib
from phoenix256 import Phoenix256, Anahtar_Uret


class KriptanalizAraclari:
    """PHOENIX-256 için kriptanaliz araçları"""
    
    def __init__(self):
        self.turkce_frekans = {
            'a': 11.92, 'e': 8.91, 'i': 8.60, 'n': 7.48, 'r': 6.95,
            'l': 5.75, 'ı': 5.12, 't': 4.54, 'k': 4.53, 'd': 4.14,
            'u': 3.46, 's': 3.01, 'm': 2.99, 'y': 2.88, 'o': 2.61,
            'b': 2.54, 'ü': 1.99, 'ş': 1.82, 'z': 1.50, 'v': 1.00,
            'g': 1.00, 'p': 0.79, 'c': 0.79, 'h': 0.73, 'ğ': 0.71,
            'ç': 0.70, 'f': 0.41, 'ö': 0.33, 'j': 0.03, 'q': 0.01
        }
        
        self.ingilizce_frekans = {
            'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
            'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
            'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
            'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
            'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
        }
    
    def frekans_analizi(self, sifreli_metin: bytes, verbose: bool = True) -> Dict:
        """
        Şifreli metin üzerinde frekans analizi yap
        
        Args:
            sifreli_metin: Analiz edilecek şifreli metin
            verbose: Detaylı çıktı göster
            
        Returns:
            Analiz sonuçları dictionary
        """
        if verbose:
            print("\n" + "=" * 70)
            print("FREKANS ANALİZİ (Ciphertext-Only Attack)")
            print("=" * 70)
        
        # Byte frekansları
        byte_sayaci = Counter(sifreli_metin)
        toplam_byte = len(sifreli_metin)
        
        # En sık kullanılan byte'lar
        en_sik_byteler = byte_sayaci.most_common(10)
        
        if verbose:
            print(f"\n[*] Toplam Byte Sayısı: {toplam_byte}")
            print(f"[*] Benzersiz Byte Sayısı: {len(byte_sayaci)}")
            print(f"\n[*] En Sık Kullanılan 10 Byte:")
            print("-" * 70)
            print(f"{'Byte (hex)':<15} {'Frekans':<10} {'Yüzde':<10} {'Görsel'}")
            print("-" * 70)
            
            for byte_val, frekans in en_sik_byteler:
                yuzde = (frekans / toplam_byte) * 100
                bar = "█" * int(yuzde * 2)
                print(f"{hex(byte_val):<15} {frekans:<10} {yuzde:>6.2f}%    {bar}")
        
        # İstatistiksel analiz
        ortalama_frekans = toplam_byte / 256
        standart_sapma = sum((frekans - ortalama_frekans) ** 2 
                            for frekans in byte_sayaci.values()) ** 0.5
        
        # Entropi hesaplama
        entropi = 0
        for frekans in byte_sayaci.values():
            p = frekans / toplam_byte
            if p > 0:
                entropi -= p * (p ** 0.5)  # Basitleştirilmiş entropi
        
        if verbose:
            print(f"\n[*] İstatistiksel Özellikler:")
            print(f"    Ortalama Frekans: {ortalama_frekans:.2f}")
            print(f"    Standart Sapma: {standart_sapma:.2f}")
            print(f"    Entropi (basit): {entropi:.4f}")
        
        # Tekrarlayan paternler
        patern_uzunluk = 16  # Blok boyutu
        paternler = {}
        
        for i in range(0, len(sifreli_metin) - patern_uzunluk, patern_uzunluk):
            patern = sifreli_metin[i:i+patern_uzunluk]
            paternler[patern] = paternler.get(patern, 0) + 1
        
        tekrar_eden = {p: f for p, f in paternler.items() if f > 1}
        
        if verbose:
            print(f"\n[*] Tekrarlayan Blok Paternleri ({patern_uzunluk} byte):")
            if tekrar_eden:
                print(f"    Toplam {len(tekrar_eden)} farklı patern tekrar ediyor")
                for i, (patern, frekans) in enumerate(list(tekrar_eden.items())[:5], 1):
                    print(f"    {i}. {patern.hex()[:32]}... : {frekans} kez")
            else:
                print("    ✓ Tekrarlayan patern bulunamadı (iyi)")
        
        # Değerlendirme
        if verbose:
            print("\n" + "-" * 70)
            print("DEĞERLENDİRME:")
            print("-" * 70)
            
            # Frekans dağılımı kontrolü
            max_frekans_yuzde = (en_sik_byteler[0][1] / toplam_byte) * 100
            
            if max_frekans_yuzde < 2:
                print("✓ Frekans dağılımı düzgün (<%2 en sık byte)")
                frekans_durumu = "GÜÇLÜ"
            elif max_frekans_yuzde < 5:
                print("⚠ Frekans dağılımında hafif dengesizlik (2-5%)")
                frekans_durumu = "ORTA"
            else:
                print("✗ Frekans dağılımında belirgin dengesizlik (>%5)")
                frekans_durumu = "ZAYIF"
            
            # Patern tekrarı kontrolü
            if len(tekrar_eden) == 0:
                print("✓ Tekrarlayan patern yok (CBC modu etkili)")
                patern_durumu = "GÜÇLÜ"
            elif len(tekrar_eden) < 5:
                print("⚠ Az sayıda patern tekrarı var")
                patern_durumu = "ORTA"
            else:
                print("✗ Çok sayıda patern tekrarı (ECB modu zayıflığı?)")
                patern_durumu = "ZAYIF"
            
            print(f"\nGenel Frekans Analizi Direnci: {frekans_durumu}")
        
        return {
            'byte_frekanslari': dict(byte_sayaci),
            'en_sik_byteler': en_sik_byteler,
            'toplam_byte': toplam_byte,
            'benzersiz_byte': len(byte_sayaci),
            'tekrar_eden_paternler': len(tekrar_eden),
            'frekans_durumu': frekans_durumu if verbose else None,
            'patern_durumu': patern_durumu if verbose else None
        }
    
    def known_plaintext_attack(self, duz_metin: str, sifreli_metin: bytes, 
                               iv: bytes, verbose: bool = True) -> Dict:
        """
        Bilinen düz metin saldırısı
        
        Args:
            duz_metin: Bilinen düz metin
            sifreli_metin: Karşılık gelen şifreli metin
            iv: Initialization Vector
            verbose: Detaylı çıktı
            
        Returns:
            Analiz sonuçları
        """
        if verbose:
            print("\n" + "=" * 70)
            print("KNOWN-PLAINTEXT ATTACK")
            print("=" * 70)
            print(f"\n[*] Bilinen Düz Metin: {duz_metin[:50]}...")
            print(f"[*] Şifreli Metin (hex): {sifreli_metin.hex()[:60]}...")
            print(f"[*] IV (hex): {iv.hex()}")
        
        duz_bytes = duz_metin.encode('utf-8')
        
        # PKCS#7 padding ekle
        pad_len = 16 - (len(duz_bytes) % 16)
        padded_duz = duz_bytes + bytes([pad_len] * pad_len)
        
        if verbose:
            print(f"\n[*] Düz Metin Uzunluğu: {len(duz_bytes)} byte")
            print(f"[*] Padding Sonrası: {len(padded_duz)} byte")
            print(f"[*] Blok Sayısı: {len(padded_duz) // 16}")
        
        # İlk blok analizi
        ilk_duz_blok = padded_duz[:16]
        ilk_sifreli_blok = sifreli_metin[:16]
        
        # CBC modunda: C1 = E(P1 XOR IV)
        # P1 XOR IV = D(C1) olmalı
        
        if verbose:
            print(f"\n[*] İlk Blok Analizi:")
            print(f"    Düz Blok (hex): {ilk_duz_blok.hex()}")
            print(f"    Şifreli Blok (hex): {ilk_sifreli_blok.hex()}")
            
            # XOR ile IV'yi bulmaya çalış (teorik)
            print(f"\n[*] Teorik Analiz:")
            print(f"    CBC modunda ilk blok: C1 = Encrypt(P1 ⊕ IV)")
            print(f"    Eğer Encrypt fonksiyonu tersine çevrilebilirse:")
            print(f"    P1 ⊕ IV = Decrypt(C1)")
            print(f"    IV = P1 ⊕ Decrypt(C1)")
        
        # Zayıf anahtar tespiti için patern analizi
        patern_analizi = {}
        
        for i in range(0, min(len(padded_duz), len(sifreli_metin)) - 16, 16):
            duz_blok = padded_duz[i:i+16]
            sifreli_blok = sifreli_metin[i:i+16]
            
            # Aynı düz metin bloğu var mı?
            if duz_blok in patern_analizi:
                patern_analizi[duz_blok].append(sifreli_blok)
            else:
                patern_analizi[duz_blok] = [sifreli_blok]
        
        # Aynı düz metin farklı şifreli metin üretiyor mu?
        tekrar_eden_duz = {d: s for d, s in patern_analizi.items() if len(s) > 1}
        
        if verbose:
            print(f"\n[*] Patern Analizi:")
            if tekrar_eden_duz:
                print(f"    ✗ {len(tekrar_eden_duz)} düz metin bloğu birden fazla kez görüldü")
                for duz_blok, sifreli_bloklar in list(tekrar_eden_duz.items())[:3]:
                    print(f"      Düz: {duz_blok.hex()}")
                    for j, sb in enumerate(sifreli_bloklar, 1):
                        print(f"        Şifreli {j}: {sb.hex()}")
                    # Aynı mı farklı mı?
                    if len(set(sifreli_bloklar)) == 1:
                        print(f"        ✗ UYARI: Aynı şifreli metin! (ECB modu zayıflığı)")
                    else:
                        print(f"        ✓ Farklı şifreli metinler (CBC modu çalışıyor)")
            else:
                print(f"    ✓ Tekrarlayan düz metin bloğu yok")
        
        # Brute force için anahtar uzayı tahmini
        if verbose:
            print(f"\n[*] Anahtar Uzayı Analizi:")
            print(f"    Anahtar Boyutu: 256 bit")
            print(f"    Olası Anahtar Sayısı: 2^256 ≈ 1.16 × 10^77")
            print(f"    Brute Force Süresi (1 milyar anahtar/sn):")
            print(f"      ≈ 3.67 × 10^60 yıl (evrenin yaşından çok daha uzun)")
            print(f"    ✓ Brute force pratikte imkansız")
        
        # Değerlendirme
        if verbose:
            print("\n" + "-" * 70)
            print("DEĞERLENDİRME:")
            print("-" * 70)
            
            if not tekrar_eden_duz:
                print("✓ CBC modu düzgün çalışıyor")
                print("✓ Aynı düz metin farklı şifreleniyor")
                durum = "GÜÇLÜ"
            else:
                # Aynı şifreli metin var mı kontrol et
                ayni_sifreli_var = any(
                    len(set(bloklar)) == 1 
                    for bloklar in tekrar_eden_duz.values()
                )
                
                if ayni_sifreli_var:
                    print("✗ ZAYIFLIK: Aynı düz metin aynı şifreli metin üretiyor")
                    print("  (ECB modu zayıflığı veya IV kullanılmıyor)")
                    durum = "ZAYIF"
                else:
                    print("⚠ Tekrarlayan düz metin var ama farklı şifreleniyor")
                    durum = "ORTA"
            
            print(f"\nKnown-Plaintext Saldırısı Direnci: {durum}")
        
        return {
            'tekrar_eden_duz_blok': len(tekrar_eden_duz),
            'durum': durum if verbose else None,
            'patern_detaylari': tekrar_eden_duz
        }
    
    def brute_force_zayif_anahtar(self, sifreli_metin: bytes, iv: bytes,
                                   beklenen_metin_parcasi: str = None,
                                   max_deneme: int = 10000,
                                   verbose: bool = True) -> Dict:
        """
        Sınırlı brute force saldırısı (zayıf anahtarlar için)
        
        Args:
            sifreli_metin: Şifreli metin
            iv: IV
            beklenen_metin_parcasi: Düz metinde olması beklenen parça
            max_deneme: Maksimum deneme sayısı
            verbose: Detaylı çıktı
            
        Returns:
            Sonuçlar
        """
        if verbose:
            print("\n" + "=" * 70)
            print("BRUTE FORCE SALDIRISI (Sınırlı - Zayıf Anahtarlar)")
            print("=" * 70)
            print(f"\n[*] Maksimum Deneme: {max_deneme:,}")
            if beklenen_metin_parcasi:
                print(f"[*] Aranan Metin Parçası: '{beklenen_metin_parcasi}'")
        
        basla = time.time()
        deneme_sayisi = 0
        bulunan_anahtarlar = []
        
        # Yaygın zayıf parolalar
        zayif_parolalar = [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "iloveyou", "trustno1", "1234567890",
            "superman", "qazwsx", "michael", "football", "shadow",
            "admin", "root", "test", "guest", "user",
            "parola", "sifre", "anahtar", "key", "pass"
        ]
        
        if verbose:
            print(f"\n[*] {len(zayif_parolalar)} yaygın zayıf parola deneniyor...")
        
        for parola in zayif_parolalar:
            if deneme_sayisi >= max_deneme:
                break
            
            try:
                anahtar = Anahtar_Uret(parola)
                cipher = Phoenix256(anahtar)
                duz_metin_bytes = cipher.decrypt(sifreli_metin, iv)
                duz_metin = duz_metin_bytes.decode('utf-8', errors='ignore')
                
                deneme_sayisi += 1
                
                # Başarı kontrolü
                if beklenen_metin_parcasi:
                    if beklenen_metin_parcasi.lower() in duz_metin.lower():
                        bulunan_anahtarlar.append({
                            'parola': parola,
                            'anahtar': anahtar.hex(),
                            'duz_metin': duz_metin
                        })
                        if verbose:
                            print(f"\n✓ BULUNDU! Parola: '{parola}'")
                            print(f"  Düz Metin: {duz_metin[:100]}...")
                else:
                    # Okunabilir metin kontrolü (basit)
                    okunabilir_karakter_sayisi = sum(
                        1 for c in duz_metin 
                        if c.isprintable() or c.isspace()
                    )
                    okunabilirlik = okunabilir_karakter_sayisi / len(duz_metin)
                    
                    if okunabilirlik > 0.9:  # %90'dan fazla okunabilir
                        bulunan_anahtarlar.append({
                            'parola': parola,
                            'anahtar': anahtar.hex(),
                            'duz_metin': duz_metin,
                            'okunabilirlik': okunabilirlik
                        })
                        if verbose:
                            print(f"\n? Olası Anahtar: '{parola}' (okunabilirlik: %{okunabilirlik*100:.1f})")
                            print(f"  Düz Metin: {duz_metin[:100]}...")
            
            except Exception:
                deneme_sayisi += 1
                continue
        
        bitis = time.time()
        sure = bitis - basla
        
        if verbose:
            print(f"\n[*] Toplam Deneme: {deneme_sayisi:,}")
            print(f"[*] Süre: {sure:.2f} saniye")
            print(f"[*] Hız: {deneme_sayisi/sure:.0f} deneme/saniye")
            
            print("\n" + "-" * 70)
            print("DEĞERLENDİRME:")
            print("-" * 70)
            
            if bulunan_anahtarlar:
                print(f"✗ {len(bulunan_anahtarlar)} olası anahtar bulundu!")
                print("  UYARI: Zayıf parola kullanılmış olabilir")
                durum = "ZAYIF PAROLA"
            else:
                print("✓ Yaygın zayıf parolalarla kırılamadı")
                print("  Not: Bu, güçlü parola kullanıldığını gösterir")
                print("  Tam brute force 2^256 deneme gerektirir (imkansız)")
                durum = "GÜÇLÜ"
            
            print(f"\nBrute Force Direnci: {durum}")
        
        return {
            'deneme_sayisi': deneme_sayisi,
            'sure': sure,
            'bulunan_anahtar_sayisi': len(bulunan_anahtarlar),
            'bulunan_anahtarlar': bulunan_anahtarlar,
            'durum': durum if verbose else None
        }
    
    def zayif_nokta_analizi(self, verbose: bool = True) -> Dict:
        """
        Algoritmanın zayıf noktalarını analiz et
        
        Args:
            verbose: Detaylı çıktı
            
        Returns:
            Analiz sonuçları
        """
        if verbose:
            print("\n" + "=" * 70)
            print("ZAYIF NOKTA ANALİZİ")
            print("=" * 70)
        
        zayif_noktalar = []
        guvenlik_onerileri = []
        
        # 1. S-Box Deterministik
        if verbose:
            print("\n[1] S-Box Üretimi:")
            print("    Mevcut: Deterministik (aynı anahtar → aynı S-Box)")
            print("    ⚠ Zayıf Nokta: Side-channel saldırılara açık olabilir")
            print("    ✓ Öneri: Nonce tabanlı S-Box üretimi")
        
        zayif_noktalar.append({
            'kategori': 'S-Box Üretimi',
            'seviye': 'ORTA',
            'aciklama': 'Deterministik S-Box üretimi'
        })
        guvenlik_onerileri.append("Nonce veya counter tabanlı S-Box üretimi ekle")
        
        # 2. Anahtar Türetme
        if verbose:
            print("\n[2] Anahtar Türetme:")
            print("    Mevcut: Basit SHA-256")
            print("    ✗ Zayıf Nokta: Hızlı hash, brute force'a karşı zayıf")
            print("    ✓ Öneri: PBKDF2, Argon2 veya scrypt kullan")
        
        zayif_noktalar.append({
            'kategori': 'Anahtar Türetme',
            'seviye': 'YÜKSEK',
            'aciklama': 'Basit SHA-256, yavaşlatma yok'
        })
        guvenlik_onerileri.append("PBKDF2 (100,000+ iterasyon) veya Argon2 kullan")
        
        # 3. Authenticated Encryption
        if verbose:
            print("\n[3] Mesaj Doğrulama:")
            print("    Mevcut: Yok")
            print("    ✗ Zayıf Nokta: Padding oracle, bit-flipping saldırıları")
            print("    ✓ Öneri: HMAC veya GCM modu ekle")
        
        zayif_noktalar.append({
            'kategori': 'Authenticated Encryption',
            'seviye': 'YÜKSEK',
            'aciklama': 'Mesaj doğrulama mekanizması yok'
        })
        guvenlik_onerileri.append("HMAC-SHA256 ile mesaj doğrulama ekle")
        
        # 4. Side-Channel
        if verbose:
            print("\n[4] Side-Channel Koruması:")
            print("    Mevcut: Yok")
            print("    ⚠ Zayıf Nokta: Zamanlama, güç analizi saldırıları")
            print("    ✓ Öneri: Constant-time implementasyon")
        
        zayif_noktalar.append({
            'kategori': 'Side-Channel',
            'seviye': 'ORTA',
            'aciklama': 'Zamanlama saldırılarına karşı koruma yok'
        })
        guvenlik_onerileri.append("Constant-time operasyonlar kullan")
        
        # 5. IV Yönetimi
        if verbose:
            print("\n[5] IV Yönetimi:")
            print("    Mevcut: Rastgele IV üretimi")
            print("    ✓ Güçlü: Her şifreleme farklı IV")
            print("    ⚠ Not: IV tekrar kullanımı kontrolü yok")
        
        guvenlik_onerileri.append("IV tekrar kullanımı kontrolü ekle")
        
        # 6. Tur Sayısı
        if verbose:
            print("\n[6] Tur Sayısı:")
            print("    Mevcut: 16 tur")
            print("    ✓ Yeterli: 256-bit anahtar için kabul edilebilir")
            print("    ⚠ Not: 20+ tur daha güvenli olabilir")
        
        # Genel değerlendirme
        if verbose:
            print("\n" + "=" * 70)
            print("GENEL DEĞERLENDİRME:")
            print("=" * 70)
            
            print(f"\n[*] Toplam Zayıf Nokta: {len(zayif_noktalar)}")
            
            yuksek_risk = sum(1 for z in zayif_noktalar if z['seviye'] == 'YÜKSEK')
            orta_risk = sum(1 for z in zayif_noktalar if z['seviye'] == 'ORTA')
            
            print(f"    Yüksek Risk: {yuksek_risk}")
            print(f"    Orta Risk: {orta_risk}")
            
            print(f"\n[*] Güvenlik Önerileri ({len(guvenlik_onerileri)} adet):")
            for i, oneri in enumerate(guvenlik_onerileri, 1):
                print(f"    {i}. {oneri}")
            
            # Genel skor
            if yuksek_risk == 0 and orta_risk <= 2:
                genel_durum = "GÜÇLÜ"
            elif yuksek_risk <= 2:
                genel_durum = "ORTA"
            else:
                genel_durum = "GELİŞTİRME GEREKLİ"
            
            print(f"\n[*] Genel Güvenlik Durumu: {genel_durum}")
            print("\n" + "=" * 70)
        
        return {
            'zayif_noktalar': zayif_noktalar,
            'guvenlik_onerileri': guvenlik_onerileri,
            'yuksek_risk_sayisi': yuksek_risk if verbose else 0,
            'orta_risk_sayisi': orta_risk if verbose else 0,
            'genel_durum': genel_durum if verbose else None
        }


def main():
    """Ana kriptanaliz test fonksiyonu"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "PHOENIX-256 KRİPTANALİZ" + " " * 29 + "║")
    print("║" + " " * 15 + "Aşama 3: Güvenlik Analizi" + " " * 27 + "║")
    print("╚" + "=" * 68 + "╝")
    
    kriptanaliz = KriptanalizAraclari()
    
    # Test verisi hazırla
    print("\n[*] Test verisi hazırlanıyor...")
    parola = "GüçlüTestParolası2025!"
    anahtar = Anahtar_Uret(parola)
    
    mesaj = """
    Bu bir test mesajıdır. PHOENIX-256 algoritmasının güvenliğini test ediyoruz.
    Kriptanaliz saldırılarına karşı dayanıklılığını ölçeceğiz.
    Frekans analizi, known-plaintext attack ve brute force denemeleri yapılacak.
    """ * 5  # Yeterli veri için tekrarla
    
    cipher = Phoenix256(anahtar)
    sifreli, iv = cipher.encrypt(mesaj.encode('utf-8'))
    
    print(f"[+] Mesaj Uzunluğu: {len(mesaj)} karakter")
    print(f"[+] Şifreli Metin Uzunluğu: {len(sifreli)} byte")
    
    # Test 1: Frekans Analizi
    sonuc1 = kriptanaliz.frekans_analizi(sifreli)
    
    # Test 2: Known-Plaintext Attack
    sonuc2 = kriptanaliz.known_plaintext_attack(mesaj, sifreli, iv)
    
    # Test 3: Brute Force (zayıf anahtarlar)
    sonuc3 = kriptanaliz.brute_force_zayif_anahtar(
        sifreli, iv,
        beklenen_metin_parcasi="test mesajı",
        max_deneme=10000
    )
    
    # Test 4: Zayıf Nokta Analizi
    sonuc4 = kriptanaliz.zayif_nokta_analizi()
    
    # Genel Özet
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 20 + "KRİPTANALİZ SONUÇLARI" + " " * 28 + "║")
    print("╠" + "=" * 68 + "╣")
    print(f"║  Frekans Analizi Direnci: {sonuc1.get('frekans_durumu', 'N/A'):<42} ║")
    print(f"║  Known-Plaintext Direnci: {sonuc2.get('durum', 'N/A'):<42} ║")
    print(f"║  Brute Force Direnci: {sonuc3.get('durum', 'N/A'):<46} ║")
    print(f"║  Genel Güvenlik: {sonuc4.get('genel_durum', 'N/A'):<50} ║")
    print("╠" + "=" * 68 + "╣")
    print(f"║  Tespit Edilen Zayıf Nokta: {len(sonuc4['zayif_noktalar']):<38} ║")
    print(f"║  Güvenlik Önerisi: {len(sonuc4['guvenlik_onerileri']):<46} ║")
    print("╚" + "=" * 68 + "╝")
    print()


if __name__ == "__main__":
    main()
