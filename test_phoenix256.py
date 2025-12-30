"""
PHOENIX-256 Test Senaryoları
Aşama 2: Algoritmanın Kodlanması - Test ve Doğrulama

Test 1: Basit Doğrulama
Test 2: Anahtar Hassasiyeti (Çığ Etkisi)
"""

import os
from phoenix256 import Phoenix256, Anahtar_Uret, Sifrele, Desifrele


def test_1_basit_dogrulama():
    """
    Test 1: Basit Doğrulama
    Kısa bir metni şifreleyip, deşifre ettikten sonra orijinal düz metinle 
    aynı olduğunu kanıtlama.
    """
    print("\n" + "=" * 70)
    print("TEST 1: BASİT DOĞRULAMA")
    print("=" * 70)
    
    # Test verileri
    test_mesajlari = [
        "Merhaba Dünya!",
        "PHOENIX-256 güvenli bir algoritmadır.",
        "1234567890 !@#$%^&*() ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "Türkçe karakterler: ğüşıöçĞÜŞİÖÇ",
        "Çok uzun bir metin: " + "A" * 1000
    ]
    
    parola = "TestParolası2025!"
    anahtar = Anahtar_Uret(parola)
    
    print(f"\n[*] Kullanılan Parola: {parola}")
    print(f"[*] Anahtar (hex): {anahtar.hex()}")
    print(f"\n[*] Toplam {len(test_mesajlari)} test mesajı denenecek...\n")
    
    basarili = 0
    basarisiz = 0
    
    for i, mesaj in enumerate(test_mesajlari, 1):
        print(f"\n--- Test Mesajı {i} ---")
        mesaj_ozet = mesaj[:50] + "..." if len(mesaj) > 50 else mesaj
        print(f"Düz Metin: {mesaj_ozet}")
        print(f"Uzunluk: {len(mesaj)} karakter")
        
        try:
            # Şifreleme
            sifreli, iv = Sifrele(mesaj, anahtar)
            print(f"Şifreli (hex): {sifreli.hex()[:80]}...")
            print(f"IV (hex): {iv.hex()}")
            
            # Deşifreleme
            cozulmus = Desifrele(sifreli, anahtar, iv)
            
            # Doğrulama
            if mesaj == cozulmus:
                print("✓ BAŞARILI - Orijinal metin ile eşleşiyor")
                basarili += 1
            else:
                print("✗ BAŞARISIZ - Orijinal metin ile eşleşmiyor!")
                print(f"  Beklenen: {mesaj[:50]}")
                print(f"  Alınan: {cozulmus[:50]}")
                basarisiz += 1
                
        except Exception as e:
            print(f"✗ HATA: {str(e)}")
            basarisiz += 1
    
    # Özet
    print("\n" + "-" * 70)
    print(f"TEST 1 SONUÇLARI:")
    print(f"  Başarılı: {basarili}/{len(test_mesajlari)}")
    print(f"  Başarısız: {basarisiz}/{len(test_mesajlari)}")
    print(f"  Başarı Oranı: %{(basarili/len(test_mesajlari)*100):.1f}")
    print("=" * 70)
    
    return basarili == len(test_mesajlari)


def test_2_anahtar_hassasiyeti():
    """
    Test 2: Anahtar Hassasiyeti (Çığ Etkisi)
    Şifreleme sırasında kullanılan anahtarın tek bir bitini değiştirip, 
    deşifreleme sonucunun tamamen anlamsız olduğunu gösterme.
    """
    print("\n" + "=" * 70)
    print("TEST 2: ANAHTAR HASSASİYETİ (ÇIĞ ETKİSİ)")
    print("=" * 70)
    
    # Test mesajı
    mesaj = "Bu mesaj anahtar hassasiyetini test etmek için kullanılıyor."
    print(f"\n[*] Test Mesajı: {mesaj}")
    
    # Orijinal anahtar
    parola = "OrijinalAnahtar123"
    anahtar1 = Anahtar_Uret(parola)
    print(f"\n[*] Orijinal Anahtar (hex): {anahtar1.hex()}")
    
    # Sabit IV kullan (aynı şifreli metni elde etmek için)
    iv = os.urandom(16)
    print(f"[*] IV (hex): {iv.hex()}")
    
    # Orijinal anahtar ile şifreleme
    cipher1 = Phoenix256(anahtar1)
    sifreli1, _ = cipher1.encrypt(mesaj.encode('utf-8'), iv)
    print(f"\n[+] Orijinal Anahtar ile Şifreli Metin (hex):")
    print(f"    {sifreli1.hex()}")
    
    # Anahtarın tek bir bitini değiştir
    anahtar2_list = bytearray(anahtar1)
    # İlk byte'ın ilk bitini değiştir (XOR ile)
    anahtar2_list[0] ^= 0x01
    anahtar2 = bytes(anahtar2_list)
    
    print(f"\n[*] Değiştirilmiş Anahtar (1 bit farklı) (hex): {anahtar2.hex()}")
    
    # Fark analizi
    fark_sayisi = sum(bin(a ^ b).count('1') for a, b in zip(anahtar1, anahtar2))
    print(f"[*] Anahtarlar arası bit farkı: {fark_sayisi} bit (256 bit içinde)")
    
    # Değiştirilmiş anahtar ile şifreleme
    cipher2 = Phoenix256(anahtar2)
    sifreli2, _ = cipher2.encrypt(mesaj.encode('utf-8'), iv)
    print(f"\n[+] Değiştirilmiş Anahtar ile Şifreli Metin (hex):")
    print(f"    {sifreli2.hex()}")
    
    # Şifreli metinleri karşılaştır
    print("\n" + "-" * 70)
    print("ŞİFRELİ METİN KARŞILAŞTIRMASI:")
    print("-" * 70)
    
    # Bit farkı hesapla
    bit_farki = sum(bin(a ^ b).count('1') for a, b in zip(sifreli1, sifreli2))
    toplam_bit = len(sifreli1) * 8
    fark_yuzdesi = (bit_farki / toplam_bit) * 100
    
    print(f"Toplam Bit Sayısı: {toplam_bit}")
    print(f"Farklı Bit Sayısı: {bit_farki}")
    print(f"Fark Yüzdesi: %{fark_yuzdesi:.2f}")
    
    # Byte farkı
    byte_farki = sum(1 for a, b in zip(sifreli1, sifreli2) if a != b)
    byte_fark_yuzdesi = (byte_farki / len(sifreli1)) * 100
    print(f"\nFarklı Byte Sayısı: {byte_farki}/{len(sifreli1)}")
    print(f"Byte Fark Yüzdesi: %{byte_fark_yuzdesi:.2f}")
    
    # Çığ etkisi değerlendirmesi
    print("\n" + "-" * 70)
    print("ÇIĞ ETKİSİ DEĞERLENDİRMESİ:")
    print("-" * 70)
    
    # İdeal çığ etkisi %50 civarındadır
    if 45 <= fark_yuzdesi <= 55:
        print(f"✓ MÜKEMMEL - Çığ etkisi ideal aralıkta (%{fark_yuzdesi:.2f})")
        cig_durumu = "MÜKEMMEL"
    elif 40 <= fark_yuzdesi <= 60:
        print(f"✓ İYİ - Çığ etkisi kabul edilebilir aralıkta (%{fark_yuzdesi:.2f})")
        cig_durumu = "İYİ"
    elif 30 <= fark_yuzdesi <= 70:
        print(f"⚠ ORTA - Çığ etkisi orta seviyede (%{fark_yuzdesi:.2f})")
        cig_durumu = "ORTA"
    else:
        print(f"✗ ZAYIF - Çığ etkisi yetersiz (%{fark_yuzdesi:.2f})")
        cig_durumu = "ZAYIF"
    
    # Yanlış anahtar ile deşifreleme denemesi
    print("\n" + "-" * 70)
    print("YANLIŞ ANAHTAR İLE DEŞİFRELEME:")
    print("-" * 70)
    
    try:
        yanlis_cozum = cipher2.decrypt(sifreli1, iv)
        yanlis_metin = yanlis_cozum.decode('utf-8', errors='replace')
        print(f"Orijinal Mesaj: {mesaj}")
        print(f"Yanlış Anahtar ile Çözüm: {yanlis_metin}")
        
        # Benzerlik kontrolü
        if mesaj == yanlis_metin:
            print("✗ UYARI: Yanlış anahtar doğru sonuç verdi! (Güvenlik açığı)")
            benzerlik = "AYNI"
        else:
            # Karakter benzerliği
            benzer_karakter = sum(1 for a, b in zip(mesaj, yanlis_metin) if a == b)
            benzerlik_yuzdesi = (benzer_karakter / len(mesaj)) * 100
            print(f"Benzer Karakter Sayısı: {benzer_karakter}/{len(mesaj)}")
            print(f"Benzerlik: %{benzerlik_yuzdesi:.2f}")
            
            if benzerlik_yuzdesi < 10:
                print("✓ BAŞARILI - Yanlış anahtar tamamen farklı sonuç verdi")
                benzerlik = "FARKLI"
            else:
                print(f"⚠ UYARI - Yanlış anahtar bazı karakterleri doğru çözdü (%{benzerlik_yuzdesi:.2f})")
                benzerlik = "KISMİ"
    except Exception as e:
        print(f"✓ MÜKEMMEL - Yanlış anahtar deşifreleme hatası verdi: {str(e)}")
        benzerlik = "HATA"
    
    # Özet
    print("\n" + "=" * 70)
    print("TEST 2 SONUÇLARI:")
    print(f"  Çığ Etkisi: {cig_durumu} (%{fark_yuzdesi:.2f} bit değişimi)")
    print(f"  Yanlış Anahtar Sonucu: {benzerlik}")
    
    # Başarı kriteri: Çığ etkisi en az %40 ve yanlış anahtar farklı sonuç vermeli
    basarili = (fark_yuzdesi >= 40) and (benzerlik in ["FARKLI", "HATA"])
    
    if basarili:
        print(f"  Genel Değerlendirme: ✓ BAŞARILI")
    else:
        print(f"  Genel Değerlendirme: ✗ GELİŞTİRME GEREKLİ")
    
    print("=" * 70)
    
    return basarili


def test_3_ek_guvenlik_testleri():
    """
    Test 3: Ek Güvenlik Testleri
    - Aynı mesajın farklı IV ile farklı şifrelenmesi
    - Farklı uzunluklarda mesajların doğru işlenmesi
    - Özel karakterler ve binary veri desteği
    """
    print("\n" + "=" * 70)
    print("TEST 3: EK GÜVENLİK TESTLERİ")
    print("=" * 70)
    
    anahtar = Anahtar_Uret("TestAnahtarı123")
    cipher = Phoenix256(anahtar)
    
    # Test 3.1: Aynı mesaj, farklı IV
    print("\n[Test 3.1] Aynı Mesaj, Farklı IV")
    print("-" * 70)
    mesaj = "Aynı mesaj, farklı şifreli metin olmalı"
    
    sifreli1, iv1 = cipher.encrypt(mesaj.encode('utf-8'))
    sifreli2, iv2 = cipher.encrypt(mesaj.encode('utf-8'))
    
    print(f"Mesaj: {mesaj}")
    print(f"Şifreli 1 (hex): {sifreli1.hex()[:60]}...")
    print(f"Şifreli 2 (hex): {sifreli2.hex()[:60]}...")
    
    if sifreli1 != sifreli2:
        print("✓ BAŞARILI - Farklı IV'ler farklı şifreli metin üretiyor")
        test_3_1 = True
    else:
        print("✗ BAŞARISIZ - Aynı şifreli metin üretildi!")
        test_3_1 = False
    
    # Test 3.2: Farklı uzunluklar
    print("\n[Test 3.2] Farklı Mesaj Uzunlukları")
    print("-" * 70)
    
    uzunluklar = [1, 15, 16, 17, 32, 100, 256, 1000]
    test_3_2 = True
    
    for uzunluk in uzunluklar:
        mesaj = "X" * uzunluk
        try:
            sifreli, iv = cipher.encrypt(mesaj.encode('utf-8'))
            cozulmus = cipher.decrypt(sifreli, iv).decode('utf-8')
            
            if mesaj == cozulmus:
                print(f"  {uzunluk:4d} byte: ✓ Başarılı")
            else:
                print(f"  {uzunluk:4d} byte: ✗ Başarısız")
                test_3_2 = False
        except Exception as e:
            print(f"  {uzunluk:4d} byte: ✗ Hata - {str(e)}")
            test_3_2 = False
    
    # Test 3.3: Binary veri
    print("\n[Test 3.3] Binary Veri Desteği")
    print("-" * 70)
    
    binary_data = os.urandom(256)
    print(f"Binary veri (hex): {binary_data.hex()[:60]}...")
    
    try:
        sifreli, iv = cipher.encrypt(binary_data)
        cozulmus = cipher.decrypt(sifreli, iv)
        
        if binary_data == cozulmus:
            print("✓ BAŞARILI - Binary veri doğru şifrelendi/deşifrelendi")
            test_3_3 = True
        else:
            print("✗ BAŞARISIZ - Binary veri bozuldu")
            test_3_3 = False
    except Exception as e:
        print(f"✗ HATA: {str(e)}")
        test_3_3 = False
    
    # Özet
    print("\n" + "=" * 70)
    print("TEST 3 SONUÇLARI:")
    print(f"  3.1 Farklı IV: {'✓ BAŞARILI' if test_3_1 else '✗ BAŞARISIZ'}")
    print(f"  3.2 Farklı Uzunluklar: {'✓ BAŞARILI' if test_3_2 else '✗ BAŞARISIZ'}")
    print(f"  3.3 Binary Veri: {'✓ BAŞARILI' if test_3_3 else '✗ BAŞARISIZ'}")
    print("=" * 70)
    
    return test_3_1 and test_3_2 and test_3_3


def main():
    """Ana test fonksiyonu"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "PHOENIX-256 TEST SÜİTİ" + " " * 30 + "║")
    print("║" + " " * 15 + "Aşama 2: Test ve Doğrulama" + " " * 26 + "║")
    print("╚" + "=" * 68 + "╝")
    
    # Testleri çalıştır
    sonuclar = {}
    
    try:
        sonuclar['Test 1'] = test_1_basit_dogrulama()
    except Exception as e:
        print(f"\n✗ Test 1 Hatası: {str(e)}")
        sonuclar['Test 1'] = False
    
    try:
        sonuclar['Test 2'] = test_2_anahtar_hassasiyeti()
    except Exception as e:
        print(f"\n✗ Test 2 Hatası: {str(e)}")
        sonuclar['Test 2'] = False
    
    try:
        sonuclar['Test 3'] = test_3_ek_guvenlik_testleri()
    except Exception as e:
        print(f"\n✗ Test 3 Hatası: {str(e)}")
        sonuclar['Test 3'] = False
    
    # Genel özet
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 22 + "GENEL TEST SONUÇLARI" + " " * 27 + "║")
    print("╠" + "=" * 68 + "╣")
    
    for test_adi, sonuc in sonuclar.items():
        durum = "✓ BAŞARILI" if sonuc else "✗ BAŞARISIZ"
        print(f"║  {test_adi:20s} : {durum:45s} ║")
    
    print("╠" + "=" * 68 + "╣")
    
    basarili_sayi = sum(1 for s in sonuclar.values() if s)
    toplam = len(sonuclar)
    basari_orani = (basarili_sayi / toplam) * 100
    
    print(f"║  Başarılı Testler: {basarili_sayi}/{toplam}" + " " * 47 + "║")
    print(f"║  Başarı Oranı: %{basari_orani:.1f}" + " " * 50 + "║")
    
    if basarili_sayi == toplam:
        print("║" + " " * 68 + "║")
        print("║  " + "🎉 TÜM TESTLER BAŞARILI! Algoritma doğru çalışıyor." + " " * 13 + "║")
    else:
        print("║" + " " * 68 + "║")
        print("║  " + "⚠ Bazı testler başarısız. Algoritma gözden geçirilmeli." + " " * 9 + "║")
    
    print("╚" + "=" * 68 + "╝")
    print()


if __name__ == "__main__":
    main()
