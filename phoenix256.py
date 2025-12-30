"""
PHOENIX-256 Kriptografik Algoritma
Polymorphic Hybrid Obfuscation Engine with Nested Iteration eXtension

Blok Şifreleme Algoritması
- Blok Boyutu: 128-bit (16 byte)
- Anahtar Boyutu: 256-bit (32 byte)
- Tur Sayısı: 16
- Mod: CBC (Cipher Block Chaining)

Geliştirme: Aralık 2025
Amaç: Eğitim ve Kriptanaliz Çalışması
"""

import hashlib
import os
from typing import List, Tuple


class Phoenix256:
    """PHOENIX-256 Blok Şifreleme Algoritması"""
    
    # Sabitler
    BLOCK_SIZE = 16  # 128-bit = 16 byte
    KEY_SIZE = 32    # 256-bit = 32 byte
    NUM_ROUNDS = 16
    
    # GF(2^8) çarpımı için indirgeme polinomu
    GF_POLY = 0x1B  # x^8 + x^4 + x^3 + x + 1
    
    def __init__(self, key: bytes):
        """
        PHOENIX-256 şifreleme nesnesi oluştur
        
        Args:
            key: 256-bit (32 byte) şifreleme anahtarı
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Anahtar boyutu {self.KEY_SIZE} byte olmalıdır, {len(key)} byte verildi")
        
        self.master_key = key
        self.round_keys = self._key_expansion(key)
    
    def _key_expansion(self, key: bytes) -> List[bytes]:
        """
        Ana anahtardan 16 tur anahtarı üret
        
        Args:
            key: 256-bit ana anahtar
            
        Returns:
            16 adet 128-bit tur anahtarı listesi
        """
        round_keys = []
        
        # İlk iki tur anahtarı doğrudan ana anahtardan
        round_keys.append(key[:16])  # RK1
        round_keys.append(key[16:])  # RK2
        
        # Sonraki 14 tur anahtarı türet
        for i in range(2, self.NUM_ROUNDS):
            # RK_i = RotateLeft(RK_{i-2} XOR RK_{i-1}, i) XOR RC_i
            prev2 = round_keys[i-2]
            prev1 = round_keys[i-1]
            
            # XOR işlemi
            xored = bytes(a ^ b for a, b in zip(prev2, prev1))
            
            # Döngüsel sola kaydırma
            rotate_amount = (i + 1) % 16
            rotated = xored[rotate_amount:] + xored[:rotate_amount]
            
            # Tur sabiti üret
            rc = self._round_constant(i + 1)
            
            # Final XOR
            rk = bytes(a ^ b for a, b in zip(rotated, rc))
            round_keys.append(rk)
        
        return round_keys
    
    def _round_constant(self, round_num: int) -> bytes:
        """
        Tur sabiti üret
        
        Args:
            round_num: Tur numarası
            
        Returns:
            16-byte tur sabiti
        """
        # RC_i = SHA256(i || "PHOENIX") mod 2^128
        data = str(round_num).encode() + b"PHOENIX"
        hash_val = hashlib.sha256(data).digest()
        return hash_val[:16]  # İlk 128-bit al
    
    def _generate_sbox(self, round_key: bytes) -> List[int]:
        """
        Tur anahtarına bağlı dinamik S-Box üret
        
        Args:
            round_key: 128-bit tur anahtarı
            
        Returns:
            256 elemanlı ikame tablosu
        """
        # Başlangıç permütasyonu
        sbox = list(range(256))
        
        # Seed oluştur
        seed = int.from_bytes(hashlib.sha256(round_key).digest()[:4], 'big')
        
        # Fisher-Yates karıştırma (anahtar türevli)
        for i in range(255, 0, -1):
            j = (seed * i + round_key[i % 16]) % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
            seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        
        # Non-lineer dönüşüm
        for i in range(256):
            rotated = ((sbox[i] << 3) | (sbox[i] >> 5)) & 0xFF
            sbox[i] = sbox[i] ^ rotated ^ round_key[i % 16]
        
        return sbox
    
    def _invert_sbox(self, sbox: List[int]) -> List[int]:
        """
        S-Box'ın tersini oluştur
        
        Args:
            sbox: Orijinal S-Box
            
        Returns:
            Ters S-Box
        """
        inv_sbox = [0] * 256
        for i in range(256):
            inv_sbox[sbox[i]] = i
        return inv_sbox
    
    def _sub_bytes(self, state: bytearray, sbox: List[int]) -> bytearray:
        """
        S-Box kullanarak byte ikamesi yap
        
        Args:
            state: 16-byte state
            sbox: İkame tablosu
            
        Returns:
            Dönüştürülmüş state
        """
        return bytearray(sbox[b] for b in state)
    
    def _shift_rows(self, state: bytearray) -> bytearray:
        """
        Satır kaydırma işlemi (4x4 matris olarak)
        
        Args:
            state: 16-byte state
            
        Returns:
            Kaydırılmış state
        """
        new_state = bytearray(16)
        for r in range(4):
            for c in range(4):
                # state'[4r + c] = state[4r + ((c + r) mod 4)]
                new_state[4*r + c] = state[4*r + ((c + r) % 4)]
        return new_state
    
    def _inv_shift_rows(self, state: bytearray) -> bytearray:
        """
        Ters satır kaydırma işlemi
        
        Args:
            state: 16-byte state
            
        Returns:
            Ters kaydırılmış state
        """
        new_state = bytearray(16)
        for r in range(4):
            for c in range(4):
                # state'[4r + c] = state[4r + ((c - r) mod 4)]
                new_state[4*r + c] = state[4*r + ((c - r) % 4)]
        return new_state
    
    def _gf_mult(self, a: int, b: int) -> int:
        """
        GF(2^8) üzerinde çarpma
        
        Args:
            a, b: Çarpılacak değerler
            
        Returns:
            GF(2^8) çarpım sonucu
        """
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= self.GF_POLY
            b >>= 1
        return p
    
    def _mix_columns(self, state: bytearray) -> bytearray:
        """
        MixColumns dönüşümü (GF(2^8) matris çarpımı)
        
        Args:
            state: 16-byte state
            
        Returns:
            Karıştırılmış state
        """
        new_state = bytearray(16)
        
        # Her sütun için (4 sütun)
        for col in range(4):
            s0 = state[col]
            s1 = state[4 + col]
            s2 = state[8 + col]
            s3 = state[12 + col]
            
            # Matris çarpımı
            new_state[col] = self._gf_mult(0x02, s0) ^ self._gf_mult(0x03, s1) ^ s2 ^ s3
            new_state[4 + col] = s0 ^ self._gf_mult(0x02, s1) ^ self._gf_mult(0x03, s2) ^ s3
            new_state[8 + col] = s0 ^ s1 ^ self._gf_mult(0x02, s2) ^ self._gf_mult(0x03, s3)
            new_state[12 + col] = self._gf_mult(0x03, s0) ^ s1 ^ s2 ^ self._gf_mult(0x02, s3)
        
        return new_state
    
    def _inv_mix_columns(self, state: bytearray) -> bytearray:
        """
        Ters MixColumns dönüşümü
        
        Args:
            state: 16-byte state
            
        Returns:
            Ters karıştırılmış state
        """
        new_state = bytearray(16)
        
        # Her sütun için
        for col in range(4):
            s0 = state[col]
            s1 = state[4 + col]
            s2 = state[8 + col]
            s3 = state[12 + col]
            
            # Ters matris çarpımı
            new_state[col] = self._gf_mult(0x0E, s0) ^ self._gf_mult(0x0B, s1) ^ \
                            self._gf_mult(0x0D, s2) ^ self._gf_mult(0x09, s3)
            new_state[4 + col] = self._gf_mult(0x09, s0) ^ self._gf_mult(0x0E, s1) ^ \
                                self._gf_mult(0x0B, s2) ^ self._gf_mult(0x0D, s3)
            new_state[8 + col] = self._gf_mult(0x0D, s0) ^ self._gf_mult(0x09, s1) ^ \
                                self._gf_mult(0x0E, s2) ^ self._gf_mult(0x0B, s3)
            new_state[12 + col] = self._gf_mult(0x0B, s0) ^ self._gf_mult(0x0D, s1) ^ \
                                 self._gf_mult(0x09, s2) ^ self._gf_mult(0x0E, s3)
        
        return new_state
    
    def _add_round_key(self, state: bytearray, round_key: bytes) -> bytearray:
        """
        Tur anahtarı ile XOR işlemi
        
        Args:
            state: 16-byte state
            round_key: 16-byte tur anahtarı
            
        Returns:
            XOR'lanmış state
        """
        return bytearray(a ^ b for a, b in zip(state, round_key))
    
    def _modular_add(self, state: bytearray, round_key: bytes) -> bytearray:
        """
        Modüler toplama (mod 256)
        
        Args:
            state: 16-byte state
            round_key: 16-byte tur anahtarı
            
        Returns:
            Modüler toplanmış state
        """
        return bytearray((a + b) % 256 for a, b in zip(state, round_key))
    
    def _modular_subtract(self, state: bytearray, round_key: bytes) -> bytearray:
        """
        Modüler çıkarma (mod 256)
        
        Args:
            state: 16-byte state
            round_key: 16-byte tur anahtarı
            
        Returns:
            Modüler çıkarılmış state
        """
        return bytearray((a - b) % 256 for a, b in zip(state, round_key))
    
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """
        Tek bir 128-bit bloğu şifrele
        
        Args:
            plaintext: 16-byte düz metin bloğu
            
        Returns:
            16-byte şifreli metin bloğu
        """
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Blok boyutu {self.BLOCK_SIZE} byte olmalıdır")
        
        # State'i başlat
        state = bytearray(plaintext)
        
        # Başlangıç whitening
        state = self._add_round_key(state, self.round_keys[0])
        
        # 16 tur
        for round_num in range(1, self.NUM_ROUNDS):
            # S-Box üret
            sbox = self._generate_sbox(self.round_keys[round_num])
            
            # SubBytes
            state = self._sub_bytes(state, sbox)
            
            # ShiftRows
            state = self._shift_rows(state)
            
            # MixColumns (son tur hariç)
            if round_num < self.NUM_ROUNDS - 1:
                state = self._mix_columns(state)
            
            # AddRoundKey
            state = self._add_round_key(state, self.round_keys[round_num])
            
            # ModularAdd
            state = self._modular_add(state, self.round_keys[round_num])
        
        # Son whitening
        state = self._add_round_key(state, self.round_keys[0])
        
        return bytes(state)
    
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """
        Tek bir 128-bit bloğu deşifre et
        
        Args:
            ciphertext: 16-byte şifreli metin bloğu
            
        Returns:
            16-byte düz metin bloğu
        """
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Blok boyutu {self.BLOCK_SIZE} byte olmalıdır")
        
        # State'i başlat
        state = bytearray(ciphertext)
        
        # Başlangıç whitening (ters)
        state = self._add_round_key(state, self.round_keys[0])
        
        # 16 tur (ters sıra)
        for round_num in range(self.NUM_ROUNDS - 1, 0, -1):
            # ModularAdd (ters)
            state = self._modular_subtract(state, self.round_keys[round_num])
            
            # AddRoundKey (ters - XOR kendi tersi)
            state = self._add_round_key(state, self.round_keys[round_num])
            
            # MixColumns (ters, son tur hariç)
            if round_num < self.NUM_ROUNDS - 1:
                state = self._inv_mix_columns(state)
            
            # ShiftRows (ters)
            state = self._inv_shift_rows(state)
            
            # SubBytes (ters)
            sbox = self._generate_sbox(self.round_keys[round_num])
            inv_sbox = self._invert_sbox(sbox)
            state = self._sub_bytes(state, inv_sbox)
        
        # Son whitening (ters)
        state = self._add_round_key(state, self.round_keys[0])
        
        return bytes(state)
    
    def _pad(self, data: bytes) -> bytes:
        """
        PKCS#7 padding uygula
        
        Args:
            data: Padding uygulanacak veri
            
        Returns:
            Padding uygulanmış veri
        """
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data: bytes) -> bytes:
        """
        PKCS#7 padding kaldır
        
        Args:
            data: Padding kaldırılacak veri
            
        Returns:
            Padding kaldırılmış veri
        """
        pad_len = data[-1]
        return data[:-pad_len]
    
    def encrypt(self, plaintext: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        CBC modunda veri şifrele
        
        Args:
            plaintext: Şifrelenecek düz metin
            iv: Initialization Vector (None ise rastgele üretilir)
            
        Returns:
            (şifreli_metin, iv) tuple'ı
        """
        # IV oluştur
        if iv is None:
            iv = os.urandom(self.BLOCK_SIZE)
        elif len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV boyutu {self.BLOCK_SIZE} byte olmalıdır")
        
        # Padding uygula
        padded = self._pad(plaintext)
        
        # CBC şifreleme
        ciphertext = b''
        prev_block = iv
        
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            # XOR with previous ciphertext block (CBC)
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            # Encrypt
            encrypted = self.encrypt_block(xored)
            ciphertext += encrypted
            prev_block = encrypted
        
        return ciphertext, iv
    
    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        CBC modunda veri deşifre et
        
        Args:
            ciphertext: Şifreli metin
            iv: Initialization Vector
            
        Returns:
            Düz metin
        """
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV boyutu {self.BLOCK_SIZE} byte olmalıdır")
        
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Şifreli metin blok boyutunun katı olmalıdır")
        
        # CBC deşifreleme
        plaintext = b''
        prev_block = iv
        
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            # Decrypt
            decrypted = self.decrypt_block(block)
            # XOR with previous ciphertext block (CBC)
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            plaintext += xored
            prev_block = block
        
        # Padding kaldır
        return self._unpad(plaintext)


def Anahtar_Uret(parola: str) -> bytes:
    """
    Kullanıcı parolasından 256-bit anahtar üret
    
    Args:
        parola: Kullanıcı parolası (string)
        
    Returns:
        32-byte (256-bit) anahtar
    """
    # SHA-256 kullanarak parolayı hash'le
    return hashlib.sha256(parola.encode('utf-8')).digest()


def Sifrele(duz_metin: str, anahtar: bytes) -> Tuple[bytes, bytes]:
    """
    Düz metni şifrele
    
    Args:
        duz_metin: Şifrelenecek metin (string)
        anahtar: 256-bit şifreleme anahtarı
        
    Returns:
        (şifreli_metin, iv) tuple'ı
    """
    cipher = Phoenix256(anahtar)
    plaintext_bytes = duz_metin.encode('utf-8')
    return cipher.encrypt(plaintext_bytes)


def Desifrele(sifreli_metin: bytes, anahtar: bytes, iv: bytes) -> str:
    """
    Şifreli metni deşifre et
    
    Args:
        sifreli_metin: Şifreli metin (bytes)
        anahtar: 256-bit şifreleme anahtarı
        iv: Initialization Vector
        
    Returns:
        Düz metin (string)
    """
    cipher = Phoenix256(anahtar)
    plaintext_bytes = cipher.decrypt(sifreli_metin, iv)
    return plaintext_bytes.decode('utf-8')


if __name__ == "__main__":
    # Basit kullanım örneği
    print("=" * 60)
    print("PHOENIX-256 Kriptografik Algoritma - Demo")
    print("=" * 60)
    
    # Anahtar üret
    parola = "GüçlüParola123!"
    anahtar = Anahtar_Uret(parola)
    print(f"\n[+] Parola: {parola}")
    print(f"[+] Anahtar (hex): {anahtar.hex()[:64]}...")
    
    # Şifreleme
    mesaj = "Bu bir gizli mesajdır. PHOENIX-256 ile korunmaktadır."
    print(f"\n[+] Düz Metin: {mesaj}")
    
    sifreli, iv = Sifrele(mesaj, anahtar)
    print(f"[+] IV (hex): {iv.hex()}")
    print(f"[+] Şifreli Metin (hex): {sifreli.hex()}")
    
    # Deşifreleme
    cozulmus = Desifrele(sifreli, anahtar, iv)
    print(f"\n[+] Deşifre Edilmiş: {cozulmus}")
    
    # Doğrulama
    if mesaj == cozulmus:
        print("\n[✓] Başarılı! Şifreleme ve deşifreleme doğru çalışıyor.")
    else:
        print("\n[✗] Hata! Deşifreleme başarısız.")
    
    print("=" * 60)
