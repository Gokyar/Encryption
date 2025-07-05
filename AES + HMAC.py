from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import binascii


# ŞİFRELEME KISMI
def aes_sifrele(anahtar, veri):
    cipher = AES.new(anahtar, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(veri.encode(), AES.block_size))

    hmac_key = get_random_bytes(16)
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(iv + encrypted_data)
    hmac_value = h.digest()

    return iv, encrypted_data, hmac_value, hmac_key


def sifrele():
    anahtar = get_random_bytes(16)
    veri = input("Şifrelenecek metni girin: ")
    iv, encrypted_data, hmac_value, hmac_key = aes_sifrele(anahtar, veri)

    with open("sifreli_veri.txt", "w") as f:
        f.write(binascii.hexlify(iv).decode() + "\n")
        f.write(binascii.hexlify(encrypted_data).decode() + "\n")
        f.write(binascii.hexlify(hmac_value).decode() + "\n")

    with open("anahtar.txt", "wb") as f:
        f.write(anahtar)

    with open("hmac_anahtar.txt", "wb") as f:
        f.write(hmac_key)

    print("Metin başarıyla şifrelendi ve dosyalara kaydedildi.")



# ŞİFRE ÇÖZME KISMI
def aes_coz(anahtar, hmac_anahtar, iv_hex, encrypted_data_hex, hmac_hex):
    
    iv = binascii.unhexlify(iv_hex)
    
    encrypted_data = binascii.unhexlify(encrypted_data_hex)
    
    hmac_degeri = binascii.unhexlify(hmac_hex)

    h = HMAC.new(hmac_anahtar, digestmod=SHA256)
    
    h.update(iv + encrypted_data)
    
    try:
        h.verify(hmac_degeri)
    except ValueError:
        raise ValueError("HMAC doğrulaması başarısız! Veri bozulmuş olabilir.")

    cipher = AES.new(anahtar, AES.MODE_CBC, iv)
    
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    return decrypted_data.decode()


def coz():
    try:
        with open("sifreli_veri.txt", "r") as f:
            iv_hex = f.readline().strip()
            encrypted_data_hex = f.readline().strip()
            hmac_hex = f.readline().strip()

        with open("anahtar.txt", "rb") as f:
            aes_key = f.read()

        with open("hmac_anahtar.txt", "rb") as f:
            hmac_key = f.read()

        sonuc = aes_coz(aes_key, hmac_key, iv_hex,encrypted_data_hex,hmac_hex)
        print("Çözülmüş metin:", sonuc)
    except Exception as e:
        print("Hata:", str(e))


while True:
    print("\n--- AES + HMAC Programı ---")
    print("1 - Metin şifrele")
    print("2 - Şifreyi çöz")
    print("3 - Çıkış")
    secim = input("Seçiminizi girin (1/2): ")

    if secim == "1":
        sifrele()
    elif secim == "2":
        coz()
    elif secim == "3":
        break
    else:
        print("Geçersiz seçim!")

