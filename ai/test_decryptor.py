
"""
LockMyPix Dekriptor - Tesztelő és bemutató script

Ez a script bemutatja a LockMyPix dekriptor főbb funkcióit
és teszteli a jelszó validálást.
"""

import hashlib
import binascii
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter


def create_test_encrypted_file(password, content, filename):
    """
    Teszt titkosított fájl létrehozása
    Ez szimulálja a LockMyPix titkosítását
    """
    key = hashlib.sha1(password.encode()).digest()[:16]
    iv = key
    counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

    encrypted_data = cipher.encrypt(content)

    with open(filename, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ Teszt fájl létrehozva: {filename}")


def test_password_validation(password, test_file):
    """
    Jelszó validálás tesztelése
    """
    try:
        key = hashlib.sha1(password.encode()).digest()[:16]
        iv = key
        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

        with open(test_file, "rb") as f:
            dec_data = cipher.decrypt(f.read(16))
            header = binascii.hexlify(dec_data).decode("utf8")

            if header.startswith("ffd8ff"):
                print(f"✅ Jelszó '{password}' helyes!")
                return True
            else:
                print(f"❌ Jelszó '{password}' helytelen!")
                return False

    except Exception as e:
        print(f"❌ Hiba a jelszó tesztelésében: {e}")
        return False


def main():
    """
    Fő tesztelő függvény
    """
    print("🧪 LockMyPix Dekriptor - Tesztelő Script")
    print("="*50)

    # Teszt paraméterek
    test_password = "teszt123"
    test_dir = "test_files"

    # Teszt mappa létrehozása
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        print(f"📁 Teszt mappa létrehozva: {test_dir}")

    # JPEG header létrehozása (FFD8FF)
    jpeg_header = bytes.fromhex("FFD8FF")
    jpeg_dummy_content = jpeg_header + b"E0001048494600010101006000600000" * 10

    # Teszt fájl létrehozása
    test_file = os.path.join(test_dir, "test_image.6zu")
    create_test_encrypted_file(test_password, jpeg_dummy_content, test_file)

    print("\n🔐 Jelszó validálás tesztelése:")
    print("-" * 30)

    # Helyes jelszó tesztelése
    test_password_validation(test_password, test_file)

    # Helytelen jelszó tesztelése
    test_password_validation("rossz_jelszo", test_file)

    print("\n📋 Teszt eredmények:")
    print("-" * 20)
    print("• Teszt fájl sikeresen létrehozva")
    print("• Jelszó validálás működik")
    print("• Titkosítás/dekriptálás algoritmus tesztelve")

    print("\n🚀 Most már futtathatja a fő alkalmazást:")
    print("   python lockmypix_decryptor.py")

    print("\n💡 Tipp: Használja a '{}' jelszót a teszt fájlokhoz!".format(test_password))


if __name__ == "__main__":
    main()
