import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
import argparse
import os
from pathlib import Path
import logging
import binascii


logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("LockMyPix_decryption_log.log"),
        logging.StreamHandler()
    ]
)


# ez nem a teljes listája a lehetséges kiterjesztéseknek
extension_map = {
    ".vp3": ".mp4",
    ".vo1": ".webm",
    ".v27": ".mpg",
    ".vb9": ".avi",
    ".v77": ".mov",
    ".v78": ".wmv",
    ".v82": ".dv",
    ".vz9": ".divx",
    ".vi3": ".ogv",
    ".v1u": ".h261",
    ".v6m": ".h264",
    ".6zu": ".jpg",
    ".tr7": ".gif",
    ".p5o": ".png",
    ".8ur": ".bmp",
    ".33t": ".tiff",  # ez lehet .tif is
    ".20i": ".webp",
    ".v93": ".heic",
    ".v91": ".flv",  # ez a kulcs tartozik az .flv és .eps fájlokhoz
    ".v80": ".3gpp",
    ".vo4": ".ts",
    ".v99": ".mkv",
    ".vr2": ".mpeg",
    ".vv3": ".dpg",
    ".v81": ".rmvb",
    ".vz8": ".vob",
    ".wi2": ".asf",
    ".vi4": ".h263",
    ".v2u": ".f4v",
    ".v76": ".m4v",
    ".v75": ".ram",
    ".v74": ".rm",
    ".v3u": ".mts",
    ".v92": ".dng",
    ".r89": ".ps",
    ".v79": ".3gp",
}


def test_password(input_dir, password):
    for file in os.listdir(input_dir):
        if file.endswith(".6zu"):
            key = hashlib.sha1(password.encode()).digest()[:16]
            iv = key
            counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            encrypted_path = os.path.join(input_dir, os.fsdecode(file))
            with open(encrypted_path, "rb+") as enc_data:
                dec_data = cipher.decrypt(enc_data.read(16))
                header = binascii.hexlify(dec_data).decode("utf8")
                if header.startswith("ffd8ff"):
                    return True
                else:
                    logging.warning(f"A {password} nem megfelelő jelszó")
                    return False
        else:
            logging.warning("Nem található jpg fájl a jelszó ellenőrzéséhez")
            print("A jelszót nem lehet ellenőrizni. Mégis folytatod?")
            progress = ""
            while progress != "i" and progress != "n":
                progress = input("i/n: ").lower()
            if progress == "i":
                logging.info("A jelszó ellenőrzése sikertelen, a felhasználó által folytatva")
                return True
            else:
                logging.warning("A jelszó ellenőrzése sikertelen, a felhasználó kilépett")
                return False


def write_to_output(output_dir, filename, dec_data):
    basename, ext = os.path.splitext(filename)
    if extension_map.get(ext):
        filename += extension_map.get(ext)
    else:
        filename += ".unknown"
        logging.warning(f"A {filename} fájl kiterjesztése ismeretlen")

    if not Path(output_dir).exists():
        logging.info(f"Kimeneti mappa létrehozása: {output_dir}")
        os.mkdir(output_dir)

    with open(os.path.join(output_dir, filename), "wb") as f:
        f.write(dec_data)
        logging.info(f"A {filename} nevű feloldott fájl a {output_dir} mappába mentve")


def decrypt_image(password, input_dir, output_dir):
    logging.info("Titkosítás feloldása elkezdődött")
    logging.info(f"Jelszó: {password}")
    logging.info(f"Bemeneti mappa: {input_dir}")
    logging.info(f"Kimeneti mappa: {output_dir}")

    key = hashlib.sha1(password.encode()).digest()[:16]
    iv = key  # Az IV (inicializációs vektor) egyenlő a kulccsal
    logging.info(f"AES kulcs: {key}")
    logging.info(f"AES IV (inicializációs vektor): {iv}")

    if not Path(input_dir).exists():
        logging.warning(f"A bemeneti mappa nem található: {input_dir}")
        raise SystemExit(1)

    for file in os.listdir(input_dir):
        encrypted_file = os.fsdecode(file)
        encrypted_path = os.path.join(input_dir, encrypted_file)

        # Új rejtjel objektum létrehozása fájlonkánt
        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

        logging.info(f"Fájl feldolgozása: {encrypted_file}")
        with open(encrypted_path, "rb") as enc_data:
            dec_data = cipher.decrypt(enc_data.read())
            write_to_output(output_dir, encrypted_file, dec_data)


def main():
    parser = argparse.ArgumentParser("LockMyPix Decrypt")
    parser.add_argument("password",
                        help="Add meg az alkalmazás jelszavát")

    parser.add_argument("input",
                        help="Az exportált titkosított fájlok mappája")

    parser.add_argument("output",
                        help="A feloldott fájlok mappája")

    args = parser.parse_args()
    decrypt_image(args.password, args.input, args.output)
    logging.info("A titkosítás feloldása befejeződött")


if __name__ == "__main__":
    main()
