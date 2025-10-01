# LockMyPix Dekriptor

## 📖 Leírás

Ez a program egy modern PyQt6 alkalmazás, amely lehetővé teszi a LockMyPix Android alkalmazással titkosított fájlok dekriptálását. A program automatikusan felismeri a .6zu kiterjesztésű titkosított fájlokat és visszaállítja őket eredeti formátumukba.

## 🔧 Telepítés

### Előfeltételek
- Python 3.8 vagy újabb
- pip csomagkezelő

### Telepítési lépések

1. **Függőségek telepítése:**
```bash
pip install -r requirements.txt
```

2. **Program indítása:**
```bash
python lockmypix_decryptor.py
```

## 🚀 Használat

### 1. Indítás
Indítsa el a programot a `python lockmypix_decryptor.py` paranccsal.

### 2. Bemeneti mappa kiválasztása
- Kattintson a "📂 Tallózás" gombra a "Bemeneti mappa" mellett
- Válassza ki azt a mappát, ahol a titkosított .6zu fájlok vannak

### 3. Kimeneti mappa beállítása
- A program automatikusan beállítja a kimeneti mappát az "unlocked" nevű almappára
- Szükség esetén módosíthatja a "📂 Tallózás" gombbal

### 4. Dekriptálás indítása
- Kattintson az "▶️ Indítás" gombra
- Adja meg a LockMyPix alkalmazásban használt jelszót
- A program ellenőrzi a jelszót, majd megkezdi a dekriptálást

### 5. Folyamat követése
- A haladás a progress bar-on követhető
- Az állapotok a napló ablakban láthatók
- Szükség esetén a "⏹️ Leállítás" gombbal megszakítható

### 6. Napló megtekintése
- A "📋 Napló megnyitása" gombbal megnyitható a részletes napló fájl
- A naplók a `logs/` mappában kerülnek mentésre

## 📁 Támogatott fájltípusok

A program automatikusan felismeri és konvertálja a következő fájltípusokat:

### Képfájlok
- .6zu → .jpg
- .tr7 → .gif  
- .p5o → .png
- .8ur → .bmp
- .33t → .tiff
- .20i → .webp
- .v93 → .heic
- .v92 → .dng

### Videófájlok
- .vp3 → .mp4
- .vo1 → .webm
- .v27 → .mpg
- .vb9 → .avi
- .v77 → .mov
- .v78 → .wmv
- .v99 → .mkv
- És sok más...

## ⚠️ Fontos megjegyzések

1. **Jelszó biztonság**: A program nem tárolja a jelszavakat
2. **Backup**: Készítsen biztonsági mentést az eredeti fájlokról
3. **Teljesítmény**: Nagy fájlok esetén a dekriptálás hosszabb időt vehet igénybe
4. **Hibakezelés**: Hibás jelszó esetén a program jelzi és leállítja a műveletet

## 🐛 Hibaelhárítás

### "Helytelen jelszó" hiba
- Ellenőrizze, hogy a helyes jelszót adta-e meg
- Győződjön meg róla, hogy vannak .6zu fájlok a bemeneti mappában

### Importálási hibák
- Telepítse újra a függőségeket: `pip install -r requirements.txt`
- Ellenőrizze a Python verzióját: `python --version`

### Fájl hozzáférési hibák
- Ellenőrizze a mappák írási/olvasási jogosultságait
- Győződjön meg róla, hogy a fájlok nem használatban vannak más programokban

## 📄 Licenc

Ez a program a LockMyPix dekriptálására szolgál digitális forensics célokra.
Csak saját fájljaira használja!

## 🤝 Hozzájárulás

A program a c-sleuth/lock-my-pix-android-decrypt GitHub repository alapján készült.
