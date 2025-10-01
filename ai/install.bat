@echo off
chcp 65001 >nul
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                LockMyPix Dekriptor Telepítő                  ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo 🚀 LockMyPix Dekriptor telepítése...
echo.

REM Python verzió ellenőrzése
echo ⏳ Python verzió ellenőrzése...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python nincs telepítve vagy nem található a PATH-ban!
    echo 💡 Kérem telepítse a Python 3.8+ verziót: https://python.org
    pause
    exit /b 1
)

echo ✅ Python megtalálva!
python --version

echo.
echo ⏳ Függőségek telepítése...
pip install PyQt6>=6.4.0
if errorlevel 1 (
    echo ❌ Hiba a PyQt6 telepítésekor!
    pause
    exit /b 1
)

pip install pycryptodome>=3.15.0
if errorlevel 1 (
    echo ❌ Hiba a pycryptodome telepítésekor!
    pause
    exit /b 1
)

echo.
echo ✅ Telepítés sikeres!
echo.
echo 🧪 Teszt futtatása...
python test_decryptor.py

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    Telepítés befejezve!                      ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo 🎯 A program indításához írja be:
echo    python lockmypix_decryptor.py
echo.
echo 📚 További információk a README.md fájlban találhatók.
echo.
pause
