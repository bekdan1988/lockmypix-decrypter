#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                LockMyPix Dekriptor Telepítő                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🚀 LockMyPix Dekriptor telepítése..."
echo ""

# Python verzió ellenőrzése
echo "⏳ Python verzió ellenőrzése..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 nincs telepítve!"
    echo "💡 Kérem telepítse a Python 3.8+ verziót"
    exit 1
fi

echo "✅ Python megtalálva!"
python3 --version

echo ""
echo "⏳ Függőségek telepítése..."

# pip3 ellenőrzése
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 nincs telepítve!"
    exit 1
fi

pip3 install PyQt6>=6.4.0
if [ $? -ne 0 ]; then
    echo "❌ Hiba a PyQt6 telepítésekor!"
    exit 1
fi

pip3 install pycryptodome>=3.15.0
if [ $? -ne 0 ]; then
    echo "❌ Hiba a pycryptodome telepítésekor!"
    exit 1
fi

echo ""
echo "✅ Telepítés sikeres!"
echo ""
echo "🧪 Teszt futtatása..."
python3 test_decryptor.py

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Telepítés befejezve!                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🎯 A program indításához írja be:"
echo "   python3 lockmypix_decryptor.py"
echo ""
echo "📚 További információk a README.md fájlban találhatók."
echo ""
