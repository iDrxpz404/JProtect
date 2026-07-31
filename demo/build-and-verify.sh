#!/bin/bash
# OpAddon Demo — build, protect, decompile, and verify
# Requires: java 17+, maven
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPADDON_DIR="$(dirname "$SCRIPT_DIR")"
VIRT_JAR="$OPADDON_DIR/target/virtualizer.jar"
CFR_CP="$OPADDON_DIR/target/classes"

if [ ! -f "$VIRT_JAR" ]; then
    echo "[1/5] Building virtualizer..."
    cd "$OPADDON_DIR" && mvn package -DskipTests -q
fi

echo "[2/5] Compiling demo app..."
cd "$SCRIPT_DIR"
mkdir -p original
javac --release 17 -cp src -d original src/opaddon/annotation/Virtualize.java src/LicenseManager.java
cd original && jar cf ../original.jar . && cd ..

echo "[3/5] Running aggressive protection..."
java -jar "$VIRT_JAR" --input original.jar --output protected.jar --config aggressive.json

echo "[4/5] Extracting & running protected app..."
rm -rf protected && mkdir protected && cd protected && jar xf ../protected.jar && cd ..
echo ""
echo "══════════════════════════════════════════════"
echo "  ORIGINAL OUTPUT"
echo "══════════════════════════════════════════════"
java -cp original LicenseManager TEST-KEY-1234
echo ""
echo "══════════════════════════════════════════════"
echo "  PROTECTED OUTPUT"
echo "══════════════════════════════════════════════"
java -cp "protected:$CFR_CP" LicenseManager TEST-KEY-1234
echo ""

echo "[5/5] CFR decompilation comparison..."
echo ""
echo "--- UNPROTECTED (CFR decompiles to original source) ---"
java -cp "$CFR_CP:$(ls $OPADDON_DIR/target/dependency/*.jar 2>/dev/null | tr '\n' ':')" org.benf.cfr.reader.Main original/LicenseManager.class 2>/dev/null | head -60
echo ""
echo "--- PROTECTED (CFR shows only VMInterpreter.execute) ---"
java -cp "$CFR_CP:$(ls $OPADDON_DIR/target/dependency/*.jar 2>/dev/null | tr '\n' ':')" org.benf.cfr.reader.Main protected/LicenseManager.class 2>/dev/null | head -60
echo ""
echo "══════════════════════════════════════════════"
echo "  DEMO COMPLETE — original logic is hidden"
echo "══════════════════════════════════════════════"
