#!/usr/bin/env bash
# generate_parser.sh
#
# One-time step: downloads the ANTLR4 tool jar and generates the Python
# parser from the COBOL-85 grammar in cobcheck/parser/Cobol85.g4.
#
# Requirements: Java 11+, internet access (first run only).
# Generated files are committed to version control so teammates don't need Java.

set -euo pipefail

ANTLR_VERSION="4.13.2"
JAR_URL="https://www.antlr.org/download/antlr-${ANTLR_VERSION}-complete.jar"
JAR_PATH="scripts/antlr-${ANTLR_VERSION}-complete.jar"
GRAMMAR_DIR="cobcheck/parser"
OUTPUT_DIR="cobcheck/parser/generated"

echo "==> Checking for ANTLR jar..."
if [ ! -f "$JAR_PATH" ]; then
    echo "==> Downloading ANTLR ${ANTLR_VERSION} tool jar..."
    curl -L -o "$JAR_PATH" "$JAR_URL"
fi

echo "==> Creating output directory..."
mkdir -p "$OUTPUT_DIR"

echo "==> Generating Python parser from Cobol85.g4..."
java -jar "$JAR_PATH" \
    -Dlanguage=Python3 \
    -visitor \
    -listener \
    -package generated \
    -o "$OUTPUT_DIR" \
    "$GRAMMAR_DIR/Cobol85.g4"

echo "==> Creating __init__.py in generated/"
touch "$OUTPUT_DIR/__init__.py"

echo ""
echo "Done. Generated files written to $OUTPUT_DIR/"
echo "Commit these files so teammates don't need Java."