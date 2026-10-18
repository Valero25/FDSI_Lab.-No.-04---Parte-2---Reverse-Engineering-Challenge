#!/bin/bash
# Uso: bash baseline.sh [carpeta_con_binarios]
cd "${1:-/mnt/c/Users/Juan/Downloads/FDSI_Guia2_Reverse_Engineering_ESTUDIANTES (1)}" || exit 1
B="crackme_level1 crackme_level2 crackme_level2_stripped"
echo "# FDSI - Reverse Engineering Challenge - Baseline forense"
echo "# Fecha (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# Host: $(uname -srm) | $(. /etc/os-release; echo "$PRETTY_NAME")"
echo; echo "## 1. file"; file $B
echo; echo "## 2. sha256sum"; sha256sum $B
echo; echo "## 3. Verificación contra hashes oficiales de la guía"
cat <<H | sha256sum -c
61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c  crackme_level1
8dc5931dfbf74d7371de9ca9ed8cc57bfe0af4521346202dcd1c701dd8b6f4e5  crackme_level2
c8e638741272a87ee3b30fe8878898c1aa977e6a879a1ec0b271034b5bb9aed3  crackme_level2_stripped
H
for f in $B; do echo; echo "## 4. readelf -h $f"; readelf -h "$f"; done
for f in $B; do
  echo; echo "## 5. Linking / símbolos: $f"
  echo "-- Intérprete:"; readelf -l "$f" | grep -i "interpreter"
  echo "-- Librerías (NEEDED):"; readelf -d "$f" | grep NEEDED
  echo "-- Secciones de símbolos/debug:"; readelf -S -W "$f" | grep -E "\.symtab|\.strtab|\.debug" || echo "   (ninguna .symtab/.debug: binario stripped)"
  echo "-- nm (primeras líneas):"; nm "$f" 2>&1 | head -5
done
