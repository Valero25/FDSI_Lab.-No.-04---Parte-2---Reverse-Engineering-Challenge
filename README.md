# FDSI_Lab.-No.-04---Parte-2---Reverse-Engineering-Challenge

Laboratorio de ingeniería inversa sobre crackmes académicos (ELF Linux x86-64) de la Guía 2 de FDSI.

**Equipo:** Ana Gabriela Fiquitiva Poveda · Juan David Valero Abril

Informe principal: [reverse-analysis.md](reverse-analysis.md)

## Estructura

```
docs/
└── evidence/
    └── reverse/
        ├── baseline.sh      # script que genera baseline.txt (ejecutar en WSL/Linux)
        ├── baseline.txt     # file, sha256sum, readelf
        ├── level1.md        # hipótesis → evidencia → resultado
        ├── level2.md        # Ghidra, pseudocódigo propio y Boss stripped
        ├── gdb.md           # confirmación dinámica
        ├── screenshots/     # capturas de Ghidra
        └── vm-evidence/     # salidas de strings/objdump/GDB generadas en la VM Ubuntu
reverse-analysis.md          # informe y preguntas de análisis
README.md
```

Los binarios no se versionan en este repositorio; su integridad se verifica con los SHA-256 de `baseline.txt`.

## Regenerar la baseline

```bash
bash docs/evidence/reverse/baseline.sh > docs/evidence/reverse/baseline.txt 2>&1
```

## Entrega

Tag: `lab-reverse-v1`
