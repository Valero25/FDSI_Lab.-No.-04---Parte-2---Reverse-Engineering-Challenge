# Reverse Engineering Challenge — Informe de análisis

**Curso:** FDSI · Guía 2 · 2026-2
**Equipo:** Ana Gabriela Fiquitiva Poveda · Juan David Valero Abril
**Entorno:**
- Análisis en terminal y dinámico: VM Ubuntu `lab3-server` (x86_64) · binutils 2.46 · GDB 17.1
- Decompilación: Ghidra 12.1.4 PUBLIC sobre Windows 11 (JDK 21)

## Resumen

| Reto | Técnica principal | Hallazgo | Resultado |
|---|---|---|---|
| Nivel 1 | `strings` + `objdump` | `strcmp(argv[1], "REDTEAM-101")`; FLAG ofuscada con XOR `0x5A` en `print_flag` | `FLAG{strings_are_evidence}` |
| Nivel 2 | Ghidra + `objdump -s` + GDB | Longitud 17; `candidate[i] ^ k[i % 4] == expected[i]`, con `k = 23 51 17 6a` | Clave `FDSI-REVERSE-2026` → `FLAG{ghidra_plus_gdb}` |
| Boss (stripped) | `_start` → `main` → xrefs a cadenas + patrón de instrucciones | Validación en `FUN_00401156` (misma lógica y direcciones) | Misma clave → `FLAG{ghidra_plus_gdb}` |

Detalle: [baseline](docs/evidence/reverse/baseline.txt) · [nivel 1](docs/evidence/reverse/level1.md) · [nivel 2 + boss](docs/evidence/reverse/level2.md) · [GDB](docs/evidence/reverse/gdb.md)

## Integridad de los binarios

Los tres SHA-256 coinciden con los publicados en la guía (`baseline.txt` §3: `OK` para los tres). `baseline.txt` se generó con `baseline.sh` en WSL Ubuntu sobre los archivos originales, y la misma verificación se repitió en la VM `lab3-server` después de copiarlos por `scp` ([vm_setup.txt](docs/evidence/reverse/vm-evidence/vm_setup.txt)): tres `OK`.

Un hash criptográfico identifica el contenido exacto de un archivo: cambiar un solo bit produce un hash completamente distinto. Por eso garantiza que todos los equipos analizan **el mismo binario** que distribuyó el docente (direcciones, bytes y FLAGs comparables), que el archivo no se corrompió al copiarlo ni fue manipulado, y deja constancia reproducible de qué se analizó.

## Preguntas de análisis

### 1. ¿Qué información pudiste obtener sin ejecutar el binario?

Prácticamente todo:

- **Formato y plataforma** (`file`, `readelf -h`): ELF64 x86-64, ejecutable no PIE (`Type: EXEC`, direcciones fijas desde `0x400000`), enlazado dinámicamente con `libc.so.6`, con o sin símbolos/DWARF.
- **Funciones importadas** (`strings`, `nm -D`): `strcmp` en el Nivel 1 delató una comparación directa; `strlen` y `putchar` en el Nivel 2 sugirieron control de longitud e impresión carácter a carácter.
- **Secretos embebidos**: la contraseña `REDTEAM-101` en claro en `.rodata`; los arreglos `k` y `expected` del Nivel 2 (`objdump -s -j .rodata`).
- **El algoritmo completo** (`objdump -d` / Ghidra): `strcmp` + `test`/`jne` en el Nivel 1; longitud 17, `XOR` con clave cíclica de 4 bytes y acumulación con `OR` en el Nivel 2.
- **Las propias FLAGs**: ambas se pueden decodificar estáticamente (XOR `0x5A` en `print_flag`; la clave del Nivel 2 se obtiene invirtiendo el XOR).

### 2. ¿Por qué una contraseña compilada como string es un diseño inseguro?

Porque el compilador guarda los literales de cadena **tal cual** en la sección `.rodata` del ejecutable. Quien tenga el binario tiene la contraseña: basta `strings` para verla en segundos, sin ejecutar nada ni saber ensamblador. Además:

- Es la misma para todas las copias distribuidas: filtrarla una vez la compromete para siempre, y cambiarla exige recompilar y redistribuir.
- La validación ocurre en el cliente, que controla el atacante: aunque estuviera ofuscada, puede parchear el `jne` de `0x401248` o leer el valor en memoria con GDB.
- Ofuscarla (XOR, como `print_flag`) no la protege: la clave de descifrado viaja en el mismo binario.

### 3. ¿Qué cambió entre `crackme_level2` y `crackme_level2_stripped`?

`strip` eliminó `.symtab`, `.strtab` y todas las secciones `.debug_*` (de 36 a 28 secciones, de 18 200 a 14 424 bytes). Se perdieron los nombres de funciones (`main`, `validate_key`, `reveal_flag`), de variables globales (`k.1`, `expected.0`) y locales (`candidate`, `score`), los tipos y la correspondencia con el código fuente: `nm` responde `no symbols`, GDB ya no acepta `break validate_key` y Ghidra muestra `FUN_00401156`.

**No cambió** el código máquina (mismas instrucciones en las mismas direcciones), los datos de `.rodata` ni la tabla dinámica `.dynsym` (imports de libc). Por eso la misma clave funciona. La validación se reencontró siguiendo `_start` → `mov rdi,0x401267` (`main`) → la función cuyo retorno decide entre `"License accepted."` e `"Invalid license."`, y confirmando el patrón `strlen` / `and eax,0x3` / `xor eax,ecx` / `sete`.

### 4. ¿Qué ventaja tuvo Ghidra sobre objdump?

`objdump` es un desensamblador lineal: entrega instrucciones una tras otra y el analista debe reconstruir mentalmente variables, bucles y condiciones. Ghidra:

- **Decompila** a pseudocódigo C: el bucle `for (i = 0; i < 0x11; i++)` y la expresión `candidate[i] ^ k[i & 3]` se leen directamente en lugar de seguir `[rbp-0x10]` a través de 20 instrucciones.
- Permite **renombrar y tipar** variables y funciones; los cambios se propagan a todo el análisis.
- Muestra **referencias cruzadas** (xrefs): desde la cadena `"License accepted."` se llega a `main` y de ahí a la función de validación; imprescindible en el binario stripped.
- Ofrece **grafo de flujo de control**, árbol de símbolos, vista de datos de `.rodata` y anotaciones persistentes en un proyecto.

`objdump` sigue siendo útil para extraer evidencia exacta y rápida en terminal (`-s -j .rodata`, `--disassemble=función`).

### 5. ¿Qué confirmó GDB que el análisis estático por sí solo no demostraba?

El análisis estático produce una **hipótesis**; GDB la demostró con valores reales en ejecución:

- Que `validate_key` recibe en `rdi` exactamente la cadena introducida.
- Que los arreglos `k` y `expected` que hay en memoria **durante la ejecución** son los mismos bytes leídos en `.rodata` (nada los modifica antes de validar).
- Que la transformación real es la deducida: en `0x4011b9`, `0x41 ^ 0x23 = 0x62` (≠ `expected[0]`) con `AAAA…` y `0x46 ^ 0x23 = 0x65` (= `expected[0]`) con la clave reconstruida.
- Que el valor de retorno pasa de **0** a **1** y que ese valor es el que hace que `main` imprima `License accepted.` y la FLAG.

### 6. ¿Por qué Burp Suite no es una herramienta de ingeniería inversa de binarios?

Burp Suite es un **proxy de interceptación HTTP/HTTPS**: se coloca entre el navegador y el servidor para ver, modificar y repetir peticiones (Proxy, Repeater, Intruder). Trabaja sobre **tráfico de red de aplicaciones web**, es decir, sobre la interfaz externa de un sistema.

La ingeniería inversa de binarios analiza el **código máquina** de un ejecutable (instrucciones, registros, memoria, secciones ELF) con desensambladores, decompiladores y depuradores como objdump, Ghidra y GDB. Los crackmes de este laboratorio no hacen ninguna comunicación de red, así que Burp no tiene nada que interceptar. Son enfoques complementarios: Burp para probar el comportamiento de una aplicación web desde fuera (caja negra), Ghidra/GDB para entender la lógica interna de un programa compilado.

### 7. ¿Qué controles de desarrollo evitarían embebidos inseguros de secretos en software real?

- **No validar secretos en el cliente**: la verificación de licencias o credenciales debe hacerse en un servidor controlado.
- Si hay que comparar localmente, guardar solo un **hash con sal y algoritmo lento** (Argon2id, bcrypt, scrypt), nunca el valor en claro ni ofuscado con XOR.
- **Gestores de secretos** (HashiCorp Vault, AWS/Azure Secrets Manager) y variables de entorno o archivos de configuración fuera del repositorio, inyectados en despliegue.
- **Escaneo automático de secretos** en el ciclo de desarrollo: hooks pre-commit y CI con `gitleaks`, `trufflehog` o *GitHub secret scanning*; análisis estático (SAST) que marque credenciales *hardcoded* (CWE-798).
- **Revisión de código** con lista de verificación que incluya secretos embebidos.
- **Builds de release sin símbolos ni información de depuración** (`strip`, `-s`, sin `-g`), sabiendo que es solo una medida de *defensa en profundidad*, no un control de seguridad.
- **Rotación y revocación** de claves y licencias, para que un secreto filtrado tenga un impacto limitado.
- Usar **secretos por usuario o por instalación** (licencias firmadas criptográficamente y verificadas con clave pública) en lugar de una clave única compartida.

## Módulo opcional — Burp Suite

<!-- Laboratorio de PortSwigger usado, request interceptada, cambio en Repeater, diferencia entre análisis web y RE. -->

## Cierre (3 minutos)

1. **Qué observamos:** dos programas que piden una contraseña o licencia y responden éxito o fallo. `strings` mostró `strcmp` y una cadena sospechosa (`REDTEAM-101`) en el Nivel 1; en el Nivel 2 no había nada en claro, solo `strlen`.
2. **Qué hipótesis formulamos:** Nivel 1, comparación directa con un literal. Nivel 2, una transformación byte a byte reversible contra un arreglo esperado.
3. **Qué función o condición encontramos:** `test eax,eax` / `jne` tras `strcmp` en `main` (Nivel 1). En `validate_key` (Nivel 2), longitud 17 y `candidate[i] ^ k[i % 4] == expected[i]`. En el binario stripped, la misma función (`FUN_00401156`), localizada desde `_start` y por las referencias a las cadenas de resultado.
4. **Cómo la confirmamos en ejecución:** ejecutando las claves (`Access granted.` / `License accepted.` y las FLAGs) y con GDB, observando el XOR en `rax`/`rcx` en `0x4011b9` y el retorno `0` → `1` de `validate_key`.
5. **Qué enseñanza de desarrollo seguro extraemos:** todo lo que va dentro de un binario distribuido es público para un atacante. Ni los literales, ni la ofuscación XOR, ni el strip protegen un secreto. La validación debe hacerse en el servidor o con hashes robustos, y los secretos deben gestionarse fuera del código.
