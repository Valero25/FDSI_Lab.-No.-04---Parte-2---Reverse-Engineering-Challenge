# Confirmación dinámica con GDB

> Objetivo: demostrar en ejecución que el pseudocódigo de `level2.md` es correcto.
> Entorno: VM Ubuntu `lab3-server` x86_64 · GDB 17.1 · binario `crackme_level2` (SHA-256 verificado).

## Metodología

Se ejecuta GDB en modo `-batch` para que la sesión sea reproducible y quede guardada como evidencia (`evidence/gdb_fail.txt`, `evidence/gdb_ok.txt`):

| Comando | Propósito |
|---|---|
| `break validate_key` | Detenerse al entrar a la rutina de validación (GDB la coloca en `0x401162`, tras el prólogo). |
| `x/s $rdi` | Ver la clave recibida (1.er argumento, convención System V). |
| `x/4bx 0x40208b` / `x/17bx 0x402090` | Volcar en memoria los arreglos `k` y `expected` hallados estáticamente. |
| `break *0x4011b9` | Detenerse en `xor eax,ecx` (la transformación) en la 1.ª iteración. |
| `info registers rax rcx` + `stepi` | Ver operandos y resultado del XOR. |
| `finish` | Ejecutar hasta el `ret` y mostrar el valor de retorno (`rax`). |

```bash
gdb -q -batch -ex 'set debuginfod enabled off' -ex 'set disassembly-flavor intel' \
  -ex 'break validate_key' -ex 'run <CLAVE>' -ex 'x/s $rdi' \
  -ex 'x/4bx 0x40208b' -ex 'x/17bx 0x402090' \
  -ex 'break *0x4011b9' -ex 'continue' -ex 'info registers rax rcx' \
  -ex 'stepi' -ex 'info registers rax' -ex 'delete' -ex 'finish' -ex 'continue' \
  ./crackme_level2 2>&1 | tee evidence/gdb_<caso>.txt
```

## 1. Clave fallida: `AAAAAAAAAAAAAAAAA` (17 × 'A')

Se usan 17 caracteres a propósito para superar el control de longitud y llegar al bucle.

```text
Breakpoint 1 at 0x401162: file /mnt/data/reverse_fsi_lab/crackme_level2.c, line 10.

Breakpoint 1, validate_key (candidate=0x7fffffffe60e 'A' <repeats 17 times>) at ...crackme_level2.c:10
0x7fffffffe60e: 'A' <repeats 17 times>
0x40208b <k.1>: 0x23    0x51    0x17    0x6a
0x402090 <expected.0>:  0x65    0x15    0x44    0x23    0x0e    0x03    0x52    0x3c
0x402098 <expected.0+8>:        0x66    0x03    0x44    0x2f    0x0e    0x63    0x27    0x58
0x4020a0 <expected.0+16>:       0x15
Breakpoint 2 at 0x4011b9: file /mnt/data/reverse_fsi_lab/crackme_level2.c, line 15.

Breakpoint 2, validate_key (candidate=0x7fffffffe60e 'A' <repeats 17 times>) at ...crackme_level2.c:15
rax            0x23                35
rcx            0x41                65
0x00000000004011bb      15      in /mnt/data/reverse_fsi_lab/crackme_level2.c
rax            0x62                98
0x00000000004012d2 in main (argc=2, argv=0x7fffffffe368) at ...crackme_level2.c:36
Value returned is $1 = 0
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
Invalid license.
[Inferior 1 (process 11305) exited with code 03]
```

- `rdi` → `candidate` = `"AAAAAAAAAAAAAAAAA"`.
- En memoria, `k` y `expected` coinciden **byte a byte** con lo leído estáticamente en `.rodata`.
- 1.ª iteración: `rcx = 0x41 ('A')`, `rax = k[0] = 0x23` → tras el XOR `rax = 0x62`, distinto de `expected[0] = 0x65` → `score ≠ 0`.
- Retorno de `validate_key`: **0** → `Invalid license.`

## 2. Clave válida: `FDSI-REVERSE-2026`

```text
Breakpoint 1, validate_key (candidate=0x7fffffffe60e "FDSI-REVERSE-2026") at ...crackme_level2.c:10
0x7fffffffe60e: "FDSI-REVERSE-2026"
Breakpoint 2 at 0x4011b9: file /mnt/data/reverse_fsi_lab/crackme_level2.c, line 15.

Breakpoint 2, validate_key (candidate=0x7fffffffe60e "FDSI-REVERSE-2026") at ...crackme_level2.c:15
rax            0x23                35
rcx            0x46                70
0x00000000004011bb      15      in /mnt/data/reverse_fsi_lab/crackme_level2.c
rax            0x65                101
0x00000000004012d2 in main (argc=2, argv=0x7fffffffe368) at ...crackme_level2.c:36
Value returned is $1 = 1
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
License accepted.
FLAG{ghidra_plus_gdb}
[Inferior 1 (process 11354) exited normally]
```

- 1.ª iteración: `rcx = 0x46 ('F')`, `rax = k[0] = 0x23` → `0x46 ^ 0x23 = 0x65` = `expected[0]` ✔.
- Retorno de `validate_key`: **1** → `License accepted.` y `FLAG{ghidra_plus_gdb}`.

## 3. Relación instrucciones ↔ pseudocódigo

| Dirección | Instrucción | Pseudocódigo | Observado en GDB |
|---|---|---|---|
| `0x40115e` | `mov [rbp-0x28],rdi` | `candidate = argv[1]` | `x/s $rdi` → clave introducida |
| `0x401162` | `mov [rbp-0x18],0x11` | `key_len = 17` | breakpoint 1 se detiene aquí |
| `0x401171` | `call strlen` + `cmp` + `je` | `si strlen(candidate) != 17: return 0` | ambas claves (17 chars) entran al bucle |
| `0x4011a8` | `and eax,0x3` | `i mod 4` | — |
| `0x4011b5` | `movzx eax,[rdx+rax]` | `k[i mod 4]` | `rax = 0x23` = `k[0]` |
| `0x4011b9` | `xor eax,ecx` | `transformed = candidate[i] ^ k[i mod 4]` | `0x41^0x23=0x62` / `0x46^0x23=0x65` |
| `0x4011cf` | `xor al,[rbp-0x19]` | `expected[i] ^ transformed` | 0 solo si coinciden |
| `0x4011d5` | `or [rbp-0x4],eax` | `score |= diferencia` | — |
| `0x4011eb` | `sete al` | `return score == 0` | `finish` → `0` / `1` |

## 4. Conclusión

GDB confirmó lo que el análisis estático solo permitía suponer:

1. Los arreglos `k` y `expected` que se cargan **en tiempo de ejecución** son exactamente los de `.rodata` (no se modifican antes de validar).
2. La transformación real es `candidate[i] XOR k[i % 4]`: se observó con valores concretos en `rax`/`rcx` en la instrucción `0x4011b9`.
3. El valor de retorno de `validate_key` cambia de **0** (clave fallida) a **1** (clave reconstruida), y ese valor es el que decide el camino en `main`.

> Sesiones completas generadas en la VM: [`vm-evidence/gdb_fail.txt`](vm-evidence/gdb_fail.txt), [`vm-evidence/gdb_ok.txt`](vm-evidence/gdb_ok.txt)
