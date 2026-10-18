# Nivel 1 — "Strings are evidence"

> Binario: `crackme_level1` · SHA-256 `61e980febe84b1003b5a3b641468e915b984f7fdd835be9828af54233f88c68c` (verificado: OK)
> Entorno: VM Ubuntu `lab3-server` x86_64 · binutils 2.46
> Restricción: análisis sin consultar el código fuente.

## 1. Observación inicial (ejecución con datos falsos)

```text
$ ./crackme_level1
=== FDSI CrackMe Level 1 ===
Uso: ./crackme_level1 <password>

$ ./crackme_level1 prueba
=== FDSI CrackMe Level 1 ===
Access denied.
```

- El programa espera la contraseña como **primer argumento** (`argv[1]`).
- Hay dos caminos: `Access granted.` (éxito) y `Access denied.` (fallo).

## 2. Evidencia estática con `strings`

```bash
strings -n 5 crackme_level1 | tee evidence/level1_strings.txt
```

Líneas relevantes:

```text
putchar
printf
strcmp
...
!).(H
,3>?49?'H
REDTEAM-101
=== FDSI CrackMe Level 1 ===
Uso: %s <password>
Access granted.
Access denied.
...
password
print_flag
```

| Evidencia | Interpretación |
|---|---|
| `strcmp` importada de libc | La validación es una comparación directa de cadenas, sin hash ni transformación. |
| `REDTEAM-101` | Única cadena no descriptiva en `.rodata`, ubicada junto a los mensajes de éxito/fallo → candidata a contraseña. |
| `password`, `print_flag` (info DWARF) | El binario conserva símbolos y debug: existe una variable `password` y una función que imprime la FLAG. |
| `putchar` | La FLAG probablemente se imprime carácter a carácter. |
| `!).(H`, `,3>?49?'H` | Fragmentos de instrucciones `movabs` con constantes: la FLAG está ofuscada dentro del código, por eso no aparece en claro. |

## 3. Hipótesis

`main` ejecuta `strcmp(argv[1], password)` con `password = "REDTEAM-101"`. Si devuelve 0, imprime `Access granted.` y llama a `print_flag()`, que decodifica la FLAG.

## 4. Confirmación en el desensamblado de `main`

```bash
objdump -d -M intel crackme_level1 > evidence/level1_objdump.txt
grep -B10 -A8 "call.*strcmp" evidence/level1_objdump.txt
```

```asm
40122c:  mov    rax,QWORD PTR [rbp-0x20]   ; rax = argv
401230:  add    rax,0x8                    ; &argv[1]
401234:  mov    rax,QWORD PTR [rax]        ; rax = argv[1]  (entrada del usuario)
401237:  mov    rdx,QWORD PTR [rbp-0x8]    ; rdx = password ("REDTEAM-101")
40123b:  mov    rsi,rdx                    ; 2.º argumento
40123e:  mov    rdi,rax                    ; 1.er argumento
401241:  call   401060 <strcmp@plt>        ; strcmp(argv[1], password)
401246:  test   eax,eax                    ; ¿resultado == 0?
401248:  jne    401265 <main+0x8d>         ; distinto → "Access denied."
40124a:  lea    rax,[rip+0xdf0]            ; 0x402041 → "Access granted."
401254:  call   401040 <puts@plt>
401259:  call   401156 <print_flag>        ; camino de éxito
```

- Convención System V x86-64: `rdi` = 1.er argumento, `rsi` = 2.º argumento.
- `test eax,eax` + `jne` es la **única decisión** de la autenticación: si `strcmp` ≠ 0 se salta al mensaje de fallo.

## 5. Prueba de la hipótesis

```text
$ ./crackme_level1 REDTEAM-101
=== FDSI CrackMe Level 1 ===
Access granted.
FLAG{strings_are_evidence}
```

**FLAG Nivel 1:** `FLAG{strings_are_evidence}`

> Salidas generadas en la VM: [ejecución inicial](vm-evidence/level1_run.txt) · [strings](vm-evidence/level1_strings.txt) · [main/strcmp](vm-evidence/level1_main_strcmp.txt) · [print_flag](vm-evidence/level1_print_flag.txt) · [resultado](vm-evidence/level1_result.txt)

## 6. ¿Por qué la FLAG no salía en `strings`? (`print_flag`)

```bash
objdump -d -M intel --disassemble=print_flag crackme_level1
```

```asm
40115e:  movabs rax,0x282e29211d1b161c     ; 26 bytes cifrados se copian al stack
...                                         ; en [rbp-0x30 .. rbp-0x17]
401196:  mov    BYTE PTR [rbp-0x9],0x5a     ; clave XOR = 0x5A
40119a:  mov    QWORD PTR [rbp-0x8],0x0     ; i = 0
4011af:  movzx  eax,BYTE PTR [rax]          ; c = buf[i]
4011b2:  xor    al,BYTE PTR [rbp-0x9]       ; c ^= 0x5A
4011ba:  call   putchar                     ; imprime c
4011bf:  add    QWORD PTR [rbp-0x8],0x1     ; i++
4011c4:  cmp    QWORD PTR [rbp-0x8],0x19    ; mientras i <= 25 (26 caracteres)
```

Pseudocódigo:

```text
print_flag():
    buf = [0x1c, 0x16, 0x1b, 0x1d, 0x21, ...]   // 26 bytes
    para i en 0..25: putchar(buf[i] XOR 0x5A)
    putchar('\n')
```

Comprobación: `0x1c ^ 0x5a = 0x46 'F'`, `0x16 ^ 0x5a = 0x4c 'L'`, `0x1b ^ 0x5a = 0x41 'A'`, `0x1d ^ 0x5a = 0x47 'G'`, `0x21 ^ 0x5a = 0x7b '{'`.

La FLAG solo está **ofuscada** (XOR con una clave de un byte embebida en el mismo binario), no protegida: se puede recuperar estáticamente sin ejecutar el programa.

## 7. ¿Por qué `strings` puede revelar secretos embebidos?

- Las constantes de cadena de C (`"REDTEAM-101"`) se almacenan **literalmente** en la sección `.rodata` del ELF; compilar no cifra ni oculta datos.
- `strings` extrae cualquier secuencia de ≥ N bytes imprimibles del archivo, sin necesidad de ejecutarlo ni entender su formato.
- Además, el binario no está stripped y conserva DWARF, que expone nombres como `password` y `print_flag`, lo que guía al analista.
- Ofuscar (como el XOR de `print_flag`) solo retrasa el análisis: la clave y el algoritmo viajan dentro del mismo binario.

**Lección de desarrollo seguro:** no incrustar secretos en el cliente. La verificación debe hacerse en el servidor o contra un hash con sal (bcrypt/Argon2), y los binarios de producción no deben distribuirse con símbolos de depuración.
