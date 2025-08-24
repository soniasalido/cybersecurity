
## Tamaños
word en Intel x86 = 16 bits (2 bytes).

dword = double word = el doble de un word → 32 bits (4 bytes).

qword = quad word = 64 bits (8 bytes).

| Nombre  | Tamaño  | Equivalente |
| ------- | ------- | ----------- |
| `byte`  | 8 bits  | 1 byte      |
| `word`  | 16 bits | 2 bytes     |
| `dword` | 32 bits | 4 bytes     |
| `qword` | 64 bits | 8 bytes     |


Cuando Ghidra pone dword, está indicando que el valor ocupa 4 bytes (32 bits).

Ejemplos típicos:
```
mov eax, dword ptr [ebp-4]   ; mueve un valor de 32 bits desde [ebp-4] a eax
mov dword ptr [esp+8], 1     ; guarda un 1 en la dirección [esp+8] (como entero de 32 bits)
```

Otro Ejemplo:
```
Si en memoria tenemos:
[ebp-4] = 11 22 33 44   (4 bytes)

mov eax, dword ptr [ebp-4]
En EAX quedará:
0x44332211   (porque x86 es little endian: guarda primero el byte menos significativo).
```

**dword en Ghidra = un entero de 32 bits (4 bytes).**

Otro ejemplo:
```
En la dirección 0x1000 guardamos el valor 0x11223344AABBCCDD (8 bytes).

En memoria (little endian), se guarda al revés, byte a byte:
Dirección    Valor (hex)
0x1000  →    DD
0x1001  →    CC
0x1002  →    BB
0x1003  →    AA
0x1004  →    44
0x1005  →    33
0x1006  →    22
0x1007  →    11
```

**🧩 Cómo lo interpreta el ensamblador:**
| Operación                     | Tamaño            | Lectura desde `0x1000` | Resultado                  |
| ----------------------------- | ----------------- | ---------------------- | -------------------------- |
| `mov al, byte ptr [0x1000]`   | 8 bits (1 byte)   | `DD`                   | `AL = 0xDD`                |
| `mov ax, word ptr [0x1000]`   | 16 bits (2 bytes) | `CCDD`                 | `AX = 0xCCDD`              |
| `mov eax, dword ptr [0x1000]` | 32 bits (4 bytes) | `AABBCCDD`             | `EAX = 0xAABBCCDD`         |
| `mov rax, qword ptr [0x1000]` | 64 bits (8 bytes) | `11223344AABBCCDD`     | `RAX = 0x11223344AABBCCDD` |


**Resumiento:**
- byte → 1 byte = 8 bits = char.
- word → 2 bytes = 16 bits = short.
- dword → 4 bytes = 32 bits = int.
- qword → 8 bytes = 64 bits = long long.

