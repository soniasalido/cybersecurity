# Memory Segmentation 8086

## 🔹 1. Contexto del 8086

El Intel 8086 fue un procesador de 16 bits con un bus de direcciones de 20 bits, lo que le permitía acceder a 1 MB de memoria (2²⁰ = 1,048,576 direcciones).

El problema: los registros internos eran de 16 bits, así que no podían direccionar directamente más de 64 KB (2¹⁶ = 65,536).

➡️ **Solución: Intel introdujo la segmentación de memoria.**

## 🔹 2. Qué es la segmentación
- La memoria se divide en segmentos de 64 KB.  
- Un segment register (registro de segmento) indica el inicio de un segmento, y un offset (desplazamiento) dentro del segmento apunta a la dirección exacta.
- Fórmula para obtener la dirección física: `Dirección física = Segment * 16 + Offset`.
  - El segment se multiplica por 16 (desplazamiento de 4 bits a la izquierda).
  - Luego se suma el offset de 16 bits.
- Esto da una dirección de 20 bits.

## 🔹 3. Registros de segmento principales
[Memory Segmentation](capturas/Memory-Segmentation.png)

El 8086 tiene 4 registros de segmento:
- **CS (Code Segment)**
  - Apunta al segmento donde está el código (instrucciones).
  - Usado junto con el registro IP (Instruction Pointer).

- **DS (Data Segment)**
  - Apunta al segmento de datos (variables, información).
  - Usado junto con los registros generales (AX, BX, etc.) al acceder a memoria.

- **SS (Stack Segment)**
  - Apunta al segmento de la pila.
  - Usado junto con SP (Stack Pointer) y BP (Base Pointer).

- **ES (Extra Segment)**
  - Segmento extra, usado en operaciones de cadenas (ej. MOVS, LODS, STOS) como destino adicional.

## 🔹 4. Ejemplo práctico
Supongamos:
- DS = 0x1000
- Offset = 0x0020

Dirección física = 0x1000 × 0x10 + 0x0020  
= 0x10000 + 0x0020  
= 0x10020  

(Multiplicamos por 0x10 porque estamos escribiendo en hexadecimal. 0x10 (hex) = 16 (dec). Es exactamente la misma operación.)

## 🔹 5. Importante
- Dos segmentos pueden superponerse (ejemplo: CS = 0x1000 y DS = 0x1001), porque se definen solo con el valor base.
- El direccionamiento efectivo depende de qué registro de segmento se esté usando.
- La segmentación permitió que el 8086 pudiera usar 1 MB de memoria con registros de 16 bits.


_________________________________________________________________________
# Ejemplo práctico para entender cómo funciona la segmentación en el 8086
Imaginamos que tenemos el código:
```
MOV AX, 1000h   ; Cargamos el valor 1000h en AX
MOV DS, AX      ; Ahora DS = 1000h (segmento de datos)
MOV BX, 0020h   ; Offset = 0020h
MOV AL, [BX]    ; Cargamos en AL el byte de memoria en DS:BX
```

Se carga el segmento de datos (DS): `DS = 1000h`  
Se carga el offset en BX: `BX = 0020h`  
Se accede a memoria usando DS:BX
- Dirección física = DS × 10h + BX
- Dirección física = 1000h × 10h + 0020h
- Dirección física = 10000h + 20h = 10020h

👉 Por lo tanto, el MOV AL, [BX] leerá el byte almacenado en la dirección 0x10020.

_________________________________________________________________________
# Ejemplo con el Code Segment (CS)
Cuando se ejecuta una instrucción, la CPU usa:
```
Dirección física de la instrucción = CS × 10h + IP
```

Supongamos:
```
CS = 2000h
IP = 0030h
```

Dirección física = `2000h × 10h + 0030h = 20000h + 30h = 20030h`

👉 Significa que la próxima instrucción se buscará en la dirección 0x20030 de la memoria.


_________________________________________________________________________
# Ejemplo con la pila (SS:SP)
```
MOV AX, 3000h
MOV SS, AX      ; Segmento de pila = 3000h
MOV SP, 00FFh   ; Offset = 00FFh
PUSH BX         ; Guardamos BX en la pila
```
El PUSH BX hará:
- Dirección física = SS × 10h + SP
- Dirección física = 3000h × 10h + 00FFh
- Dirección física = 30000h + 00FFh = 300FFh

👉 El valor de BX se guarda en la dirección 0x300FF.


_________________________________________________________________________
# 🔹 Resumen intuitivo
- CS:IP → dónde está el código.
- DS:offset → dónde están los datos.
- SS:SP → dónde está la pila.
- ES:offset → segmento extra (usado en operaciones con cadenas).


__________________________________________________________________________
# mini-programa 8086 (modo real, DOS) que muestra segmentación
Usando CS:IP, DS:offset, SS:SP y ES:DI
```
; ---------------------------------------------
; 8086 Memory Segmentation - Demo
; - Muestra valores de CS, DS, ES, SS
; - Usa DS:SI -> ES:DI con REP MOVSB
; - Usa la pila (SS:SP) con PUSH/POP
; Ensamblar (MASM/TASM):
;   MASM seg8086.asm;
;   LINK seg8086.obj;
; Ejecutar en DOS/emu8086/DOSBox.
; ---------------------------------------------

.MODEL  small
.STACK  100h

.DATA
title   db 13,10, '== 8086 Memory Segmentation ==', 13,10,'$'
lblCS   db 13,10, 'CS = $'
lblDS   db 13,10, 'DS = $'
lblES   db 13,10, 'ES = $'
lblSS   db 13,10, 'SS = $'
crlf    db 13,10, '$'

srcTxt  db 'Hola desde DS:SI -> ES:DI', 13,10
srcLen  EQU $ - srcTxt

dstTxt  db 64 dup('$')      ; destino con '$' para imprimir con AH=09h

popped  dw 0                ; aquí guardaremos un valor pasado por la pila

.CODE
start:
    ; ----- Inicializa segmentos de datos -----
    mov     ax, @data
    mov     ds, ax          ; DS = segmento de datos
    mov     es, ax          ; ES = (para la demo lo igualamos a DS)

    ; ----- Título -----
    mov     dx, OFFSET title
    mov     ah, 09h
    int     21h

    ; ----- Mostrar CS, DS, ES, SS en hex -----
    mov     dx, OFFSET lblCS
    mov     ah, 09h
    int     21h
    push    cs
    pop     ax              ; AX = CS
    call    PrintHexAX

    mov     dx, OFFSET lblDS
    mov     ah, 09h
    int     21h
    mov     ax, ds
    call    PrintHexAX

    mov     dx, OFFSET lblES
    mov     ah, 09h
    int     21h
    mov     ax, es
    call    PrintHexAX

    mov     dx, OFFSET lblSS
    mov     ah, 09h
    int     21h
    mov     ax, ss
    call    PrintHexAX

    mov     dx, OFFSET crlf
    mov     ah, 09h
    int     21h

    ; ----- Copia de cadenas con segmentación -----
    ; DS:SI -> ES:DI usando REP MOVSB
    lea     si, srcTxt          ; SI = offset origen  (en DS)
    lea     di, dstTxt          ; DI = offset destino (en ES)
    mov     cx, srcLen          ; longitud
    cld                         ; dirección hacia adelante
    rep     movsb               ; copia srcLen bytes de DS:SI a ES:DI

    ; Imprime el destino (termina en '$')
    mov     dx, OFFSET dstTxt   ; DS:DX -> '$'-string
    mov     ah, 09h
    int     21h

    ; ----- Uso de la pila (SS:SP) -----
    mov     ax, 0ABCDh
    push    ax                  ; escribe en SS:SP (SP -= 2)
    pop     ax                  ; lee desde SS:SP (SP += 2)
    mov     popped, ax          ; guardamos para “usar” el valor

    ; Línea en blanco
    mov     dx, OFFSET crlf
    mov     ah, 09h
    int     21h

    ; Salir a DOS
    mov     ax, 4C00h
    int     21h

; ----- Rutina: imprime AX en hexadecimal (4 dígitos) -----
; Usa DOS AH=02h (teletipo)
PrintHexAX PROC
    push    cx
    push    dx
    mov     dx, ax      ; trabajamos en DX
    mov     cx, 4
@@nibble:
    rol     dx, 4       ; saca nibble alto a lo bajo
    mov     al, dl
    and     al, 0Fh
    add     al, '0'
    cmp     al, '9'
    jbe     @@out
    add     al, 7       ; 'A' - ':' = 7
@@out:
    mov     ah, 02h
    int     21h
    loop    @@nibble
    pop     dx
    pop     cx
    ret
PrintHexAX ENDP

END start

```
