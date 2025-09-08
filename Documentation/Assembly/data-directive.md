# Data Directive - Directiva de Datos
En 8086/Assembly, data directive (directiva de datos) es una pseudoinstrucción del ensamblador que le dice cómo reservar e inicializar memoria para nuestras variables. No la ejecuta la CPU; la usa el ensamblador para colocar bytes en el segmento de datos (u otro segmento).

## Tipos más usados
- DB (Define Byte): reserva 1 byte por elemento.  
msg db 'Hola', 13,10,'$'

- DW (Define Word): reserva palabras de 16 bits.  
tabla dw 10, 20, 30

- DD (Define Doubleword, 32 bits): útil para direcciones o datos largos (aunque en 8086 se manipula en dos palabras).
ptr dd 12345678h

(También existen DQ 64-bit y DT 80-bit en algunos ensambladores.)

## Extras útiles:
-DUP: repetición/relleno.  
buffer db 64 dup(?) ← 64 bytes sin inicializar  
ceros dw 8 dup(0) ← 8 words inicializados a 0  

- ?: reserva sin inicializar.  
temp db ?

- EQU: constante simbólica (no reserva memoria).  
FINLINE EQU 13


## .DATA vs directivas de datos

.DATA (o DATA SEGMENT / ENDS) es una directiva de segmentación: abre/cierra el segmento de datos.

DB, DW, DD… son directivas de definición: dentro (o fuera) de ese segmento crean variables y colocan sus bytes.

## Detalles clave
- Little-endian: en memoria, los valores multibyte se guardan con el byte bajo primero (p. ej., dw 1234h → bytes 34h 12h).
- Un label (como msg) representa el offset dentro de su segmento; puedes obtenerlo con OFFSET msg o LEA.
- En 8086, para usar los datos debes cargar DS con el segmento correcto (típicamente @data en MASM/TASM).


## Data directives y acceso a datos

### Strings (cadenas)  
- Terminada en $ (para DOS int 21h/ah=09h):
  ```
  msg db 'Hola mundo',13,10,'$'
  ; Uso:
  mov ax, @data
  mov ds, ax
  lea dx, msg        ; DS:DX -> '$'-string
  mov ah, 09h
  int 21h
  ```

- Terminada en 0 (C-style):
  ```
  s0  db "Hola",0
  ; Recorrido con LODSB hasta 0:
  mov ax,@data
  mov ds,ax
  lea si,s0
  cld
  .next:
  lodsb              ; AL = [DS:SI], SI++
  test al,al         ; ¿AL==0?
  jz .done
  ; ... usar AL ...
  jmp .next
  .done:
  ```

- Copia de cadenas (DS:SI → ES:DI) con instrucciones de cadenas:
  ```
  src db "Texto a copiar",0
  dst db 64 dup(0)
  
  mov ax,@data
  mov ds,ax
  mov es,ax
  lea si,src
  lea di,dst
  mov cx, LENGTHOF src       ; si tu ensamblador lo soporta; si no, pon la longitud a mano
  cld
  rep movsb                   ; copia CX bytes
  ```

### Reservas con DUP y sin inicializar
```
buf1  db 64 dup(?)      ; 64 bytes sin inicializar
buf0  db 32 dup(0)      ; 32 bytes a cero
wtab  dw 128 dup(?)     ; 128 words
```
- ? = no inicializa (más rápido de ensamblar/cargar).
- dup(x) repite el patrón x.


## Tabla rápida — 8086 data directives y acceso

| Directiva | Tamaño / Tipo         | Ejemplo                   | ¿Para qué sirve? / Notas                                     |
| --------- | --------------------- | ------------------------- | ------------------------------------------------------------ |
| `DB`      | 1 byte                | `msg db 'Hola',13,10,'$'` | Definir bytes (texto, flags, etc.).                          |
| `DW`      | 2 bytes (word)        | `val dw 0A23h`            | Valores de 16 bits. **Little-endian** en memoria.            |
| `DD`      | 4 bytes (dword)       | `ptr dd 12345678h`        | Datos de 32 bits (se guardan como 4 bytes little-endian).    |
| `DQ`      | 8 bytes               | `big dq 0`                | (Según ensamblador) 64-bit. En 8086 se maneja por partes.    |
| `DT`      | 10 bytes              | `ext dt 0`                | (Según ensamblador) 80-bit (p. ej., FP extendido).           |
| `DUP`     | Repetición            | `buffer db 64 dup(?)`     | Reserva repetida: `?` = sin inicializar, `0` = inicializado. |
| `?`       | Sin inicializar       | `temp dw ?`               | Reserva espacio sin cargar bytes en el binario.              |
| `EQU`     | Constante simbólica   | `FINLINE EQU 13`          | No reserva memoria; reemplazo en ensamblado.                 |
| `.DATA`   | Segmento de datos     | `.DATA …`                 | Datos **inicializados**. Cargar `DS` con `@data`.            |
| `.DATA?`  | Datos sin inicializar | `.DATA? …`                | Sección tipo **BSS** (no ocupa en el ejecutable).            |



## Acceso típico (patrones)
| Uso                         | Snippet (resumen)                                                                                   | Nota                                    |
| --------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------- |
| Imprimir cadena DOS (`$`)   | `msg db 'Hola',13,10,'$'`<br>`mov ax,@data \| mov ds,ax`<br>`lea dx,msg`<br>`mov ah,09h \| int 21h` | `int 21h/AH=09h` imprime hasta `$`.     |
| Leer `arrB[i]` (bytes)      | `arrB db 10,20,30`<br>`mov bx,OFFSET arrB`<br>`mov si,2`<br>`mov al,[bx+si]`                        | Índice directo (1 byte/elem).           |
| Leer `arrW[i]` (words)      | `arrW dw 1000h,2000h`<br>`mov bx,OFFSET arrW`<br>`mov si,1 \| shl si,1`<br>`mov ax,[bx+si]`         | Multiplica índice ×2.                   |
| Copiar cadena DS\:SI→ES\:DI | `mov es,ds`<br>`lea si,src \| lea di,dst`<br>`mov cx,len \| cld \| rep movsb`                       | Instrucciones de cadena.                |
| Puntero **near** (offset)   | `pMsg dw OFFSET msg`<br>`mov dx,[pMsg]`                                                             | 16-bit offset en el **mismo** segmento. |
| Puntero **far** (seg\:off)  | `pFar dw OFFSET lbl, SEG lbl`<br>`mov di,[pFar] \| mov ax,[pFar+2] \| mov es,ax`                    | 32-bit: `segment:offset`.               |
| Forzar tamaño               | `mov byte ptr [bx],1`<br>`mov word ptr [bx],1234h`                                                  | Desambigua acceso a memoria.            |


## Modos de direccionamiento y segmento por defecto
| EA (Effective Address)                       | Segmento por defecto | Comentario                                        |
| -------------------------------------------- | -------------------- | ------------------------------------------------- |
| `[bx]`, `[si]`, `[di]`, `[bx+si]`, `[bx+di]` | **DS**               | Acceso a datos típico.                            |
| `[bp]`, `[bp+si]`, `[bp+di]`                 | **SS**               | Usar pila/frames. Para DS explícito: `[ds:bp+…]`. |
| Con override                                 | `mov al,[es:di]`     | `ES:`, `DS:`, `SS:`, `CS:` fuerzan segmento.      |
