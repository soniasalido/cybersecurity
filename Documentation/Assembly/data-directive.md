En 8086/Assembly, data directive (directiva de datos) es una pseudoinstrucción del ensamblador que le dice cómo reservar e inicializar memoria para nuestras variables. No la ejecuta la CPU; la usa el ensamblador para colocar bytes en el segmento de datos (u otro segmento).

Tipos más usados

DB (Define Byte): reserva 1 byte por elemento.
msg db 'Hola', 13,10,'$'

DW (Define Word): reserva palabras de 16 bits.
tabla dw 10, 20, 30

DD (Define Doubleword, 32 bits): útil para direcciones o datos largos (aunque en 8086 se manipula en dos palabras).
ptr dd 12345678h

(También existen DQ 64-bit y DT 80-bit en algunos ensambladores.)

Extras útiles:

DUP: repetición/relleno.
buffer db 64 dup(?) ← 64 bytes sin inicializar
ceros dw 8 dup(0) ← 8 words inicializados a 0

?: reserva sin inicializar.
temp db ?

EQU: constante simbólica (no reserva memoria).
FINLINE EQU 13
