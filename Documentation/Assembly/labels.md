# Labels
Una label (etiqueta) es un nombre simbólico que el programador da a una dirección de memoria o instrucción.

El ensamblador sustituye la label por la dirección real durante la traducción del código.

## Tipos de Labels

### 1. Labels de datos

```
byte1: db 0ABh
```
- byte1 → es el nombre (label) que le damos a la dirección de memoria donde se guardará ese dato.
- db → directiva (define byte), que reserva 1 byte en memoria.
- 0ABh → valor inicial que tendrá ese byte.

👉 Cuando el ensamblador procese esto, reservará 1 byte en el **segmento de datos** y lo inicializará con ABh.  
El nombre byte1 será simplemente **un alias de la dirección de esa celda de memoria.**

**Uso en el programa:**
```
mov al, byte1      ; mueve el contenido de [byte1] → AL = ABh
mov [byte1], 5     ; guarda 05h en la dirección de byte1
```

**Importante:** cuando usamos el nombre de la label sin corchetes, muchas veces el ensamblador lo interpreta como la dirección, no el contenido.  
Por eso mov ax, byte1 no mete 0ABh en AX, sino la dirección de la variable.  
Si queremos el contenido, se usan corchetes: mov al, [byte1].


### 2. Labels de código

Sirven para marcar posiciones dentro del segmento de código, para poder saltar, llamar o volver.
