## Métodos para estructurar la tabla de particiones en una unidad de almacenamiento
MBR y GPT son los esquemas de partición que organizan el almacenamiento en los discos duros.

### 1. MBR - Master Boot Record:
MBR es el esquema de partición más antiguo y se ha utilizado desde 1983 en sistemas con BIOS.

**Se encuentra en el primer sector del disco duro (sector 0) y contiene:**
- El código del gestor de arranque: Un pequeño programa que inicia el sistema operativo.
- La tabla de particiones: Contiene información sobre hasta 4 particiones primarias.
- El "Magic Number": Un identificador que indica que el MBR es válido.

**Limitaciones de MBR:**
- Soporta discos de hasta 2 TB: Cualquier espacio adicional no es reconocido.
- Máximo de 4 particiones primarias: Para más particiones, se debe crear una partición extendida con particiones lógicas dentro.
- No incluye redundancia: Si el MBR se corrompe, el disco puede volverse inaccesible.

### 2. GPT - GUID Partition Table:
GPT es el sucesor de MBR y es parte del estándar UEFI. Almacena información sobre particiones en múltiples ubicaciones dentro del disco, lo que lo hace más seguro y flexible.

**Ventajas de GPT sobre MBR**
- Soporta discos de más de 2 TB: Puede manejar hasta 9.4 ZB (zettabytes).
- Permite hasta 128 particiones sin necesidad de particiones extendidas.
- Mayor seguridad: Contiene copias redundantes de la tabla de particiones en diferentes partes del disco, lo que permite recuperar datos si una copia se corrompe.
- Usa CRC32 (Cyclic Redundancy Check) para verificar la integridad de los datos.

## Conceptos básicos de MBR
Un **disco organizado mediante particiones DOS tiene un MBR (Master Boot Record) en el primer sector de 512 bytes del disco**. Este sector es esencial para el arranque del sistema operativo y la gestión de particiones en discos organizados con particiones DOS. Puede ser utilizado con sistemas de archivos como FAT32 y NTFS.



## Estructura del MBR. El MBR contiene tres partes principales:
**1. Código de arranque (Bootloader)**
- Es un pequeño programa que se ejecuta al iniciar la computadora.
- Su función es encontrar y cargar el sistema operativo desde la tabla de particiones.
- En sistemas Windows, este código puede ser el NTLDR (Windows XP) o BOOTMGR (Windows 7 en adelante).

**2. Tabla de particiones (Partition Table)**
- Contiene información sobre las particiones del disco.
- Puede manejar hasta 4 particiones primarias o 3 primarias + 1 extendida.

**3. Firma del disco (Disk Signature)**
- Un identificador único que ayuda al sistema operativo a reconocer el disco.
- Su valor es 0x55AA en hexadecimal, lo que indica que el MBR es válido.


## Campos de la Tabla de Particiones en MBR
La tabla de particiones tiene cuatro entradas, cada una de las cuales puede describir una partición de DOS. Cada entrada tiene los siguientes campos:
| Campo |	Descripción |
|---|---|
| Starting CHS address |		Dirección CHS (Cylinder-Head-Sector) de inicio de la partición. |
| Ending CHS address |		Dirección CHS de final de la partición. |
| Starting LBA address |		Dirección en LBA (Logical Block Addressing) donde comienza la partición. |
| Number of sectors in partition |		Cantidad de sectores que conforman la partición. |
| Type of partition |		Código que indica el tipo de sistema de archivos (FAT32, NTFS, Linux, etc.). |
| Flags |		Indicadores especiales, como si la partición es arrancable (bootable). |


## Direcciones CHS vs. LBA
- **CHS (Cylinder-Head-Sector)**
 - Método antiguo de direccionamiento basado en cilindros, cabezales y sectores del disco.
 - Solo funciona para discos de menos de 8 GB debido a las limitaciones del BIOS antiguo.

- **LBA (Logical Block Addressing)**
 - Sistema moderno basado en bloques lógicos en lugar de cilindros y cabezales.
 - Permite gestionar discos de varios terabytes (TB).
 - Es utilizado en todos los sistemas operativos modernos con MBR y GPT.


**Cada entrada de la tabla describe el diseño de una partición en direcciones CHS y LBA.**

## El Campo de Tipo de Partición
En la tabla de particiones del MBR (Master Boot Record), cada partición tiene un campo de tipo de partición que indica qué tipo de datos se espera que contenga la partición.

**Ejemplos Comunes de Tipos de Partición**
| Código | Sistema de Archivos |
| 0x07 | 	NTFS (Windows) |
| 0x0B / 0x0C | 	FAT32 (Windows) |
| 0x83 | 	EXT4 (Linux) |
| 0x82 | 	Swap (Linux) |
| 0x05 / 0x0F | 	Partición Extendida |


**Diferencias entre Windows y Linux en el Uso del Tipo de Partición**
- Windows: Depende del campo de tipo de partición para montar el sistema de archivos. Si el tipo de partición no es compatible, Windows no mostrará la partición.
- Linux: No depende del tipo de partición, puede ignorarlo. Por ejemplo, si un usuario tiene una partición con tipo NTFS, pero dentro hay un sistema de archivos FAT32, Linux lo montará como FAT32 sin problema.

**🔹 Ejemplo de uso para ocultar particiones en Windows:**
- Algunas herramientas pueden modificar el tipo de partición para que Windows no la reconozca. Por ejemplo, si una partición tiene un sistema de archivos FAT32, pero el tipo de partición se cambia a Linux (0x83), Windows no la mostrará en el Explorador de Archivos.

## El Campo Flag en la Tabla de Particiones
Cada entrada de la tabla de particiones del MBR también contiene un campo flag, que indica cuál es la partición de arranque.

**🔹 ¿Cómo funciona el Flag de Arranque?**
- El flag de arranque marca una partición como bootable, lo que significa que el BIOS buscará el gestor de arranque en esa partición.
- Solo una partición primaria puede estar marcada como arrancable en el MBR.
- Si ninguna partición tiene este flag activado, el sistema no podrá arrancar.



El MBR es un método sencillo para describir hasta cuatro particiones. Sin embargo, muchos sistemas requieren más particiones que eso. Por ejemplo, consideremos un disco de 12 GB que el usuario desea dividir en seis particiones de 2 GB porque utiliza varios sistemas operativos. No podemos describir las seis particiones utilizando las cuatro entradas de la tabla de particiones. La solución a este problema de diseño es lo que hace que las particiones de DOS sean tan complejas. La teoría básica detrás de la solución es usar una, dos o tres de las entradas en el MBR para particiones normales y luego crear una "partición extendida" que llenará el resto del disco. Las particiones extendidas tienen tipos especiales que se utilizan en las entradas de su tabla de particiones.


## Estructura de datos MBR
Las tablas de particiones de DOS existen en el MBR y en el primer sector de cada partición extendida. Convenientemente, todos utilizan la misma estructura de 512 bytes. Los primeros 446 bytes están reservados para el código de arranque ensamblador. El código debe existir en el MBR porque se usa cuando se inicia la computadora, pero las particiones extendidas no lo necesitan y podrían contener datos ocultos. El diseño del MBR en forma tabular se puede encontrar en la siguiente tabla:
Data structures for the DOS partition table:
Byte Range  Description                Essential

0–445       Boot Code                  No

446–461     Partition Table Entry #1   Yes

462–477     Partition Table Entry #2   Yes

478–493     Partition Table Entry #3   Yes

494–509     Partition Table Entry #4   Yes

510–511     Signature value (0xAA55)   No 

![](https://niguelas.org/extras/capturas/estructuraMBR-Wikipedia.png)
![](https://niguelas.org/extras/capturas/estructuraMBR2.png)


## Editor hexadecimal
Abrimos con Active Disk Editor una imagen de un sistema Windows XP con sistema de archivos FAT32.
Aquí están los primeros 512 bytes, que es el primer sector del disco. Eso significa que este es el Master Boot Record (MBR).  Vemos que la tabla de particiones para este disco es MBR. La información aparece en el sector 0. El MBR comprende los primeros 512 bytes (sector 0), y dentro de él se encuentra la tabla de particiones, alojada a partir del byte 446.

La tabla de particiones ocupa 64 bytes, conteniendo 4 registros de 16 bytes, los cuales definen las particiones primarias (estas a su vez pueden tener particiones extendidas). En ellas se almacena toda la información básica sobre la partición: si es arrancable, si no lo es, el formato, el tamaño y el sector de inicio.

La columna de la izquierda es el desplazamiento de bytes de la fila en decimal, las 8 columnas del medio son 16 bytes de datos en hexadecimal y la última columna es el equivalente ASCII de los datos. Un '.' existe donde no hay ningún carácter ASCII imprimible para el valor. Cada símbolo hexadecimal representa 4 bits, por lo que un byte necesita 2 símbolos hexadecimales.

![](https://niguelas.org/extras/capturas/estructuraMBR.png)


## Code (446 bytes)
446 bytes si incluye disk signature y nulls.
440 bytes si no los incluye.

El código de arranque en un disco DOS existe en los primeros 446 bytes del primer sector de 512 bytes, que es el MBR. El final del sector contiene la tabla de particiones. El código de arranque estándar de Microsoft procesa la tabla de particiones en el MBR e identifica qué partición tiene configurada la bandera de arranque. Cuando encuentra dicha partición, busca en el primer sector de la partición y ejecuta el código que se encuentra allí. El código al inicio de la partición será específico del sistema operativo. Los virus del sector de arranque se insertan en los primeros 446 bytes del MBR para que se ejecuten cada vez que se inicia la computadora.

Cuando se tienen varios sistemas operativos en una computadora, hay dos maneras de manejar esto. Windows maneja esto al tener un código en la partición de arranque que permite al usuario seleccionar qué sistema operativo cargar. En otras palabras, el código de arranque en el MBR se ejecuta primero y carga el código de arranque de Windows. El código de inicio de Windows permite al usuario elegir una partición diferente desde la cual iniciar. El otro método es cambiar el código en el MBR. El nuevo código MBR presenta al usuario una lista de opciones y el usuario elige desde qué partición iniciar. Por lo general, esto requiere más código y utiliza algunos de los sectores no utilizados que existen antes de que comience la primera partición.
![](https://niguelas.org/extras/capturas/code.png)


## Valores de Flags
Las flags sirven por ejemplo para saber si una partición es de arranque o no. Un método para almacenar esta información es asignarle un byte completo y guardar el valor 0 o 1. Sin embargo, esto desperdicia mucho espacio porque sólo se necesita 1 bit, pero se asignan 8 bits. Un método más eficaz consiste en agrupar varias de estas condiciones binarias en un solo valor. Cada bit del valor corresponde a una característica u opción. Con frecuencia se denominan indicadores porque cada bit indica si una condición es verdadera. Para leer el valor de una flag, necesitamos convertir el número a binario y luego examinar cada bit.


00 00 00 00 00 2C 49 6E  --  12 81 12 81 00 00 80 01

01 00 0C FE FF FF 3F 00  --  00 00 D9 A6 3F 01 00 00 


## Disk signature (4 bytes):
![](https://niguelas.org/extras/capturas/1ra-Particion.png)

Flags: 000001B0 – 08 09 0A 0B -->

12 81 12 81 - Se lee en little-endian: De derecha a izquierda en cada columna de bytes: Disk Signature: 81 12 81 12.
 

## Nulls (2 Bytes):
Flags: 000001B0 – 0C 0D -->

00 00


## Estructura de datos para entradas de partición tipo DOS.
Vemos un ejemplo para la primera partición de nuestra imagen de WindowsXP:

-- -- -- -- -- -- -- --  --  -- -- -- -- -- -- 80 01

01 00 0C FE FF FF 3F 00  --  00 00 D9 A6 3F 01 -- -- 

Byte Range Description Essential

0–0 Bootable Flag No --> 80

1–3 Starting CHS Address Yes --> 01 01 00 litle endian--> 00 01 01 big endian

4–4 Partition Type No --> 0C

5–7 Ending CHS Address Yes --> FE FF FF litle endian --> FF FF FE big endian

8–11 Starting LBA Address Yes --> 3F 00 00 00 litle endian --> 00 00 00 3F big endian

12–15 Size in Sectors Yes  --> D9 A6 3F 01 litle endian --> 01 3F A6 D9 big endian




## Análisis de la primera partición:
![](https://niguelas.org/extras/capturas/templates.png)
![](https://niguelas.org/extras/capturas/1ra-Particion.png)

+ Active Partition flag: 000001B0 – 0E --> 0x80 El indicador de arranque es 80 lo que implica que es una partición arrancable.

+ CHS del primer sector:

  Start Cylinder: Flag Position: 000001B0 - 0F → Valor que contiene → 0x01

  Start Head: Flag Position: 00001C0 - 00  → Valor que contiene →  0x01

  Start Sector: Flag Position: 000001C0 - 01  → Valor que contiene →  0x00


+ Type System ID: Flag 000001C0 – 02 --> 0C  --> Significa que el sistema de ficheros es FAT32
![](https://niguelas.org/extras/capturas/type-sistem.png)


+ CHS del último sector:

  Start Cylinder: Flag Position: 000001C0 - 03 → Valor que contiene → 0xFE

  Start Head: Flag Position: 00001C0 - 04  → Valor que contiene →  0xFF

  Start Sector: Flag Position: 000001C0 - 05  → Valor que contiene →  0xFF


+ Starting LBA Address (Relative Sectors): Flag Position: 000001C0 – De 06 a 09
  LBA es la abreviatura de Dirección de bloque lógico. Esto significa que los sectores de un disco se numeran secuencialmente comenzando con el número LBA 0. Cada sector se identifica por un número LBA inequívoco.

  01 00 0C FE FF FF 3F 00  --  00 00 D9 A6 3F 01 00 00 
  Starting LBA Address: 3F 00  --  00 00. Se lee en little-endian: Se lee de derecha a izquierda en cada columna de bytes: 00 00 00 3F. Si lo convertimos de hexadecimal a decimal: 63. Esta primera partición empieza en el sector 63. Esta partición FAT32 comienza en el sector número 63.

  Nuestro editor hexadecimal muestra compensaciones en bytes, no en números de sector. Entonces, necesitamos encontrar el desplazamiento de bytes de este sector número 2048 . Podemos hacerlo fácilmente multiplicando 63 por 512 porque hay 512 bytes en un sector.

  63 x 512 = 32256

  Nuevamente, tenemos que convertir este desplazamiento de bytes decimal 32256 en hexadecimal antes de ir allí:

  32256 (decimal) = 7E00 (hexadecimal)

  Ahora, 7E00 es el desplazamiento de bytes en hexadecimal en donde puede encontrar la partición FAT32:
 ![](https://niguelas.org/extras/capturas/incioFAT.png)

  El primer sector de la partición FAT32 se llama sector de arranque.


+ Size (total sectors): Flags Position: 000001C0 – De 0A a 0D:
  
  01 00 0C FE FF FF 3F 00  --  00 00 D9 A6 3F 01 00 00 

  Total sectors: D9 A6 3F 01. Se lee en little-endian: Se lee de derecha a izquierda en cada columna de bytes: 01 3F A6 D9. Si convertimos ese número hexadecimal en decimal: 20948697.
  Tamaño de la primera partición en sectores: 20948697.
  Tamaño 20948697 (sectores) x 512 bytes (tamaño del sector) = 10725732864 bytes. Convertido a gigabytes: 10,7Gb.


## Análisis de la segunda, tercera y cuarta partición:
No hay.
