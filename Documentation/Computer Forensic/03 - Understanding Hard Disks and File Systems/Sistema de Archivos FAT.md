
## ¿Un sistema de archivos FAT32 puede usar GPT?
Un sistema de archivos FAT32 puede usarse con una tabla de particiones GPT (GUID Partition Table). La compatibilidad entre el sistema de archivos y el esquema de particiones es independiente, lo que significa que puedes usar FAT32 con tanto MBR (Master Boot Record) como GPT.


## Listamos la estructura de las particiones que tiene la imagen:
Usaremos la herramienta mmls de Sletuhkit para listar el contenido de la tabla de particiones:
```
.\mmls.exe -t dos Z:\CHFI\LABS\EvidenceFiles\Forensic-Images\WinXP-32bits.dd
```
![](https://niguelas.org/extras/capturas/detalleImagen.png)

La herramienta mmls organiza las entradas de la tabla de particiones según su sector inicial e identifica los sectores que no están asignados a una partición. Las dos primeras líneas, numeradas 00 y 01, son la tabla de particiones primaria y el espacio no utilizado entre la tabla de particiones y la primera partición. Vemos en el resultado que la línea 02 es una partición con un sistema de archivos FAT32. La línea 03 es una partición de espacio no asignado en el disco.

Para obtener las particiones del sistema de archivos de la imagen del disco, tomamos el sector inicial y el tamaño de cada partición y los conectamos con el comando dd. Por ejemplo para extraer la partición FAT32:
```
dd if=WinXP-32bits.dd of=partion1.dd bs=512 skip=63 count=0020948697
```
Este comando toma el archivo WinXP-32bits.dd como entrada y guardan el resultado en un archivo denominado particion1.dd y se copian bloques de 512 bytes cada uno.
La primera partición se extrae omitiendo 63 bloques antes de copiar y luego copiar 20.948.697 bloques. En la salida de mmls, vimos que la partición comenzó en el sector 63, por lo que es posible que se sienta inclinado a omitir solo 62 bloques. Sin embargo, hay que recordar que las direcciones del sector comienzan en 0, por lo que debemos omitir 63. La extensión .dd se usa aquí para mostrar que estos archivos son archivos de imágenes sin formato (raw) que fueron creados con una herramienta similar a dd.


## MBR o GPT?
FAT32 puede usar MBR o GPT para organizar las particiones del disco.
En nuestro ejemplo, el sistema usado es MBR. Se recomienta la lectura del documento: Master Boot Record para entender cómo se llega al punto de encontrar cual es el primer sector de la partición FAT32.
[Master Boot Record](https://github.com/soniasalido/CHFI/blob/main/Modulo03/Master%20Boot%20Record.md)

### Primer Sector de la partición FAT32
![](https://niguelas.org/extras/capturas/FAT-Layout.png)
![](https://niguelas.org/extras/capturas/Fat16-Fat32-Compared.png)
![](https://niguelas.org/extras/capturas/incioFAT.png)
![](https://niguelas.org/extras/capturas/primerSectorFAT32.png)
![](https://niguelas.org/extras/capturas/FAT-Boot-Sector-VBR.png)

En una partición FAT32, el primer sector se llama sector de arranque, también conocido como Boot Sector o Volume Boot Record (VBR). Este sector es crítico para el proceso de arranque y contiene información esencial sobre la configuración de la partición y el sistema de archivos.

+ El sector de arranque de una partición FAT32 típicamente incluye lo siguiente:
 - Código de Arranque: Un programa pequeño utilizado durante el proceso de arranque del sistema operativo. Este código es responsable de cargar los archivos adicionales necesarios para iniciar el sistema operativo.
 - Información del Sistema de Archivos: Detalles sobre la configuración de la partición FAT32, como el tamaño de los sectores, el tamaño del cluster, el número de sectores reservados, el número de FATs, el número de entradas en la tabla de directorio raíz, etc.

 - Datos de la BIOS: Incluye la firma de arranque, que es necesaria para que la BIOS identifique el sector como un sector de arranque válido.

 - Tablas de Asignación de Archivos (FAT): Después del sector de arranque, siguen una o más copias de la FAT, que es una tabla que lleva un registro de qué clusters están siendo utilizados y cómo están enlazados los archivos y directorios.

 - Sector de Reserva: Espacio reservado para el uso del sistema operativo, normalmente incluye el sector de arranque y las tablas FAT.

+ Tamaño del sector: Flags Position: 7E00 - 0B y 0C --> En este sector de arranque, el desplazamiento 0x0B contiene 2 bytes que especifican el número de bytes por sector. El valor que puede encontrar en esta ubicación es 00 02 y, como es habitual, está en little-endian. Convertido a big-endian y obtenemos 02 00 . Al convertir este número hexadecimal a decimal nos da 512 . Eso significa que claramente se aplica la regla de 512 bytes por sector dentro de esta partición FAT32.


+ Número de sectores por cada clúster: Flag Position: 7E00 - 0D --> En este sector de arranque, el desplazamiento 0x0D contiene un byte que especifica el número de sectores por cada clúster. Vemos qué hay en ese lugar. En nuestro sector de arranque, esta ubicación contiene el valor 0x10. La conversión de hexa a decimal nos da 16 como respuesta. Eso significa que cada clúster en esta partición es en realidad 16 sectores.

  
+ Número de sectores reservados en esta partición FAT32: Flags Position: 7E00 - 0E y 0F --> En este sector de arranque, el desplazamiento 0x0E contiene 2 bytes que especifican el número de sectores reservados en esta partición FAT32. Es decir, la cantidad de sectores entre el inicio de la partición y la tabla FAT1. El valor en ese desplazamiento nos da 22 00 , que está en little-endian. En big-endian, obtenemos el valor hexadecimal 0x0022 , que es 34 en decimal. Es decir, hay 34 sectores en el área reservada antes de la tabla FAT1. Es importante señalar que estos 34 sectores incluyen el propio sector de arranque. En otras palabras, el sector de arranque es sólo un sector más en el área reservada.
  

+ Número de tablas FAT: En el sistema de archivos FAT32, el Número de Tablas FAT (File Allocation Tables) se encuentra en el sector de arranque, también conocido como el Registro de Arranque Principal (MBR, por sus siglas en inglés) del volumen FAT32. Este sector es el primer sector del volumen y contiene la información necesaria para el arranque y el acceso a los archivos del sistema. En este sector de arranque, el desplazamiento 0x10 contiene un byte que especifica el número de tablas FAT que tenemos en esta partición. Generalmente hay 2 tablas llamadas FAT1 y FAT2, pero es mejor ver si es cierto. El valor en ese desplazamiento especifica el valor 02 en hexadecimal. En decimal, el valor es 2 y eso significa que tenemos dos tablas FAT.

+ Número de sectores por cada tabla FAT: El desplazamiento 0x16 en el sector de arranque tiene 2 bytes que especifican el número de sectores en cada tabla FAT. Hay una cosa importante a tener en cuenta aquí. Si estos dos bytes contienen algún valor distinto de cero, podemos tomar ese número. Sin embargo, si la ubicación contiene todos ceros en esos dos bytes, eso significa que el espacio no es suficiente para especificar la información. En ese caso, tenemos que ir al desplazamiento 0x24 e interpretar allí 4 bytes.

  El valor en los dos bytes en el desplazamiento 0x16 nos da 00 00 en nuestra imagen. Eso significa que tenemos que ir al 0x24 y tomar los 4 bytes que tiene. En nuestra imagen tenemos EB 27 00 00. La conversión de little-endian nos da el valor 00 00 27 EB que es 10219 en decimal. Por lo tanto, concluimos que hay 10219 sectores en una tabla FAT. Como tenemos dos tablas FAT, ocupan el doble de ese espacio. 10219 x 2 = 20438.





### Directorio Raíz
En el sistema de archivos FAT32, la ubicación del directorio raíz se determina por varios valores en la Región Reservada del volumen FAT32, que está al principio del volumen. Para encontrar el comienzo del directorio raíz en FAT32, debes leer la información contenida en el Sector de Arranque del volumen (también conocido como Registro de Arranque Principal o MBR). Aquí están los pasos y los valores clave para ubicar el directorio raíz:
 - Sectores por Cluster: Este valor indica cuántos sectores componen un cluster. Es importante porque FAT32 utiliza clusters para asignar espacio.
 - Número de Reservas de Sectores: Esto incluye el sector de arranque y suele ser un pequeño número (frecuentemente 32 en FAT32).
 - Número de Tablas FAT: Normalmente son dos (para redundancia).
 - Sectores por Tabla FAT: Este valor varía dependiendo del tamaño del volumen.
 - Número de Sectores Reservados: Incluye los sectores de la Región Reservada.

???? Para calcular la ubicación del directorio raíz en FAT32, puedes usar la siguiente fórmula:

 Comienzo del directorio raiz = (Numero de sectores reservados + (Numero de tablas FAT * Sectores por tabla FAT))* Tamaño del sector.

 Número de sectores reservados en esta partición FAT32: 34
 
 Número de tablas FAT: 2
 
 Sectores por tabla FAT: 10219
 
 Tamaño del sector: 512
 
 Comienzo directorio raiz: (34 + (2*10219))*512 = 10481664 en decimal. 9ff000 en hexadecimal.
 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 ?????


 En Active Disk Editor podemos navegar al Root Directory, haciendo el programa los cálculos necesarios para acceder diréctamente: 
 ![](https://niguelas.org/extras/capturas/directorio-raiz1.png)
 ![](https://niguelas.org/extras/capturas/directorio-raiz2.png)

 El Root Directory es una serie de entradas que describen ficheros. Cada entrada de 32 bytes contiene:
  - Single short (8.3) filename (SFN)
  - Attributos.
  - Mac times.
  - Start Cluster.
  - Size.
  - Otros metadatos.
  - Additonal 32B entries contain the file's long filename (LFN)

 Cada entrada en el directorio raíz de un sistema de archivos FAT (incluyendo FAT32) ocupa 32 bytes y contiene información sobre un archivo o directorio. A continuación, te detallo la estructura de una entrada de directorio de 32 bytes en FAT:
  - Nombre del Archivo (bytes 0-10, 11 bytes en total): Los primeros 8 bytes contienen el nombre del archivo en formato ASCII, y los siguientes 3 bytes contienen la extensión del archivo. Este es el antiguo formato 8.3, donde los nombres de archivo tienen un máximo de 8 caracteres y las extensiones un máximo de 3 caracteres.
  - Atributos del Archivo (byte 11, 1 byte): Indica si la entrada es un archivo, un directorio, o si tiene otros atributos como sistema, archivo oculto, etc.
  - Reservado para Uso por NT (byte 12, 1 byte): Este byte es utilizado por Windows NT para otros fines.
  - Hora de Creación en Milisegundos (byte 13, 1 byte): El milisegundo de creación del archivo o directorio.
  - Hora de Creación (bytes 14-15, 2 bytes): La hora a la que fue creado el archivo o directorio.
  - Fecha de Creación (bytes 16-17, 2 bytes): La fecha en que fue creado el archivo o directorio.
  - Fecha de Último Acceso (bytes 18-19, 2 bytes): La última fecha en la que el archivo o directorio fue accedido.
  - Primera Clúster de Alto Orden (bytes 20-21, 2 bytes): En FAT32, estos dos bytes, junto con los dos bytes del offset 26-27, forman el número de clúster en el que comienza el archivo o directorio.
  - Hora de Última Modificación (bytes 22-23, 2 bytes): La última hora en la que el archivo o directorio fue modificado.
  - Fecha de Última Modificación (bytes 24-25, 2 bytes): La última fecha en la que el archivo o directorio fue modificado.
  - Primera Clúster de Bajo Orden (bytes 26-27, 2 bytes): Los dos bytes más bajos del número de clúster en el que comienza el archivo o directorio.
  - Tamaño del Archivo (bytes 28-31, 4 bytes): El tamaño total del archivo en bytes. Para directorios, este valor es generalmente 0.

  ![](https://niguelas.org/extras/capturas/sfn.png)
  
 El directorio raíz contiene entradas de 32 bytes de longitud. Este índice es un tipo especial de archivo que almacena las sub-carpetas y archivos que componen cada carpeta. Cada entrada del directorio contiene el nombre del archivo o carpeta (máximo 8 caracteres), su extensión (máximo 3 caracteres), sus atributos (archivo, carpeta, oculto, del sistema, o volumen), la fecha y hora de creación, la dirección del primer cluster donde están los datos, y por último, el tamaño que ocupa. El directorio raíz ocupa una posición concreta en el sistema de archivos, pero los índices de otras carpetas ocupan la zona de datos como cualquier otro archivo. Los nombres largos se almacenan ocupando varias entradas en el índice para el mismo archivo o carpeta.



### Ficheros eliminados
Ahora nuestro documento de referencia indica qué bytes en una entrada de directorio especifica qué información. El primer byte de una entrada del directorio raíz es importante. Si se elimina un archivo, el primer byte simplemente se establece en 0xE5 . Ahora puede identificar 3 entradas que tienen el primer byte establecido en 0xE5 y, por lo tanto, simplemente eliminan archivos. Seleccionaré solo un archivo de este directorio raíz y lo exploraré. Depende de usted ocuparse de los archivos restantes.


### Relacción entre las estructuras de entradas de directorio, Clusters y la estructura FAT
![](https://niguelas.org/extras/capturas/directoryEntry-Cluster-FAT.png)

 
### Fat, Slack y Espacion Unallocated:
![](https://niguelas.org/extras/capturas/fat-slack-unallocated.png)


### ¿Dónde está el primer FAT Cluster?
![](https://niguelas.org/extras/capturas/where-is-the-frist-cluster.png)
 
