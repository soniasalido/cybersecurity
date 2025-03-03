
### Análisis forense de una imagen con sleuthkit:
+ Comandos para ver información de los discos montados: Verificar la Partición Correcta: Asegúrate de que estás especificando la partición correcta. Puedes usar comandos como lsblk, fdisk -l, o blkid para listar las particiones y sus tipos de sistemas de archivos.
  - Comando lsblk.
  - Comando fdisk -l
  - Comando blkid

+ Usar mmls para identificar la estructura de las particiones: El comando mmls se usa principalmente para mostrar la tabla de particiones de un disco o imagen de disco. Proporciona información detallada sobre cada partición, como el sistema de archivos, el tamaño y los sectores de inicio y fin
```
mmls datos.dd
```
![](https://niguelas.org/extras/capturas/mmls.png)

Con mmls descubrimos el offset que tiene la partición que queremos investigar: 00000128: Especifica el desplazamiento (offset) al sistema de archivos si la imagen de disco contiene varias particiones.

+ Usar fsstat: La herramienta fsstat en TSK recupera y muestra detalles asociados con un sistema de archivos:
```
fsstat -o 00000128 datos.dd
```
![](https://niguelas.org/extras/capturas/fsstat.png)


+ Comando img_stat: Obtener Detalles de un Archivo o Directorio:
  - Se utiliza específicamente para mostrar estadísticas e información sobre una imagen de disco. Este comando es útil para obtener detalles generales sobre la imagen de disco antes de profundizar en un análisis más detallado con otras herramientas de Sleuth Kit.
  - Para obtener más detalles sobre un archivo o directorio específico, puedes usar la herramienta istat para mostrar la información del inodo:
  ```
  img_stat datos.dd
  ```
  ![](https://niguelas.org/extras/capturas/img_stat.png)
  

+ Comando fls: Sirve para listar los archivos y directorios en un sistema de archivos, incluyendo aquellos que han sido borrados pero aún se encuentran en las estructuras del sistema de archivos.
  - Listar archivos y directorios de una imagen:
  ```
  fls -o 00000128 datos.dd -1
  ```
  ![](https://niguelas.org/extras/capturas/fls.png)
  
  - Listar los Archivos de un Directorio de forma recurrente. Con la opcion -r se listan recursivamente los contenidos de los directorios:
  ```
  fls -r -p ~/Escritorio/Evidencias/Linux_Evidence_001.img > estructuraDirectorios.txt
  .\fls.exe -r -p "C:\Users\usuario\Desktop\Evidencias\Linux_Evidence_001.img" > estructuraDirectorios.txt
  .\fls.exe -r -p -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd > C:\Users\usuario\Desktop\estructuraDirectorios.txt
  ```
    ![](https://niguelas.org/extras/capturas/fls-r-p.png)


  - Examinar un Directorio Específico: Si conoces el inodo del directorio que deseas examinar, puedes especificarlo directamente:
    ```
    fls ~/Escritorio/Evidencias/Linux_Evidence_001.img [inodo]
    .\fls.exe "C:\Users\usuario\Desktop\Evidencias\Linux_Evidence_001.img" [inodo]
    ```
    
  - Examinar un Directorio y sus subdirectorios: Tenemos que obtener primero el inode del directorio a examinar.
    ```
    fls -r -p ~/Escritorio/Evidencias/Linux_Evidence_001.img [inodo]
    .\fls.exe -r -p "C:\Users\usuario\Desktop\Evidencias\Linux_Evidence_001.img" [inodo]
    ```
    
  - Examinar los ficheros eliminados de una imagen: 
    ```
    fls -d ~/Escritorio/Evidencias/Linux_Evidence_001.img > ficherosBorrados.txt
    .\fls.exe -d "C:\Users\usuario\Desktop\Evidencias\Linux_Evidence_001.img" > ficherosBorrados.txt
    .\fls.exe -d -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd
    ```
    ![](https://niguelas.org/extras/capturas/fls-d.png)


  - Listar los directorios y Examinar los ficheros que están en la papelera de una imagen: Usamos el comando fls para ver los directorios que tiene una imagen. Buscamos el inodo de la papelera, en Windows Xp se llama Recycled. A continuación usamos el comando fls con el inodo de la papelera para que nos muestre lo que contien:
  ![](https://niguelas.org/extras/capturas/winXP.png)


+ Comando istat: Muestra los detalles de un inodo específico en sistemas de archivos basados en inodos, como NTFS (usado en Windows), EXT3/EXT4 (usados en muchas distribuciones Linux), y otros. Un inodo es una estructura de datos que contiene información esencial sobre un archivo en estos sistemas de archivos, como permisos, fechas de modificación, y ubicaciones de los bloques de datos. La información mostrada incluye:
  - Permisos y Propietario: Detalles sobre los permisos del archivo (como lectura, escritura, ejecución) y la identidad del propietario y el grupo.
  - Fechas de Acceso, Modificación y Cambio: Fechas de cuando el archivo fue accedido, modificado y cuando el inodo fue cambiado por última vez.
  - Ubicación de los Bloques de Datos: Dónde se almacenan físicamente los datos del archivo en el disco.
  - Tamaño del Archivo: El tamaño total del archivo.
  - Conteo de Enlaces: Número de enlaces duros al inodo.
  - Flags Específicos del Sistema de Archivos: Como flags de compresión o cifrado, específicos del tipo de sistema de archivos.
![](https://niguelas.org/extras/capturas/istat.png)
```
istat [opciones] imagen_de_disco inodo
istat -o 00000128 datos.dd -1
istat ~/Escritorio/Evidencias/Linux_Evidence_001.img [inodo]
\istat.exe "C:\Users\usuario\Desktop\Evidencias\Linux_Evidence_001.img" [inodo]
\istat.exe -o 00000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 67-128-1
```
Mostramos los detalles de un inodo que contiene un fichero pdf:
![](https://niguelas.org/extras/capturas/istat-inode.png)
![](https://niguelas.org/extras/capturas/istat-kali.png)


+ Comando ils: Lista la información del Inodo. El comando ils de Sleuth Kit permite listar información de inodos en un sistema de archivos:
```
ils ~/Escritorio/Evidencias/Linux_Evidence_001.img [inodo]
.\ils.exe "C:\Users\usuario\Desktop\Evidencias\Linux_Evidence_001.img" [inodo]
```

+ Comando icat: Recupera el Contenido del Inodo. Para extraer el contenido del inodo, utilizamos el comando icat:
![](https://niguelas.org/extras/capturas/icat.png)
Recuperamos un fichero de la imagen datos.dd:
```
icat -o 0000000128 ~/Escritorio/datos.dd 46-128-1 > ~/Escritorio/ROF.pdf
file ~/Escritorio/ROF.pdf
open ~/Escritorio/ROF.pdf
```
![](https://niguelas.org/extras/capturas/icat-proceso.png)


Otro ejemplo de recuperación de un fichero borrado en un sistema de archivos ext4:
![](https://niguelas.org/extras/capturas/recuperacion-foto-ext4.png)


### NOTA: Estos mismos comandos ejecutados en Windows, sólo recupera ficheros .txt. Falla comn pdf y .jpg


+ Commando ffind: Si conocemos el número de inodo, podemos usar findd para encontrar la ubicación exacta de ese archivo en el sistema de archivos.
```
.\ffind.exe -o 000000128 datos.dd 46-128-1
```


### Examinar ficheros eliminados de WinXP con FAT
```
PS C:\Users\usuario\Desktop\sleuthkit-4.12.1-win32\bin> .\fls.exe -dpr -o 0000000063  "Z:\CHFI\LABS\EvidenceFiles\Forensic Images\WinXP-32bits.dd" > C:\Users\usuario\Desktop\caca\ficherosBorrados.txt

104558606:	Documents and Settings/usuario/Escritorio/Alqeda/370389859-CHFI-v8-Module-02-Computer-Forensics-Investigation-Process.pdf
```
![](https://niguelas.org/extras/capturas/ficherosRecuperados.png)

Vemos un documento pdf que vamos a intentar recuperar. Tiene el Inodo: 104558606. Con el comando istat, mostramos la información de ese inodo:
```
PS C:\Users\usuario\Desktop\sleuthkit-4.12.1-win32\bin> .\istat.exe -o 0000000063  "Z:\CHFI\LABS\EvidenceFiles\Forensic Images\WinXP-32bits.dd" 104558606
```
![](https://niguelas.org/extras/capturas/informacionInodo.png)
Vemos que el documento pdf ocupa los sectores:

Sectors:
6556712 6556713 6556714 6556715 6556716 6556717 6556718 6556719
6556720 6556721 6556722 6556723 6556724 6556725 6556726 6556727

El fichero empieza en el sector 6556712 + el offset (63) = 6556775.
El fichero termina en el sector 6556727 + el offset (63) = 6556790.

Vamos a Active Disk Editor. Pulsamos el gotón de Go to Sector e introducimos el sector en el cual comienza el fichero: 6556775
Obtenemos:
![](https://niguelas.org/extras/capturas/detallePDF.png)
Podemos ver el fichero pdf en el disco. Tiene un offset: 03357068800 ----- 03357076480


Buscamos ahora un fichero que esté en la papelera:
![](https://niguelas.org/extras/capturas/detallePapelera.png)

Vamos a recuperar el fichero que está en el inodo: 104558653
```
└─$ icat -o 0000000063 WinXP-32bits.dd 104558653 > /home/kali/Escritorio/computerForensicProcess.pdf
```
![](https://niguelas.org/extras/capturas/fichero.png)





## Recuperar datos con dd --> Encontrar el $MFT
Del NTFS Boot Sector Bytes, buscamos en los flags: 48 a 55. Su valor es 04 00 00 00 00 00 00 en litle endian - 04 en big endian.
El starting cluster addres de $MFT es 04.

![](https://niguelas.org/extras/capturas/MFT-location.png)

En el flag 13 encontramos cuantos sectores tiene un cluster: 08. Cada cluster tiene 8 sectores.

Como el $MFT está en el 4to cluster. 8x4= 32 sectores de desfase desde el inicio de la partición.
En Active Disk Editor, pulsamos el botón de Go to Sector y le indicamos el sector 32:

![](https://niguelas.org/extras/capturas/sector.png)


Investigamos la estructura de las particiones de esta imagen:

![](https://niguelas.org/extras/capturas/estructura-disco2.png)

Vemos que la partición NFS tiene un offset de 2048. Como el $MFT tiene un offset de 32 --> 2048 + 32 = 2080.
Así sabemos que el $MFT está localizado en el sector 2080 del fichero de imagen del fichero de Windows. Comprobamos con FTK Imager:

![](https://niguelas.org/extras/capturas/mft-con-ftk.png)


Con sleuthkit mostramos información con $MFT que sabemos que se encuentra en el inodo 0:

![](https://niguelas.org/extras/capturas/muestra-mft-sleuthkit.png)

Como sabemos el offset que tiene el MFT y los sectores que ocupa (de 4 al 67), vamos a extraer este fichero usando dd:

![](https://niguelas.org/extras/capturas/copiar-mft.png)

Podemos abrir el documento con cualquier editor hexadecimal:
![](https://niguelas.org/extras/capturas/editor-mft.png)

El MFT lo podríamos haber exportado directamente con FTK, pero haciendolo de manera manual, se entiende cómo se almaceman los ficheros en un sistema NTFS:
![](https://niguelas.org/extras/capturas/export-mft-ftk.png)



## Buscando un fichero
Con FTK buscamos dentro de una imagen un fichero cualquiera, como por ejemplo dd.exe:

![](https://niguelas.org/extras/capturas/fichero-situacion-ftk.png)

Observamos que se encuentra en el MFT Record Number: 335

Analizamos con sleuthkit la estructura de particiones de esa imagen sobre la que estamos trabajando:

![](https://niguelas.org/extras/capturas/analisis-particion-sleuthkit.png)

Ahora conocemos el offset de la partición que contiene al fichero dd.exe: 01026048. Pedimos que nos muestre la entrada MFT para el fichero dd.exe:
![](https://niguelas.org/extras/capturas/datos-entrada-mft-de-un-fichero.png)

Ahora conocemos toda la información del fichero dd.exe y podríamos recuperarlo con el comando dd.




