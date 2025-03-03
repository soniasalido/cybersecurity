
------------------------------------------------
# Sistemas de Ficheros NTFS




## NTFS
El sistema de archivos NTFS contiene un archivo denominado tabla de archivos maestros o MFT. Hay al menos una entrada en el MFT para cada archivo en un volumen del sistema de archivos NTFS, incluido el propio MFT. Toda la información sobre un archivo, incluido su tamaño, marca de fecha y hora, permisos y contenido de datos, se almacena en entradas de MFT o en espacio fuera de la MFT descrita por entradas de MFT.

A medida que los archivos se agregan a un volumen del sistema de archivos NTFS, se agregan más entradas al MFT y el MFT aumenta de tamaño. Cuando los archivos se eliminan de un volumen del sistema de archivos NTFS, sus entradas MFT se marcan como libres y se pueden reutilizar. Sin embargo, el espacio en disco que se ha asignado para estas entradas no se reasigna y el tamaño de MFT no disminuye.

![](https://niguelas.org/extras/capturas/layout-volume.png)
![](https://niguelas.org/extras/capturas/estructura.png)


## Boot sector bytes:
![](https://niguelas.org/extras/capturas/boot-sector-ntfs.png)
![](https://niguelas.org/extras/capturas/boot-sector-ntfs-2.png)
![](https://niguelas.org/extras/capturas/boot-sector-ntfs-3.png)



## Encontrar el $MFT
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

### Recuperación de archivos basada en metadatos
En algunos casos, es posible que desee buscar pruebas en archivos eliminados. Existen dos métodos principales para recuperar archivos eliminados: basado en metadatos y basado en aplicaciones. La recuperación basada en metadatos funciona cuando los metadatos del archivo eliminado todavía existen. Si los metadatos se borraron o si la estructura de metadatos se reasignó a un archivo nuevo, deberemos confiar en técnicas basadas en aplicaciones. 

Una vez que encuentre la estructura de metadatos del archivo, la recuperación es sencilla. No es diferente de leer el contenido de un archivo asignado. Por ejemplo, la Figura siguiente se muestra un ejemplo en el que la entrada de metadatos no asignados todavía tiene sus direcciones de unidad de datos y podemos leer fácilmente el contenido. Por otro lado podemos ver un ejemplo en el que el sistema operativo borró las direcciones cuando se eliminó el archivo. 
![](https://niguelas.org/extras/capturas/scenarios-unallocated-files.png)

Debemos tener cuidado al realizar una recuperación basada en metadatos porque las estructuras de metadatos y las unidades de datos pueden desincronizarse porque las unidades de datos se asignan a archivos nuevos. Considere el ejemplo dado en la Figura anterior. El contenido de la unidad de datos 9.009 se sobrescribiría si fuera asignado por la entrada de metadatos 70, aunque la entrada 67 todavía apunte a ellos. Cuando intentamos recuperar el contenido de los metadatos 67, obtendremos datos del archivo usando la entrada de metadatos 70.

Al recuperar archivos eliminados, puede resultar difícil detectar cuándo se ha reasignado una unidad de datos. Consideremos una secuencia de asignaciones y eliminaciones para reforzar este punto.
La entrada de metadatos 100 asigna la unidad de datos 1.000 y guarda datos en ella. Luego se elimina el archivo de la entrada 100 y tanto la entrada 100 como la unidad de datos 1000 quedan sin asignar. Se crea un nuevo archivo en la entrada de metadatos 200 y se reasigna la unidad de datos 1000. Posteriormente, ese archivo también se elimina. Si analizáramos este sistema, encontraríamos dos entradas de metadatos no asignados que tienen la misma dirección de unidad de datos.



### Archivos de metadatos del sistema
+ $MFT:
  - MFT es una base de datos llamadas Master File Table, internamente $MFT.
  - La MFT contiene un registro por cada fichero y carpeta en el volumne NTFS.
  - Las primeras 16 entradas de la MFT están reservadas para metadatos de NTFS -- Los ficheros de sistema. ( $LOGFILE, $VOLUME...).
  - Atributos de fichero, tamaño, fecha y horas timestamp y permisos son grabados como entradas MFT.
  - Cuando el numero de ficheros crece, el tamaño del MFT se incrementa.
  - Cuando un fichero es borrados, la entrada $MFT es marcada como libre, para re reutilizado por otro fichero en el futuro.
  - Uno de los archivos de metadatos del sistema de archivos más importantes es el archivo $MFT porque contiene la tabla maestra de archivos (MFT), que tiene una entrada para cada archivo y directorio. Por lo tanto, lo necesitamos para encontrar otros archivos. La dirección inicial de la MFT se proporciona en el sector de arranque. El diseño de la MFT se determina procesando la entrada 0 en la MFT.
  - La primera entrada de MFT se denomina $MFT y su atributo $DATA contiene los clústeres utilizados por MFT. El archivo $MFT también tiene un atributo $BITMAP, que se utiliza para gestionar el estado de asignación de las entradas MFT. El archivo $MFT también tiene los atributos estándar $FILE_NAME y $STANDARD_INFORMATION, que se describen en la sección "Categoría de metadatos".
  - En Windows, el archivo $MFT comienza lo más pequeño posible y crece a medida que se crean más archivos y directorios. El archivo $MFT puede fragmentarse, pero se reserva algo de espacio para su ampliación.
![](https://niguelas.org/extras/capturas/file-mf-t-2.png)
  ```
  .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 0
  ```
  ![](https://niguelas.org/extras/capturas/$MFT.png)

+ $MFTMirr:
  - El archivo $MFT es muy importante porque se utiliza para buscar todos los archivos. Por lo tanto, tiene el potencial de ser un punto de fallo catastrófico si el puntero en el sector de arranque o la entrada $MFT está dañada. Para solucionar este problema, existe una copia de seguridad de las entradas importantes de MFT que se pueden utilizar durante la recuperación. La entrada 1 de MFT es para el archivo $MFTMirr, que tiene un atributo no residente que contiene una copia de seguridad de las primeras entradas de MFT.
  - El atributo $DATA del archivo $MFTMirr asigna clústeres en el medio del sistema de archivos y guarda copias de al menos las primeras cuatro entradas de MFT, que son para $MFT, $MFTMirr, $LogFile y $Volume. Si hay problemas para determinar el diseño de la MFT, una herramienta de recuperación puede usar el tamaño del volumen para calcular dónde se encuentra el sector medio del sistema de archivos y leer los datos de la copia de seguridad. Cada entrada MFT tiene una firma que se puede utilizar para verificar que es una entrada MFT. Con estas cuatro entradas de respaldo, la herramienta de recuperación puede determinar el diseño y el tamaño de MFT, la ubicación de $LogFile para que se pueda recuperar el sistema de archivos y la versión y la información de estado de los atributos de $Volume.
![](https://niguelas.org/extras/capturas/file-mftmirr.png)
  ```
  .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 1
  ```
  ![](https://niguelas.org/extras/capturas/$mftmirr.png)
  En nuestra imagen de ejemplo tiene xxxx clústeres y el atributo $DATA para $MFTMirr comienza en el clúster del medio. Los datos temporales se eliminaron de esta salida, pero tenían los mismos valores que se mostraron para $MFT.

  ![](https://niguelas.org/extras/capturas/situacion-mft-mirror.png)

  En la zona verde MFT zone es donde puede ir creciendo el MFT si es necesario. Si agota el espacio de la MFT zone, entonces seguirá creciendo de forma fragmentada.

  
+ $LOGFILE:
  - El $LogFile está en la entrada 2 de MFT y se utiliza como diario NTFS. Tiene los atributos de archivo estándar y almacena los datos de registro en el atributo $DATA. Desafortunadamente, no se conocen los detalles exactos de la estructura de datos. El registro está organizado en páginas de 4.096 bytes. Los dos primeros son para el área de reinicio y tienen la firma "RSTR" en las primeras cuatro páginas de cada página:
  - El registro está organizado en páginas de 4.096 bytes. Los dos primeros son para el área de reinicio y tienen la firma "RSTR" en las primeras cuatro páginas de cada página.
  - Este registro contiene solo el contenido nuevo y no contiene el nombre de la ruta del archivo que se está actualizando. Probablemente exista una referencia en este registro que apunte a otro registro que identifique el nombre del archivo.
![](https://niguelas.org/extras/capturas/file-logfile.png)
    ```
    .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 2
    ```
  ![](https://niguelas.org/extras/capturas/$logfile.png)


+ $VOLUME:
  - El archivo de metadatos del sistema de archivos $Volume se encuentra en la entrada 3 de MFT y contiene la etiqueta del volumen y otra información de la versión. Tiene dos atributos únicos que se supone que ningún otro archivo debe tener. El atributo $VOLUME_NAME contiene el nombre Unicode del volumen y el atributo $VOLUME_INFORMATION contiene la versión NTFS y el estado sucio.
  - $VOLUME_NAME y $VOLUME_INFORMATION son exclusivos de esta entrada de MFT y contienen los datos interesantes. Debemos tener en cuenta que el atributo $DATA existe, pero tiene un tamaño de 0. Los datos temporales se eliminaron de la salida, pero eran los mismos valores que se vieron en los archivos de metadatos del sistema de archivos anteriores.
![](https://niguelas.org/extras/capturas/file-volume.png)
  ```
  .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 3
  ```
  ![](https://niguelas.org/extras/capturas/$volume.png)


+ $ATTRDEF:
  - El archivo de metadatos del sistema de archivos $AttrDef es la entrada 4 de MFT. El atributo $DATA de este archivo define los nombres y los identificadores de tipo para cada tipo de atributo. Hay algunos problemas de lógica circular con NTFS y este es uno de ellos. ¿Cómo se supone que debes leer el atributo $DATA del archivo $AttrDef para saber cuál es el identificador de tipo para $DATA? Afortunadamente, existen valores predeterminados para los atributos. Este archivo permite que cada sistema de archivos tenga atributos únicos para sus archivos y permite que cada sistema de archivos redefina el identificador de los atributos estándar.

  ![](https://niguelas.org/extras/capturas/file-attrdef.png)
  ```
  .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 4
  ```
  ![](https://niguelas.org/extras/capturas/$attrdef.png)


+ . (Root Directory):
  - El directorio raíz de un NTFS, llamado . (punto) es un directorio ordinario. Si el volumen tiene puntos de análisis, el directorio tendrá un flujo de datos con nombre llamado $MountMgrDatabase.
![](https://niguelas.org/extras/capturas/file-root.png)
  ```
  .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 5
  ```
  ![](https://niguelas.org/extras/capturas/root.png)


+ $BITMAP:
  - Este archivo enumera qué clústeres están en uso. Cada bit de este archivo representa un LCN.

    ![](https://niguelas.org/extras/capturas/file-bitmap.png)
    ```
    .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 6
    ```
  ![](https://niguelas.org/extras/capturas/$bitmap.png)


+ $BOOT:
  - Este es el archivo del sistema que permite que el sistema arranque. Este archivo de metadatos apunta al sector de arranque del volumen. Contiene información sobre el tamaño del volumen, los clústeres y la MFT. Es el único archivo que no se puede reubicar.
    ![](https://niguelas.org/extras/capturas/file-boot.png)
    ```
    .\istat.exe -o 0000000128 C:\Users\usuario\Desktop\Evidencias\datos.dd 7
    ```
  ![](https://niguelas.org/extras/capturas/$boot.png)



## Entradas MFT
![](https://niguelas.org/extras/capturas/mft-entries.png)

![](https://niguelas.org/extras/capturas/mft-entry-format.png)

![](https://niguelas.org/extras/capturas/mft-entry-example.png)

[https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html](https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html)
