El sistema de archivos de un disco de almacenamiento es la estructura lógica que un sistema operativo usa para organizar, gestionar y almacenar datos en un dispositivo de almacenamiento, como un disco duro, SSD, USB o tarjeta de memoria.

## ¿Qué es un Sistema de Archivos?
Un sistema de archivos define cómo se guardan, acceden y organizan los datos en un disco. Actúa como una "tabla de contenido" que permite al sistema operativo localizar archivos y carpetas de manera eficiente.

## Funciones del Sistema de Archivos
✔️ Organizar datos en carpetas y archivos.
✔️ Gestionar el espacio disponible en el disco.
✔️ Controlar los permisos de acceso a los archivos.
✔️ Optimizar la lectura y escritura de datos.
✔️ Evitar la fragmentación excesiva del disco.

## Estructura del Sistema de Archivos. Un sistema de archivos generalmente tiene las siguientes partes:
**1. Boot Sector (Sector de Arranque)**
- Contiene información sobre el sistema de archivos.
- En discos con MBR/GPT, también almacena el código de arranque.

**2. Superbloque / Master File Table (MFT)**
- Contiene metadatos sobre el sistema de archivos.
- Guarda información sobre el espacio libre, la cantidad de archivos y la estructura de directorios.

**3. Tabla de Asignación de Archivos**
- Indica qué clusters están ocupados o libres.
- Ejemplo: FAT (File Allocation Table) en FAT32, o MFT (Master File Table) en NTFS.

**4. Región de Datos**
- Espacio donde se almacenan los archivos y carpetas.
- Los datos se dividen en clusters o bloques.

## Tipos de Sistemas de Archivos
Existen diferentes sistemas de archivos según el sistema operativo y el tipo de dispositivo.
| Sistema de Archivos	| SO Compatible	| Tamaño Máx. de Archivo	| Tamaño Máx. de Partición	| Características |
| FAT32		| Windows, Linux, Mac		| 4 GB		| 2 TB	| Compatible con casi todos los dispositivos, pero limitado en tamaño de archivos. |
| NTFS	| 	Windows		| 16 TB		| 256 TB	| Permite permisos de usuario, cifrado y compresión. |
| exFAT	| 	Windows, Mac, Linux	| 	16 EB	| 	128 PB	| Ideal para discos USB y tarjetas SD de gran tamaño. |
| EXT4	| 	Linux	| 	16 TB	| 	1 EB	| Rápido y confiable, usado en distribuciones Linux. |
| APFS	| 	MacOS	| 	8 EB	| 	8 EB	| Optimizado para SSD y encriptación. |

