## EXT4
En UNIX y Linux, todo se considera un archivo, incluidas las unidades de disco, monitores, unidades de cinta, tarjetas de interfaz de red, memoria del sistema y directorios. Los archivos UNIX se definen como objetos, lo que significa que un archivo, como un objeto en un lenguaje de programación orientado a objetos, tiene propiedades y métodos (acciones como escribir, eliminar y leer) que se pueden realizar en él.

UNIX/Linux tiene cuatro componentes que definen el sistema de archivos: el boot block (bloque de arranque), superblock (superbloque), inode block (bloque de inodo) y data block (bloque de datos). Un bloque es la unidad de asignación de disco más pequeña en el sistema de archivos UNIX/Linux y puede tener 512 bytes o más; El tamaño del bloque depende de cómo se inicia el volumen del disco.  Cada uno de estos cuatro elementos juega un papel fundamental en la forma en que Ext4 gestiona y almacena los datos en un disco.

### El bloque de inicio:
Contiene el código de arranque: instrucciones para el inicio. Una computadora UNIX/Linux tiene solo un bloque de arranque, en el disco duro principal.

### Inodos (i-nodes):
Un inodo es una estructura de datos que contiene información esencial sobre un archivo o un directorio. Esta información incluye metadatos como los permisos de archivo, propietario, grupo, tamaño del archivo, hora de última modificación, y un puntero a los bloques de datos donde se almacena el contenido real del archivo.
Cada archivo o directorio en el sistema de archivos Ext4 tiene un inodo único que lo identifica. Los inodos se almacenan en una tabla de inodos y cada inodo tiene un número de identificación único.
Los inodos contienen metadatos de archivos y directorios y proporcionan un mecanismo para vincular datos almacenados en bloques de datos. Cuando se crea un archivo o directorio en un sistema de archivos Linux, se asigna un inodo que contiene la siguiente información:
  - El modo y tipo del archivo o directorio.
  - El número de enlaces a un archivo o directorio.
  - El UID y GID del propietario del archivo o directorio.
  - El número de bytes en el archivo o directorio.
  - La hora del último acceso al archivo o directorio y la hora de la última modificación.
  - Hora del último cambio de estado del archivo del inodo.
  - La dirección del bloque para los datos del archivo.
  - Las direcciones de bloque indirecto, doble indirecto y triple indirecto para los datos del archivo.
  - Estado de uso actual del inodo.
  - El número de bloques reales asignados a un archivo.
  - Número de generación de archivo y número de versión
  - El enlace del inodo de continuación.

Las únicas piezas de metadatos que no están en un inodo son el nombre del archivo y la ruta. Los inodos contienen horas de modificación, acceso y creación (MAC), no nombres de archivos. Nombre y Ruta del Archivo:
  - Estos son manejados por el sistema de directorios, no por los inodos.
  - Cada entrada en un directorio es un par que vincula un nombre de archivo con un número de inodo. Esto significa que el nombre del archivo y su ruta (la cadena de directorios que conduce a él) se almacenan en el sistema de archivos, pero separados de los inodos.
  - Esto permite que existan múltiples nombres para el mismo archivo (a través de enlaces duros), ya que cada nombre en diferentes directorios puede apuntar al mismo número de inodo.
  - Los nombres y rutas de los archivos se almacenan en las estructuras de directorios, no en los inodos. Los directorios en estos sistemas de archivos son en realidad una forma especial de archivo que mapea nombres de archivos a inodos. Su funcionamiento:
    - Directorios como Archivos Especiales: Un directorio es esencialmente un archivo que contiene una lista de entradas. Cada entrada asocia el nombre de un archivo (o subdirectorio) con un número de inodo. Este número de inodo es una referencia al inodo que contiene todos los metadatos del archivo o directorio.
    - Estructura de una Entrada de Directorio:
      - En un sistema de archivos como Ext4, cada entrada en un directorio típicamente incluye:
        - Nombre del Archivo: El nombre del archivo o subdirectorio.
        - Número de Inodo: Una referencia al inodo correspondiente en la tabla de inodos.
      - Estas entradas permiten al sistema de archivos encontrar rápidamente el inodo correspondiente a un nombre de archivo dado.
    - Rutas de Archivos:
      - La ruta de un archivo (por ejemplo, /home/usuario/documentos/archivo.txt) se construye siguiendo las entradas de directorio desde el directorio raíz (/) hasta el archivo específico.
      - Cada componente de la ruta (como home, usuario, documentos) es un directorio que contiene una entrada para el siguiente componente de la ruta.
      - Al final de esta cadena, hay una entrada de directorio en documentos que asocia el nombre archivo.txt con su número de inodo.
    - Búsqueda de Archivos:
      - Cuando buscas un archivo por su ruta, el sistema de archivos comienza en el directorio raíz y sigue las entradas de directorio de acuerdo con los componentes de la ruta hasta que llega al archivo deseado.
    - Enlaces Duros y Símbolos:
      - Los enlaces duros permiten que un archivo tenga múltiples nombres en diferentes ubicaciones, todos apuntando al mismo inodo.
      - Los enlaces simbólicos (symlinks) son archivos especiales que contienen una ruta a otro archivo o directorio.

Un inodo asignado tiene 13 punteros que se vinculan a bloques de datos y otros punteros donde se almacenan los archivos:
  - Los punteros del 1 al 10 se vinculan directamente a los bloques de almacenamiento de datos en el bloque de datos del disco y contienen direcciones de bloque que indican dónde se almacenan los datos en el disco. Estos punteros son punteros directos porque cada uno está asociado con un bloque de almacenamiento de datos.
  - A medida que crece un archivo, el sistema operativo proporciona hasta tres capas de punteros de inodo adicionales. En el inodo de un archivo, los primeros 10 punteros se denominan punteros indirectos. Los punteros de la segunda capa se denominan punteros dobles indirectos y los punteros de la última o tercera capa se denominan punteros triples indirectos.
   - Para ampliar la asignación de almacenamiento, el sistema operativo inicia el undécimo puntero del inodo original, que se vincula a 128 inodos de puntero. Cada puntero se vincula directamente a 128 bloques ubicados en el bloque de datos de la unidad. Si los 10 punteros en el inodo original se consumen con datos de archivo, el undécimo puntero se vincula a otros 128 punteros. El primer puntero de este grupo indirecto de inodos apunta al bloque 11. El último bloque de estos 128 inodos es el bloque 138.
  - El término "inodo indirecto" se refiere al undécimo puntero del inodo original, que apunta a otro grupo de punteros de inodo. En otras palabras, está vinculado indirectamente al inodo original.
  - Si se necesita más almacenamiento, el puntero número 12 del inodo original se utiliza para vincular otros 128 punteros de inodo. A partir de cada uno de estos punteros, se crean otros 128 punteros. Esta segunda capa de punteros de inodo se vincula directamente a los bloques del bloque de datos de la unidad. El primer bloque al que apuntan estos punteros dobles indirectos es el bloque 139.
Si se necesita más almacenamiento, el puntero 13 se vincula a 128 inodos de puntero, cada uno de los cuales apunta a otros 128 punteros, y cada puntero en esta segunda capa apunta a una tercera capa de 128 punteros. Los datos del archivo se almacenan en estos bloques de datos: Buscar imágenes de "Inode pointers in the Linux file system".

Todos los discos tienen más capacidad de almacenamiento de lo que afirma el fabricante. Por ejemplo, un disco de 240 GB podría tener en realidad 240,5 GB de espacio libre porque los discos siempre tienen sectores defectuosos. Windows no realiza un seguimiento de los sectores defectuosos, pero Linux lo hace en un inodo llamado inodo de bloque defectuoso. El inodo raíz es el inodo 2 y el inodo del bloque defectuoso es el inodo 1. Algunas herramientas forenses ignoran el inodo 1 y no recuperan datos valiosos para los casos.
Alguien que intente engañar a un investigador puede acceder al inodo del bloque defectuoso, enumerar los sectores buenos en él y luego ocultar información en estos sectores supuestamente "malos".
Para encontrar bloques defectuosos en su computadora Linux, puede usar el comando badblocks, aunque debe iniciar sesión como root para hacerlo. Linux incluye otros dos comandos que proporcionan información sobre bloques defectuosos: mke2fs y e2fsck. El comando badblocks puede destruir datos valiosos, pero los comandos mke2fs y e2fsck incluyen salvaguardas que les impiden sobrescribir información importante.


+ Los "orphan inodes" (inodos huérfanos):
En un sistema de archivos se refieren a inodos que no están vinculados a ningún directorio pero que aún están marcados como en uso. Estos suelen ser el resultado de operaciones de sistema de archivos que no se completaron correctamente, generalmente debido a fallas del sistema o cortes de energía. La idea de usar inodos huérfanos para esconder información en un contexto forense es teóricamente posible, pero es compleja y tiene limitaciones significativas:
  - Un archivo asociado con un inodo huérfano aún podría contener datos hasta que el sistema de archivos reasigne ese inodo y los bloques de datos asociados a un nuevo archivo.
  - Acceso Difícil: Acceder a estos datos requeriría herramientas especializadas y un conocimiento profundo de la estructura interna del sistema de archivos, ya que no se pueden acceder a través de los medios normales del sistema operativo.
  - Volatilidad: Los inodos huérfanos son por naturaleza temporales y pueden ser limpiados por el sistema de archivos en cualquier momento, especialmente durante el proceso de montaje o mediante herramientas como fsck.


### El superbloque:
Es una estructura de datos crítica que contiene información vital sobre el sistema y se considera parte de los metadatos. Especifica la geometría del disco y el espacio disponible y realiza un seguimiento de todos los inodos (que se analizan con más detalle en la siguiente sección). El superbloque también administra el sistema de archivos, incluida información de configuración, como el tamaño del bloque de la unidad, los nombres del sistema de archivos, los bloques reservados para inodos y el nombre del volumen. Hay un superbloque principal al comienzo del sistema de archivos, pero también hay copias de seguridad del superbloque distribuidas por todo el sistema de archivos para mejorar la resiliencia y la capacidad de recuperación en caso de corrupción.


### El bloque de datos:
Son segmentos de espacio en el disco donde se almacenan los datos reales de los archivos y directorios. El tamaño de estos bloques es fijo y es definido al crear el sistema de archivos. Los tamaños comunes de bloques son 1 KB, 2 KB, 4 KB, etc. Los inodos apuntan a estos bloques de datos. Si un archivo es lo suficientemente grande como para abarcar varios bloques, el inodo contendrá una referencia a cada uno de estos bloques. Ext4 es conocido por su robustez, eficiencia y soporte para grandes volúmenes de datos. La manera en que gestiona los inodos, superbloques y bloques de datos contribuye significativamente a estas características.


### Leer la información contenida en un inodo en un sistema de archivos Ext4:
Generalmente utilizas herramientas de línea de comandos en un entorno Linux. Aquí hay algunos métodos comunes:
  - Comando ls -i:
    - Este comando lista los archivos junto con sus números de inodo. No proporciona información detallada sobre el inodo, pero te permite identificar el número de inodo asociado a cada archivo.
      ```
      ls -i archivo.txt
      ```

  - Comando stat:
    - stat es una herramienta más detallada que muestra información específica del inodo para un archivo, como el tamaño del archivo, permisos, número de inodo, cantidad de enlaces, y más.
      ```
      stat archivo.txt
      ```

  - Comandos debugfs:
    - debugfs es una herramienta de depuración para sistemas de archivos Ext2/Ext3/Ext4. Puede ser usada para examinar y modificar inodos, bloques y su contenido en un sistema de archivos. Sin embargo, se debe tener cuidado al usarla, ya que puede dañar el sistema de archivos si se utiliza incorrectamente.
    - Advertencia: Hay que tener mucho cuidado especialmente en sistemas de archivos montados o en uso, ya que pueden causar daños si se usan incorrectamente.
      ```
      sudo debugfs -R 'stat <inodo-numero>' /dev/sda1
      ```
      Reemplaza <inodo-numero> con el número de inodo y /dev/sda1 con el dispositivo de almacenamiento correcto.
      
  - Comandos dumpe2fs:
    - dumpe2fs proporciona información detallada sobre el sistema de archivos, incluyendo los inodos. Este comando es útil para obtener información a nivel de sistema de archivos.
      - Para mostrar la información sobre el sistema de archivos, incluyendo el estado del sistema de archivos, el número total de inodos y bloques, el tamaño de los bloques, la lista de los superbloques de respaldo, y mucho más:
       ```
      sudo dumpe2fs /dev/nvme0n1p2 > infoSistemaArchivos.txt
      ```
       
      - Ver solo Información del Superbloque: Usaremos la opción -h para mostrar solo los detalles del encabezado del superbloque, que es mucho más conciso.
       ```
      sudo dumpe2fs -h /dev/nvme0n1p2
      sudo dumpe2fs /dev/nvme0n1p2 | grep –i superblock
      ```      

      - Filtrar por Grupo de Bloques: Para obtener información sobre un grupo de bloques específico, puedes usar la opción -g.
       ```
      sudo dumpe2fs -g /dev/nvme0n1p2
      ```       
