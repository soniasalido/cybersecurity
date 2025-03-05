## ¿Qué es una partición de un disco?
Una partición de disco es una división lógica dentro de un disco duro o SSD que permite organizar y gestionar el almacenamiento de datos de manera más eficiente. Aunque físicamente el disco sea una sola unidad, las particiones permiten que el sistema operativo y los usuarios lo traten como si fueran varias unidades independientes.

### Tipos de particiones en discos duros:
MBR → Usa primarias, extendidas y lógicas para superar la limitación de 4 particiones.  
GPT → Usa solo particiones primarias. No utiliza particiones extendidas ni lógicas.

### Funciones y beneficios de las particiones:
- Permiten instalar varios sistemas operativos en un mismo disco (ejemplo: Windows y Linux en diferentes particiones).
- Facilitan la organización de archivos (ejemplo: separar archivos personales de los del sistema).
- Ayudan en la recuperación de datos al mantener el sistema operativo en una partición y los datos en otra.
- Mejoran la seguridad y el rendimiento, ya que los errores en una partición no afectan a las demás.
  
## Métodos para estructurar la tabla de particiones en una unidad de almacenamiento
MBR y GPT son los esquemas de partición que organizan el almacenamiento en los discos duros.

### 1. MBR - Master Boot Record (Registro de Arranque Principal):
MBR es el esquema de partición más antiguo y se ha utilizado desde 1983 en sistemas con BIOS.

**El MBR se encuentra en el primer sector del disco duro (sector 0) y contiene:**
- El código del gestor de arranque: Un pequeño programa que inicia el sistema operativo.
- La tabla de particiones: Contiene información sobre hasta 4 particiones primarias.
- El "Magic Number": Un identificador que indica que el MBR es válido.

**Limitaciones de MBR:**
- Soporta discos de hasta 2 TB: Cualquier espacio adicional no es reconocido.
- Máximo de 4 particiones primarias: Para más particiones, se debe crear una partición extendida con particiones lógicas dentro.
- No incluye redundancia: Si el MBR se corrompe, el disco puede volverse inaccesible.

### 2. GPT - GUID Partition Table (Tabla de Particiones GUID):
GPT es el sucesor de MBR y es parte del estándar UEFI. Almacena información sobre particiones en múltiples ubicaciones dentro del disco, lo que lo hace más seguro y flexible.

**Ventajas de GPT sobre MBR**
- Soporta discos de más de 2 TB: Puede manejar hasta 9.4 ZB (zettabytes).
- Permite hasta 128 particiones sin necesidad de particiones extendidas.
- Mayor seguridad: Contiene copias redundantes de la tabla de particiones en diferentes partes del disco, lo que permite recuperar datos si una copia se corrompe.
- Usa CRC32 (Cyclic Redundancy Check) para verificar la integridad de los datos.

## ¿Existen otros métodos?
MBR y GPT son los estándares principales, pero han existido otros métodos más específicos o menos utilizados:
- Apple Partition Map (APM): Usado antiguamente en Macs antes de la llegada de Intel y GPT.
- BSD Disklabel: Un esquema utilizado en sistemas BSD.
- Sun/SGI Label: Usado en estaciones de trabajo de Sun y SGI.
- **LVM (Logical Volume Manager):** No es un esquema de particionado en sí, pero permite manejar volúmenes lógicos en Linux.

Sin embargo, en términos de compatibilidad con sistemas operativos modernos, MBR y GPT son los dos métodos universales y recomendados. 
