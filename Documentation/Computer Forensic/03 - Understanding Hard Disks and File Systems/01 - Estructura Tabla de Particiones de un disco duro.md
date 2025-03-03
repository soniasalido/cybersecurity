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

