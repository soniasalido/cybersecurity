
# BIOS y UEFI son los firmwares que gestionan el arranque de un ordenador

El firmware es un tipo de software específico y permanente que está almacenado en un hardware para controlar su funcionamiento. Es una especie de "programa integrado" en dispositivos electrónicos que actúa como un intermediario entre el hardware y el software.

El firmware es el software interno que permite el funcionamiento del hardware. Sin él, los dispositivos no podrían realizar tareas básicas. A diferencia del software convencional, no se elimina al apagar el dispositivo y en muchos casos, puede ser actualizado para mejorar su rendimiento o corregir errores.

## Características del Firmware
- Software embebido: Está grabado en chips de memoria de solo lectura (ROM, EEPROM, Flash) dentro del hardware.
- Bajo nivel: Funciona a nivel de hardware, sin necesidad de un sistema operativo.
- No volátil: Permanece en el dispositivo incluso cuando se apaga.
- Puede ser actualizado: Algunos firmware permiten actualizaciones para corregir errores o mejorar funcionalidades (ejemplo: BIOS/UEFI en computadoras).


# ¿Qué es BIOS y Cómo Funciona?
El BIOS es un pequeño programa almacenado en un chip de memoria ROM (Read-Only Memory) en la placa base. Su trabajo comienza tan pronto como se presiona el botón de encendido de la computadora.

## Proceso de Arranque con BIOS:
**1. POST (Power-On Self Test):**
- Verifica el estado del hardware (memoria RAM, procesador, teclado, tarjeta de video, etc.).
- Si encuentra errores, puede emitir "beeps" (códigos de sonido) o mostrar un mensaje en pantalla.

**2. Búsqueda del MBR en el Disco de Arranque:**
- BIOS busca el disco duro o dispositivo de almacenamiento donde está instalado el sistema operativo.
- Localiza el MBR (Master Boot Record) en el primer sector del disco.
- Carga el gestor de arranque desde el MBR.

**3. Carga del Sistema Operativo:**
- Una vez encontrado el gestor de arranque, lo ejecuta para iniciar el sistema operativo (Windows, Linux, etc.).
- El control se transfiere al sistema operativo y BIOS deja de intervenir.


## Características de BIOS
- Modo de 16 bits: BIOS funciona en un modo de procesamiento limitado, lo que reduce su velocidad y capacidades.
- Almacenado en ROM/EPROM: Se encuentra en un chip de memoria en la placa base, aunque versiones más modernas permiten actualizarlo (Flash BIOS).
- Configuración a través del Setup: Permite a los usuarios ajustar opciones de hardware como la secuencia de arranque, la velocidad del ventilador y el control de periféricos.
- Soporte para MBR: Solo puede arrancar desde discos con MBR, lo que limita el tamaño del disco a 2 TB y permite un máximo de 4 particiones primarias.
- No tiene soporte para arranque seguro (Secure Boot), lo que puede hacer que el sistema sea más vulnerable a malware que se ejecuta antes del sistema operativo.

## Limitaciones del BIOS
- Soporte limitado para discos grandes: No puede arrancar discos de más de 2 TB debido a su dependencia de MBR.
- Arranque lento: Funciona en modo de 16 bits y solo puede ejecutar una tarea a la vez.
- Sin interfaz gráfica: Solo permite navegación con teclado en una interfaz basada en texto.
- Falta de seguridad: No tiene medidas avanzadas como Secure Boot.


# ¿Qué es UEFI y Cómo Funciona?
UEFI (Unified Extensible Firmware Interface)
- Es el reemplazo moderno de BIOS, diseñado para superar sus limitaciones.
- Usa una interfaz gráfica y admite funciones avanzadas como arranque seguro (Secure Boot).
- No depende del MBR, sino que usa el EFI System Partition (ESP) para almacenar archivos de arranque.
- UEFI utiliza GPT para localizar el sistema operativo y arrancar el equipo: UEFI funciona con GPT en lugar de MBR. GUID Partition Table es el esquema de partición moderno, diseñado para reemplazar a MBR. Ubica la tabla de particiones en múltiples ubicaciones en el disco para evitar corrupción de datos.

## ¿UEFI puede usar MBR?
Sí, UEFI puede arrancar desde un disco MBR, pero no es lo ideal y depende del modo de arranque configurado en el firmware.

### Modos de Arranque en UEFI: UEFI permite dos modos de arranque principales:
- Modo UEFI Nativo → Requiere discos con GPT.
- Modo Legacy (Compatibilidad con BIOS) → Permite arrancar desde MBR.

### UEFI puede arrancar desde un disco MBR en los siguientes casos:
- Modo Legacy Boot (CSM - Compatibility Support Module)
  - Muchas placas base con UEFI incluyen un modo de compatibilidad con BIOS, llamado CSM.
  - Si el CSM está activado, UEFI puede arrancar discos configurados con MBR, como si fuera un sistema basado en BIOS.
  - Esto es útil para sistemas operativos antiguos que no admiten GPT.

- Algunos UEFI Pueden Arrancar MBR sin CSM
  - En algunos sistemas UEFI, es posible configurar manualmente el firmware para permitir el arranque desde MBR sin necesidad de activar el modo Legacy, pero esto no es común.
  - Depende de cómo el sistema UEFI esté diseñado y del sistema operativo instalado.
