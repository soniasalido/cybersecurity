


## Recolección del tiempo del sistema:
 - Comando Get-Date en power shell:
   ```
   Get-Date    
   Get-Date -Format "yyyy-MM-dd"
   Get-Date -Format "HH:mm:ss"
   ```
 - Comando Time en cmd:
   ```
   date /t & time /t  
   ```

## Saber las sesiones abiertas en un sistema operativo Windows:
  - A través del Command Prompt (CMD) con permisos de administrador: Estos comandos muestran las sesiones activas y disponibles en el equipo:
    - query session.
    - qwinsta.


## Usuarios están actualmente conectados (logged-on) en un sistema Windows utilizando PowerShell.
Podemos usar el comando Get-WmiObject junto con la clase Win32_ComputerSystem. Este comando nos proporcionará detalles sobre los usuarios que tienen sesiones activas en la máquina, sólo los que estén conectados actualmente, no los usuarios que han iniciado sesión y cerrado sesión anteriormente. 
```
Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
```


## Net sessions commands:
Comando: net sessions [\\<ComputerName>] [/delete] [/list]

## Collecting Open Files:
Comando net file.

## Información de Red: Comando netstat.
Comando netstat 
```
netstat -c
netstat -a 192.168.1.73
netstat -ano
netstat -r
```


## Listar los procesos en ejecución en la sesión de inicio de sesión en un sistema operativo Windows: Para listar los procesos en ejecución en una sesión de inicio de sesión específica en un sistema operativo Windows a través del Command Prompt (CMD), puedes utilizar una combinación de comandos. Primero, necesitas identificar el ID de la sesión (Session ID) y luego listar los procesos asociados con esa sesión. Aquí te explico cómo hacerlo:
  - Abrimos el Command Prompt (CMD) como administrador:
  - Identificamos el ID de la sesión (Session ID). Este comando mostrará una lista de todas las sesiones activas, incluyendo un "ID" para cada una.:
    ```
    query session
    ```
  - Listamos los procesos para una sesión específica: Uilizamos el comando query process, reemplazando <SessionID> con el ID de sesión que identificamos anteriormente. Este comando mostrará todos los procesos que se están ejecutando en esa sesión de inicio de sesión específica:
      ```
      query process /id:<SessionID>
      ```

## Listar procesos con powerShell:
 - El comando Get-Process recupera el conjunto de procesos que se están ejecutando en la computadora local o en una computadora remota. Esto enumerará todos los procesos junto con información básica como ID de proceso (PID), uso de CPU, uso de memoria, nombre de proceso, etc.
   ```
   Get-Process | Format-Table -AutoSize
   ```
​
## Enumerar todas las DLL cargadas para un proceso específico:
 - El comando Get-Module:
   ```
   $processName = "YourProcessName"  # Replace with the actual process name
   Get-Process -Name $processName | ForEach-Object { $_.Modules }
   ```
   Este script enumerará todas las DLL cargadas por un proceso especificado. Reemplazamos "YourProcessName" con el nombre del proceso que nos interese.


 - Para encontrar todos los procesos que tienen una DLL específica cargada, el script se vuelve un poco más complejo. Tendríamos que iterar sobre todos los procesos y verificar sus módulos:
   ```
   $dllName = "YourDllName.dll"  # Replace with the name of the DLL
   Get-Process | Where-Object { $_.Modules.FileName -contains $dllName }
   ```

## Comando para ver los archivos abiertos actualmente:
  - Ejecutar power shell como administrador.
  - Ejecutamos el comando: openfiles /query


## Comando para mostrar las aplicaciones y servicios con sus Process ID (PID) de todos las tareas que se están ejecutando y filtrar por un texto:
```
.\tasklist.exe /v | findstr ssh
```

## Comando de powershell puedo usar para saber si mi tarjeta de red esta habilitado el modo promiscuo:
```
Get-NetAdapter | Get-NetAdapterAdvancedProperty
```


## Handle
 En PowerShell, para imitar la funcionalidad de la herramienta de control de Sysinternals, que muestra información sobre identificadores abiertos (como archivos, claves de registro, etc.), normalmente se utilizaría una combinación de cmdlets. Sin embargo, PowerShell no tiene un cmdlet integrado que corresponda directamente a todas las funcionalidades de handle.

 Para obtener información básica relacionada con el identificador, puede utilizar el cmdlet Get-Process. Puede mostrarle información sobre procesos, que inherentemente incluye cierta información de manejo. Por ejemplo:
 ```
 Get-Process | Select-Object Name, HandleCount
 ```
 Este comando enumerará todos los procesos con sus respectivos recuentos de identificadores. Sin embargo, esto es bastante limitado en comparación con la información detallada proporcionada por handle.

 Para obtener información más detallada sobre los identificadores, normalmente necesitará utilizar herramientas o API externas, ya que los cmdlets integrados de PowerShell no brindan acceso directo a la información de identificadores de bajo nivel. En algunos casos, los scripts de PowerShell pueden invocar programas externos (como  de Sysinternals) y luego analizar el resultado, pero esto requiere tener esas herramientas externas instaladas en su sistema.
 


## netstat -ano
 - El comando netstat -ano en Windows es una herramienta poderosa utilizada para mostrar información de la red. Aquí te explico qué hace cada parte del comando:
 - netstat: Es una abreviatura de "network statistics" (estadísticas de red). Este comando es utilizado para mostrar estadísticas de red y detalles sobre las conexiones de red del computador, tanto entrantes como salientes.
 -a: Esta opción hace que netstat muestre todas las conexiones y puertos de escucha activos. Incluye tanto las conexiones TCP como UDP.
 -n: Esta bandera indica a netstat que muestre las direcciones y números de puerto en forma numérica, en lugar de intentar determinar los nombres de dominio (DNS) de las direcciones IP y los nombres de los servicios para los puertos.
 -o: Esta opción hace que netstat incluya el ID del proceso (PID) asociado con cada conexión. Esto es útil para identificar qué procesos específicos en tu sistema están utilizando conexiones de red.


## Service/Driver Information: Para cmd & PowerShell.
wmic service list brief | more


## Command History: Sólo para cmd:
doskey
doskey [/history]


## Locally Shared Resources:  Para cmd & PowerShell.
net share


## Examinar el File System: Sólo para cmd:
Comando: dir /o:d
Obtendremos una lista de todos los archivos y directorios en el directorio actual, organizados por fecha, comenzando con los más antiguos.



# Examinar los procesos de la Memoria

Si el proceso es sospechoso, recopila más información mediante el volcado de la memoria utilizada por el proceso utilizando herramientas como ProcDump y Process Dumper.
Cuando se identifica un proceso sospechoso en un sistema, los administradores de sistemas o los profesionales de seguridad informática a menudo necesitan recopilar más información para analizar y entender el comportamiento del proceso. Esto se hace generalmente a través de un "volcado de memoria" del proceso. Un volcado de memoria implica capturar el contenido de la memoria que el proceso está utilizando en un momento dado. Esto puede proporcionar detalles valiosos sobre lo que el proceso estaba haciendo, incluyendo:
 - Cadenas de texto que el proceso estaba procesando.
 - Conexiones de red abiertas.
 - Claves de registro y otros recursos del sistema con los que el proceso estaba interactuando.

Herramientas como ProcDump y Process Dumper son utilizadas para realizar estos volcados de memoria. 


##Recopilación del estado de la red

### Comando Ipconfig

### Detectar en Windows el modo promíscuo de la tarjeta:
Detectar el modo promiscuo de una tarjeta de red en Windows directamente a través de la línea de comandos puede ser complicado, ya que Windows no ofrece un comando nativo específico para esta tarea.
 - Uso de Wireshark o Herramientas Similares.
 - Utilizando PowerShell y Windows API: Esto es complejo ya que la API de Windows no proporciona una forma directa y sencilla de verificar el modo promiscuo de una tarjeta de red.
 - Herramienta PromiscDetect.
 - Herramienta Promqry de microsoft.


### Comando de linux puedo usar para saber si mi tarjeta de red esta habilitado el modo promiscuo:
  - Comando ip link show: Este comando mostrará información sobre todas las interfaces de red. Busca la línea que corresponde a tu tarjeta de red (por ejemplo, eth0, wlan0, etc.) y revisa el Estado de la Interfaz: Si la interfaz está en modo promiscuo, verás la palabra PROMISC en la línea de estado de esa interfaz.
    ```
    ip link show
    ```

## Examinando Archivos de Cola de Impresión


## Recopilando Contenidos del Portapapeles


## Recopilando Información de Servicios y Controladores
```
wmic service list brief | more
```
Según las entradas del registro, los servicios y controladores se inician automáticamente cuando se inicia el sistema. La mayoría de los usuarios ni siquiera ven estos servicios en ejecución como procesos porque en realidad no hay indicaciones obvias, como ocurre con los procesos normales. Sin embargo, estos servicios se ejecutan en segundo plano. Algunas aplicaciones de malware se instalan como un servicio o incluso como un controlador del sistema. Por lo tanto, los investigadores deben verificar la información del servicio/dispositivo en busca de programas maliciosos instalados. Los investigadores pueden recopilar información relacionada con los servicios utilizando la herramienta de línea de comandos de la lista de tareas. La herramienta mostrará el nombre de la imagen y los servicios PID relacionados. Los investigadores pueden usar el Comando de Instrumental de administración de Windows (wmic), para ver la lista de servicios en ejecución, sus ID de proceso, modo de inicio, estado y estado.


## Recopilando Historial de Comandos
 - En powerShell:
   ```
   Get-History
   Get-History | Select-Object CommandLine
   Get-History | Select-Object CommandLine | Out-File -FilePath "ruta\historialComandos.txt"
   ```

 - En cmd: El comando doskey /history en CMD (Command Prompt) de Windows se utiliza para mostrar el historial de comandos que has ingresado durante la sesión actual de CMD. No se recopilaa el historial de comandos ingresados en sesiones previas.
   ```
   doskey /history
   ```
- En Linux: Usamos el comando histroy:
de comandos ingresados en sesiones previas.
   ```
   history
   history | grep "tu_comando"
   history > historialComandos.txt
   ```

   
## Recopilando Información de Recursos Compartidos Localmente
 - Comando net share: Muestra información sobre todos los recursos que se comparten en la computadora local. Los recursos compartidos con un carácter ‘$’ al final no aparecen cuando accedes de forma remota al equipo local" se refiere a una característica específica de los recursos compartidos en Windows conocidos como "compartidos administrativos" o "shares ocultos
   - Shares Ocultos: Los recursos compartidos que terminan con un signo de dólar ('$') son compartidos de red ocultos. No aparecen en la lista de recursos compartidos disponibles cuando los usuarios exploran un dispositivo en la red. Por ejemplo, si compartes una carpeta como 'Ejemplo$', esta carpeta compartida no será visible para los usuarios que buscan recursos compartidos en tu computadora.
   - Acceso Remoto: Cuando accedes a una computadora de forma remota (por ejemplo, a través de una conexión de red), normalmente puedes ver los recursos compartidos disponibles. Sin embargo, los recursos compartidos que terminan en '$' no se muestran en esta lista. Aunque están ocultos, siguen siendo accesibles si conoces el nombre exacto del recurso compartido.
   - Uso Administrativo: Estos compartidos ocultos son comúnmente utilizados para la administración del sistema. Windows crea automáticamente ciertos compartidos administrativos ocultos para su propio uso, como 'C$' para el acceso a la unidad C:, 'ADMIN$' para acceder a los archivos de instalación de Windows, etc.
   - Propósito de Seguridad: Ocultar estos recursos compartidos es una medida de seguridad para evitar que usuarios no autorizados o no informados accedan a recursos críticos del sistema. Solo los usuarios que conocen la existencia del recurso compartido y tienen los permisos adecuados pueden acceder a él.
   - En resumen, la nota significa que los recursos compartidos que terminan en $ son ocultos y no se muestran en una búsqueda estándar de recursos compartidos en la red, pero aún así se pueden acceder directamente si conoces el nombre exacto del recurso compartido y tienes los permisos necesarios.
   



# Recopilando la información no volátil

## Mostar directorios y ficcheros ocultos:
 - En cmd:
   ```
   dir /A:H /S
   ```
   /A: Esta opción le indica a dir que muestre archivos con atributos específicos.
   H: Este atributo específico es para archivos ocultos. Al usar :H, le estás diciendo a
   /S: Lista archivos en todos los directorios y subdirectorios.
   
 - En PowerShell:
   ```
   Get-ChildItem -Force | Where-Object { $_.Attributes -match 'Hidden' }
   Get-ChildItem -Path C:\ruta\especifica -Force | Where-Object { $_.Attributes -match 'Hidden' }
   ```
   Get-ChildItem: Este cmdlet obtiene los archivos y subdirectorios en la ubicación actual o una ruta especificada.
   Force: Este parámetro hace que Get-ChildItem muestre todos los archivos y carpetas, incluidos los ocultos y del sistema.
   Where-Object { $_.Attributes -match 'Hidden' }: Este filtro selecciona solo aquellos objetos cuyos atributos incluyen 'Hidden', es decir, aquellos que son archivos o carpetas ocultos.
   Path para  buscar en un directorio específico.


## Archivo de Base de Datos ESE
Un "Archivo de Base de Datos ESE" se refiere a un archivo de base de datos utilizado por el Motor de Almacenamiento Extensible (ESE, por sus siglas en inglés), también conocido como Jet Blue. ESE es una tecnología de base de datos desarrollada por Microsoft que se utiliza en varios de sus productos.

Algunos puntos clave sobre los archivos de base de datos ESE:
 - Motor de Almacenamiento Extensible (ESE): ESE es un motor de base de datos incrustado que permite a las aplicaciones almacenar y recuperar datos mediante el uso de estructuras de datos tabulares. Es conocido por su alta velocidad y confiabilidad en entornos donde se requiere un acceso rápido a los datos, como en servidores de correo electrónico o servicios en línea.
 - Uso en Productos de Microsoft: ESE se utiliza en varios productos de Microsoft, incluyendo Microsoft Exchange Server, Active Directory, Windows Search, y algunos componentes de Windows Server.
 - Formato de Archivo: Los archivos de base de datos ESE suelen tener la extensión .edb. Estos archivos contienen las tablas de datos, índices, y otros elementos de la base de datos, estructurados de manera que permiten un acceso rápido y eficiente.
 - Resistencia y Rendimiento: ESE está diseñado para ser resistente a los fallos, proporcionando mecanismos para recuperarse de los errores sin pérdida de datos. Ofrece un alto rendimiento para aplicaciones que necesitan acceso concurrente a datos por parte de múltiples usuarios o procesos.
 - Transacciones y Bloqueo: ESE soporta transacciones para garantizar la integridad de los datos y utiliza un modelo de bloqueo sofisticado para optimizar el acceso concurrente a los datos.
 - No es una Base de Datos Relacional Completa: A diferencia de las bases de datos relacionales completas como SQL Server, ESE está destinado a ser un motor de base de datos ligero y rápido con un enfoque más especializado.


## Ver Unidades montadas en un equipo:
 - Con powerShell:
   ```
   Get-PSDrive -PSProvider FileSystem
   Get-Disk | Get-Partition
   ```
   Este comando lista todas las unidades de disco disponibles en tu sistema, incluyendo unidades de disco duro, unidades de red, y unidades USB. La información mostrada incluirá el nombre de la unidad, el espacio utilizado y el espacio disponible.

   Ver Particiones ocultas:   
   ```
   Get-Partition | Where-Object { $_.IsHidden -eq $true }
   ```

 - Con Linux:
   ```
   sudo blkid
   sudo fdisk -l
   lsblk
   lsblk -f
   lsblk -o NAME,MODEL,TRAN   
   ```
   

## Recopilando Información de la Memoria RAM

### Volcado de memoria de Windows Crash:
 - Con la herramienta DumpChk. Viene incluida en el depurador de Windows: WinDBG. DumpChk (Dump Check) es una herramienta de Windows que se utiliza para analizar los archivos de volcado de memoria (crash dumps) producidos por un error de pantalla azul (BSOD, por sus siglas en inglés, de Blue Screen of Death). Estos archivos contienen datos que pueden ayudar a identificar la causa del error. Para encontrar el Archivo de Volcado de Memoria: Los archivos de volcado de memoria generalmente se encuentran en C:\Windows\Minidump o directamente en C:\Windows y tienen una extensión .dmp. Abrimos la herramienta con permisos de administrador y elegimos la opcion Open dump file, indicando la ruta del volcado.


### Símbolos en Windows:
En el contexto de los sistemas operativos Windows, los "símbolos" (o "symbol files") se refieren a archivos especiales utilizados en el proceso de depuración. Estos archivos de símbolos proporcionan información esencial para comprender lo que está sucediendo dentro del código ejecutable (como un archivo .exe o .dll) durante el análisis de errores o problemas. 

Propósito de los Símbolos: Los archivos de símbolos contienen una variedad de datos que ayudan a los desarrolladores y profesionales de IT a identificar qué parte del código se está ejecutando en un momento dado. Esto es especialmente útil cuando se está depurando un programa o diagnósticando un fallo del sistema, como un BSOD (Blue Screen of Death).

Información Contenida: Un archivo de símbolos puede incluir nombres de funciones, nombres de variables, y líneas de código que corresponden al código binario del ejecutable. Esta información facilita la tarea de rastrear la fuente de un error o problema de rendimiento.

Uso en la Depuración: Cuando un programa se bloquea o genera un error, el depurador utiliza los archivos de símbolos para mostrar los nombres de las funciones y la ubicación exacta en el código fuente donde ocurrió el problema, en lugar de solo mostrar direcciones de memoria no descriptivas.

Tipos de Símbolos: Hay varios tipos de archivos de símbolos en Windows, incluyendo archivos .pdb (Program Database), que son generados por el compilador de Microsoft cuando un programa es compilado.

Símbolos Públicos y Privados: Microsoft proporciona símbolos públicos para muchos de sus productos, como Windows y Office. Estos símbolos públicos contienen información limitada necesaria para la depuración básica. Los símbolos privados, que contienen información más detallada, generalmente se retienen para uso interno de los desarrolladores del software.

Servidores de Símbolos: Microsoft y otras entidades mantienen servidores de símbolos que permiten a los desarrolladores y profesionales de IT descargar los archivos de símbolos necesarios durante la depuración. Herramientas como WinDbg y Visual Studio pueden configurarse para utilizar estos servidores de símbolos automáticamente.


### Recopilando el contenido de los procesos que están en la memoria.
Para ver el uso de la memoria en PowerShell, podemos utilizar el siguiente comando:
```
C:\Users\usuario\> Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 100 -Property ProcessName, WS
```
Este comando lista los 10 procesos principales en términos de uso de memoria en tu sistema. Aquí, Get-Process obtiene los procesos en ejecución, Sort-Object -Property WS -Descending los ordena en función del espacio de trabajo (memoria utilizada) de forma descendente, y Select-Object -First 100 -Property ProcessName, WS selecciona los primeros 100 procesos, mostrando sus nombres y el uso de memoria.


Para obtener y guardar los procesos que están en memoria podemos usar el comando Get-Process de PowerShel:
```
Get-Process > CapturaProcesos.txt
```

ProcDump es muy útil para la captura de volcados de procesos. Usaremos la herramienta ProcDump de sysinternals para escribir primero un Mini y luego un Full dump de un proceso con un nombre determinado.
```
PS C:\Users\usuario\Downloads\Procdump> .\procdump64.exe -mm -ma nombreProceso  C:\Users\usuario\Desktop\
```
Genera en el escritorio dos ficheros .exe con el proceso que está en memoria.
Para ver todas las opciones de dico comando: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump


### Volcado de memoria
Uso de la herramienta Userdump.exe para crear un archivo de volcado de memoria. Crearemos un archivo de volcado de memoria (.dmp).UserDump. UserDump fue una herramienta proporcionada por Microsoft, pero está obsoleta y ya no se mantiene activamente.

ProcDump es una herramienta más moderna, avanzada y versátil en comparación con UserDump, que es una herramienta más antigua y obsoleta. ProcDump es la opción preferida para la mayoría de las necesidades de depuración y análisis de procesos en Windows debido a su amplia gama de características y su integración con las herramientas actuales de Windows.


Una vez completado el proceso de volcado, utilizaremos herramientas de depuración para analizar los archivos de volcado, como por ejemplo:
 - WinDbg (Windows Debugger): Esta es probablemente la herramienta de depuración más poderosa y ampliamente utilizada en Windows. Ofrece una amplia gama de funcionalidades para analizar volcados de memoria, depurar aplicaciones en vivo y examinar el estado del sistema. WinDbg forma parte del conjunto de herramientas Debugging Tools for Windows y puede manejar tanto pequeños volcados de memoria como volcados de memoria completos.
 - IDA Pro: Aunque es más conocido como un desensamblador y depurador para ingeniería inversa, IDA Pro también puede ser útil para analizar volcados de memoria, especialmente si estás interesado en el análisis a nivel de código máquina o ensamblador. Es de pago. Tiene una version free: Ida Free.
 - GDB (GNU Debugger): Aunque GDB se asocia más comúnmente con sistemas basados en Unix, también puede ser utilizado en Windows, especialmente para programas escritos en C/C++.


### Handle.exe
Handle.exe es una herramienta de línea de comandos desarrollada por Sysinternals (ahora parte de Microsoft) que se utiliza en sistemas operativos Windows para mostrar información sobre los identificadores (handles) abiertos en el sistema. Los handles son referencias utilizadas por los programas para acceder a recursos del sistema como archivos, claves de registro, procesos, servicios, entre otros. Aquí tienes más detalles sobre Handle.exe y su utilidad:

Visualización de Handles Abiertos: Handle.exe proporciona una lista de todos los handles abiertos en el sistema o los abiertos por un proceso específico. Esto incluye información sobre qué proceso tiene un handle abierto, junto con detalles sobre el tipo de objeto (como archivo, directorio, clave de registro, etc.) y la ruta o identificador del objeto.

Diagnóstico de Problemas: Es especialmente útil para diagnosticar problemas en los que un archivo o recurso está siendo utilizado por un proceso y no se puede acceder a él o modificarlo. Por ejemplo, si un archivo no se puede eliminar porque está en uso, Handle.exe puede ayudar a identificar qué proceso está bloqueando ese archivo.

Uso en Depuración y Análisis Forense: En la depuración de software y el análisis forense, Handle.exe puede ser una herramienta valiosa para entender cómo los procesos interactúan con diferentes recursos del sistema.
```
C:\Users\usuario\Downloads\Handle> .\handle.exe > handlesAbiertos.txt
```


### Strings (parte de Sysinternals Suite):
En informática forense, esta herramienta se utiliza para la extracción de texto de archivos binarios. Se utiliza para:
 - Extracción de Cadenas de Texto: Es capaz de analizar archivos binarios (como ejecutables, archivos de sistema, archivos de memoria, etc.) y extraer todas las cadenas de texto legibles que contienen. Esto es útil para identificar información que puede ser relevante en una investigación, como direcciones IP, nombres de usuario, contraseñas, referencias a rutas de archivos, y otros datos.
 - Análisis de Malware: En el análisis de malware, puede ayudar a identificar cadenas de texto dentro de un archivo malicioso que podrían dar pistas sobre su funcionamiento, origen o propósito.
 - Recuperación de Datos: En ciertas situaciones, como cuando los archivos han sido parcialmente dañados o corruptos, puede ayudar a recuperar texto que aún sea legible.
 - Investigación de Intrusiones: En casos de intrusiones de seguridad, puede ser utilizado para examinar los archivos que han sido dejados atrás por un atacante, o modificados por él, para buscar indicios de sus acciones o intenciones.
 - Revisión de Memoria y Volcados de Disco: también puede ser utilizado para buscar información en volcados de memoria o imágenes de disco, lo que es común en investigaciones forenses para entender mejor el estado de un sistema en un punto en el tiempo.
```
C:\Users\usuario\Downloads\Strings>  .\strings.exe -a ficheroVolcadoProcesoMemoria.dmp > cadenasAsciiEncontradas.txt
```
Alternativas:
 - BinTex, pero está deprecated.
 - Ghidra de la agencia nacional de seguridad es gratuita. Desarrollada por la NSA, Ghidra es una potente herramienta de ingeniería inversa que incluye la capacidad de extraer cadenas de archivos binarios. Además, ofrece un conjunto completo de herramientas para el análisis de software.
 - Foremost: Aunque es más conocido como una herramienta de recuperación de datos, Foremost puede ser utilizado para extraer cadenas de texto de archivos binarios, especialmente en el contexto de la recuperación de archivos.


### listdlls.exe de sysinternals
ListDLLs es una herramienta de la suite Sysinternals de Microsoft que se utiliza para listar todas las bibliotecas de vínculos dinámicos (DLLs) que están cargadas en los procesos que se ejecutan en un sistema Windows. Esta herramienta es particularmente útil para la administración de sistemas, la depuración de software, y en la informática forense. A continuación, te explico con más detalle qué hace ListDLLs:

Listar DLLs Cargadas: ListDLLs puede mostrar todas las DLLs que están siendo utilizadas por los procesos activos. Esto incluye tanto las DLLs cargadas por el sistema operativo como las que son específicas de cada aplicación.

Identificar DLLs de Procesos Específicos: Puede filtrar y mostrar las DLLs utilizadas por un proceso específico, identificado por su ID de proceso (PID).

Detección de DLLs No Estándar o Sospechosas: ListDLLs es útil para identificar DLLs que podrían no ser parte del sistema operativo o de las aplicaciones instaladas comúnmente. Esto es especialmente valioso en la detección de malware, ya que algunos tipos de software malicioso inyectan DLLs en procesos para ejecutar código malicioso.

Mostrar Información Detallada: La herramienta proporciona detalles como la ruta completa de cada DLL, el PID del proceso que la ha cargado, y la versión de la DLL. Esta información puede ser crucial para el diagnóstico de problemas o para entender mejor cómo una aplicación interactúa con diferentes componentes del sistema.
```
C:\Users\usuario\Downloads\Listdlls.exe>  .\listdlls.exe -v chrome.exe
listdlls -u
listdlls -d mso.dll --> Muestra los procesos que usan esa dll
``````

### Volcado de memoria RAM
Herramientas como:
 - Belkasoft RAM Capturer.
 - AccessData FTK Imager.
 - Redline de fireeye: Redline®, la principal herramienta gratuita de seguridad para endpoints de FireEye, ofrece capacidades de investigación en hosts a los usuarios para encontrar signos de actividad maliciosa a través del análisis de memoria y archivos y el desarrollo de un perfil de evaluación de amenazas. Redline se utiliza para recolectar, analizar y filtrar datos de endpoints, así como para realizar análisis de IOC y revisión de coincidencias. Además, los usuarios de Endpoint Security (HX) de FireEye pueden abrir colecciones de triaje directamente en Redline para un análisis más profundo, permitiendo al usuario establecer la línea de tiempo y el alcance de un incidente. Esta aplicación funciona solo en Windows. Redline es una herramienta de seguridad para identificar actividades maliciosas a través del análisis de memoria y ayuda a los investigadores forenses a establecer la línea de tiempo y el alcance de un incidente.
 - Memoryze (Windows) de fireeye: Memoryze™ is free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images and on live systems can include the paging file in its analysis. It can perform all these functions on live system memory or memory image files – whether they were acquired by Memoryze or other memory acquisition tools.
 - rVMI de fireeye: rVMI is a debugger on steroids. It leverages Virtual Machine Introspection (VMI) and memory forensics to provide full system analysis. This means that an analyst can inspect userspace processes, kernel drivers, and pre-boot environments in a single tool.


### Volatility 3 en Windows.
Para instalar volatility 3 en windows seguimos los siguientes pasos:
 - Instalación de Python:
  - https://www.python.org/downloads/windows/
  - En el instalar es necesario activar las casillas de Usar privilegios de administrador & Añadir python.exe al PATH.
 - Descargamos volatility 3: https://github.com/volatilityfoundation/volatility3
 - Dentro de la carpeta de volatility:
 - pip install -r .\requirements.txt
 - python -m pip install --upgrade pip setuptools wheel
 - Descargar el Instalador de Visual Studio y ejecutar indicando que se instale Desarrollo para escritorio con C++. Esto es necesario para Yara.
 - pip install yara-python
 - pip install -r .\requirements.txt
 - Aunque da un eror, funciona.
 - Comprobamos la instalación:  python.exe  .\vol.py
 - Con una imagen de memoria RAM, empezamos el análisis:  python.exe .\vol.py -f C:\Users\usuario\Desktop\Windows_RAM.mem   windows.malfind.Malfind
 - Plugins que disponemos para volatility:
  -  windows.bigpools.BigPools
  -  windows.callbacks.Callbacks
  -  windows.cmdline.CmdLine
  -  windows.crashinfo.Crashinfo
  -  windows.devicetree.DeviceTree
  -  windows.dlllist.DllList
  -  windows.driverirp.DriverIrp
  -  windows.drivermodule.DriverModule
  -  windows.driverscan.DriverScan
  -  windows.dumpfiles.DumpFiles
  -  windows.envars.Envars
  -  windows.filescan.FileScan
  -  windows.getservicesids.GetServiceSIDs
  -  windows.getsids.GetSIDs
  -  windows.handles.Handles
  -  windows.info.Info
  -  windows.joblinks.JobLinks
  -  windows.ldrmodules.LdrModules
  -  windows.malfind.Malfind
  -  windows.mbrscan.MBRScan
  -  windows.memmap.Memmap
  -  windows.modscan.ModScan
  -  windows.modules.Modules
  -  windows.mutantscan.MutantScan
  -  windows.poolscanner.PoolScanner
  -  windows.privileges.Privs
  -  windows.pslist.PsList
  -  windows.psscan.PsScan
  -  windows.pstree.PsTree
  -  windows.registry.certificates.Certificates
  -  windows.registry.hivelist.HiveList
  -  windows.registry.hivescan.HiveScan
  -  windows.registry.printkey.PrintKey
  -  windows.registry.userassist.UserAssist
  -  windows.sessions.Sessions
  -  windows.ssdt.SSDT
  -  windows.statistics.Statistics
  -  windows.strings.Strings
  -  windows.symlinkscan.SymlinkScan
  -  windows.vadinfo.VadInfo
  -  windows.vadwalk.VadWalk
  -  windows.virtmap.VirtMap


###EXECUTIVE_READWRITE permission
¿Que significa que el plugin malfind de volatility 3 encuentre un proceso que indica: EXECUTIVE_READWRITE permission?
En el contexto de Volatility 3, que es una herramienta avanzada de análisis de memoria para forenses informáticos, el hallazgo de un proceso con "EXECUTIVE_READWRITE permission" por parte del plugin malfind puede ser indicativo de actividad sospechosa o potencialmente maliciosa.

Volatility se utiliza para analizar volcados de memoria (memory dumps) de sistemas operativos como Windows, y malfind es uno de sus plugins que se especializa en encontrar procesos y controladores que pueden estar ocultando código ejecutable malicioso. Aquí hay algunos puntos clave para entender este hallazgo: Permisos EXECUTIVE_READWRITE:
 - En el contexto de un volcado de memoria, un permiso de "EXECUTIVE_READWRITE" sugiere que un proceso tiene permisos para no solo leer y escribir en una región de memoria, sino también para ejecutar código en esa región. En condiciones normales, muchas áreas de la memoria no requieren permisos de ejecución.
 - Indicativo de Técnicas Maliciosas. Los atacantes a menudo inyectan código malicioso en un proceso legítimo y cambian los permisos de la memoria para permitir la ejecución del código. Esto puede ser un indicio de técnicas de inyección de código o de ejecución de código arbitrario.
 - Análisis Adicional: Aunque el hallazgo de malfind es un indicador, no es necesariamente una confirmación de actividad maliciosa. Se requiere un análisis adicional para determinar si se trata de un comportamiento legítimo o de malware. Este análisis puede incluir la revisión del proceso involucrado, el análisis del código en la región de memoria en cuestión, y la correlación con otros indicadores de compromiso.
 - Falsos Positivos:Algunas aplicaciones legítimas pueden utilizar técnicas que resultan en detecciones de malfind. Por lo tanto, es importante considerar el contexto y realizar un análisis exhaustivo antes de llegar a conclusiones.
 - Contexto del Sistema y del Proceso:El significado de este hallazgo también puede depender del contexto específico del sistema y del proceso. Por ejemplo, ciertas aplicaciones de software legítimas o componentes del sistema operativo pueden tener razones legítimas para poseer estos permisos.

En resumen, un hallazgo de malfind que indica "EXECUTIVE_READWRITE permission" es un fuerte indicador para una investigación más profunda, pero debe ser interpretado con cuidado y en el contexto adecuado para determinar si realmente se trata de una actividad maliciosa.


### Virtual Memory Acquisition Using FTK Imager

Los archivos hiberfil.sys, pagefile.sys y swapfile.sys son archivos de sistema críticos utilizados por Windows para administrar la memoria y el estado del sistema. Cada uno tiene un propósito específico:

### hiberfil.sys:
Este archivo se utiliza para la característica de hibernación en Windows. Cuando hibernas tu computadora, Windows guarda el contenido de la memoria RAM en hiberfil.sys. Esto permite que la computadora apague completamente sin perder el estado actual de tu sesión de trabajo. Cuando reinicias tu computadora desde la hibernación, Windows lee el contenido de este archivo para restaurar tu sesión al estado exacto en que estaba antes de la hibernación. El tamaño de hiberfil.sys suele ser aproximadamente igual al tamaño de la memoria RAM de tu computadora.

   
### pagefile.sys:
Este archivo es conocido como el archivo de paginación o archivo de intercambio. Se utiliza en la administración de la memoria virtual. Cuando la memoria RAM de tu computadora se llena, Windows mueve parte de la información de la RAM al archivo pagefile.sys en el disco duro. Esto libera RAM para nuevos datos y asegura que tu sistema no se quede sin memoria y siga funcionando correctamente. El tamaño de pagefile.sys puede variar, pero generalmente es gestionado automáticamente por Windows. Puede ser varias veces el tamaño de la memoria RAM, dependiendo de las necesidades del sistema y de cómo esté configurado.
 - Podemos hacer una exploración de este fichero con rekall-master, Disk Explorer, y Forensic Toolkit.
 - En Windows, la configuración del archivo de paginación (pagefile.sys) se almacena en el Registro, regedit.
 - Su path es: Abrimos regedit.exe:  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
 - Busca la Clave del Pagefile: Dentro de Memory Management, buscamos una clave llamada PagingFiles. Esta clave contiene la configuración del archivo de paginación, incluyendo su ubicación y tamaño.
 - La gestión del archivo de paginación se maneja mejor a través de la interfaz del sistema en Configuración del sistema > Opciones avanzadas > Rendimiento > Configuración > Opciones avanzadas > Cambiar en la sección de Memoria Virtual. Esto proporciona una interfaz más segura y fácil de usar para modificar la configuración del archivo de paginación.
 - Examining Pagefile Using Strings Command: 


   
### swapfile.sys:
Este archivo es similar a pagefile.sys, pero está especialmente diseñado para las aplicaciones modernas de la interfaz de usuario y la gestión de memoria de la plataforma Universal Windows Platform (UWP). swapfile.sys se utiliza principalmente para intercambiar (swapping) y suspender/resumir las aplicaciones de la UWP.
Este archivo permite que Windows gestione de manera más eficiente las aplicaciones en segundo plano y en suspensión, mejorando el rendimiento general y la reactividad del sistema.

Con el programa AccessData FTK Imager  podemos exportar estos ficheros para su posterior análisis.
