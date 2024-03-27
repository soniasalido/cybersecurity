# Puertos
## Estado de un puerto
- Los puertos de comunicaciones tienen dos Estados:
    - Alcanzable: Un puerto es “alcanzable” si no existe ninguna causa externa (p.ej. filtros intermedios) que evite el contacto entre los extremos. De este modo el origen tendrá información de si dicho puerto está a la escucha o está cerrado.
    - Inalcanzable: Un puerto es “inalcanzable” en cualquier otro caso. Los puertos UDP abiertos, al no negociar una conexión de manera implícita, pueden dar la apariencia de que son inalcanzables.


# Arquitectura Nmap:
Nmap ofrece muchos tipos diferentes de escaneos que pueden usarse para obtener varios resultados sobre nuestros objetivos. Básicamente, Nmap se puede dividir en las siguientes técnicas de escaneo:
    • Descubrimiento de host
    • Escaneo de puertos
    • Enumeración y detección de servicios
    • Detección de sistema operativo
    • Interacción programable con el servicio de destino (Nmap Scripting Engine)

## Técnicas de escaneo:
Sintaxis:
```
nmap <scan types> <options> <target>
```
Nmap ofrece muchas técnicas de escaneo diferentes, haciendo diferentes tipos de conexiones y utilizando paquetes estructurados de manera diferente para enviar. Aquí podemos ver todas las técnicas de escaneo que ofrece Nmap:
```
nmap --help
<SNIP>
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
<SNIP>
```


## Estados para Nmap de un puerto
La salida de Nmap es, dependiendo de las opciones que utilicemos, una lista de equipos escaneados a los que se acompaña de información adicional como el estado de sus puertos. Nmap define seis Estados distintos para recoger los distintos grados de incertidumbre en la determinación de si un puerto está abierto o cerrado, es decir, de si está a la escucha o no de nuevas conexiones o paquetes.

A diferencia del punto anterior (Estados de un puerto), estos estados no son propiedades intrínsecas de los puertos, sino que definen cómo son vistos desde el exterior. La razón de que Nmap sea considerado un escáner de puertos avanzado es, entre otros motivos, debido a esta granularidad en el estado de dichos puertos.

### Los Estados son los siguientes:
- **Abierto:** existe una aplicación en la máquina objetivo que está a la escucha de nuevas conexiones o paquetes TCP o UDP. Muestra un servicio disponible para ser usado en la red.

- **Cerrado:** es un puerto alcanzable, pero no existe una aplicación que esté a la escucha en él. Cuando el puerto se muestra como cerrado, el protocolo TCP indica que el paquete que recibimos **contiene un indicador RST**. Este método de escaneo también se puede utilizar para determinar si nuestro objetivo está vivo o no.

- **Filtrado:** Nmap no ha recibido respuestas a las sondas enviadas hacia un puerto. Suele significar que una herramienta intermedia (generalmente cortafuegos, sondas IDS/IPS, otros elementos de la red, o cualquier otro tipo de filtro) está bloqueando dicho puerto, respondiendo con poca o ninguna información (en ocasiones con un ICMP de tipo “destino inalcanzable”). Nmap no puede identificar correctamente si el puerto escaneado está abierto o cerrado porque no se devuelve una respuesta del destino para el puerto o recibimos un código de error del destino. Esta circunstancia ralentiza notablemente el escaneo para descartar que se trata de un problema de congestión de la red.

- **No filtrado:** Sólo aparece tras un análisis de tipo ACK. Es un puerto alcanzable, pero no es posible determinar si está abierto o cerrado.

- **Abierto | Filtrado:** En este caso, Nmap no ha sido capaz de determinar si el puerto está abierto o filtrado debido a falta de respuestas, bien porque ésta o la Sonda están siendo eliminadas por algún tipo de filtro de paquetes. 

- **Cerrado | Filtrado:** Sólo se obtiene tras un escaneo de tipo Idle. En este caso Nmap no ha sido capaz de determinar si el puerto está cerrado o filtrado.


# Escaneo de TCP Scan
El escaneo de TCP (Transmission Control Protocol) es una técnica utilizada en el ámbito de la seguridad informática para **identificar puertos abiertos (escuchando) en un sistema remoto**. TCP es uno de los protocolos fundamentales en las redes de Internet, encargado de establecer conexiones entre dos hosts y asegurar que los datos enviados lleguen de manera íntegra y en el orden correcto.

El proceso de escaneo de TCP busca determinar qué puertos están escuchando (abiertos) en un dispositivo. Esto se realiza enviando paquetes de datos a diferentes puertos y analizando las respuestas recibidas. Basándose en cómo responde un puerto a ciertos tipos de mensajes, un atacante o un profesional de seguridad puede inferir si el puerto está abierto, cerrado, o filtrado por un firewall.


## Tipos de escaneo de TCP:
### 1. Escaneo SYN (o half-open scan) 🠲
Este método envía un paquete TCP SYN (solicitud de conexión) a un puerto específico del sistema objetivo. Si el puerto está abierto, el sistema responde con un paquete SYN-ACK, lo que indica que está listo para establecer una conexión. El escáner entonces envía un paquete RST (reset) para cerrar la conexión antes de que se complete, evitando así la creación de una conexión completa y posiblemente el registro de la actividad de escaneo.

### 2. Escaneo de conexión completa (o escaneo TCP connect) 🠲 TCP scan (-sT)
En este caso, el escáner establece una conexión completa con el puerto objetivo utilizando el procedimiento normal de establecimiento de conexión TCP (handshake de tres vías: SYN, SYN-ACK, ACK). Aunque este método permite determinar si un puerto está abierto, también es más detectable porque la conexión se completa y puede quedar registrada en los sistemas de registro o detección de intrusiones del objetivo.

El escaneo TCP con la opción -sT se refiere al escaneo de conexión completa o escaneo TCP connect. Esta técnica utiliza el procedimiento estándar de tres vías de TCP para establecer una conexión completa con el puerto objetivo:
- SYN: El cliente (o la herramienta de escaneo) envía un paquete TCP con el flag SYN activado a un puerto específico en el servidor. Este paso solicita abrir una conexión.
- SYN-ACK: Si el puerto está escuchando (abierto), el servidor responde con un paquete TCP que tiene activados los flags SYN y ACK, indicando que está listo para aceptar la conexión.
- ACK: El cliente completa el proceso de establecimiento de conexión enviando un paquete ACK al servidor.

Una vez establecida la conexión, el escáner puede confirmar que el puerto está abierto. Luego, generalmente, terminará la conexión enviando un paquete TCP con el flag FIN para cerrarla de manera ordenada.

**Esta técnica se utiliza por defecto cuando:**
- No es posible la utilización de SYN Scan (-sS).
- Cuando el usuario no tiene suficientes privilegios para crear paquetes RAW IP.

Para su funcionamiento, usa las llamadas de alto nivel del sistema operativo para crear los paquetes (concretamente la llamada connect()) y para obtener la información de los intentos de conexión, al igual que cualquier otra aplicación.

**Esta técnica es menos eficiente que SYN Scan (-sS) porque:**
- Nmap no toma el control de los paquetes enviados, como hace en la mayoría de las otras técnicas.
- Porque termina todas las conexiones, en lugar de hacer un half-open reset. Por este motivo, es menos sigilosa, siendo probable que un IDS/IPS registre los intentos de conexión.



### 3. Escaneo FIN, Xmas, y Null 🠲
Estos métodos envían paquetes con banderas (flags) TCP inusuales o inválidas para provocar respuestas de los puertos que pueden ser interpretadas para determinar su estado. No todos los sistemas responden de la misma manera a estos paquetes, por lo que la efectividad de estos métodos puede variar.


# Bloqueo de TCP Scan
