# Modelo OSI
El Modelo OSI (Open Systems Interconnection) es un marco conceptual utilizado para comprender y diseñar la funcionalidad de los sistemas de telecomunicaciones y de redes informáticas. Desarrollado por la Organización Internacional para la Estandarización (ISO) en la década de 1970, el modelo OSI describe cómo las aplicaciones en sistemas de computación pueden comunicarse a través de una red de medios heterogéneos. El modelo OSI se divide en siete capas distintas, cada una con responsabilidades y funciones específicas.

## Las Siete Capas del Modelo OSI
- Capa Física (Layer 1):
    - Se ocupa de la transmisión y recepción de los datos sin procesar a través de un medio físico (cable, fibra óptica, inalámbrico).
    - Incluye especificaciones sobre cables, señales eléctricas, conectores y aspectos físicos de la red.
- Capa de Enlace de Datos (Layer 2) - (Ethernet):
    - Se encarga de la transferencia fiable de datos a través del medio físico.
    - Proporciona la dirección de hardware (MAC), maneja los errores del medio físico y controla el flujo de datos.
    - Ejemplos incluyen Ethernet, PPP y Switches.
- Capa de Red (Layer 3) - (IP):
    - Responsable del direccionamiento, enrutamiento y (en muchos casos) de la fragmentación y reensamblaje de los paquetes de datos.
    - Utiliza direcciones lógicas (como direcciones IP) para enrutar paquetes de un nodo a otro dentro de diferentes redes.
    - Ejemplos incluyen el protocolo IP y los routers.
- Capa de Transporte (Layer 4) - (TCP/UDP):
    - Garantiza la transferencia de datos completa y fiable entre sistemas finales a través de una red, proporcionando control de errores y flujo.
    - Dos de los protocolos de transporte más comunes son TCP (orientado a la conexión) y UDP (sin conexión).
- Capa de Sesión (Layer 5):
    - Gestiona las sesiones entre aplicaciones, estableciendo, gestionando y finalizando las conexiones entre usuarios finales.
    - Proporciona mecanismos para la recuperación de fallos y reanudación de datos.
- Capa de Presentación (Layer 6):
    - Actúa como un traductor de datos para la red, asegurando que los datos enviados desde una aplicación sean legibles por la aplicación de destino.
    - Encargada de la compresión de datos, cifrado/descifrado y conversión de formatos de datos.
- Capa de Aplicación (Layer 7):
    - La capa más cercana al usuario final, proporciona interfaces y protocolos para aplicaciones y servicios de red.
    - Ejemplos incluyen HTTP, FTP, SMTP, y servicios de Web.

## Importancia del Modelo OSI
- Facilita la Troubleshooting: Al segmentar las diferentes funciones de red en capas distintas, facilita la identificación y resolución de problemas en redes complejas.
- Promueve la Interoperabilidad y la Estándarización: Al adherirse a los estándares del modelo OSI, diferentes sistemas y dispositivos pueden comunicarse entre sí sin problemas.
- Independencia de Capas: Cada capa en el modelo OSI opera de forma independiente. Los cambios en una capa no afectan directamente a las otras, lo que permite una mayor flexibilidad y evolución de las tecnologías de red.
- Facilita el Diseño Modular: Los desarrolladores pueden crear productos de red que se centren en las funcionalidades de una capa específica del modelo OSI.

Aunque en la práctica muchas redes utilizan el modelo TCP/IP, que es un modelo más simplificado, el modelo OSI sigue siendo una herramienta fundamental para enseñar y comprender los conceptos básicos de las redes de computadoras.


## Encapsulacion de los datos en un frame
La encapsulación de datos en un frame (marco) es un proceso esencial en la capa de enlace de datos del modelo OSI (Open Systems Interconnection) para la transmisión de datos a través de una red. Este proceso implica envolver los datos con un encabezado y un finalizador (trailer) específicos para crear un frame que sea apto para la transmisión a través del medio físico de la red. Vamos a detallar este proceso:

## Proceso de Encapsulación en un Frame
- Inicio con Datos de la Capa Superior:
    - El proceso comienza cuando la capa de enlace de datos recibe un paquete de la capa de red (como un paquete IP).
- Añadir Encabezado (Header):
    - Direcciones MAC: Se añade un encabezado al paquete, que incluye la dirección MAC (Media Access Control) de origen y destino. La dirección MAC de destino identifica el dispositivo o dispositivos a los que se dirige el frame, mientras que la dirección MAC de origen identifica el emisor.
    - Información de Control: El encabezado también puede incluir información de control, como tipo de frame y otros datos necesarios para el procesamiento del frame en la red.
-Añadir Datos:
    - Payload: El paquete original (por ejemplo, un paquete IP) se incluye intacto y se considera como la carga útil (payload) del frame.
- Añadir Finalizador (Trailer):
    - Secuencia de Verificación de Trama (FCS): Al final del frame, se añade un trailer que incluye, principalmente, la Secuencia de Verificación de Trama. Esta es una suma de verificación (usualmente un Cyclic Redundancy Check, CRC) que permite al receptor detectar errores en la transmisión.
- Transmisión:
    - Frame Listo para Enviar: Una vez que el frame está completamente ensamblado con su encabezado, payload y trailer, está listo para ser enviado a través del medio físico (como cable de cobre, fibra óptica o inalámbrico).

![](https://upload.wikimedia.org/wikipedia/commons/3/3b/UDP_encapsulation.svg)


## Importancia de la Encapsulación
- Integridad de Datos: La suma de verificación (CRC) en el trailer ayuda a asegurar la integridad de los datos transmitidos.
- Control de Acceso al Medio: Las direcciones MAC en el encabezado son esenciales para la entrega de frames en una red local (LAN).
- Transparencia de Datos: El proceso de encapsulación permite que diferentes tipos de datos de la capa de red (como IPv4, IPv6, ARP, etc.) se transporten a través de la misma red física.
- Detección de Errores: El FCS permite al receptor detectar si el frame ha sido dañado o alterado durante la transmisión.

Este proceso de encapsulación en un frame es fundamental para la operación de redes de área local (LAN) como Ethernet, donde la entrega de datos entre dispositivos físicos debe ser gestionada de manera eficiente y confiable.


Veamos cómo se hacen los paquetes y qué tipo de información llevan. En términos simples, podemos decir que un paquete de red es simplemente datos reunidos para ser transferidos de un punto final/anfitrión a otro. Sin embargo, en las profundidades de una red, un paquete IP se parece a lo siguiente:
![](https://static.packt-cdn.com/products/9781789344523/graphics/assets/fda06dde-e116-47e4-9024-62fb1cf47f22.png)

Desde los primeros datos sin procesar en el cable hasta convertirse en una trama Ethernet, pasando por el paquete IP y, más adelante, hasta el tipo TCP y UDP y, finalmente, convertirse en datos de la aplicación, la información se encapsula a través de varias capas.

## Protocol Encapsulation
### 1. The internet protocol header.
El encabezado IP tiene los siguientes campos:
- Versión: La versión contiene el formato del paquete IP.
- Longitud del Encabezado IP (IHL): Longitud del encabezado del paquete IP. Generalmente hay un conteo de palabras de 32 bits en el paquete.
- DCSP: Punto de Código de Servicios Diferenciados: Anteriormente llamado TOS, este se utiliza generalmente para comunicaciones en tiempo real.
- ECN: Notificación de Congestión Explícita: La congestión puede ser detectada a través de este campo.
- Longitud Total: La longitud completa del paquete, incluyendo los datos y el encabezado.
- Identificación: Para la identificación única del paquete, sin embargo, si ocurre fragmentación, este valor será el mismo para todos los fragmentos.
- Flags: Banderas: Las banderas generalmente indican si se permite al router fragmentar los paquetes.
- Fragment Offset: Desplazamiento de Fragmentación: En casos donde ocurre la fragmentación, este campo se utiliza para indicar el desplazamiento desde el inicio del datagrama en sí.
- TTL: Tiempo de Vida: La cantidad de dispositivos a los que salta el paquete antes de que expire.
- Protocolo: La esencia del paquete que describe qué protocolo está encapsulado dentro, por ejemplo, TCP o UDP u otros protocolos de la capa de transporte.
- Header Cheksum: Checksum del Encabezado: Utilizado para la detección de errores.
- Dirección de Origen: Emisor del paquete.
- Dirección de Destino: Destino del paquete.
- Opciones: Opciones adicionales. Longitud variable.
- Padding: Relleno: Añade bits extra para hacer que la longitud del paquete sea un múltiplo de 32 bits.

```
Frame 109: 2157 bytes on wire (17256 bits), 2157 bytes captured (17256 bits) on interface \Device\NPF_{62B81473-18EB-422C-8CA0-6A11E6BB7388}, id 0
    Section number: 1
    Interface id: 0 (\Device\NPF_{62B81473-18EB-422C-8CA0-6A11E6BB7388})
    Encapsulation type: Ethernet (1)
    Arrival Time: May 31, 2016 17:42:11.054656000 CEST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1464709331.054656000 seconds
    [Time delta from previous captured frame: 0.050815000 seconds]
    [Time delta from previous displayed frame: 0.050815000 seconds]
    [Time since reference or first frame: 128.721380000 seconds]
    Frame Number: 109
    Frame Length: 2157 bytes (17256 bits)
    Capture Length: 2157 bytes (17256 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:tcp:http:data-text-lines]
    [Coloring Rule Name: HTTP]
    [Coloring Rule String: http || tcp.port == 80 || http2]
Ethernet II, Src: Microsof_00:01:20 (00:15:5d:00:01:20), Dst: Microsof_00:01:1f (00:15:5d:00:01:1f)
Internet Protocol Version 4, Src: 10.0.0.12 (10.0.0.12), Dst: 10.0.0.10 (10.0.0.10)
Transmission Control Protocol, Src Port: http (80), Dst Port: 51263 (51263), Seq: 8916, Ack: 327, Len: 2103
[3 Reassembled TCP Segments (11018 bytes): #105(5840), #107(3075), #109(2103)]
Hypertext Transfer Protocol
Line-based text data: text/html (147 lines)
```

### 2. The Transmission Control
```
Frame 109: 2157 bytes on wire (17256 bits), 2157 bytes captured (17256 bits) on interface \Device\NPF_{62B81473-18EB-422C-8CA0-6A11E6BB7388}, id 0
Ethernet II, Src: Microsof_00:01:20 (00:15:5d:00:01:20), Dst: Microsof_00:01:1f (00:15:5d:00:01:1f)
Internet Protocol Version 4, Src: 10.0.0.12 (10.0.0.12), Dst: 10.0.0.10 (10.0.0.10)
----> Transmission Control Protocol, Src Port: http (80), Dst Port: 51263 (51263), Seq: 8916, Ack: 327, Len: 2103
    Source Port: http (80)
    Destination Port: 51263 (51263)
    [Stream index: 4]
    [Conversation completeness: Complete, WITH_DATA (31)]
    [TCP Segment Len: 2103]
    Sequence Number: 8916    (relative sequence number)
    Sequence Number (raw): 1428352201
    [Next Sequence Number: 11019    (relative sequence number)]
    Acknowledgment Number: 327    (relative ack number)
    Acknowledgment number (raw): 1846370624
    0101 .... = Header Length: 20 bytes (5)
    Flags: 0x018 (PSH, ACK)
    Window: 513
    [Calculated window size: 131328]
    [Window size scaling factor: 256]
    Checksum: 0x141c [unverified]
    [Checksum Status: Unverified]
    Urgent Pointer: 0
    [Timestamps]
    [SEQ/ACK analysis]
    ----> TCP payload (2103 bytes)
    TCP segment data (2103 bytes)
[3 Reassembled TCP Segments (11018 bytes): #105(5840), #107(3075), #109(2103)]
Hypertext Transfer Protocol
Line-based text data: text/html (147 lines)
```

Podemos ver que el encabezado TCP contiene las siguientes secciones:
- Puerto de Origen: El puerto que genera el paquete.
- Puerto de Destino: El puerto al cual están dirigidos los datos para un host en particular.
- Número de Secuencia: La posición del primer byte de datos.
- Número de Acuse de Recibo: El siguiente byte de datos que el host receptor está esperando.
- Longitud del Encabezado: La longitud del encabezado de la capa de Transporte en palabras de 32 bits.
- Banderas: El campo de bits de control tiene los siguientes tipos de valores:
    - URG: Priorizar datos
    - ACK: Acusar recibo del paquete
    - PSH: Empujar datos inmediatamente
    - RST: Abortar una conexión
    - SYN: Iniciar una conexión
    - FIN: Cerrar una conexión
    - NS Protección de ocultamiento ECN-nonce
    - Reducida la Ventana de Congestión (CWR)
    - ECE ECN: El eco indica que el par puede usar ECN (si la bandera SYN está activada); de lo contrario, indica que hay congestión en la red
    - Window: El tamaño/cantidad de datos que pueden ser aceptados.
    - Checksum: Utilizado para encontrar errores al verificar el encabezado, los datos y el pseudo-encabezado.
    - Puntero Urgente: El puntero al final de los datos urgentes.
    - Opciones: Opciones adicionales.
    - Relleno: Para ajustar el tamaño mediante el relleno del encabezado.

Avanzando más abajo en la encapsulación del paquete, podemos ver que tenemos la carga útil de TCP (TCP Payload) que contiene el paquete HTTP que veremos en el siguiente punto.


### 3. The HTTP packet
```
Frame 109: 2157 bytes on wire (17256 bits), 2157 bytes captured (17256 bits) on interface \Device\NPF_{62B81473-18EB-422C-8CA0-6A11E6BB7388}, id 0
Ethernet II, Src: Microsof_00:01:20 (00:15:5d:00:01:20), Dst: Microsof_00:01:1f (00:15:5d:00:01:1f)
Internet Protocol Version 4, Src: 10.0.0.12 (10.0.0.12), Dst: 10.0.0.10 (10.0.0.10)
Transmission Control Protocol, Src Port: http (80), Dst Port: 51263 (51263), Seq: 8916, Ack: 327, Len: 2103
[3 Reassembled TCP Segments (11018 bytes): #105(5840), #107(3075), #109(2103)]
---> Hypertext Transfer Protocol
    HTTP/1.1 200 OK\r\n
        [Expert Info (Chat/Sequence): HTTP/1.1 200 OK\r\n]
        Response Version: HTTP/1.1
        Status Code: 200
        [Status Code Description: OK]
        Response Phrase: OK
    Date: Tue, 31 May 2016 15:42:07 GMT\r\n
    Server: Apache/2.4.9 (Win64) PHP/5.5.12\r\n
    X-Powered-By: PHP/5.5.12\r\n
    Link: <http://10.0.0.12/WordPress/wp-json/>; rel="https://api.w.org/"\r\n
    Keep-Alive: timeout=5, max=100\r\n
    Connection: Keep-Alive\r\n
    Transfer-Encoding: chunked\r\n
    Content-Type: text/html; charset=UTF-8\r\n
    \r\n
    [HTTP response 1/1]
    [Time since request: 3.644251000 seconds]
    [Request in frame: 99]
    [Request URI: http://10.0.0.12/wordpress/]
    HTTP chunked response
        Data chunk (8589 octets)
            Chunk size: 8589 octets
            Chunk data: 3c21444f43545950452068746d6c3e0a3c68746d6c206c616e673d22656e2d5553222063…
            Chunk boundary: 0d0a
        Data chunk (2091 octets)
            Chunk size: 2091 octets
            Chunk data: 3c73656374696f6e2069643d2261726368697665732d322220636c6173733d2277696467…
            Chunk boundary: 0d0a
        End of chunked encoding
            Chunk size: 0 octets
        \r\n
    File Data: 10680 bytes
Line-based text data: text/html (147 lines)
```
Un paquete HTTP (Hypertext Transfer Protocol) es una unidad de datos que se transmite a través de la red en el marco de una comunicación HTTP. HTTP es el protocolo utilizado para la transferencia de información en la World Wide Web, facilitando la carga y descarga de datos entre un cliente web (como un navegador) y un servidor web. Vamos a desglosar lo que implica un paquete HTTP:

- Estructura de un Paquete HTTP:
    - Solicitud HTTP (HTTP Request):
        - Método: Indica la acción que el cliente desea realizar (GET, POST, PUT, DELETE, etc.).
        - URL/URI: La dirección del recurso solicitado.
        - Versión de HTTP: Por ejemplo, HTTP/1.1 o HTTP/2.
        - Encabezados de Solicitud (Headers): Proporcionan información adicional sobre la solicitud, como el tipo de contenido, cookies, agente de usuario, etc.
        - Cuerpo (Body): En métodos como POST o PUT, el cuerpo puede contener datos enviados al servidor.
    - Respuesta HTTP (HTTP Response)
        - Estado: Código de estado y mensaje que indica el resultado de la solicitud (por ejemplo, 200 OK, 404 Not Found).
        - Versión de HTTP: La versión del protocolo HTTP utilizada.
        - Encabezados de Respuesta (Headers): Información adicional sobre la respuesta, como tipo de contenido, tamaño del contenido, cookies, cabeceras de control de caché, etc.
        - Cuerpo (Body): Los datos del recurso solicitado (por ejemplo, HTML, JSON, imágenes, etc.).

- Funcionamiento de los Paquetes HTTP:
    - Transmisión: Los paquetes HTTP se transmiten a través del protocolo TCP/IP. HTTP es un protocolo de capa de aplicación que se construye sobre la capa de transporte TCP.
    - Sin Estado: HTTP es un protocolo sin estado; cada solicitud es independiente, y el servidor no mantiene el estado entre las solicitudes diferentes.
    - Seguridad: El protocolo HTTPS (HTTP Secure) es una versión segura de HTTP que utiliza SSL/TLS para encriptar los paquetes, protegiendo así la información contra la interceptación y el acceso no autorizado.

- Uso de los Paquetes HTTP:
    - Navegación Web: Cada vez que visitas una página web, tu navegador envía solicitudes HTTP al servidor y recibe respuestas HTTP con el contenido de la página.
    - APIs Web y Servicios: Muchas APIs (Application Programming Interfaces) y servicios web utilizan HTTP para la comunicación entre clientes y servidores.
    - Transferencia de Datos: HTTP se utiliza para transferir todo tipo de datos en la Web, desde páginas web hasta archivos de imagen, video, y estilo.

En resumen, los paquetes HTTP son los bloques básicos de la transferencia de datos en la World Wide Web, permitiendo la comunicación y transferencia de información entre clientes y servidores.




# Network protocols
Los protocolos de red son un conjunto de reglas y convenciones que determinan cómo se debe transmitir la información a través de una red. Estos protocolos son fundamentales para la comunicación entre dispositivos en una red, como computadoras, servidores, routers y switches. Algunos de los aspectos más destacados de los protocolos de red incluyen:
- Formato de Datos: Definen cómo se deben estructurar y formatear los datos para su envío y recepción.
- Identificación de Dispositivos: Establecen cómo se identifican los dispositivos en la red, generalmente a través de direcciones como las direcciones IP en Internet.
- Control de Errores: Proporcionan métodos para detectar y corregir errores que pueden ocurrir durante la transmisión de datos.
- Control de Flujo: Gestionan la velocidad a la que se envían los datos para evitar que el receptor se vea sobrecargado por datos que no puede procesar rápidamente.
- Encaminamiento: Determinan cómo se deben enrutar o dirigir los datos a través de la red de un punto a otro.
- Establecimiento y Terminación de la Conexión: Definen cómo iniciar, mantener y finalizar una comunicación.

# Protocol Types:
Hay varios tipos de protocolos de red, cada uno diseñado para propósitos específicos. Algunos de los protocolos de red más comunes incluyen:
- ICMP.
- TCP/IP (Transmission Control Protocol/Internet Protocol).
- UDP: A diferencia de TCP, UDP no establece una conexión antes de enviar datos y no garantiza que los paquetes de datos enviados lleguen en orden o incluso que lleguen en absoluto. Por estas características, UDP es mucho más simple y rápido que TCP.
- IP.

# 1. ICMP
ICMP (Internet Control Message Protocol) es un protocolo utilizado en redes de computadoras para enviar mensajes de error y de operaciones de control. Es un componente integral del conjunto de protocolos de Internet (IP). A diferencia de los protocolos de transporte como TCP (Transmission Control Protocol) y UDP (User Datagram Protocol), que se utilizan para la transmisión de datos entre aplicaciones, ICMP se utiliza para el envío de mensajes relacionados con el funcionamiento de la red misma.

# 2. TCP
El protocolo TCP (Transmission Control Protocol) es uno de los protocolos fundamentales en las redes de computadoras y juega un papel crucial en la suite de protocolos de Internet (IP). TCP es un protocolo orientado a la conexión, fiable y que garantiza la entrega de datos entre un emisor y un receptor. Veamos sus características y funcionamiento más detalladamente:

## Características Clave de TCP
- TCP opera en la capa de Transporte del modelo OSI.
- Orientado a la Conexión: Antes de que se puedan enviar datos, TCP establece una conexión entre el emisor y el receptor. Esta conexión se mantiene activa durante toda la sesión de comunicación.
- Transmisión Fiable de Datos: TCP asegura que los datos enviados lleguen al destino sin errores y en el mismo orden en que se transmitieron.
- Control de Flujo: Regula la cantidad de datos que el emisor puede enviar al receptor, lo cual evita que el receptor se sobrecargue de datos.
- Control de Congestión: Reduce la tasa de envío de datos si detecta congestión en la red, minimizando así la posibilidad de pérdida de paquetes.
- Entrega Ordenada: Los datos se entregan al receptor en el orden en que fueron enviados.
- Detección y Corrección de Errores: A través de sumas de comprobación y acuses de recibo, TCP detecta errores en los datos y realiza las retransmisiones necesarias.

## Funcionamiento de TCP
- Establecimiento de la Conexión (Three-Way Handshake)
    - SYN -->: El emisor inicia la conexión enviando un segmento TCP con la bandera SYN (synchronize) activada, indicando que desea establecer una conexión.
    - SYN-ACK <--: El receptor responde con un segmento TCP con las banderas SYN y ACK (acknowledge) activadas, reconociendo la solicitud de conexión.
    - ACK -->: El emisor envía un segmento ACK final para confirmar la recepción y completar el establecimiento de la conexión.

- Transmisión de Datos: Una vez establecida la conexión, los datos se transmiten en segmentos. TCP divide los datos de la aplicación en segmentos y los envía secuencialmente al receptor. Cada segmento lleva una suma de comprobación para la detección de errores, así como números de secuencia y acuse de recibo para garantizar la entrega ordenada y fiable.

- Control de Flujo y Congestión: TCP utiliza el tamaño de la ventana y otros algoritmos para gestionar el control de flujo y la congestión, asegurando que el emisor no sobrecargue al receptor ni a la red.

- Finalización de la Conexión: La conexión se termina cuando ambas partes completan un proceso de finalización de cuatro pasos, similar al "three-way handshake" inicial, pero esta vez para cerrar la conexión de manera ordenada.
    - FIN -->: El emisor finaliza la conexión enviando un segmento con el flag FIN activado.
    - ACK <--: El receptor envia un segmento con el flag ACK activado, reconociendo la solicitud de conexión.
    - FIN <--:El receptor envia un segmento con el flag FIN activado, indicando que quiere terminar la conexión.
    - ACK -->: El emisor envia un segmento con el flag ACK activado, reconociendo la finalización de conexión.
    
## Aplicaciones de TCP
TCP se utiliza en aplicaciones donde la fiabilidad es crucial, como en la transferencia de archivos (FTP), el envío de correos electrónicos (SMTP, IMAP), y la carga de páginas web (HTTP/HTTPS). Aunque es más lento que UDP debido a su naturaleza fiable y orientada a la conexión, TCP es preferido para aplicaciones que no pueden tolerar la pérdida de datos.

## Estados TCP
TCP (Transmission Control Protocol) es un protocolo orientado a la conexión, lo que significa que establece una conexión fiable entre dos puntos finales antes de la transmisión de datos. Durante su operación, una conexión TCP pasa por varios estados que gestionan el ciclo de vida de la conexión. Los posibles estados de una conexión TCP son:
- CLOSED: Estado inicial en el que no hay una conexión activa o pendiente.
- LISTEN: El servidor está esperando una solicitud de conexión de un cliente. En este estado, el servidor ha abierto un puerto para escuchar (listen) las conexiones entrantes.
- SYN-SENT: El cliente envía un segmento SYN al servidor para comenzar la conexión y espera una confirmación. Este estado indica que el cliente ha iniciado la conexión pero aún no se ha establecido completamente.
- SYN-RECEIVED: El servidor ha recibido el segmento SYN del cliente y ha enviado una respuesta SYN-ACK. El servidor espera un ACK para confirmar la conexión.
- ESTABLISHED: Una vez que el cliente y el servidor han intercambiado los segmentos SYN y ACK, la conexión TCP está establecida y los datos pueden ser enviados. Tanto el cliente como el servidor pueden enviar y recibir datos.
- FIN-WAIT-1: El host ha iniciado la terminación de la conexión y está esperando un ACK del FIN.
- FIN-WAIT-2: El host ha recibido un ACK del FIN y está esperando un FIN del otro extremo.
- CLOSE-WAIT: El host ha recibido un FIN del otro extremo y espera que la aplicación en el host cierre la conexión.
- CLOSING: Ambos extremos han enviado FIN pero ninguno ha recibido ACK del otro.
- LAST-ACK: El host está esperando el último ACK para un FIN enviado.
- TIME-WAIT: El host espera un tiempo suficiente para estar seguro de que el extremo remoto ha recibido el ACK de su FIN antes de cerrar completamente. Este estado también asegura que no quedan paquetes rezagados en la red que podrían confundirse con una nueva conexión.
- CLOSED: El estado final después de cerrar la conexión.

Estos estados aseguran que TCP maneje la conexión de manera fiable y ordenada, estableciendo y terminando conexiones de manera controlada y asegurando que todos los datos se transmitan correctamente antes de cerrar la conexión.


# 3. UDP - User Datagrama Protocol
El protocolo UDP (User Datagram Protocol) es uno de los protocolos fundamentales en la suite de protocolos de Internet. A diferencia del TCP (Transmission Control Protocol), UDP es un protocolo sin conexión y no garantiza la entrega de datos. Es conocido por su simplicidad y eficiencia, especialmente en aplicaciones donde la velocidad es más crítica que la fiabilidad. Vamos a explorar UDP más a fondo:

## Características Clave de UDP
- Opera en la capra de Transporte del modelo OSI.
- Sin Conexión: UDP no establece una conexión previa entre el emisor y el receptor antes de enviar los datos. Esto significa que los datos se pueden enviar inmediatamente sin el proceso de establecimiento de conexión.
- No Fiable: No hay garantía de que los paquetes de datos lleguen al destino, ni que lleguen en el orden en que se enviaron o que lleguen completos.
- Sin Control de Flujo ni de Congestión: UDP no tiene mecanismos para manejar el control de flujo o la congestión en la red. Esto puede llevar a la pérdida o descarte de paquetes en redes congestionadas.
- Encabezado Ligero: El encabezado de UDP es mucho más simple y pequeño que el de TCP, lo que resulta en una menor sobrecarga de datos.
- Transmisión de Datos Datagrama: Los datos se envían en unidades llamadas datagramas. Cada datagrama se maneja de manera independiente de los demás.

## Funcionamiento de UDP
- Envío de Datos:
    - Creación de Datagramas: Los datos de la aplicación se dividen en datagramas. Cada datagrama incluye un encabezado simple que contiene el puerto de origen, el puerto de destino, la longitud total y una suma de comprobación.
    - Transmisión: Los datagramas se envían a la red sin establecer una conexión previa con el receptor. No hay acuse de recibo por parte del receptor.
- Recepción de Datos:
    - Recepción de Datagramas: El receptor obtiene los datagramas. La suma de comprobación se utiliza para verificar la integridad de los datos. Si hay un error, el datagrama se descarta generalmente sin notificación al emisor.
    - Procesamiento de Datagramas: Los datagramas se procesan independientemente. UDP no reordena los datagramas si llegan fuera de secuencia.

## Aplicaciones de UDP: UDP es ideal para aplicaciones que requieren transmisiones rápidas y en las que la pérdida de algunos paquetes de datos es aceptable. Se utiliza en situaciones como:
- Transmisión de Video y Audio: En streaming de video y voz sobre IP (VoIP), donde la latencia es más crítica que la pérdida ocasional de datos.
- Juegos en Línea: Donde la velocidad y la baja latencia son esenciales.
- Protocolos Simples de Consulta/Respuesta: Como DNS (Domain Name System), donde se intercambian mensajes pequeños y simples.
- Broadcasting y Multicasting: Envío de datos a múltiples destinatarios simultáneamente.

## Limitaciones
Aunque la eficiencia y la simplicidad son ventajas significativas de UDP, su falta de fiabilidad, control de flujo y control de congestión lo hacen inadecuado para aplicaciones que requieren una entrega garantizada y ordenada de datos, como la transferencia de archivos o la carga de páginas web. En esos casos, se prefiere TCP.


# 4. IP - Internet Protocol
El Protocolo de Internet (IP) es uno de los componentes clave de la suite de protocolos de Internet y se encarga de encaminar los paquetes de datos desde su origen hasta su destino a través de redes interconectadas. IP se encuentra en la capa de red del modelo OSI (Open Systems Interconnection) y del modelo TCP/IP, proporcionando una dirección única a cada dispositivo en la red y facilitando así la ruta de los datos a través de diferentes redes.

## Versiones de IP
- IPv4 (Protocolo de Internet versión 4): Es la versión más utilizada actualmente. Utiliza direcciones de 32 bits, lo que proporciona alrededor de 4 mil millones de direcciones únicas.
- IPv6 (Protocolo de Internet versión 6): Fue desarrollado para abordar la escasez de direcciones IP con IPv4. Utiliza direcciones de 128 bits, lo que permite un número casi ilimitado de direcciones únicas.

## Características Clave del Protocolo IP
- Direccionamiento: IP asigna una dirección única a cada dispositivo en una red, conocida como dirección IP.
- Encaminamiento de Paquetes: IP transporta datos en forma de paquetes. Cada paquete contiene tanto la dirección de origen como la dirección de destino, lo que permite que los paquetes sean encaminados a través de múltiples nodos en la red.
- Independencia de la Red Física: IP opera sobre diversas tecnologías de red física, lo que significa que puede ser utilizado en una amplia variedad de redes.
- Desencapsulamiento y Reencapsulamiento: En su viaje a través de las redes, los paquetes IP pueden ser encapsulados y desencapsulados en diferentes formatos de trama dependiendo de la red.
- No Orientado a la Conexión y No Fiable: IP no establece una conexión previa antes de enviar paquetes y no garantiza la entrega de paquetes, el orden de llegada o la integridad de los datos.

## Funcionamiento del Protocolo IP
- Transmisión de Paquetes
    - Fragmentación: Los paquetes IP pueden ser fragmentados en segmentos más pequeños si el tamaño de los paquetes excede el límite máximo de la red. Cada fragmento es luego enviado independientemente.
    - Encaminamiento: Los routers en la red utilizan la dirección IP de destino para tomar decisiones de encaminamiento, dirigiendo el paquete a través de varias redes hasta que alcanza su destino final.
- Recepción de Paquetes
    - Reensamblaje: Si un paquete ha sido fragmentado, el sistema receptor lo reensambla en el paquete original.
    - Entrega: Una vez que el paquete ha llegado a la red de destino, es entregado al dispositivo de destino basado en la dirección IP.

## Aplicaciones del Protocolo IP
El protocolo IP se utiliza para casi todas las formas de comunicación en Internet, desde la navegación web y el envío de correos electrónicos hasta la transmisión de datos y la conectividad de red en general. Es el protocolo que permite la interconexión global y la comunicación entre redes diferentes.

## Desafíos y Soluciones
- Escasez de Direcciones en IPv4: La solución a largo plazo a este problema es la adopción de IPv6, que proporciona un número significativamente mayor de direcciones IP.
- Seguridad: IP por sí mismo no proporciona mecanismos de seguridad, por lo que protocolos como IPSec han sido desarrollados para proporcionar seguridad en la capa IP.

El protocolo IP, especialmente en su versión 4, es una parte fundamental de la infraestructura de Internet, y su diseño y funcionamiento han permitido el crecimiento y la expansión de la red a nivel mundial.


# Protocols and ports.
- File transfer protocol (FTP).
- Secure Shell (SSH), Secure Copy (SCP), y Secure FTP (SFTP).
- Telnet.
- Simple Mail Transfer Protocol (SMTP).
- Damin Name System (DNS).
- Dynamic Host Configuration Protocol (DHCP).
- Hypertex Transfer Protocol (HTTP).
- Post Office Protocol (POP).
- Network Time Protocol (NTP).
- INternet Message Access Protocol (IMAP).
- Simple Network Management Protocol (SNMP).
- Ligthweight Directory Access Protocol (LDAP).
- HTTP secure (HTTPS).
- Server Message Block (SMB).
- Remote DEsktop Protocol (RDP).


# 1. File transfer protocol (FTP)
El Protocolo de Transferencia de Archivos (FTP, por sus siglas en inglés) es un protocolo estándar de comunicaciones utilizado para la transferencia de archivos entre un cliente y un servidor en una red de computadoras. FTP es parte de la suite de protocolos de Internet y fue uno de los primeros protocolos desarrollados para el uso en la naciente Internet. A continuación, se detallan sus características y funcionamiento:

## Características Clave de FTP
- Basado en Cliente-Servidor: En FTP, la transferencia de archivos se realiza entre un cliente FTP y un servidor FTP. El cliente inicia la conexión con el servidor para descargar o cargar archivos.
- Autenticación: FTP generalmente requiere que los usuarios se autentiquen con un nombre de usuario y contraseña, aunque también puede operar en modo anónimo, donde los usuarios pueden acceder con credenciales genéricas.
- Dos Canales de Comunicación: Utiliza dos conexiones separadas entre el cliente y el servidor: el canal de control (para comandos y respuestas) y el canal de datos (para la transferencia de archivos propiamente dicha).
- Modos de Transferencia: Soporta diferentes modos de transferencia, incluyendo binario (para archivos no textuales) y ASCII (para textos).
- Transferencia Activa y Pasiva: En la transferencia activa, el servidor inicia la conexión de datos, mientras que en la transferencia pasiva, es el cliente quien inicia esta conexión.

## Funcionamiento de FTP
- Establecimiento de Conexión:
    - Conexión de Control: El cliente establece una conexión con el servidor en el puerto 21 (por defecto para FTP). Esta conexión se mantiene abierta durante toda la sesión para enviar comandos y recibir respuestas.
    - Autenticación: El usuario se autentica con un nombre de usuario y contraseña. En el modo anónimo, se pueden utilizar credenciales genéricas.
- Transferencia de Archivos:
    - Establecimiento del Canal de Datos: Para transferir archivos, se establece una segunda conexión (canal de datos) entre el cliente y el servidor.
    - Modo Activo vs. Pasivo: En el modo activo, el servidor inicia la conexión de datos hacia el cliente. En el modo pasivo, el cliente inicia la conexión hacia el servidor. El modo pasivo es útil para clientes detrás de firewalls y NAT.
    - Transferencia de Archivos: Los archivos se transfieren a través del canal de datos en el modo especificado (binario o ASCII).
    - Cierre de la Conexión de Datos: Una vez completada la transferencia de archivos, la conexión de datos se cierra, pero la conexión de control permanece abierta para más comandos.
- Terminación de la Sesión: La conexión de control se cierra cuando el usuario envía un comando para terminar la sesión.
  
## Aplicaciones de FTP
- Transferencia de Archivos Grandes: Utilizado comúnmente para transferir archivos grandes, donde HTTP podría ser menos eficiente.
- Mantenimiento de Sitios Web: Para subir y descargar archivos de servidores web.
- Distribución de Software: Ampliamente utilizado para la distribución de archivos y actualizaciones de software.
- Backup y Archivo: Para transferir datos a sistemas de almacenamiento para su respaldo.

## Seguridad en FTP
- FTP Seguro (FTPS): Es una extensión de FTP que añade soporte para las capas de seguridad SSL y TLS.
- SSH File Transfer Protocol (SFTP): Una alternativa a FTP que utiliza SSH para encriptar la transferencia de archivos, proporcionando tanto seguridad como gestión de archivos.

Aunque FTP es un protocolo probado y ampliamente utilizado, su uso ha disminuido en favor de alternativas más seguras como SFTP y FTPS, especialmente en aplicaciones que requieren una transmisión segura de datos sensibles.
  
# 2. Secure Shell (SSH), Secure Copy (SCP), y Secure FTP (SFTP).
## SSH
Secure Shell (SSH) es un protocolo de red que proporciona una forma segura de acceder a una computadora sobre una red insegura. SSH se utiliza comúnmente para acceder a servidores remotos, ejecutar comandos en ellos, transferir archivos, y manejar otras tareas de red de manera segura. La seguridad es una parte integral de SSH, ya que cifra los datos para prevenir el espionaje, la captura de datos y otros ataques maliciosos.

### Características Clave de SSH
- Cifrado de Datos: SSH utiliza un cifrado fuerte para proteger la comunicación entre el cliente y el servidor. Esto asegura que los datos transmitidos no puedan ser leídos o modificados por terceros.
- Autenticación de Usuarios: SSH proporciona mecanismos para autenticar usuarios, generalmente mediante una combinación de nombre de usuario y contraseña, o a través de la autenticación basada en claves.
- Autenticación del Servidor: El cliente SSH verifica la identidad del servidor para prevenir ataques de tipo "man-in-the-middle". Esto se hace a través de claves de host que son únicas para cada servidor.
- Túneles Seguros: SSH puede crear túneles seguros para otras aplicaciones de red, lo que permite que estas se ejecuten de forma segura sobre una red no segura.
- Port Forwarding: SSH permite el reenvío de puertos, lo que significa que se pueden redirigir puertos de un host a otro a través de un túnel SSH seguro.

### Funcionamiento de SSH
- Establecimiento de la Conexión:
    - Negociación del Protocolo: Cuando se establece una conexión SSH, el cliente y el servidor negocian qué versión del protocolo SSH usar.
    - Intercambio de Claves: Se utiliza un intercambio de claves para establecer una sesión segura. Esto implica generar una clave de sesión temporal que se utiliza para cifrar la comunicación durante esa sesión.
    - Autenticación del Servidor: El cliente verifica la identidad del servidor utilizando claves de host.
    - Autenticación del Usuario: El usuario se autentica ante el servidor. Esto puede ser a través de una contraseña o mediante claves SSH, donde una clave privada en el cliente se empareja con una clave pública almacenada en el servidor.

- Uso de la Conexión:
    - Acceso a la Shell: Una vez autenticado, el usuario puede acceder a la línea de comandos (shell) del servidor remoto, permitiendo ejecutar comandos como si estuviera físicamente presente.
    - Transferencia de Archivos: Utilizando SFTP (SSH File Transfer Protocol) o SCP (Secure Copy), los usuarios pueden transferir archivos de forma segura entre el cliente y el servidor.
    - Túneles y Port Forwarding: SSH permite redirigir el tráfico de otros protocolos a través de su conexión cifrada, lo que es útil para asegurar la transferencia de datos de aplicaciones no seguras.

### Aplicaciones de SSH
- Administración Remota: SSH es una herramienta estándar para la administración segura de servidores y otros dispositivos de red.
- Transferencia Segura de Archivos: A través de SFTP y SCP, SSH se utiliza para la transferencia segura de archivos.
- Redirección de Puertos/Túneles SSH: Utilizado para asegurar conexiones de red para aplicaciones que no tienen sus propios mecanismos de cifrado.
- Automatización de Tareas: SSH se utiliza para ejecutar comandos y scripts automáticamente en servidores remotos.

### Seguridad
- Gestión de Claves: La gestión adecuada de claves públicas y privadas es crucial para la seguridad de una conexión SSH.
- Actualizaciones y Parches: Mantener el software SSH actualizado es importante para protegerse contra vulnerabilidades de seguridad conocidas.

SSH ha reemplazado a protocolos más antiguos como Telnet y rlogin, que no proporcionaban comunicaciones cifradas, haciéndolo esencial en el mundo de la administración de sistemas y la seguridad de la red.

## SCP
SCP (Secure Copy Protocol) es un protocolo utilizado para la transferencia segura de archivos entre un host local y un host remoto o entre dos hosts remotos. Está basado en el protocolo SSH (Secure Shell) y aprovecha sus mecanismos de seguridad y autenticación para garantizar la seguridad durante la transferencia de archivos. SCP es ampliamente utilizado en entornos de administración de sistemas y redes para copiar archivos de manera segura entre diferentes sistemas.

### Características Clave de SCP
- Seguridad: Utiliza SSH para la transferencia de datos, lo que asegura que toda la comunicación está cifrada y protegida de interceptaciones.
- Autenticación: La autenticación del usuario se realiza de la misma manera que en SSH, generalmente a través de nombre de usuario y contraseña o mediante claves SSH.
- Sintaxis Simple: SCP utiliza una sintaxis similar a la del comando cp (copy) de Unix/Linux, lo que facilita su uso para quienes están familiarizados con los sistemas tipo Unix.
- Preservación de Atributos: Puede preservar los atributos del archivo, como los permisos y tiempos de modificación, durante la transferencia.
- Funcionalidad Básica de Copia: SCP se utiliza principalmente para copiar archivos. No es tan completo como otros protocolos de transferencia de archivos en términos de funcionalidades, como la sincronización de directorios o la manipulación de archivos remotos.

### Funcionamiento de SCP
- Transferencia de Archivos:
    - Copiando de Local a Remoto: Los archivos se pueden copiar desde el sistema del usuario a un sistema remoto.
    - Copiando de Remoto a Local: Los archivos se pueden copiar desde un sistema remoto al sistema del usuario.
    - Copiando entre Sistemas Remotos: SCP también puede copiar archivos entre dos sistemas remotos.
- Comandos SCP:
    - La sintaxis básica del comando SCP es similar a la del comando cp, con la adición de la dirección del host remoto y la ruta del archivo. Por ejemplo:
      ```
      scp archivo.txt usuario@hostremoto:/ruta/destino
      scp usuario@hostremoto:/ruta/archivo.txt /ruta/destino
      ```

### Uso de SCP:
- SCP se utiliza en una variedad de contextos donde se necesita transferir archivos de forma segura, especialmente en tareas de administración de sistemas, donde se requiere mover archivos de configuración, scripts, o datos entre diferentes servidores.
- Es útil en scripts y automatizaciones que requieren la copia de archivos de forma segura entre sistemas en una red.

### Limitaciones:
- Interfaz de Línea de Comandos: SCP no tiene una interfaz gráfica, lo que puede ser una barrera para usuarios no técnicos.
- Funcionalidades Limitadas: A diferencia de otros protocolos más avanzados como SFTP, SCP tiene funcionalidades limitadas. Por ejemplo, no permite la manipulación de archivos o directorios remotos más allá de la simple copia.
- Rendimiento en Grandes Transferencias: En algunos casos, SCP puede ser menos eficiente que otros métodos, especialmente para la transferencia de un gran número de archivos pequeños debido a su sobrecarga de sesión SSH para cada archivo.

### Seguridad
Como SCP depende de SSH para la seguridad, su seguridad es tan robusta como la configuración de SSH del sistema. Esto incluye la gestión de claves, la configuración de ciphers, y las prácticas generales de seguridad en SSH.

En resumen, SCP es una herramienta poderosa y segura para la transferencia de archivos, especialmente valorada por su simplicidad y la seguridad que proporciona al estar basada en SSH. Sin embargo, para casos de uso que requieran funcionalidades más avanzadas, se pueden considerar alternativas como SFTP.


## SFTP

-----------------------------------------------------------------------------------------------
# ETHERNET
Ethernet es una tecnología de red para redes de área local (LAN). Es el estándar más comúnmente utilizado para conectar dispositivos en una red local, como computadoras, servidores y switches. Ethernet utiliza tanto protocolos de control de acceso al medio (MAC) como un formato de trama para manejar la transmisión de datos entre dispositivos en una red física.

Ethernet no es un protocolo como TCP (Transmission Control Protocol), sino que es una tecnología de red y un conjunto de estándares utilizados principalmente para redes de área local (LAN). Mientras que TCP es un protocolo de la capa de transporte que se encarga de la transferencia de datos entre sistemas finales a través de una red, Ethernet opera a un nivel más bajo, específicamente en las capas de enlace de datos y física del modelo OSI (Open Systems Interconnection).

## Diferencias Clave entre Ethernet y TCP
- Capas de Operación:
    - Ethernet: Opera en las capas de enlace de datos y física. Se encarga de la transmisión de datos a través de un medio físico (como cableado de cobre o fibra óptica), controla cómo se formatean los datos para la transmisión (tramas) y gestiona el acceso al medio de transmisión.
    - TCP: Opera en la capa de transporte. Se encarga de la entrega confiable y ordenada de un flujo de bytes entre aplicaciones que se ejecutan en hosts conectados a una red.

- Funciones y Responsabilidades:
    - Ethernet: Su principal responsabilidad es el transporte de tramas de datos entre dispositivos en una red local. Esto incluye el direccionamiento a nivel de hardware (direcciones MAC), la detección de errores en la transmisión y, en algunos casos, el control de acceso al medio.
    - TCP: Proporciona un servicio de transporte fiable y orientado a la conexión. Esto incluye el control de flujo, la corrección de errores, el aseguramiento de la entrega de datos en el orden correcto y la retransmisión de paquetes perdidos.

- Ámbito de Aplicación:
    - Ethernet: Es utilizado principalmente en redes de área local. Aunque Ethernet en sí no se extiende más allá de los límites de una LAN, puede ser parte de una red más grande que incluye Internet.
    - TCP: Se utiliza en todo tipo de redes, incluyendo Internet, para proporcionar comunicaciones fiables entre sistemas finales.

- Tipos de Datos Transportados:
    - Ethernet: Transporta tramas que contienen datos brutos, sin importar el tipo de esos datos. No es consciente de las aplicaciones que generan estos datos.
    - TCP: Transporta un flujo de bytes que puede ser cualquier tipo de datos generados por aplicaciones, como páginas web, correos electrónicos, o archivos.

En resumen, Ethernet y TCP son partes fundamentales de la infraestructura de red, pero operan en diferentes capas y tienen funciones distintas. Ethernet se encarga del transporte de datos a nivel local y físico, mientras que TCP se encarga de la entrega de datos a nivel de aplicación y a través de redes más amplias como Internet.


## ¿Que es Ethernet?
Ethernet es una familia de tecnologías de redes de computadoras para redes de área local (LAN) y redes de área metropolitana (MAN). Desarrollada originalmente en la década de 1970 por Xerox PARC y estandarizada por IEEE, Ethernet ha evolucionado significativamente a lo largo de los años y sigue siendo la tecnología de red alámbrica más ampliamente utilizada en la actualidad.


## Subcapas de Ethernet
- Data Link Layer. Tiene dos subcapas:
  1. Logical Link Control (LLC): La subcapa LLC (Control de Enlace Lógico) típicamente mueve los datos entre las aplicaciones de software en un sistema hacia los componentes físicos de hardware de una red, como la Tarjeta de Interfaz de Red (NIC) o los cables de medios. Cuando los bits son recibidos por LLC, ayuda con el proceso de reensamblaje y los pasa a las capas superiores de la suite de protocolos, como la pila TCP/IP.
     En este punto, podrías estar preguntándote dónde exactamente se encuentra LLC en una computadora, un switch, o incluso un router. La respuesta es bastante simple: se implementa en software dentro del firmware o del sistema operativo del dispositivo local. LLC es a menudo descrito y referido como el software del controlador del componente que interconecta la NIC del dispositivo con el sistema operativo.
     El software del controlador de la NIC es lo que interconecta el hardware físico con el sistema operativo para la comunicación en la red. El siguiente diagrama muestra ambas subcapas de la Capa de Enlace de Datos.
  
  2. Media Access Control (MAC): La subcapa MAC (Control de Acceso al Medio) define los procesos que permiten a los componentes de hardware, como la NIC, acceder a los medios (cable) en la red. MAC es responsable de manejar la encapsulación de datos y el control de acceso a los medios. La fase de encapsulación de datos agrega un encabezado de capa 2, que contiene las direcciones MAC de origen y destino, insertando un preámbulo que se utiliza para la sincronización de bits y ayuda a cualquier dispositivo receptor a identificar el inicio de un bit. Finalmente, se aplica un finalizador al final que se usa para el manejo de errores durante la transmisión de tráfico a través de la red. La segunda función de la subcapa MAC es manejar cómo los marcos acceden al medio físico, y cómo son retirados y pasan hacia arriba a la LLC para el resto del sistema anfitrión.
     
- Physical Layer.....




## Fields in an Ethernet frame
Un Ethernet frame es la unidad de datos principal utilizada en la red Ethernet. Consta de varios campos que cumplen con diferentes funciones para la transmisión eficiente y segura de datos. Estos son los campos típicos de un marco de Ethernet:
- Preamble (Preámbulo): Consiste en 7 bytes. Este campo es una secuencia de bits que permite a los dispositivos en la red sincronizar sus relojes de recepción y prepararse para la llegada de un marco. El preámbulo contiene una secuencia repetitiva de 10101010.
- Start of Frame Delimiter (SFD): Sigue al preámbulo y consta de 1 byte. Este campo marca el final del preámbulo y el inicio del encabezado del marco. El SFD tiene el patrón de bits 10101011, que señala que el siguiente byte comenzará el encabezado del marco.
- MAC Destination Address (Dirección MAC de Destino): Es un campo de 6 bytes que identifica la dirección MAC del destinatario del marco. Esta dirección puede ser unicast (un dispositivo específico), multicast (un grupo de dispositivos) o broadcast (todos los dispositivos en la red local).
- MAC Source Address (Dirección MAC de Origen): Similar al campo de dirección MAC de destino, este campo de 6 bytes identifica la dirección MAC del emisor del marco.
- EtherType / Length: Este campo de 2 bytes puede tener dos propósitos. Si el valor es menor a 1500, indica la longitud del campo de datos (payload) del marco. Si el valor es 1536 o mayor, indica el tipo de protocolo encapsulado en el campo de datos, como IP, ARP, etc.
- Data (Datos) / Payload: Este campo varía en tamaño (hasta 1500 bytes en Ethernet estándar). Contiene la información real transmitida, como un paquete IP o ARP.
- Padding: Si los datos no alcanzan el tamaño mínimo requerido para un marco Ethernet (46 bytes), se añaden bytes de relleno para alcanzar este tamaño mínimo.
- Frame Check Sequence (FCS): Este campo de 4 bytes es una suma de verificación utilizada para detectar errores en la transmisión. Se calcula mediante un algoritmo conocido como CRC (Cyclic Redundancy Check) y se añade al final del marco.

Estos campos garantizan que los datos puedan ser transportados de manera eficiente y segura a través de una red Ethernet. La estructura del marco permite a los dispositivos de la red identificar y procesar correctamente la información, desde determinar el destinatario hasta verificar la integridad de los datos recibidos.


# Formato de un paquete IPv4
![Formato de un paquete IPv4](https://irasema.neocities.org/Fundamentos_Redes/ImagenP.png)
El formato de un paquete IPv4 (Protocolo de Internet versión 4) es una estructura específica que define cómo se organizan los datos en un paquete para su transmisión a través de redes que utilizan el protocolo IPv4. Un paquete IPv4 consta de un encabezado seguido por los datos reales (payload). El encabezado del paquete IPv4 tiene varios campos que especifican información crucial para el enrutamiento y la entrega del paquete. Aquí hay una descripción detallada de estos campos:

## Encabezado del Paquete IPv4
- Version (4 bits): Indica la versión del protocolo IP. Para IPv4, este campo tiene el valor de 4.
- Internet Header Length (IHL) (4 bits): Especifica la longitud del encabezado en palabras de 32 bits. El tamaño mínimo del encabezado es de 5 palabras (20 bytes) y el máximo es de 15 palabras (60 bytes).
- Type of Service (TOS) (8 bits): Este campo, ahora redefinido como DSCP (Differentiated Services Code Point) y ECN (Explicit Congestion Notification), se usa para determinar la prioridad del paquete y cómo debe ser manejado.
- Total Length (16 bits): Indica el tamaño total del paquete en bytes, incluyendo el encabezado y los datos. El tamaño máximo es de 65,535 bytes.
- Identification (16 bits): Es un identificador único asignado al paquete cuando se fragmenta un datagrama original. Ayuda en la reensamblación de los fragmentos.
- Flags (3 bits): Controlan y proporcionan información sobre la fragmentación. Incluyen el bit de "No Fragmentar" y el bit "Más Fragmentos".
- Fragment Offset (13 bits): Indica la posición del fragmento en el datagrama original. Se utiliza durante el proceso de reensamblaje de fragmentos.
- Time To Live (TTL) (8 bits): Es un contador que limita la vida útil del paquete. Se reduce en uno por cada router que pasa; si llega a cero, el paquete se descarta. Esto previene que los paquetes circulen indefinidamente.
- Protocol (8 bits): Indica el protocolo de la capa superior (como TCP o UDP) para el que se transportan los datos.
- Header Checksum (16 bits): Es una suma de verificación utilizada para verificar errores en el encabezado. Se recalcula en cada punto donde el paquete es procesado.
- Source IP Address (32 bits): La dirección IPv4 del emisor del paquete.
- Destination IP Address (32 bits): La dirección IPv4 del destinatario del paquete.
- Options (variable): Campo opcional que se utiliza para soportar características adicionales como seguridad, registro de ruta y medición de tiempo. No es comúnmente utilizado.
- Padding (variable): Asegura que el encabezado tenga una longitud múltiple de 32 bits. Este campo se llena con ceros si es necesario.

## Datos (Payload)
Después del encabezado, sigue la parte de datos del paquete. Este payload contiene la información (datos de la aplicación) que se está transmitiendo.

## Importancia del Formato de Paquete IPv4
El formato del paquete IPv4 es crucial para el funcionamiento de las redes basadas en IP. A través de sus diversos campos, se maneja la identificación, el enrutamiento, la fragmentación, el ensamblaje y la calidad de servicio de los datos transmitidos a través de Internet y otras redes basadas en IP. Este formato estructurado y detallado permite que los dispositivos en la red procesen y dirijan eficientemente los datos hacia sus destinos finales.


If you're interested in learning about packet analysis and network forensics, The Honeynet Project (www.honeynet.org) is a good place to
start. Their challenges will broaden your analytical skills as a network professional:
https://www.honeynet.org/


# Formato de un paquete IPv6
![Formato de un paquete IPv4](https://docs.oracle.com/cd/E19957-01/820-2981/images/HeaderFormat.gif)




------------------------------------------------------------------------------------------------
## Flags de TCP
TCP (Protocolo de Control de Transmisión) utiliza varios flags en su cabecera para controlar el flujo de datos y la gestión de la conexión. Estos flags son parte de un campo de 9 bits en la cabecera de TCP y cada uno tiene un propósito específico:
- URG (Urgent): Indica que el campo "Puntero Urgente" es significativo. Se utiliza para señalar que hay datos importantes que deben ser procesados de manera urgente.
- ACK (Acknowledgment): Significa que el campo de "Número de Acuse de Recibo" es válido y confirma la recepción exitosa de los datos.
- PSH (Push): Le indica al receptor que debe pasar los datos recibidos a la aplicación inmediatamente, sin esperar a llenar su buffer.
- RST (Reset): Se utiliza para reiniciar la conexión. Es enviado si hay un error grave y la conexión no puede continuar de manera normal.
- SYN (Synchronize): Se usa durante el establecimiento de una conexión para sincronizar los números de secuencia entre los dispositivos que se conectan. Un paquete con el flag SYN activado es típicamente el primer paso en el establecimiento de una conexión TCP (three-way handshake).
- FIN (Finish): Se utiliza para finalizar la conexión de manera ordenada. Indica que el emisor ha terminado de enviar datos.

Estos flags permiten que TCP maneje de manera efectiva el control de flujo, la gestión de errores, el inicio y la finalización de sesiones, y otras funcionalidades cruciales para una comunicación fiable y ordenada. Además, un segmento TCP puede tener múltiples flags activados según sea necesario para diversas operaciones y estados de la conexión.


En TCP, los flags están organizados en un campo de 9 bits en la cabecera del segmento TCP. Desde la derecha, los flags son:
NS (1 bit), CWR (1 bit), ECE (1 bit), URG (1 bit), ACK (1 bit), PSH (1 bit), RST (1 bit), SYN (1 bit) y FIN (1 bit).

```
Transmission Control Protocol, Src Port: 1928, Dst Port: 80, Seq: 0, Len: 0
    Source Port: 1928
    Destination Port: 80
    [Stream index: 9]
    [Conversation completeness: Incomplete (35)]
    [TCP Segment Len: 0]
    Sequence Number: 0    (relative sequence number)
    Sequence Number (raw): 219337238
    [Next Sequence Number: 1    (relative sequence number)]
    Acknowledgment Number: 803762974
    Acknowledgment number (raw): 803762974
    0101 .... = Header Length: 20 bytes (5)
    Flags: 0x002 (SYN)
        000. .... .... = Reserved: Not set
        ...0 .... .... = Accurate ECN: Not set
        .... 0... .... = Congestion Window Reduced: Not set
        .... .0.. .... = ECN-Echo: Not set
        .... ..0. .... = Urgent: Not set
        .... ...0 .... = Acknowledgment: Not set
        .... .... 0... = Push: Not set
        .... .... .0.. = Reset: Not set
        .... .... ..1. = Syn: Set
        .... .... ...0 = Fin: Not set
        [TCP Flags: ··········S·]
    Window: 512
    [Calculated window size: 512]
    Checksum: 0x0fc4 [unverified]
    [Checksum Status: Unverified]
    Urgent Pointer: 0
    [Timestamps]
```


## El filtro de Wireshark tcp.flags==0x003
- Se utiliza para seleccionar paquetes TCP que tienen específicamente activados los flags SYN y ACK.
- El Número hexadecimal 0x003 ==  se convierte en binario como 000000011.
- Implica:
    - El penúltimo bit representa el flag SYN está activado.
    - El último bit que representa el flag ACK está activado.


## SYN
SYN es un término clave en el protocolo de control de transmisión (TCP), uno de los protocolos fundamentales de Internet. Específicamente, SYN se refiere a un "synchronize sequence number" (número de secuencia de sincronización) y se utiliza durante el proceso de establecimiento de una conexión TCP, conocido como el "three-way handshake" (apretón de manos de tres vías).

## Funcionamiento del three-way handshake usando SYN y SYN-ACK:
- SYN: El cliente envía un segmento TCP con el bit SYN activado al servidor para iniciar una nueva conexión. Junto con el SYN, el cliente envía un número de secuencia inicial (ISN) que se utiliza para el control de orden y pérdida de paquetes.

- SYN-ACK: Al recibir el SYN, el servidor responde con un segmento que tiene tanto el bit SYN como el bit ACK activados. Esto confirma la recepción del SYN del cliente y también incluye el propio número de secuencia inicial del servidor.

- ACK: Finalmente, el cliente responde al servidor con un segmento ACK, confirmando la recepción del SYN del servidor.

Este proceso establece una conexión bidireccional fiable, donde tanto el cliente como el servidor acuerdan sus números de secuencia iniciales, lo cual es crucial para la gestión de la transmisión de datos en TCP. Una vez completado este proceso, los datos pueden comenzar a fluir entre el cliente y el servidor en una sesión TCP segura y confiable.


## Qué es SYN y ACK
En el mundo de las redes informáticas, se utilizan diferentes protocolos para asegurar la correcta transmisión de los datos. Uno de los protocolos más importantes es el Protocolo de Control de Transmisión (TCP). TCP es un protocolo orientado a conexión, lo que significa que antes de que se puedan transferir datos, es necesario establecer una conexión entre los dispositivos.

Para establecer una conexión TCP, se utiliza un método llamado «handshaking». El handshaking implica una serie de intercambios de mensajes entre los dispositivos, en los que se establecen ciertos parámetros de la conexión. Uno de los mensajes más importantes en este proceso son los mensajes SYN y ACK.

SYN es la abreviatura de «synchronize», que significa «sincronizar». Cuando un dispositivo desea establecer una conexión TCP con otro dispositivo, envía un mensaje SYN al dispositivo de destino. Este mensaje contiene un número de secuencia inicial (ISN) que se utiliza para identificar la conexión. El dispositivo de destino responde con un mensaje ACK, que significa «acknowledge», que significa «reconocimiento». El mensaje ACK también contiene el número de secuencia inicial (ISN) que se recibió del mensaje SYN. Al enviar el mensaje ACK, el dispositivo de destino confirma que ha recibido el mensaje SYN y que está listo para establecer la conexión.

El número de secuencia inicial (ISN) es un número aleatorio que se utiliza para evitar que los paquetes de datos se mezclen con los paquetes de datos de otra conexión. El ISN se elige al azar y se incluye en el mensaje SYN. Una vez que el dispositivo de destino recibe el mensaje SYN, utiliza el ISN para generar su propio número de secuencia, que se utiliza para identificar los paquetes de datos en la conexión.



## Numero de secuencia inicial (ISN)
- El número de secuencia TCP es un valor de 32 bits que se utiliza en el protocolo de control de transmisión (TCP) para identificar cada byte de datos que se transmite entre dos dispositivos. Este valor se utiliza para asegurar que los datos se transmitan y reciban correctamente y en el orden adecuado.
- El número de secuencia inicial (ISN) es la primera secuencia que se utiliza al iniciar una conexión TCP. Es un número aleatorio que se genera en el dispositivo emisor y se envía al receptor para establecer la conexión. El ISN se utiliza para iniciar la secuencia de números de secuencia que se utilizan durante la transmisión de datos.

- ¿Por qué es importante el número de secuencia TCP?. El número de secuencia TCP es importante porque permite a los dispositivos asegurar que los datos se transmitan y reciban correctamente. Cada byte de datos se identifica con su propio número de secuencia, lo que permite al receptor reconstruir los datos en el orden correcto.

- ¿Cómo se utiliza el número de secuencia TCP?. Cuando se envía un paquete de datos TCP, se incluye un número de secuencia que identifica el primer byte de datos en el paquete. El receptor utiliza este número de secuencia para reconstruir los datos en el orden correcto. El receptor también envía un número de acuse de recibo (ACK) que indica al emisor que se ha recibido correctamente el paquete. El emisor utiliza el número de ACK para confirmar que el paquete se ha recibido correctamente y enviar el siguiente paquete.


## Qué es un three way handshake
El three way handshake es un término que se utiliza en informática para referirse al proceso de establecimiento de una conexión entre dos dispositivos que se comunican a través de una red. Este proceso se lleva a cabo mediante el intercambio de paquetes entre el dispositivo emisor y el receptor, y se compone de tres fases o etapas.

Las tres fases del three way handshake
La primera fase del proceso consiste en que el dispositivo emisor envía un paquete al receptor, conocido como SYN (sincronización), indicando que desea establecer una conexión. Este paquete incluye un número de secuencia inicial (ISN), que se utiliza para identificar la conexión y asegurar que los paquetes se envían y reciben en el orden correcto.

En la segunda fase del proceso, el receptor responde al emisor con un paquete SYN-ACK. Este paquete indica que el receptor ha recibido el paquete SYN y está dispuesto a establecer la conexión. Además, incluye un número de secuencia inicial (ISN) propio, que se utilizará para identificar la conexión.

Finalmente, en la tercera fase del proceso, el dispositivo emisor responde al receptor con un paquete ACK, indicando que ha recibido el paquete SYN-ACK y que está listo para comenzar a enviar y recibir datos a través de la conexión establecida. Este paquete también incluye el número de secuencia inicial (ISN) del receptor, que se utilizará para asegurar que los paquetes se envían y reciben en el orden correcto.



## El ataque TCP SYN Flood
Es un tipo de ataque de denegación de servicio (DoS) que explota una característica del Protocolo de Control de Transmisión (TCP), específicamente el proceso de establecimiento de la conexión conocido como "three-way handshake".

En un ataque TCP SYN Flood, un atacante envía rápidamente una gran cantidad de solicitudes de conexión TCP con el bit SYN activado hacia un servidor objetivo, pero nunca completa el proceso de "three-way handshake". Esto se logra típicamente no respondiendo al mensaje SYN-ACK del servidor o enviando los paquetes SYN con una dirección IP de origen falsificada.

Funcionamiento del ataque:
- Envío Masivo de Paquetes SYN: El atacante inicia el ataque enviando una gran cantidad de paquetes TCP con el flag SYN a la máquina objetivo.
- Respuestas del Servidor: El servidor, al recibir cada solicitud SYN, responde con un paquete SYN-ACK, esperando un paquete ACK final para completar la conexión.
- No Finalización del Three-Way Handshake: En un escenario normal, el cliente respondería con un paquete ACK, completando el proceso de three-way handshake. Sin embargo, en un ataque SYN Flood, el atacante nunca envía el ACK. Puede ser porque los paquetes SYN originales tenían una dirección IP de origen falsificada o simplemente porque el atacante elige no enviar los ACKs.
- Consumo de Recursos del Servidor: Cada conexión incompleta consume recursos en el servidor, normalmente en forma de entradas en una tabla de conexiones semi-abiertas. Dado que el servidor espera por un tiempo para la respuesta ACK antes de cerrar una conexión, el ataque puede consumir rápidamente los recursos disponibles, impidiendo que el servidor maneje conexiones legítimas.
- Denegación de Servicio: Como resultado, el servidor puede volverse incapaz de procesar solicitudes legítimas, efectivamente negando el servicio a usuarios legítimos.

Los ataques TCP SYN Flood fueron especialmente efectivos y populares en las décadas de 1990 y principios de 2000, pero desde entonces, las defensas contra ellos han mejorado significativamente. Las técnicas para mitigar estos ataques incluyen el aumento de la capacidad de la tabla de conexiones, el uso de "SYN cookies" para manejar conexiones semi-abiertas de manera más eficiente, y el empleo de sistemas de detección y prevención de intrusiones.


- Conversación en un ataque TCP SYN Flood
   no.  Time        Source      Destination  Proto.  Length   Info
  - 3	  0.000457    10.0.0.8    10.0.0.16    TCP      54      1919 → 80 [SYN] Seq=0 Win=512 Len=0
  - 19  0.000644    10.0.0.16   10.0.0.8     TCP      58      80 → 1919 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0 MSS=1460
  - 141 0.001778    10.0.0.8    10.0.0.16    TCP      54      1919 → 80 [RST] Seq=1 Win=0 Len=0


## El flag RST (Reset) en TCP
Este flag es utilizado para indicar que una conexión debe ser inmediatamente reseteada o reiniciada. Este flag es una parte integral de la cabecera de un segmento TCP y tiene usos específicos y significativos en la gestión de conexiones TCP.

Aquí están los detalles clave sobre el flag RST en TCP:
- Indicador de Reinicio: Cuando el flag RST está activado en un segmento TCP, señala que la conexión actual debe ser terminada y reseteada. Esto puede ser utilizado en varias situaciones, como por ejemplo:
  - Si un paquete se recibe inesperadamente en un puerto donde no hay proceso escuchando, el host receptor enviará un segmento con el flag RST para informar al emisor que la conexión no es válida.
  - Si hay un error o problema en la conexión, como un número de secuencia inesperado que no se puede reconciliar, se puede enviar un segmento RST para reiniciar la conexión.
- Terminación Anormal de la Conexión: A diferencia del proceso normal de terminación de una conexión TCP, que implica un "four-way handshake" usando flags FIN y ACK, el uso de RST es una forma más abrupta de cerrar la conexión. Esto puede ser necesario en situaciones de error o cuando una conexión no es válida o no deseada.
- Prevención de Ataques de Seguridad: El flag RST también puede ser utilizado en la seguridad de la red para cerrar conexiones que son sospechosas o parte de un ataque de red. Por ejemplo, firewalls y sistemas de detección de intrusos pueden enviar segmentos RST para interrumpir comunicaciones maliciosas.
- Reinicio Rápido: El reinicio de una conexión mediante el flag RST es más rápido que el cierre ordenado, ya que no requiere el intercambio de múltiples mensajes para cerrar la conexión de forma limpia. Sin embargo, el uso de RST puede resultar en la pérdida de datos no confirmados.

En resumen, el flag RST es una herramienta crucial en TCP para manejar situaciones de error, cerrar conexiones de manera no estándar y rápida, y para la seguridad de la red. Su uso es esencial para mantener la robustez y la integridad de las comunicaciones en la red.


## Analyze Traffic for SYN-FIN Flood DoS Attack
Se realiza una búsqueda en wireshar con el filtro:
```
tcp.flags==0x003
```
Se busca los paquetes que tengan activados los flags SYN y FIN.


## Protocolo ARP (adress Resolution Protocol)
El Protocolo de Resolución de Direcciones (ARP, por sus siglas en inglés) es un protocolo fundamental utilizado en redes IP para encontrar la dirección MAC (Control de Acceso al Medio) que corresponde a una dirección IP específica. ARP opera en la capa de enlace de datos del modelo OSI y es esencial para la comunicación en redes que utilizan el Protocolo de Internet (IP).

Funcionamiento del protocolo ARP:
- Propósito Básico: ARP se utiliza para mapear una dirección IP (usada en la capa de red) a una dirección MAC (usada en la capa de enlace de datos). Esta resolución es necesaria porque aunque los paquetes IP se envían en base a direcciones IP, en una red local, la comunicación entre dispositivos se realiza a través de direcciones MAC.
- Funcionamiento de ARP:
    - Solicitud ARP: Cuando un dispositivo necesita comunicarse con otro dispositivo en la misma red local y conoce la dirección IP pero no la dirección MAC, envía una solicitud ARP. Esta solicitud se envía a todas las máquinas en la red local (broadcast), preguntando "¿Quién tiene la dirección IP X? Envíame tu dirección MAC".
    - Respuesta ARP: El dispositivo en la red que tiene la dirección IP solicitada responde con un mensaje ARP que contiene su dirección MAC.
- Tabla ARP: Los dispositivos mantienen una tabla ARP, que es una lista de mapeos de direcciones IP a direcciones MAC. Cuando un dispositivo recibe una respuesta ARP, actualiza su tabla ARP con esta nueva información, reduciendo la necesidad de enviar futuras solicitudes ARP para el mismo host.
- Comunicación en Redes Locales y Externas:
    - En una red local, si un dispositivo necesita comunicarse con otro en la misma red, utiliza ARP para encontrar la dirección MAC correspondiente a la dirección IP del destino.
    - Para comunicarse con dispositivos fuera de la red local (en Internet, por ejemplo), un dispositivo utiliza ARP para obtener la dirección MAC del router o gateway predeterminado.
- Seguridad en ARP: Aunque ARP es crucial para la comunicación en redes IP, también puede ser un vector de ataque. Los ataques de "ARP spoofing" o "ARP poisoning" pueden llevarse a cabo cuando un atacante envía mensajes ARP falsos a la red, lo que puede llevar a redireccionar el tráfico o interceptar datos.

En resumen, ARP es un componente esencial en la comunicación de redes IP, permitiendo que los dispositivos en una red local se comuniquen entre sí o con el gateway para acceder a redes externas, traduciendo direcciones IP a direcciones MAC.

## Protocolo NBNS:
El Protocolo de Servicio de Nombres NetBIOS (NBNS) es un protocolo utilizado para la resolución de nombres en redes que utilizan el sistema NetBIOS. NetBIOS (Network Basic Input/Output System) es una API que permite la comunicación entre aplicaciones en diferentes computadoras dentro de una red local (LAN). NBNS desempeña un papel similar al DNS (Sistema de Nombres de Dominio) pero en un contexto de red local y específicamente para nombres NetBIOS.


## Protocolo LLMNR
El protocolo LLMNR (Link-Local Multicast Name Resolution) es un protocolo de resolución de nombres diseñado como un sucesor de NBNS (NetBIOS Name Service) en redes donde no está disponible un servidor DNS. LLMNR permite a los hosts en una red local identificar y comunicarse entre sí por nombre, en lugar de por dirección IP, sin necesidad de un servidor DNS centralizado.


## Mac Flooding Attack
Un intento de "mac flooding" (inundación de direcciones MAC) es un tipo de ataque de seguridad de red dirigido a switches de red. El objetivo de este ataque es sobrecargar la tabla de direcciones MAC del switch, que es una tabla que el switch utiliza para saber a qué puerto enviar los paquetes de datos en función de las direcciones MAC de destino. Los detalles de este ataque son los siguientes:

- Funcionamiento de los Switches: Un switch de red mantiene una tabla de direcciones MAC para asociar cada dirección MAC con el puerto correspondiente del switch. Cuando un paquete llega a un puerto del switch, el switch consulta esta tabla para decidir a qué puerto reenviar el paquete.
- Objetivo del Ataque: En un ataque de inundación de MAC, el atacante envía una gran cantidad de paquetes con diferentes direcciones MAC falsas. Esto se hace para llenar la tabla de direcciones MAC del switch, que tiene una capacidad limitada.
- Efecto del Ataque: Cuando la tabla de direcciones MAC está llena, el switch no puede añadir nuevas entradas. En este punto, el switch puede empezar a comportarse como un hub, reenviando paquetes a todos los puertos en lugar de solo al puerto que corresponde a la dirección MAC de destino. Esto se conoce como un estado de "fall-back" o "modo de inundación".
- Consecuencias de la Seguridad: El efecto de convertir el switch en un hub es que los paquetes que estaban destinados a una sola máquina pueden ser vistos por todas las máquinas conectadas al switch. Esto permite al atacante espiar el tráfico de la red y potencialmente capturar datos sensibles, como contraseñas y otra información confidencial.
- Prevención y Mitigación: Para prevenir y mitigar los ataques de inundación de MAC, los switches modernos suelen incluir características de seguridad como limitar el número de direcciones MAC que pueden aprenderse en un puerto específico y la capacidad de deshabilitar automáticamente un puerto que parece estar participando en un ataque de inundación de MAC.

En resumen, el mac flooding es un ataque que busca comprometer la seguridad de una red aprovechando las limitaciones en la gestión de la tabla de direcciones MAC de los switches. Su objetivo es permitir que un atacante capture tráfico no destinado a su propio host, violando así la privacidad y la seguridad de la red.


## ARP Poisoning Attempt
Un intento de envenenamiento ARP (ARP Poisoning Attempt) es un tipo de ataque de red que se dirige al protocolo ARP (Protocolo de Resolución de Direcciones). ARP es utilizado en redes IPv4 para mapear direcciones IP a direcciones MAC, que son únicas para cada dispositivo en una red local. El envenenamiento ARP es una técnica utilizada por los atacantes para interceptar o modificar el tráfico en una red LAN.

Aquí está cómo funciona un ataque de envenenamiento ARP:

Manipulación de Tablas ARP: En un escenario normal, cuando un dispositivo (A) necesita comunicarse con otro dispositivo (B), pregunta quién tiene la dirección IP de B y espera una respuesta con la dirección MAC de B. El atacante, sin embargo, responde a la solicitud de A con su propia dirección MAC, incluso si no es el dispositivo B.

Intercepción de Tráfico: Como resultado, el dispositivo A actualizará su tabla ARP con información incorrecta, pensando que la dirección MAC del atacante es en realidad la de B. Esto hace que A envíe el tráfico destinado a B al atacante en su lugar.

Ataques de "Hombre en el Medio" (MitM): Una vez que el atacante recibe el tráfico, puede elegir interceptarlo, modificarlo o simplemente espiarlo antes de reenviarlo a B (si elige hacerlo). Esto se conoce como un ataque de hombre en el medio (MitM).

Doble Envenenamiento ARP: En un ataque más sofisticado, el atacante puede también enviar respuestas ARP falsificadas a B, haciéndole creer que el atacante es A. De esta manera, el atacante se coloca entre A y B, interceptando o manipulando el tráfico en ambas direcciones.

El envenenamiento ARP es peligroso porque puede permitir a un atacante capturar datos sensibles, como contraseñas y otros datos personales, o manipular el tráfico de la red para redirigir a los usuarios a sitios maliciosos. Este tipo de ataque es particularmente efectivo en redes LAN donde ARP se usa sin medidas de seguridad adicionales para autenticar las respuestas ARP.


Filtro de wireshark para ver este ataque: arp.duplicate-address-detected

## Filtros útiles
- Buscar credenciales de inicio de sesión capturadas en una solicitud HTTP POST: http.request.method=="POST"
- Mostrar errores de autenticación en ftp: ftp.response.code == 530
- Mostrar inicios de sesión exitosos en ftp: ftp.response.code == 230
- Mostar inicios de sesión fallidos en SMB: smb2.cmd == 0x01 && smb2.nt_status != 0x00000000




## ARP spoofing - ARP cache poisoning
Is used in a man-in-the-middle attack. In order to understand why this is an effective attack, let's step through the normal use of ARP on a LAN. On a LAN, hosts are identified by their MAC or physical addresses. In order to
communicate with the correct host, each device keeps track of all LAN hosts' MAC addresses in an ARP or MAC address table, also known as an ARP cache table.

Entries in the ARP or MAC address table will time out after a while. Under normal circumstances, when the device needs to communicate with another device on the network, it needs the MAC address. The device will first check the ARP cache and, if there is no entry in the table, the device will send an ARP request broadcast out to all hosts on the network. The ARP request asks the question, who has (the requested) IP address? Tell me (the requesting) IP address. The device will then wait for an ARP reply.

The ARP reply is a response that holds information on the host's IP address and the requested MAC address. Once received, the ARP cache is updated to reflect the MAC address.
In an ARP spoofing attack, an attacker will do the following:
- Send an unsolicited, spoofed ARP reply message that contains a spoofed MAC address for the attacker's machine to all hosts on the LAN.
- After the ARP reply is received, all devices on the LAN will update their ARP or MAC address tables with the incorrect MAC address. This effectively poisons the cache on the end devices.
- Once the ARP tables are poisoned, this will allow an intruder to impersonate another host to gain access to sensitive information.

Once the attacker begins to receive the traffic destined to another host, they will use active sniffing to gather the misdirected traffic in an attempt to gain sensitive information. 


# Combatiendo el Tunneling y la Encriptación
Los datos a veces se cifran utilizando TLS, SSL, mecanismos de cifrado personalizados o WEP/WPA2 en el espacio inalámbrico. Vamos a ver los siguientes temas:
- Descifrar TLS utilizando navegadores
- Decodificar un túnel DNS malicioso
- Descifrar paquetes 802.11
- Decodificar capturas de teclado


## Decrypting TLS using browsers
Una de las características ocultas del popular navegador Chrome es el soporte para registrar la clave de sesión simétrica utilizada durante el cifrado del tráfico con TLS en un archivo de nuestra elección. Veamos qué sucede cuando intentamos capturar un paquete cifrado con TLS:
.........
Hands on Network Forensics. Pag 140




## Notas
https://www.calculator.net/ip-subnet-calculator.html?

- We can redirect them into a pcap file providing a destination file via the -w argument:
tcpdump -A -i eth1 -w /tmp/tcpdump.pcap



- Ficheros del libro Hands On Network Forensic: https://github.com/nipunjaswal/networkforensics/tree/master
- 

