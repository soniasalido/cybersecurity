## Formas de capturar tráfico:
- Network Taps: Los Network Taps (puntos de acceso de red) son dispositivos de hardware que se utilizan para acceder y monitorear el tráfico de datos en una red de comunicaciones. El término "Tap" se refiere a "Test Access Point" (Punto de Acceso de Prueba). Estos dispositivos se colocan entre dos puntos de una red, como entre un switch y un router, para capturar una copia exacta del tráfico que pasa entre estos puntos sin interferir con la transmisión de datos.
- MAC Floods: Las inundaciones de MAC son una táctica comúnmente utilizada por equipos rojos como una forma de capturar paquetes activamente. La inundación de MAC tiene como objetivo sobrecargar el switch y llenar la tabla CAM. Una vez que la tabla CAM está llena, el switch ya no aceptará nuevas direcciones MAC y, por lo tanto, para mantener la red activa, el switch enviará paquetes a todos los puertos del switch. Nota: Esta técnica debe usarse con extrema precaución y con consentimiento explícito previo.
- ARP Poisoning: El envenenamiento ARP es otra técnica utilizada por equipos rojos para capturar paquetes activamente. Mediante el envenenamiento ARP, puedes redirigir el tráfico desde el(los) host(s) hacia la máquina desde la que estás monitoreando. Esta técnica no sobrecargará el equipo de red como lo hace la inundación MAC; sin embargo, aún debe usarse con precaución y solo si otras técnicas como los Network Taps no están disponibles.


## Filtrado de paquetes:
- Filtros de visualización: Podemos aplicar filtros de visualización de dos maneras:
  - A través de la pestaña analizar.
  - En la barra de filtro en la parte superior de la captura de paquetes.
- Operadores de Filtrado:
  - and - operator: and / &&
  - or - operator: or / ||
  - equals - operator: eq / ==
  - not equal - operator: ne / !=
  - greater than - operator: gt /  >
  - less than - operator: lt / <
  - contains
  - matches
  - bitwise_and
  - operators
- Documentación: Filtros Wiresharl: https://wiki.wireshark.org/DisplayFilters

## Packet Dissection
Esta sección cubre cómo Wireshark utiliza las capas OSI para desglosar los paquetes y cómo usar estas capas para el análisis. 

![](https://assets.tryhackme.com/additional/wireshark101/12.png)


### Packet Details
Puedes hacer doble clic en un paquete en la captura para abrir sus detalles. Los paquetes consisten de 5 a 7 capas basadas en el modelo OSI. Podemos ver las 7 capas distintas en el paquete: marco/paquete (Frame), fuente (source) [MAC], fuente (Source) [IP], protocolo (Protocol), errores de protocolo (Protocol Errors), protocolo de aplicación (Application Protocol) y datos de aplicación (Application Data):

![](https://assets.tryhackme.com/additional/wireshark101/13.png)

- Frame (Layer 1) --> Esto te mostrará qué marco/paquete estás observando, así como detalles específicos de la Capa Física del modelo OSI.

  ![](https://assets.tryhackme.com/additional/wireshark101/14.png)

- Source [MAC] (Layer 2) --> Esto te mostrará las direcciones MAC de origen y destino; de la Capa de Enlace de Datos del modelo OSI.

  ![](https://assets.tryhackme.com/additional/wireshark101/15.png)

- Source [IP] (Layer 3) --> Esto te mostrará las direcciones IPv4 de origen y destino; de la Capa de Red del modelo OSI.

  ![](https://assets.tryhackme.com/additional/wireshark101/16.png)

- Protocol (Layer 4) --> Esto te mostrará detalles del protocolo utilizado (UDP/TCP) junto con los puertos de origen y destino; de la Capa de Transporte del modelo OSI.

  ![](https://assets.tryhackme.com/additional/wireshark101/17.png)

- Protocol Errors --> Esta es una continuación de la 4ª capa que muestra segmentos específicos de TCP que necesitaban ser reensamblados.

  ![](https://assets.tryhackme.com/additional/wireshark101/18.png)

- Application Protocol (Layer 5) --> Esto mostrará detalles específicos del protocolo que se está utilizando, como HTTP, FTP, SMB, etc. De la Capa de Aplicación del modelo OSI.

  ![](https://assets.tryhackme.com/additional/wireshark101/19.png)

- Application Data --> Esta es una extensión de la capa 5 que puede mostrar los datos específicos de la aplicación.

  ![](https://assets.tryhackme.com/additional/wireshark101/20.png)


## ARP Traffic
ARP o Protocolo de Resolución de Direcciones es un protocolo de Capa 2 que se utiliza para conectar direcciones IP con direcciones MAC. Contendrán mensajes de SOLICITUD y mensajes de RESPUESTA. Para identificar paquetes, el encabezado del mensaje contendrá uno de dos códigos de operación:
- Request
- Reply

Multiple ARP requests and replies:

![](https://assets.tryhackme.com/additional/wireshark101/21.png)

Es útil notar que la mayoría de los dispositivos se identificarán a sí mismos o Wireshark los identificará, como por ejemplo Intel_78; un ejemplo de tráfico sospechoso serían muchas solicitudes de una fuente no reconocida. Sin embargo, necesitas habilitar una configuración dentro de Wireshark para resolver direcciones físicas. Para habilitar esta característica, navega a Ver > Resolución de Nombres > Asegúrate de que la opción Resolver Direcciones Físicas esté marcada.

Mirando la captura de pantalla a continuación, podemos ver que un dispositivo Cisco está enviando Solicitudes ARP, lo que significa que deberíamos poder confiar en este dispositivo, sin embargo, siempre debes mantener precaución al analizar paquetes.

![](https://assets.tryhackme.com/additional/wireshark101/22.png)

## Visión General del Tráfico ARP

- Paquetes de Solicitud ARP: Podemos comenzar a analizar paquetes observando el primer paquete de Solicitud ARP y examinando los detalles del paquete:

  ![](https://assets.tryhackme.com/additional/wireshark101/23.png)

- Observando los detalles del paquete mencionados anteriormente, los detalles más importantes del paquete están resaltados en rojo. El Opcode es una abreviatura de código de operación y te indicará si es una Solicitud ARP o una Respuesta. El segundo detalle resaltado es hacia dónde está dirigido el paquete, que en este caso, es una solicitud de difusión a todos. Paquetes de Respuesta ARP:

  ![](https://assets.tryhackme.com/additional/wireshark101/24.png)

  Observando los detalles del paquete anterior, podemos ver por el Opcode que es un paquete de Respuesta ARP. También podemos obtener otra información útil como la dirección MAC y la dirección IP que se enviaron junto con la respuesta, ya que este es un paquete de respuesta, sabemos que esta fue la información enviada junto con el mensaje.

  ARP es uno de los protocolos más simples de analizar, todo lo que necesitas recordar es identificar si es un paquete de solicitud o de respuesta y quién lo está enviando.


## Opcode
En el contexto de los protocolos de red, como el Protocolo de Resolución de Direcciones (ARP), el opcode es un campo dentro del paquete ARP que indica si el paquete es una solicitud (ARP Request) o una respuesta (ARP Reply).

En ARP, específicamente, los opcodes tienen asignados valores numéricos para distinguir entre diferentes tipos de mensajes:
- Solicitud ARP (ARP Request): Generalmente tiene el valor de opcode 1. Este tipo de paquete se envía para solicitar la dirección MAC (Media Access Control) que corresponde a una dirección IP conocida en la red.
- Respuesta ARP (ARP Reply): Tiene el valor de opcode 2. Este paquete se envía en respuesta a una solicitud ARP, proporcionando la dirección MAC solicitada.

Para filtrar y ver solamente las respuestas ARP en Wireshark, puedes utilizar el siguiente filtro de visualización:
```
arp.opcode == 2
```

eth.addr == 80:fb:06:f0:45:d7


## ICMP o Protocolo de Mensajes de Control de Internet
Se utiliza para analizar varios nodos en una red. Esto se usa más comúnmente con utilidades como ping y traceroute. 

### Resumen del Tráfico ICMP
- Solicitud ICMP:
  - Vemos los detalles de un paquete de solicitud de ping. Hay algunas cosas importantes dentro de los detalles del paquete que podemos notar primero siendo el tipo y código del paquete. Un tipo que es igual a 8 significa que es un paquete de solicitud, si es igual a 0 es un paquete de respuesta. Cuando estos códigos son alterados o no parecen correctos, eso es típicamente una señal de actividad sospechosa.
  - Hay otros dos detalles dentro del paquete que son útiles para analizar: la marca de tiempo y los datos. La marca de tiempo puede ser útil para identificar el momento en que se solicitó el ping; también puede ser útil para identificar actividades sospechosas en algunos casos. También podemos mirar la cadena de datos, que típicamente será solo una cadena de datos aleatoria.
    ![](capturas/https://assets.tryhackme.com/additional/wireshark101/icmp/2.png)


- Respuesta ICMP:
  - Vemos que el paquete de respuesta es muy similar al paquete de solicitud. Una de las principales diferencias que distingue a un paquete de respuesta es el código, en este caso, puedes ver que es 0, confirmando que es un paquete de respuesta.
  - Las mismas técnicas de análisis para los paquetes de solicitud se aplican aquí también, nuevamente la principal diferencia será el tipo de paquete.
  - ![](https://assets.tryhackme.com/additional/wireshark101/icmp/3.png)



##  Tráfico TCP
TCP o Protocolo de Control de Transmisión maneja la entrega de paquetes, incluyendo la secuenciación y los errores. Documentación TCP de la IETF: https://datatracker.ietf.org/doc/html/rfc793

A continuación, vemos un ejemplo de un escaneo con Nmap, escaneando los puertos 80 y 443. Podemos decir que el puerto está cerrado debido al paquete RST, ACK en rojo.
![](https://assets.tryhackme.com/additional/wireshark101/25.png)

Al analizar paquetes TCP, Wireshark puede ser muy útil y codificar los paquetes en colores según el nivel de peligro.

TCP puede proporcionar una visión útil de una red al analizarla; sin embargo, también puede ser difícil de analizar debido al número de paquetes que envía. Aquí es donde podrías necesitar utilizar otras herramientas como RSA NetWitness y NetworkMiner para filtrar y analizar más a fondo las capturas.


### Resumen del Tráfico TCP
Algo común que verás al analizar paquetes TCP es lo que se conoce como el handshake (saludo) TCP. Incluye una serie de paquetes: syn, syn-ack, ack; que permiten a los dispositivos establecer una conexión.

![](https://assets.tryhackme.com/additional/wireshark101/26.png)

Típicamente, cuando este saludo está fuera de orden o cuando incluye otros paquetes, como un **paquete RST**, algo sospechoso o incorrecto está sucediendo en la red. El escaneo con Nmap en la sección anterior es un ejemplo perfecto de esto. Un paquete RST, o paquete de reinicio, es un tipo de mensaje utilizado en el Protocolo de Control de Transmisión (TCP) para indicar que una conexión debe ser terminada inmediatamente. En el contexto de TCP, que es un protocolo orientado a conexión y diseñado para proporcionar una comunicación fiable entre dispositivos en una red, un paquete RST se utiliza en varias situaciones, como:

Cerrar una conexión de manera anormal: Si un dispositivo recibe paquetes inesperados para una conexión que no reconoce o para una sesión que ha sido cerrada, puede enviar un paquete RST para informar al emisor que no hay una conexión establecida y que debe cesar el envío de más paquetes.

Rechazar intentos de conexión: Si un servidor recibe una solicitud de conexión (un paquete SYN) a un puerto que no está escuchando o que está filtrado, puede responder con un paquete RST para indicar que la conexión no puede establecerse.

Interceptar comunicaciones: En algunas técnicas de seguridad de red y análisis, los paquetes RST se utilizan para interrumpir conexiones existentes o bloquear el establecimiento de nuevas conexiones, como parte de una acción de firewall o de un sistema de prevención de intrusiones.

### Análisis de Paquetes TCP
Para analizar paquetes TCP, no entraremos en los detalles de cada aspecto individual de los paquetes; sin embargo, observaremos algunos de los comportamientos y estructuras que tienen los paquetes. A continuación, vemos los detalles de un paquete SYN. Lo principal que queremos buscar al observar un paquete TCP es el número de secuencia y el número de acuse de recibo.
![](https://assets.tryhackme.com/additional/wireshark101/27.png)


En este caso, vemos que el puerto no estaba abierto porque el número de acuse de recibo es 0.

Dentro de Wireshark, también podemos ver el número de secuencia original navegando a editar > preferencias > protocolos > TCP > números de secuencia relativos (desmarcar casillas).

![](https://assets.tryhackme.com/additional/wireshark101/28.png)


![](https://assets.tryhackme.com/additional/wireshark101/29.png)

Típicamente, los paquetes TCP necesitan ser observados en su conjunto para contar una historia, en lugar de examinar uno por uno en detalle.


## Resumen de DNS

DNS o protocolo de Servicio de Nombres de Dominio se utiliza para resolver nombres con direcciones IP. Documentación de DNS de la IETF: https://www.ietf.org/rfc/rfc1035.txt

Hay un par de cosas que se detallan a continuación que debes tener en mente al analizar paquetes DNS.
- Consulta-Respuesta
- Solo Servidores DNS
- UDP

Si alguno de estos está fuera de lugar, entonces los paquetes deben ser examinados más a fondo y deberían considerarse sospechosos. A continuación, podemos ver una captura de paquete con múltiples consultas y respuestas DNS.
![](https://assets.tryhackme.com/additional/wireshark101/30.png)

Al observar instantáneamente los paquetes, podemos ver qué están consultando; esto puede ser útil cuando tienes muchos paquetes y necesitas identificar tráfico sospechoso o inusual rápidamente:


### Resumen del Tráfico DNS

- Consulta DNS: Al observar la consulta a continuación, realmente tenemos dos bits de información que podemos usar para analizar el paquete. El primer dato en el que podemos fijarnos es de dónde proviene la consulta; en este caso, es UDP 53, lo que significa que este paquete pasa esa verificación. Si fuera TCP 53, entonces debería considerarse tráfico sospechoso y necesitaría ser analizado más a fondo. También podemos observar qué está consultando; esto puede ser útil, junto con otra información, para construir la historia de lo que ocurrió.
![](https://assets.tryhackme.com/additional/wireshark101/31.png)

Al analizar paquetes DNS, realmente necesitamos entender el entorno y si el tráfico sería considerado normal dentro de tu entorno.

Respuesta DNS: A continuación, vemos un paquete de respuesta, es similar al paquete de consulta, pero también incluye una respuesta, la cual puede ser utilizada para verificar la consulta:
![](https://assets.tryhackme.com/additional/wireshark101/32.png)




### Tráfico HTTP
HTTP es uno de los protocolos más directos para el análisis de paquetes; el protocolo va directo al grano y no incluye ningún tipo de saludo inicial ni requisitos previos antes de la comunicación.

Standart HTTP/1.1: https://www.ietf.org/rfc/rfc2616.txt

![](https://assets.tryhackme.com/additional/wireshark101/33.png)

Arriba podemos ver un ejemplo de paquete HTTP. Al observar un paquete HTTP, podemos recopilar fácilmente información, ya que el flujo de datos no está encriptado como su contraparte HTTPS. Algunos de los datos importantes que podemos recopilar del paquete incluyen el URI de solicitud, datos de archivo, servidor.

![](https://assets.tryhackme.com/additional/wireshark101/34.png)

Profundizamos en la captura de paquetes: Podemos ver los detalles de una de las solicitudes HTTP:

![](https://assets.tryhackme.com/additional/wireshark101/35.png)


A partir de este paquete podemos identificar información muy importante como el host, el agente de usuario, el URI solicitado y la respuesta.

Podemos utilizar algunas de las funciones integradas de Wireshark para ayudar a digerir todos estos datos y organizarlos para análisis futuros. Podemos comenzar viendo una característica muy útil en Wireshark para organizar los protocolos presentes en una captura, la Jerarquía de protocolos. Vaya a Estadísticas > Jerarquía de protocolos:

![](https://assets.tryhackme.com/additional/wireshark101/36.png)


Esta información puede resultar muy útil en aplicaciones prácticas como la búsqueda de amenazas para identificar discrepancias en las capturas de paquetes.

La siguiente característica de Wireshark que veremos es Exportar objeto HTTP. Esta característica nos permitirá organizar todos los URI solicitados en la captura. Para utilizar Exportar objeto HTTP, navegue hasta archivo > Exportar objetos > HTTP.

![](https://assets.tryhackme.com/additional/wireshark101/37.png)


La última característica que cubriremos en esta sección de esta sala son los Endpoints. Esta función permite al usuario organizar todos los Endpoints e IPs que se encuentran dentro de una captura específica. Al igual que las otras funciones, esto puede resultar útil para identificar de dónde se origina una discrepancia. Para utilizar la función Puntos finales, vaya a Estadísticas > Endpoints:

![](https://assets.tryhackme.com/additional/wireshark101/38.png)


## Tráfico HTTPS
HTTPS o Protocolo Seguro de Transferencia de Hipertexto puede ser uno de los protocolos más molestos de entender desde la perspectiva del análisis de paquetes y puede ser confuso comprender los pasos necesarios para analizar paquetes HTTPS.

### Visión General del Tráfico HTTPS
Antes de enviar información encriptada, el cliente y el servidor necesitan acordar varios pasos para crear un túnel seguro:
- El cliente y el servidor acuerdan una versión del protocolo.
- El cliente y el servidor seleccionan un algoritmo criptográfico.
- El cliente y el servidor pueden autenticarse entre sí; este paso es opcional.
- Se crea un túnel seguro con una clave pública.

Podemos comenzar a analizar el tráfico HTTPS mirando los paquetes del saludo inicial (handshake) entre el cliente y el servidor. A continuación, se muestra un paquete de Saludo de Cliente que muestra la Capa de Registro SSLv2, el Tipo de Handshake y la Versión SSL.

![](https://assets.tryhackme.com/additional/wireshark101/39.png)

A continuación se muestra el paquete de Saludo del Servidor que envía información similar al paquete de Saludo del Cliente; sin embargo, esta vez incluye detalles de la sesión e información del certificado SSL.

![](https://assets.tryhackme.com/additional/wireshark101/40.png)

A continuación se muestra el paquete de intercambio de claves del cliente; esta parte del protocolo de enlace determinará la clave pública que se utilizará para cifrar más mensajes entre el cliente y el servidor.

![](https://assets.tryhackme.com/additional/wireshark101/41.png)

En el siguiente paquete, el servidor confirmará la clave pública y creará el túnel seguro; todo el tráfico posterior a este punto se cifrará según las especificaciones acordadas enumeradas anteriormente.

![](https://assets.tryhackme.com/additional/wireshark101/41.png)

El tráfico entre el Cliente y el Servidor ahora está cifrado y necesitará la clave secreta para descifrar el flujo de datos que se envía entre los dos hosts.

![](https://assets.tryhackme.com/additional/wireshark101/42.png)


### Análisis Práctico de Paquetes HTTPS
Tryhackme Wireshar 101 --> Para practicar y obtener experiencia práctica con paquetes HTTPS, podemos analizar el PCAP snakeoil2_070531 y la clave de descifrado. Ve a la carpeta /root/Rooms/Wireshark101 en el AttackBox y extrae la carpeta task12.zip; también puedes descargar esto en esta tarea.

![](https://assets.tryhackme.com/additional/wireshark101/43.png)

Al observar la captura de paquetes anterior, podemos ver que todas las solicitudes están cifradas. Al observar más de cerca los paquetes, podemos ver el protocolo de enlace HTTPS, así como las solicitudes cifradas. Echemos un vistazo más de cerca a una de las solicitudes cifradas: el paquete 36.

![](https://assets.tryhackme.com/additional/wireshark101/44.png)

Podemos confirmar por los detalles del paquete que los Datos de Aplicación están encriptados. Puedes usar una clave RSA en Wireshark para ver los datos sin encriptar. Para cargar una clave RSA navega a Editar > Preferencias > Protocolos > TLS > [+]. Si estás utilizando una versión antigua de Wireshark, será SSL en lugar de TLS. Necesitarás completar las diversas secciones en el menú con las siguientes preferencias:
- Dirección IP: 127.0.0.1
- Puerto: start_tls
- Protocolo: http
- Archivo de clave: ubicación de la clave RSA

![](https://assets.tryhackme.com/additional/wireshark101/45.png)

Ahora que tenemos una clave RSA importada a Wireshark, si volvemos a la captura de paquetes podemos ver que el flujo de datos ahora no está cifrado.

![](https://assets.tryhackme.com/additional/wireshark101/46.png)


Ahora podemos ver las solicitudes HTTP en flujos de datos no cifrados. Si observamos más de cerca uno de los detalles del paquete, podemos ver más de cerca el flujo de datos no cifrados.

![](https://assets.tryhackme.com/additional/wireshark101/47.png)

Al observar los detalles del paquete, podemos ver información muy importante, como el URI de solicitud y el agente de usuario, que pueden ser muy útiles en aplicaciones prácticas de Wireshark, como la búsqueda de amenazas y la administración de redes.

Ahora podemos usar otras funciones para organizar el flujo de datos, como usar la función de exportación de objetos HTTP. Para acceder a esta función, vaya a Archivo > Exportar objetos > HTTP.

![](https://assets.tryhackme.com/additional/wireshark101/48.png)


# Packet Filtering
Wireshark tiene un potente motor de filtros que ayuda a los analistas a acotar el tráfico y centrarse en el evento de interés. Wireshark tiene dos tipos de enfoques de filtrado:
- Filtros de captura: Se utilizan para "capturar" solo los paquetes válidos para el filtro utilizado. 
- Filtros de visualización: Se utilizan para "ver" los paquetes válidos para el filtro utilizado.

Los filtros son consultas específicas diseñadas para protocolos disponibles en la referencia oficial de protocolos de Wireshark. Mientras que los filtros son la única opción para investigar el evento de interés, hay dos maneras diferentes de filtrar el tráfico y eliminar el ruido del archivo de captura. La primera utiliza consultas, y la segunda utiliza el menú de clic derecho. Wireshark proporciona una potente interfaz gráfica de usuario, y hay una regla de oro para los analistas que no quieren escribir consultas para tareas básicas: "Si puedes hacer clic en ello, puedes filtrarlo y copiarlo".

## Aplicar como Filtro
Esta es la manera más básica de filtrar tráfico. Mientras investigas un archivo de captura, puedes hacer clic en el campo que quieres filtrar y usar el "menú de clic derecho" o el menú "Analizar --> Aplicar como Filtro" para filtrar el valor específico. Una vez que aplicas el filtro, Wireshark generará la consulta de filtro requerida, la aplicará, mostrará los paquetes según tu elección y ocultará los paquetes no seleccionados del panel de lista de paquetes. Ten en cuenta que el número de paquetes totales y mostrados siempre se muestra en la barra de estado.
![](capturas/463abd0a5cad55831b54a37c17092505.png)


## Filtro de Conversación
Cuando usas la opción "Aplicar como Filtro", filtrarás solo una única entidad del paquete. Esta opción es una buena manera de investigar un valor particular en los paquetes. Sin embargo, supongamos que quieres investigar un número de paquete específico y todos los paquetes vinculados, enfocándote en direcciones IP y números de puerto. En ese caso, la opción "Filtro de Conversación" te ayuda a ver solo los paquetes relacionados y ocultar el resto de los paquetes fácilmente. Puedes usar el "menú de clic derecho" o el menú "Analizar --> Filtro de Conversación" para filtrar conversaciones.

![](capturas/6b31a8581e560286aee74fb9a608dfc9.png)


## Colorear Conversación
Esta opción es similar al "Filtro de Conversación" con una diferencia. Resalta los paquetes vinculados sin aplicar un filtro de visualización y disminuir el número de paquetes vistos. Esta opción funciona con la opción de "Reglas de Coloración" y cambia los colores de los paquetes sin considerar la regla de color aplicada previamente. Puedes usar el "menú de clic derecho" o el menú "Ver --> Colorear Conversación" para colorear un paquete vinculado con un solo clic. Ten en cuenta que puedes usar el menú "Ver --> Colorear Conversación --> Restablecer Coloración" para deshacer esta operación.

![](capturas/b7a7ce6afa9c421e6bfaebac719d348c.png)

## Preparar como Filtro
Similar a "Aplicar como Filtro", esta opción ayuda a los analistas a crear filtros de visualización usando el menú de "clic derecho". Sin embargo, a diferencia de la anterior, este modelo no aplica los filtros después de la elección. Añade la consulta requerida al panel y espera el comando de ejecución (enter) o otra opción de filtrado elegida usando ".. y/o .." del menú de "clic derecho".


![](capturas/0291e6095277eaebf8f9a8f8df0f1ec6.png)

## Aplicar como Columna
Por defecto, el panel de lista de paquetes proporciona información básica sobre cada paquete. Puedes usar el "menú de clic derecho" o "Analizar --> Aplicar como Columna" para añadir columnas al panel de lista de paquetes. Una vez que hagas clic en un valor y lo apliques como columna, será visible en el panel de lista de paquetes. Esta función ayuda a los analistas a examinar la aparición de un valor/campo específico en los paquetes disponibles en el archivo de captura. Puedes habilitar/deshabilitar las columnas mostradas en el panel de lista de paquetes haciendo clic en la parte superior del panel de lista de paquetes.
![](capturas/8eac68abb9c10fccce114f6ad803a5dd.png)


## Seguir Flujo
Wireshark muestra todo en tamaño de porción de paquete. Sin embargo, es posible reconstruir los flujos y ver el tráfico bruto tal como se presenta en el nivel de aplicación. Seguir los flujos de protocolo ayuda a los analistas a recrear los datos a nivel de aplicación y entender el evento de interés. También es posible ver los datos del protocolo no encriptados, como nombres de usuario, contraseñas y otros datos transferidos.

Puedes usar el "menú de clic derecho" o "Analizar --> Seguir Flujo de TCP/UDP/HTTP" para seguir los flujos de tráfico. Los flujos se muestran en un cuadro de diálogo separado; los paquetes que provienen del servidor se resaltan con azul, y aquellos que provienen del cliente se resaltan con rojo.

![](capturas/d578e89a1f4a526fb8ede6fdf1a5f1b5.png)

Una vez que sigues un flujo, Wireshark crea y aplica automáticamente el filtro requerido para ver el flujo específico. Recuerda, una vez que se aplica un filtro, el número de paquetes vistos cambiará. Necesitarás usar el "botón X" ubicado en el lado derecho superior de la barra de filtro de visualización para remover el filtro de visualización y ver todos los paquetes disponibles en el archivo de captura.


# Estadísticas
Este menú ofrece múltiples opciones de estadísticas listas para investigar, que ayudan a los usuarios a ver el panorama general en términos del alcance del tráfico, los protocolos disponibles, endpoints y conversaciones, y algunos detalles específicos de protocolos como DHCP, DNS y HTTP/2. Para un analista de seguridad, es crucial saber cómo utilizar la información estadística. Esta sección proporciona un resumen rápido del pcap procesado, que ayudará a los analistas a crear una hipótesis para una investigación. Puedes usar el menú "Estadísticas" para ver todas las opciones disponibles.

## Direcciones Resueltas
Esta opción ayuda a los analistas a identificar direcciones IP y nombres DNS disponibles en el archivo de captura, proporcionando la lista de las direcciones resueltas y sus hostnames. Ten en cuenta que la información del hostname se toma de las respuestas DNS en el archivo de captura. Los analistas pueden identificar rápidamente los recursos accedidos usando este menú. Así pueden detectar recursos accedidos y evaluarlos de acuerdo al evento de interés. Puedes usar el menú "Estadísticas --> Direcciones Resueltas" para ver todas las direcciones resueltas por Wireshark.

![](capturas/38baec5d1f2fcdf85c0e1e2a78fe3bfe.png)


## Jerarquía de Protocolos
Esta opción desglosa todos los protocolos disponibles del archivo de captura y ayuda a los analistas a ver los protocolos en una vista de árbol basada en contadores de paquetes y porcentajes. De esta manera, los analistas pueden ver el uso general de los puertos y servicios y centrarse en el evento de interés. La regla de oro mencionada en la sala anterior es válida en esta sección; puedes hacer clic derecho y filtrar el evento de interés. Puedes usar el menú "Estadísticas --> Jerarquía de Protocolos" para ver esta información.

![](capturas/725ea0a97383aeee70ddfae49743cce1.png)


## Conversaciones
Conversación representa el tráfico entre dos endpoints específicos. Esta opción proporciona la lista de las conversaciones en cinco formatos base; ethernet, IPv4, IPv6, TCP y UDP. De esta manera, los analistas pueden identificar todas las conversaciones y contactar endpoints para el evento de interés. Puedes usar el menú "Estadísticas --> Conversaciones" para ver esta información.
![](capturas/c54cc40b174b5ee7540b063ae3b075ed.png)

## Endpoints
La opción de endpoints es similar a la opción de conversaciones. La única diferencia es que esta opción proporciona información única para un solo campo de información (Ethernet, IPv4, IPv6, TCP y UDP). De esta manera, los analistas pueden identificar los endpoints únicos en el archivo de captura y usarlo para el evento de interés. Puedes usar el menú "Estadísticas --> Endpoints" para ver esta información.

Wireshark también admite la resolución de direcciones MAC a un formato legible por humanos usando el nombre del fabricante asignado por IEEE. Ten en cuenta que esta conversión se realiza a través de los primeros tres bytes de la dirección MAC y solo funciona para los fabricantes conocidos. Cuando revisas los endpoints ethernet, puedes activar esta opción con el botón de "Resolución de nombres" en la esquina inferior izquierda de la ventana de endpoints.

![](capturas/8971957ac8c031276167d110ce187d4e.png)

La resolución de nombres no se limita solo a las direcciones MAC. Wireshark también proporciona opciones de resolución de nombres para IP y puertos. Sin embargo, estas opciones no están habilitadas por defecto. Si deseas utilizar estas funcionalidades, necesitas activarlas a través del menú "Editar --> Preferencias --> Resolución de Nombres". Una vez que habilites la resolución de nombres para IP y puertos, verás las direcciones IP y nombres de puertos resueltos en el panel de lista de paquetes y también podrás ver los nombres resueltos en los menús de "Conversaciones" y "Endpoints".

![](capturas/f19928be2591fd6aa59550e0a96f7563.png)

Vista del menú de endpoints con resolución de nombres:

![](capturas/fb672714d13bf9a40502134193102907.png)


Además de la resolución de nombres, Wireshark también ofrece un mapeo de geolocalización IP que ayuda a los analistas a identificar las direcciones de origen y destino en el mapa. Pero esta característica no está activada por defecto y necesita datos suplementarios como la base de datos GeoIP. Actualmente, Wireshark admite las bases de datos de MaxMind, y las últimas versiones de Wireshark vienen configuradas con el resolvedor de DB de MaxMind. Sin embargo, todavía necesitas los archivos DB de MaxMind y proporcionar la ruta de la base de datos a Wireshark usando el menú "Editar --> Preferencias --> Resolución de Nombres --> Directorios de base de datos de MaxMind". Una vez que descargues e indiques la ruta, Wireshark proporcionará automáticamente información GeoIP bajo los detalles del protocolo IP para las direcciones IP coincidentes.

![](capturas/5bac23950841825eef688ca87dcd63d6.png)


Endpoints and GeoIP view.

![](capturas/4056095d90ec25260a5538f23649e057.png)


# Packet Filtering using queries
Ya vimos que existen dos tipos de filtros en Wireshark. Aunque ambos utilizan una sintaxis similar, se utilizan para diferentes propósitos. Recordemos la diferencia entre estas dos categorías.
- Filtros de Captura: Este tipo de filtro se utiliza para guardar solo una parte específica del tráfico. Se establece antes de capturar el tráfico y no se puede cambiar durante la captura.

- Filtros de Visualización: Este tipo de filtro se utiliza para investigar los paquetes reduciendo el número de paquetes visibles, y se puede cambiar durante la captura.

Nota: No puedes usar las expresiones de filtro de visualización para capturar tráfico y viceversa.

El caso de uso típico es capturar todo y filtrar los paquetes según el evento de interés. Solo los profesionales experimentados utilizan filtros de captura y capturan tráfico. Esta es la razón por la cual Wireshark admite más tipos de protocolos en los filtros de visualización. 


## Sintaxis del Filtro de Captura
Estos filtros utilizan desplazamientos de byte, valores hexadecimales y máscaras con operadores booleanos, y no es fácil entender/predecir el propósito del filtro a primera vista. La sintaxis base se explica a continuación:
- Ámbito: host, net, port y portrange.
- Dirección: src, dst, src or dst, src and dst.
- Protocolo: ether, wlan, ip, ip6, arp, rarp, tcp y udp.
- Filtro de muestra para capturar tráfico del puerto 80: tcp port 80

Puedes leer más sobre la sintaxis de filtro de captura:
- https://www.wireshark.org/docs/man-pages/pcap-filter.html
- https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters#useful-filters

![](capturas/50a3e8a1cce46524f6de3ea14efd99e2.png)


## Sintaxis del Filtro de Visualización
Esta es la característica más poderosa de Wireshark. Soporta 3000 protocolos y permite realizar búsquedas a nivel de paquete bajo la descomposición del protocolo. La "Referencia de Filtro de Visualización" oficial proporciona una descomposición de todos los protocolos soportados para filtrado.

Filtro de muestra para capturar tráfico del puerto 80: tcp.port == 80
Wireshark tiene una opción integrada (Expresión de Filtro de Visualización) que almacena todas las estructuras de protocolo soportadas para ayudar a los analistas a crear filtros de visualización. 

![](capturas/aa2ca30ccfff2d7eba16d031f0ab1f38.png)


## Operadores de Comparación & Expresiones Lógicas
Puedes crear filtros de visualización utilizando diferentes operadores de comparación para encontrar el evento de interés. Los operadores primarios se muestran en la tabla a continuación.

![](capturas/wireshark-oper.png)

## Barra de Herramientas de Filtro de Paquetes
La barra de herramientas de filtro es donde creas y aplicas tus filtros de visualización. Es una barra de herramientas inteligente que te ayuda a crear filtros de visualización válidos con facilidad. Antes de comenzar a filtrar paquetes, aquí tienes algunos consejos:
- Los filtros de paquetes se definen en minúsculas.
- Los filtros de paquetes tienen una característica de autocompletado para desglosar los detalles del protocolo, y cada detalle se representa con un "punto".
- Los filtros de paquetes tienen una representación de tres colores explicada a continuación:
  - Verde: Filtro Válido.
  - Red: Filtro Inválido.
  - Amarillo: Filtro de advertencia. Este filtro funciona, pero es poco fiable, y se sugiere cambiarlo por un filtro válido.

![](capturas/98be05db82a2b7a2fd449c2155512f87.png)

Las características de la barra de herramientas de filtro se muestran a continuación:
![](capturas/b929ceb69199b99071fa95ce11d8ca44.png)


## Advanced Filtering

### Filter: "contains"
- Filter: contains.
- Type:	Comparison Operator.
- Description:	Search a value inside packets. It is case-sensitive and provides similar functionality to the "Find" option by focusing on a specific field.
- Example: Find all "Apache" servers.
- Workflow:	List all HTTP packets where packets' "server" field contains the "Apache" keyword.
```
http.server contains "Apache"
```
![](capturas/fb733f3af660c22a26d44e4087dc38a3.png)


### Filter: "matches"
- Filter: matches.
- Type:	Comparison Operator.
- Description:	Search a pattern of a regular expression. It is case insensitive, and complex queries have a margin of error.
- Example:	Find all .php and .html pages.
- Workflow	List all HTTP packets where packets' "host" fields match keywords ".php" or ".html".
```
http.host matches "\.(php|html)"
```

![](capturas/c7c03c7306f9965b97423f8431a944cb.png)


### Filter: "in"
- Filter: in.
- Type:	 Set Membership.
- Description:	Search a value or field inside of a specific scope/range.
- Example:	Find all packets that use ports 80, 443 or 8080.
- Workflow:	List all TCP packets where packets' "port" fields have values 80, 443 or 8080.
```
tcp.port in {80 443 8080}
```

![](capturas/db1cac52cf9ff629c21d104834cb689e.png)


### Filter: "upper"
- Filter: upper.
- Type:	Function.
- Description:	Convert a string value to uppercase.
- Example:	Find all "APACHE" servers.
- Workflow	Convert all HTTP packets' "server" fields to uppercase and list packets that contain the "APACHE" keyword.
```
upper(http.server) contains "APACHE"
```

![](capturas/289b8e6c53ab1adfd894874b7053de75.png)


### Filter: "lower"
- Filter: lower.
- Type:	Function.
- Description:	Convert a string value to lowercase.
- Example:	Find all "apache" servers.
- Workflow:	Convert all HTTP packets' "server" fields info to lowercase and list packets that contain the "apache" keyword.
```
lower(http.server) contains "apache"
```

![](capturas/6cb5da0c3d4b10a3f29f15a193b9ab92.png)



### Filter: "string"
- Filter: string.
- Type:	Function.
- Description:	Convert a non-string value to a string.
- Example:	Find all frames with odd numbers.
- Workflow:	Convert all "frame number" fields to string values, and list frames end with odd values.
```
string(frame.number) matches "[13579]$"
```

![](capturas/2f67a74f70e2f1a9acdbeee9bddd31d4.png)


### Marcadores y Botones de Filtrado
Crear filtros y guardarlos como marcadores y botones para su uso posterior. En la barra de herramientas de filtro tiene una sección de marcadores de filtro para guardar los filtros creados por el usuario, lo que ayuda a los analistas a reutilizar filtros favoritos/complejos con un par de clics. Similar a los marcadores, puedes crear botones de filtro listos para aplicar con un solo clic.

![](capturas/197e4e319adb4b8a70d7a4ca419bd52f.png)


Creating and using display filter buttons.

![](capturas/95212f1e231477a046950011715208ab.png)


## Profiles
Wireshark is a multifunctional tool that helps analysts to accomplish in-depth packet analysis. As we covered during the room, multiple preferences need to be configured to analyse a specific event of interest. It is cumbersome to re-change the configuration for each investigation case, which requires a different set of colouring rules and filtering buttons. This is where Wireshark profiles come into play. You can create multiple profiles for different investigation cases and use them accordingly. You can use the "Edit --> Configuration Profiles" menu or the "lower right bottom of the status bar --> Profile" section to create, modify and change the profile configuration.

![](capturas/9254b0bb582c55723327550a68c9a11e.png)


-----------------------------------------------

https://www.wolf.university/learnwireshark/ebook/learnwireshark.pdf

https://www.wolf.university/networkanalysisusingwireshark2cookbook/ebook/networkanalysisusingwireshark2cookbook_ebook.pdf


Elegir profile

Edición -- Preferencias -- Apaciencia -- Columnas -- Botón + para añadir columna -- Nombre: Delta -- Tipo: Delta TIme Displayed.

Edición -- Preferencias -- Apaciencia -- Diseño -- Panel 1: Listado de Paquetes -- Panel 2: Detalles de paquete --- Panel 3: Diagrama de paquetes

Visualización -- Reglas de Coloreado --  Botón + para añadir regla -- xxxxxxx

Añadir botón de filtro -- Nombre: Anomalías TCP -- Valor: tcp.analysis.flags

Tráfico hacia la máquina destino -- Nombre ip-dst  -- Valor: ip.dst==192.168.18.202

Tráfico desde la máquina destino -- Nombre ip-src  -- Valor: ip.src==192.168.18.202

Sobre un paquete --- En Transmission Control Protrocol -- [TCP Segment Len] boton derecho --> Aplicar como columna --> Se muestra en el panel 1 una nueva columna que muestra la longitud del payload.


# Opciones de captura
Botón Opciones de captura -- Administrar Interfaces -- Pestaña Entrada - Quitar los interfaces que no necesitemos analizar para que el tráfico que se captura sea más limpio.

Si se necesita capturar el payload por completo, hay que modificar el dato --> Longitud de Instantánea (En ingles Snaplen (B)) dentro de la ventana Administrar Interfaces ya que por defecto no captura todo el payload

Botón Opciones de captura -- Administrar Interfaces -- Pestaña Salida - Mejor trocear en ficheros la captura que se realiza para no generar un unico fichero muy grande - Establecer la carpeta y el nombre del fichero con la extension. Activamos la casilla de crear un nuevo fichero automaticamente after 500 megabytes. Activamos Use a ring buffer with 10 files.

Elegimos el interfaz para hacer la captura. Y terminamos con el botón Start.


# Capturing packets with Dumpcap - Command Line Capture

## En Windows
Abrimos command prompt
```
cd program files
cd wireshark
path
## Verificamos que en el path esté wireshark
## Si no aparece hay que añadirlo: System Properties - Ennvironmet variables -- .......
dumpcap -h
dumpcap -D ## Muestra las interfaces que dispone el host y les pone un numero
dumpcap -i 1 -w ~/Escritorio/sample.pcapng
dumpcap -i 1 -w ~/Escritorio/sample.pcapng -b filesize: 500000  -b files:10      ## Para hacer un ring buffer
```


# ¿Donde hacemos la captura del tráfico de red?
Lo ponemos en el end point? o en otros sitios?
Eso depende del problema que tenemos, de lo que queremos analizar con wireshark.


# How to Filter Traffic
La diferencia entre un filtro de captura y un filtro de visualización es la siguiente:
- Filtro de Captura: Se utiliza para definir qué paquetes de datos serán capturados por una herramienta de análisis de red. El filtro se aplica durante la captura de paquetes, determinando cuáles paquetes son retenidos para su análisis posterior.
  - port 53
  - ip 192.168......
  - tcp <<-- Si usamos este filtro nos perdemos los paquetes icmp. Si acotamos mucho la captura nos podemos perder mensajes importantes.

- Filtro de Visualización: Se aplica a los paquetes de datos que ya han sido capturados. Este filtro ayuda a los usuarios a buscar y visualizar específicamente ciertos paquetes o tipos de datos dentro de un conjunto de datos capturados más grande, sin afectar la colección original de datos capturados.
  - ip.addr==192.168.18.202
  - Hacer un filtro de visualización de forma automática: Sobre un paquete, hacemos click en el botón derecho y en el menú elegimos los opción Conversation Filter .... Especificamos lo que queremos un filtrp basado en la dirección ethernet en este paquete, o si queremos un filtro basado en la dirección IPv4, o queremos que dea una conversación tcp.
  - Otra forma de hacer un filtro de visualización --> Sobre un paquete --> En Transmission Contrl Protocol hacemos click con el boton derecho --> Prepare as Filter --> and selected. Esto escribe de forma automatica el filtro.
  - Quitar mensajes de una captura: !arp -- not arp -- not (arp or ipv6). Esto quita de la vista estos mensajes.
  - Filtro para mostrar los paquetes tcp de varios puertos: tcp.por in {80 443 8080}
  - String Filters: Cuando buscamos una palabra en concreto -->
    - frame contains google -- Case sensitive
    - frame matches google -- Case insensitive


El lenguaje utilizado para capture filters es diferente al usado en display filters


## Name Resolution
Ir a Preferencias -- Name Resolution --- marcar la opción Resolve a MAC addresses --  marcar la opción Resolve transport names --  marcar la opción Resolve network IP addresses --  marcar la opción Use captured DNS ... --  marcar la opción Use an external network ....

Sobre una ip que queramos  --- Boton Derecho --- Edit Resolved Name --- Escribimos el nombre que queremos y ya no muestra la IP, mostrará el nombre que le dimos.

Para que estos cambios se queden guardados en el pcapng --> Menu View -- Reload as File Format/Capture --- Save

Para quitar esos nombres que le dimos a las ips --> Hacemos click en uno de los paquetes que tengan ese nombre, hacemos click boton derecho sobre el nombre -- Edit resolve name --- Eliminamos el nombre --- y ya aparece la ip otro vez



## Using the time column
El tiempo se mide desde el primer paquete que entró en el device que wireshark captura el tréfico. Para cambiar esto y que se muestre la hora del sistema --> View Menu --> Time Display Format --> TIme of Day (muestra la hora del sistema donde esté instalado wireshark) -- También podemos elegir UTC Time of DAY

Marcar un paquete como referencia de tiempo: sobre el paquete hacemos click botón derecho en la columna time -- Set/Unset time reference


Seleccionar varios paquetes de una request, boton derecho --  Set/Unset time reference -- Veremos como se marca a Cero los paquetes que correspondan con el response del request anterior.


Quitar todas las marcas de tiempo: Menu editar - Unset all time references.


Time since firs frame in this tcp stream -- hacer columna. Esto habla del tiempo con respecto a su anterior paquete dentro de esa conversación. Se puede hacer columna. Es util.



## Reading pcap with Wireshark Statistics
Menu Statistics --> Conversations --> Muestra por capas de direcciones cuantas conversaciones tenemos en ese filero de tráfico.   
Usamos Statistics para ver las conversaciones y hacernos una idea de lo que ocurre.
Aplicamos filtros a esas conversaciones para mostrar una parte de todo el tráfico que tiene el pcapng.

## Extracting files from pcaps


# Filtros
- Capturar peticiones de ping --> Capturar y analizar específicamente los paquetes ICMP que son de tipo 8. En el contexto de ICMP, el tipo 8 corresponde a los mensajes de "echo request", comúnmente conocidos como peticiones de ping.
  ```
  icmp.type == 8
  ```
- Respuestas a solicitudes de ping --> Capturar y analizar específicamente los paquetes ICMP que son de tipo 0. En el contexto de ICMP, el tipo 0 corresponde a los mensajes de "echo reply", que son comúnmente conocidos como respuestas a solicitudes de ping.
  ```
  icmp.type == 0
  ```
- Analizar el tráfico HTTP: Mostar solo las solicitudes HTTP.
  ```
  http.request.uri
  ```

# Case study
## 1. ICMP Flood or something else
Hands On Network Forensic - Pag 104
Packet number 179 has a system path in it. This is going south! The found traces denote that someone is accessing this system using an ICMP shell. The ICMP shell is a backdoor that makes use of data fields to send replies to a command sent by the attacker. Since all the requests originated from 192.168.153.129, we have our attacker. We can also see another strange thing: The ICMP packets are missing data fields, apart from the packets' ICMP backdoor packets. This gives us an edge to only focus on the packets having data, for this, we can type data as the filter:

.\tshark.exe -Y data -r C:\Users\Apex\Desktop\Wire\icmp_camp.pcapng -T fields -e data
-Y data -> -Y se utiliza para aplicar un "display filter" (filtro de visualización) en Tshark. En este caso, el filtro es data, lo que significa que el comando buscará paquetes que contengan datos (payload) en su interior.
-r C:\Users\Apex\Desktop\Wire\icmp_camp.pcapng --> ruta de archivo se utiliza para leer un archivo de captura de paquetes existente.
-T fields --> -T fields especifica que la salida debe ser en formato de "campos". Esto significa que Tshark generará una salida basada en campos específicos de los paquetes, en lugar del formato de salida predeterminado.
-e data --> -e se utiliza para especificar un campo específico que se desea incluir en la salida. Aquí, data es el campo que se extraerá de cada paquete filtrado. En el contexto de los paquetes de red, data generalmente se refiere al payload o carga útil del paquete, que es la parte del paquete que contiene los datos reales transmitidos.



# SiLK
(System for Internet-Level Knowledge) es un conjunto de herramientas de análisis de tráfico de red diseñado para facilitar la recopilación, el almacenamiento y el análisis de grandes conjuntos de datos de flujo de red. Desarrollado por el CERT (Computer Emergency Response Team) de la Universidad Carnegie Mellon, SiLK está orientado principalmente a la seguridad de redes y análisis forense. 
https://tools.netsa.cert.org/silk/download.html


# DynamiteLab
https://lab.dynamite.ai/


## Filtros
```
http contains "<script>" || http contains "javascript:" || http contains "onerror=" || http contains "alert("

http || tcp.port == 80 || tcp.port == 443

(http.request or tls.handshake.type eq 1) and !(ssdp)

http.response.code == 500

http.request.uri contains "SELECT" || http.request.uri contains "UNION" || http.request.uri contains "DROP" || http.request.uri contains "OR '1'='1'"

http.request.method == "POST"

ip.src == <SRC IP Address> and ip.dst == <DST IP Address>

tcp.port eq <Port #> or <Protocol Name>

udp.port eq <Port #> or <Protocol Name>

dns.qry.type == 1 && dns.flags.response == 1”

tcp.port == 80 && http.request.method == "GET"

http.server matches "Microsoft" && http.server contains "IIS/7.5"

string(ip.ttl) matches "[02468]$"

tcp.checksum_bad.expert

tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024 

icmp.type==3 and icmp.code==3

http.request.full_uri

frame contains "api"

http.content_type contains "application/json"

tls contains "application/json"


```

What is the IP address of the hostname starts with "bbc"? --> dns.qry.name contains "bbc"


-------------------------------------------------
## Determinar el tipo de escaneo se utilizó para escanear el puerto TCP 80 
Para determinar qué tipo de escaneo se utilizó para escanear el puerto TCP 80 utilizando Wireshark, debemos seguir algunos pasos y prestar atención a ciertos patrones de paquetes que pueden indicar el tipo de escaneo. Los tipos de escaneo más comunes incluyen escaneo SYN (a veces llamado "half-open scan"), escaneo de conexión completa (TCP Connect), escaneo FIN, escaneo Xmas, entre otros. Cada uno tiene características distintivas en términos de los flags de TCP utilizados:
- Abrir Wireshark y cargar el archivo de captura: Primero, abre Wireshark y carga el archivo de captura que deseas analizar.

- Filtrar por tráfico hacia el puerto 80: Para centrarte en el tráfico dirigido al puerto 80, puedes utilizar el filtro de visualización tcp.port == 80. Esto filtrará tanto el tráfico de salida como el de entrada asociado con el puerto 80.

- Identificar patrones de escaneo:
  - Escaneo SYN (Half-open Scan): Busca paquetes donde solo el flag SYN está establecido (sin el ACK). Un intento de conexión que no se completa (es decir, sin los paquetes de seguimiento SYN-ACK y ACK) puede indicar un escaneo SYN. Filtro de ejemplo: tcp.flags.syn == 1 && tcp.flags.ack == 0.

  - Escaneo TCP Connect: Este es un escaneo de conexión completa, por lo que buscarías una secuencia completa de handshake TCP (SYN, SYN-ACK, ACK) seguida de un cierre de conexión (FIN o RST). Este tipo de escaneo es más difícil de diferenciar del tráfico normal solo con filtros, pero la presencia de múltiples conexiones completas a diferentes puertos puede ser un indicador.

  - Escaneo FIN, Xmas, o Null: Estos escaneos se caracterizan por el envío de paquetes con combinaciones inusuales de flags o sin flags. Por ejemplo, un escaneo FIN solo tiene el flag FIN establecido, el escaneo Xmas tiene los flags FIN, PSH y URG establecidos, y un escaneo Null no tiene flags establecidos. Filtros de ejemplo: tcp.flags.fin == 1 && tcp.flags.urg == 0 && tcp.flags.push == 0 para FIN, tcp.flags.fin == 1 && tcp.flags.urg == 1 && tcp.flags.push == 1 para Xmas, y tcp.flags == 0 para Null.

- Examinar detalles de los paquetes: Selecciona los paquetes que coincidan con los filtros anteriores y revisa los detalles en el panel inferior de Wireshark. Presta especial atención a los flags de TCP y a cualquier patrón de paquetes que parezca indicar un escaneo.

- Utilizar "Conversations" y "Endpoints": Las herramientas "Conversations" y "Endpoints" bajo el menú "Statistics" pueden ayudarte a identificar patrones de escaneo al mostrarte una vista resumida de las conexiones y los hosts involucrados.

Estos pasos deberían ayudarte a identificar el tipo de escaneo utilizado para investigar el puerto TCP 80 en tu captura de Wireshark. Sin embargo, la interpretación de los datos capturados puede variar dependiendo del contexto específico del tráfico de red y de las técnicas de escaneo empleadas.


## "UDP close port" messages 
En Wireshark, los mensajes que indican un puerto cerrado para conexiones UDP se identifican generalmente a través de mensajes ICMP de tipo 3, código 3, los cuales indican "Destination Unreachable: Port Unreachable". Esto se debe a que UDP, a diferencia de TCP, no establece una conexión (no hay un handshake de tres pasos), por lo que la única forma de saber si un puerto UDP está cerrado es si el host de destino responde con un mensaje ICMP indicando que el puerto es inalcanzable.
```
icmp.type == 3 && icmp.code == 3
```

Este filtro mostrará todos los mensajes ICMP de tipo 3, código 3, que corresponden a respuestas de "puerto inalcanzable" enviadas por un host cuando recibe un paquete dirigido a un puerto UDP que no está escuchando.

Es importante tener en cuenta que no todos los sistemas o dispositivos envían respuestas ICMP ante paquetes UDP dirigidos a puertos cerrados, y algunos firewalls o dispositivos de red pueden bloquear estos mensajes ICMP por razones de seguridad. Esto significa que la ausencia de una respuesta ICMP no garantiza que un puerto esté abierto, sino que simplemente no se recibió ninguna confirmación de su estado.                          


## TCP Scans

- Filtrar Intentos de Conexión TCP: Filtrar todos los intentos de conexión TCP con:
```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```
Este filtro mostrará todos los paquetes SYN, que son el primer paso en el establecimiento de una conexión TCP. Sin embargo, este filtro también capturará escaneos SYN y otras conexiones TCP legítimas.

- Buscar Conexiones TCP Completadas: Cconexiones TCP que se completan, es decir, donde hay un "handshake" de tres vías (SYN, SYN-ACK, ACK), podríamos necesitar revisar manualmente las conexiones para confirmar que siguen el patrón completo de conexión. Este enfoque requiere analizar las secuencias de paquetes más que usar un filtro simple.

- Observar Conexiones Rápidamente Terminadas: Muchos escaneos "TCP Connect" terminan la conexión inmediatamente después de establecerla, enviando un paquete FIN o RST para cerrarla:
```
tcp.flags.fin == 1 or tcp.flags.reset == 1
```
Y luego revisamos si estas terminaciones ocurren poco después de una conexión exitosa, lo que podría indicar un escaneo.

- Análisis Estadístico: Wireshark ofrece herramientas estadísticas que pueden ayudar a identificar patrones anómalos, como un número elevado de intentos de conexión a diferentes puertos de un host en un corto periodo. Ve a Statistics > Endpoints o Statistics > Conversations para tener una visión general de las conexiones y buscar patrones que parezcan inusuales.


## Number of “TCP Connect” scans?
To respond to this question, we should use the next command:
```
tcp.flags.syn ==1 and tcp.flags.ack==0 and tcp.window_size>1024
```
El filtro en Wireshark tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024 se descompone en tres partes, cada una de las cuales aplica una condición específica para filtrar los paquetes TCP. Aquí te explico qué hace cada parte del filtro:

tcp.flags.syn == 1: Esta condición filtra los paquetes que tienen el flag SYN establecido a 1. El flag SYN se utiliza en el inicio de la conexión TCP para sincronizar los números de secuencia entre el cliente y el servidor. Un paquete con el flag SYN establecido (y ACK no establecido, como veremos en la siguiente condición) indica un intento de iniciar una nueva conexión TCP, comúnmente el primer paso en el handshake de tres vías de TCP.

tcp.flags.ack == 0: Esta condición busca paquetes que no tienen el flag ACK establecido. En el contexto de una conexión TCP, el flag ACK se utiliza para reconocer la recepción de paquetes. Al combinar esta condición con la anterior, el filtro se centra en los paquetes que están intentando iniciar una conexión (con SYN) pero que no son parte de una respuesta en un handshake de TCP (donde se esperaría que ACK estuviera establecido). Esencialmente, esto filtra los paquetes que representan el primer paso de un intento de conexión TCP, excluyendo los paquetes SYN-ACK que son el segundo paso en el proceso de handshake.

tcp.window_size > 1024: Esta condición filtra los paquetes que tienen un tamaño de ventana TCP mayor a 1024 bytes. El tamaño de la ventana TCP indica la cantidad de datos que un lado está dispuesto a recibir (y puede almacenar en su buffer) antes de recibir un acuse de recibo. Un tamaño de ventana mayor a 1024 bytes sugiere que el emisor está dispuesto a recibir una cantidad relativamente grande de datos sin acuse de recibo, lo cual puede ser indicativo de una configuración de host o de las capacidades de red entre los dos puntos finales.

Cuando combinas estas tres condiciones, el filtro selecciona los paquetes que son intentos iniciales de establecer una conexión TCP (indicado por SYN sin ACK) con una capacidad declarada de recibir más de 1024 bytes de datos antes de necesitar un acuse de recibo. Este filtro podría usarse para identificar intentos de conexión inicial bajo ciertas condiciones, posiblemente como parte de una investigación sobre comportamientos de red específicos, escaneos de puertos, o configuraciones de red.



## Analizar anuncios ARP gratuitos
Los anuncios ARP gratuitos son respuestas ARP enviadas sin una solicitud previa, a menudo utilizados por dispositivos al asignarse a sí mismos una dirección IP para anunciar su presencia. Estos pueden indicar un cambio de dirección IP o un conflicto:
```
arp.isgratuitous == 1
```



# Herramienta Tools --> Credential
"Algunos disectores de Wireshark (FTP, HTTP, IMAP, POP y SMTP) están programados para extraer contraseñas en texto plano del archivo de captura. Puedes ver las credenciales detectadas usando el menú "Herramientas --> Credenciales". Esta característica solo funciona después de versiones específicas de Wireshark (v3.1 y posteriores). Dado que la característica solo funciona con protocolos particulares, se sugiere realizar comprobaciones manuales y no confiar enteramente en esta característica para decidir si hay una credencial en texto plano en el tráfico.

Una vez que uses la característica, se abrirá una nueva ventana y proporcionará las credenciales detectadas. Mostrará el número del paquete, protocolo, nombre de usuario e información adicional. Esta ventana es clickeable; hacer clic en el número del paquete seleccionará el paquete que contiene la contraseña, y hacer clic en el nombre de usuario seleccionará el paquete que contiene la información del nombre de usuario. La parte adicional indica el número del paquete que contiene el nombre de usuario."





## ¡Resultados Accionables!
Wireshark no solo se trata de detalles de paquetes; también puede ayudarte a crear reglas de firewall listas para implementar con un par de clics. Puedes crear reglas de firewall utilizando el menú "Herramientas --> Reglas de ACL de Firewall". Una vez que uses esta característica, se abrirá una nueva ventana y proporcionará una combinación de reglas (basadas en IP, puerto y dirección MAC) para diferentes propósitos. Ten en cuenta que estas reglas se generan para implementación en una interfaz de firewall externa.

Actualmente, Wireshark puede crear reglas para:
- Netfilter (iptables).
- Cisco IOS (estándar/extendido).
- IP Filter (ipfilter).
- IPFirewall (ipfw).
- Packet filter (pf).
- Firewall de Windows (netsh formato nuevo/antiguo).

![](capturas/wireshark-acls.png)



-----------------------------------------------------
Congratulations! You just finished the "Wireshark: The Traffic Analysis" room.

In this room, we covered how to use the Wireshark to detect anomalies and investigate events of interest at the packet level. Now, we invite you to complete the Wireshark challenge room: Carnage, Warzone 1 and Warzone 2.

Wireshark is a good tool for starting a network security investigation. However, it is not enough to stop the threats. A security analyst should have IDS/IPS knowledge and extended tool skills to detect and prevent anomalies and threats. As the attacks are getting more sophisticated consistently, the use of multiple tools and detection strategies becomes a requirement. The following rooms will help you step forward in network traffic analysis and anomaly/threat detection.

NetworkMiner
Snort
Snort Challenge -  The Basics
Snort Challenge - Live Attacks
Zeek
Zeek Exercises
Brim
