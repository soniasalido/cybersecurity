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
![](https://assets.tryhackme.com/additional/wireshark101/12.png)


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
```
