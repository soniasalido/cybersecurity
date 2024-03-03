El ARP Poisoning, también conocido como ARP Spoofing, es un tipo de ataque en redes de computadoras que se lleva a cabo en la capa de enlace de datos (capa 2 del modelo OSI). Este ataque explota el protocolo ARP (Address Resolution Protocol), que es utilizado en redes IPv4 para mapear direcciones IP a direcciones MAC de hardware. A continuación, te explico en detalle cómo funciona este ataque y sus implicaciones:

Funcionamiento del Protocolo ARP
- ARP en Redes Normales: Cuando un dispositivo en una red local quiere comunicarse con otro dispositivo, necesita conocer su dirección MAC. Si solo conoce la dirección IP, utiliza ARP para resolver la dirección MAC. Envía una solicitud ARP a todos los dispositivos en la red (broadcast) preguntando "¿Quién tiene esta dirección IP? Envíame tu dirección MAC".
- Respuesta ARP: El dispositivo con la dirección IP solicitada responde con su dirección MAC, y la comunicación puede comenzar.

Mecánica del ARP Poisoning
- Envío de Respuestas ARP Falsificadas: En un ataque de ARP Poisoning, el atacante envía respuestas ARP no solicitadas a la víctima, a la puerta de enlace de la red, o a ambos. Estas respuestas contienen la dirección MAC del atacante en lugar de la dirección MAC real correspondiente a la dirección IP solicitada.
- Modificación de la Tabla ARP: Como resultado, la víctima y/o la puerta de enlace actualizan sus tablas ARP con la información falsa, asociando la dirección IP del dispositivo objetivo (por ejemplo, la puerta de enlace) con la dirección MAC del atacante.
- Intercepción del Tráfico: Con las tablas ARP modificadas, el tráfico que se supone debe ir al dispositivo objetivo es enviado al atacante. Esto permite al atacante interceptar, leer o modificar los datos antes de reenviarlos al destinatario original, si así lo decide.

Objetivos y Consecuencias
- Man-In-The-Middle (MITM): El atacante se coloca entre dos partes que creen estar comunicándose directamente entre sí. Puede espiar o alterar la comunicación.
- Denegación de Servicio (DoS): Si el atacante no reenvía los paquetes interceptados, puede interrumpir la comunicación, resultando en un ataque de DoS.
- Suplantación de Identidad y Ataques a la Privacidad: El atacante puede obtener acceso no autorizado a datos confidenciales, como credenciales de inicio de sesión y otra información personal.

-----------------------------------------
### El Protocolo ARP
El Protocolo ARP (Address Resolution Protocol) es un protocolo de red que se utiliza para traducir direcciones de nivel de red (como direcciones IP) en direcciones físicas de nivel de enlace (como direcciones MAC). Cuando un dispositivo necesita enviar datos a otro dispositivo en una red, utiliza la dirección IP del dispositivo de destino para localizarlo. Sin embargo, la dirección IP no es suficiente para enviar los datos directamente al dispositivo de destino, ya que se necesita la dirección física de nivel de enlace para poder enviar los datos a través de la red. Es aquí donde entra en juego el Protocolo ARP. Cuando un dispositivo necesita la dirección física de nivel de enlace de otro dispositivo en la misma red, utiliza el Protocolo ARP para enviar una solicitud de "Quién es" ("Who is") que contiene la dirección IP del dispositivo de destino. El dispositivo que tiene la dirección IP solicitada responde con un mensaje que contiene su dirección física de nivel de enlace. De esta manera, el dispositivo que inició la solicitud ARP puede obtener la dirección física de nivel de enlace del dispositivo de destino y enviar los datos a través de la red.

-------------------------------------------
### ¿ARP Spoofing es igual que ARP poisoning?
Sí, "ARP Spoofing" y "ARP Poisoning" se refieren básicamente al mismo tipo de ataque en el contexto de la seguridad de redes informáticas. Ambos términos describen un proceso en el que un atacante envía mensajes ARP (Address Resolution Protocol) falsificados en una red local (LAN). El objetivo de este ataque es asociar la dirección MAC (Media Access Control) del atacante con la dirección IP de otro host, como la puerta de enlace predeterminada (router) o un servidor específico, lo que permite al atacante interceptar o modificar el tráfico de red destinado a ese host.

A pesar de que los términos se usan indistintamente, pueden enfocarse ligeramente en diferentes aspectos del ataque:
- ARP Spoofing tiende a enfocarse en el acto de enviar mensajes ARP falsificados para engañar a los dispositivos en la red. Es decir, "spoofing" (suplantación) se refiere a la falsificación de la identidad de un dispositivo.
- ARP Poisoning se centra más en el resultado del ataque: "envenenar" las tablas ARP de otros dispositivos en la red con direcciones MAC incorrectas.

----------------------------------------
### El ARP Spoofing (Suplantación ARP)
El ARP Spoofing (Suplantación ARP) es una técnica de ataque informático en la que un atacante envía mensajes ARP falsos en una red local para asociar su propia dirección MAC con la dirección IP de otro dispositivo legítimo en la misma red. En una red local, cada dispositivo tiene una dirección IP única y una dirección MAC única. La dirección IP se utiliza para enrutar el tráfico de red a través de la red, mientras que la dirección MAC se utiliza para enrutar el tráfico dentro de la red local. El Protocolo ARP se utiliza para asociar las direcciones IP con las direcciones MAC en la red. En un ataque ARP Spoofing, un atacante envía mensajes ARP falsos a otros dispositivos en la red, informando de que la dirección IP del dispositivo legítimo apunta a la dirección MAC del atacante en lugar de su propia dirección MAC. Esto puede hacer que otros dispositivos de la red envíen tráfico al atacante en lugar del dispositivo legítimo, lo que permite al atacante interceptar, modificar o redirigir el tráfico de red.

Se trata de la construcción de tramas de solicitud y respuesta ARP modificadas con el objetivo de envenenar la tabla ARP (relación de las direcciones IP-MAC) de una víctima y forzarla a que envíe los paquetes a un equipo atacante, en lugar de hacerlo a su destino legítimo.

El protocolo Ethernet trabaja mediante direcciones MAC, no mediante direcciones IP. Cuando un host quiere comunicarse con una IP emite una trama ARP-Request a la dirección de Broadcast, pidiendo la MAC del host poseedor la IP con la que quiere comunicarse. El ordenador con la IP solicitada responde con un ARP-Reply indicando su MAC. Los Switches y los ordenadores guardan una tabla local con la relación direcciones IP-MAC llamada "tabla ARP". Dicha tabla ARP puede ser falseada por un computador atacante que emita tramas ARP-REPLY indicando su MAC como destino válido para una IP específica, como por ejemplo la de un router, de esta manera la información dirigida al router pasaría por el computador atacante quien podrá escuchar dicha información y redirigirla, si así lo desea.

El protocolo ARP trabaja a nivel de la capa de enlace de datos del modelo OSI, por lo que esta técnica sólo puede ser utilizada en el segmento de red o vlan.


----------------------------------------
Este laboratorio necesita una red nat que compartirán las máquinas virtuales.


Este laboratorio cuenta con dos máquina virtuales:
- Windows 10 con configuración de la red: red nat. IP 10.0.2.15 - MAC: 08-00-27-8A-47-EB
- Ubuntu 23.10 con configuración de la red: red nat. IP: 10.0.2.4 - MAC: 08:00:27:ab:bd:f3

Comprobamos que la máquina virtual linux vea a la windows:
```
ping 10.0.2.15
PING 10.0.2.15 (10.0.2.15) 56(84) bytes of data.
64 bytes from 10.0.2.15: icmp_seq=1 ttl=128 time=0.942 ms
64 bytes from 10.0.2.15: icmp_seq=2 ttl=128 time=0.509 ms
64 bytes from 10.0.2.15: icmp_seq=3 ttl=128 time=0.995 ms
^C
--- 10.0.2.15 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2043ms
rtt min/avg/max/mdev = 0.509/0.815/0.995/0.217 ms
```


Comprobamos que la máquina virtual windows vea a la Linux:
```
C:\Windows\system32>ping 10.0.2.4
Haciendo ping a 10.0.2.4 con 32 bytes de datos:
Respuesta desde 10.0.2.4: bytes=32 tiempo<1m TTL=64
Respuesta desde 10.0.2.4: bytes=32 tiempo=1ms TTL=64
Respuesta desde 10.0.2.4: bytes=32 tiempo=1ms TTL=64
Respuesta desde 10.0.2.4: bytes=32 tiempo=1ms TTL=64

Estadísticas de ping para 10.0.2.4:
    Paquetes: enviados = 4, recibidos = 4, perdidos = 0
    (0% perdidos),
Tiempos aproximados de ida y vuelta en milisegundos:
    Mínimo = 0ms, Máximo = 1ms, Media = 0ms
```

En la máquina Windows:
- No hace falta desactivar el antivirus de Windows. Funciona igualmente.
- Abrimor Wireshark  para snifar el tráfico.
- Comprobamos en la máquina windows la tabla de arp que tiene:
  ```
  arp -a
  Interfaz: 10.0.2.15 --- 0x4
  Dirección de Internet          Dirección física      Tipo
  10.0.2.1              52-54-00-12-35-00     dinámico
  10.0.2.255            ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  224.0.0.251           01-00-5e-00-00-fb     estático
  224.0.0.252           01-00-5e-00-00-fc     estático
  239.255.255.250       01-00-5e-7f-ff-fa     estático
  255.255.255.255       ff-ff-ff-ff-ff-ff     estático
  ```



En la máquina Linux instalamos dsniff y lanzamos el ataque unos segundos:
```
sudo apt-get install dsniff
sudo apt install nmap
sudo nmap --iflist
[sudo] contraseña para usuario: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-03 20:29 CET
************************INTERFACES************************
DEV     (SHORT)   IP/MASK       TYPE     UP MTU   MAC
lo      (lo)      127.0.0.1/8   loopback up 65536
lo      (lo)      ::1/128       loopback up 65536
enp0s3  (enp0s3)  10.0.2.4/24   ethernet up 1500  08:00:27:AB:BD:F3
docker0 (docker0) 172.17.0.1/16 ethernet up 1500  02:42:1B:03:99:67

**************************ROUTES**************************
DST/MASK       DEV     METRIC GATEWAY
10.0.2.0/24    enp0s3  100
172.17.0.0/16  docker0 0
169.254.0.0/16 enp0s3  1000
0.0.0.0/0      enp0s3  100    10.0.2.1
::1/128        lo      0
::1/128        lo      256
sudo arpspoof -i [interfazAtancante] -t [ipVíctima] [ipPuertaEnlace]
sudo arpspoof -i enp0s3 -t 10.10.10.5 10.10.10.1
```
![](capturas/arp-spoof-attack.png)
