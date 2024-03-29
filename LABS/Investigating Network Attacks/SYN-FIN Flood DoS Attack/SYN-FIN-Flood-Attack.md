El ataque de Denegación de Servicio (DoS) conocido como "SYN-FIN Flood" es una variante específica de los ataques de inundación que se llevan a cabo en redes informáticas. Este tipo de ataque explota el funcionamiento del protocolo TCP (Transmission Control Protocol), que es un estándar fundamental en la comunicación de datos en Internet y otras redes.

Funcionamiento de este ataque:
- Funcionamiento Normal de TCP: En una comunicación TCP normal, el establecimiento de una conexión sigue un proceso conocido como "handshake" de tres vías. Primero, el cliente envía un paquete SYN (synchronize) al servidor para iniciar la conexión. Luego, el servidor responde con un paquete SYN-ACK (synchronize-acknowledge), y finalmente, el cliente envía un paquete ACK (acknowledge) para confirmar.

- Paquetes SYN y FIN: En TCP, el flag SYN se utiliza para iniciar una conexión, mientras que el flag FIN se utiliza para finalizarla. Estos dos flags no están destinados a ser usados juntos en condiciones normales de operación.

- El Ataque SYN-FIN Flood: En un ataque SYN-FIN Flood, el atacante envía una gran cantidad de paquetes TCP al objetivo con ambos flags, SYN y FIN, activados. Este comportamiento es anómalo y no se ajusta a las especificaciones normales de TCP.

- Confusión y Sobrecarga del Servidor: Los servidores que reciben estos paquetes pueden comportarse de manera impredecible, ya que la combinación de flags SYN y FIN no representa un estado normal en el proceso de establecimiento o cierre de una conexión TCP. El servidor puede intentar procesar estos paquetes anómalos, lo que consume recursos y puede llevar a una sobrecarga.

- Denegación de Servicio: Como resultado de esta sobrecarga, el servidor puede volverse incapaz de manejar tráfico legítimo, lo que lleva a una denegación de servicio. Los usuarios legítimos del servidor experimentarán tiempos de respuesta lentos o la imposibilidad de conectarse.

Este tipo de ataque es un ejemplo de cómo los actores maliciosos pueden usar el conocimiento técnico del funcionamiento de los protocolos de red para interrumpir servicios en línea. Las medidas de protección contra ataques de este tipo incluyen la configuración de cortafuegos, la detección de anomalías en el tráfico de red y la mitigación de ataques en los proveedores de servicios de Internet (ISP) y en los propios servidores.

Este laboratorio cuenta con dos máquina virtuales:
- Windows 10 con configuración de la red: red interna. IP 10.10.10.5
- Ubuntu 23.10 con configuración de la red: red interna. IP: 10.10.10.3

Comprobamos que las máquina virtuales se vean haciendo un ping:
![](capturas/ping.png)
![](capturas/ping.win.png)


En la máquina Windows:
- No hace falta desactivar el antivirus de Windows. Funciona igualmente.
- Abrimor Wireshark  para snifar el tráfico.


El la máquina Linux usamos la herramienta hping3 para enviar paquetes con las flags SYN y FIN activadas:
```
sudo apt install hping3
sudo hping3 -S -F -p 80 10.10.10.5
```
![](capturas/SYN-FIN-Attack.png)


En la máquina Windows vemos el tráfico con Wireshark:
![](capturas/SYN-FIN-Attack-2.png)
```
14	7.560799	PCSSystemtec_ab:bd:f3	Broadcast	ARP	60	Who has 10.10.10.1? Tell 10.10.10.3
15	8.272117	10.10.10.3	10.10.10.5	TCP	60	2967 → 80 [FIN, SYN] Seq=0 Win=512 Len=0
16	8.580082	PCSSystemtec_ab:bd:f3	Broadcast	ARP	60	Who has 10.10.10.1? Tell 10.10.10.3
19	10.279783	10.10.10.3	10.10.10.5	TCP	60	2969 → 80 [FIN, SYN] Seq=0 Win=512 Len=0
21	11.282479	10.10.10.3	10.10.10.5	TCP	60	2970 → 80 [FIN, SYN] Seq=0 Win=512 Len=0

```

Filtro wireshark para detectar este ataque:
```
cp.flags.syn == 1 and tcp.flags.fin == 1
```


