# Puertos
## Estado de un puerto
Los puertos de comunicaciones tienen dos Estados: alcanzable e inalcanzable. Un puerto es “alcanzable” si no existe ninguna causa externa (p.ej. filtros intermedios) que evite el contacto entre los extremos. De este modo el origen tendrá información de si dicho puerto está a la escucha o está cerrado. Será “inalcanzable” en cualquier otro caso. Los puertos UDP abiertos, al no negociar una conexión de manera implícita, pueden dar la apariencia de que son inalcanzables.



# Escaneo y bloqueo de TCP Scan
Sintaxis:
```
nmap <scan types> <options> <target>
```

**Arquitectura Nmap:**
Nmap ofrece muchos tipos diferentes de escaneos que pueden usarse para obtener varios resultados sobre nuestros objetivos. Básicamente, Nmap se puede dividir en las siguientes técnicas de escaneo:
    • Descubrimiento de host
    • Escaneo de puertos
    • Enumeración y detección de servicios
    • Detección de sistema operativo
    • Interacción programable con el servicio de destino (Nmap Scripting Engine)

**Técnicas de escaneo:**
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
