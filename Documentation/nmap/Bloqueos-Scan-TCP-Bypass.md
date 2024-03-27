
# Bloqueo de TCP Scan

## Bloqueo de escaneo de puertos abiertos
Rechazaremos SYN flags con IPTables en el ubuntu server. Aplicaremos un filtro de firewall que ahora evitará la comunicación de protocolo de enlace de 3 vías en la red y resistirá al atacante para realizar un escaneo TCP al rechazar el paquete SYN en la red.

Ejecutamos el siguiente comando para hacer una regla de filtrado para bloquear el paquete SYN en el ubuntu server→
```
iptables -I INPUT -p tcp --tcp-flags ALL SYN -j REJECT --reject-with tcp-reset
■ -I: Inserta una regla en una cadena en un punto especificado por un valor entero definido por el usuario.
■ INPUT: Cadenas por donde van a circular los paquetes dentro del sistema: Contiene los paquetes destinados al equipo local con cualquier origen.
■ -p: Configura el protocolo IP para la regla.
■ -cp-flags ALL SYN: Permite a los paquetes TCP con bits específicos o banderas, ser coincididos con una regla. Máscara que configura las banderas a ser examinadas en el paquete: ALL. Bandera que se debe configurar para poder coincidir: SYN.
■ -j REJECT: Salta a un objetivo particular cuando un paquete coincide con una regla particular. Objetivo: REJECT. Envía un paquete de error de vuelta al sistema remoto y deja caer el paquete.
■ --reject-with tcp-reset: El objetivo REJECT acepta --reject-with <tipo> (donde <tipo> es el tipo de rechazo) el cual permite devolver información más detallada con el paquete de error. Se rechaza con el tipo tcp-reset que se emplea para cerrar de una forma elegante conexiones TCP abiertas.
```



# Bypass del bloqueo de paquetes SYN del Firewall
Esta técnica se basa en enviar sondas TCP con distintos flags activados, como por ejemplo Null, FIN, Xmas. Se aprovecha de una indefinición en el estándar RFC 793 para provocar una respuesta en el objetivo que determine si un puerto está abierto o cerrado. El fundamento de esta técnica reside en que los puertos cerrados de equipos compatibles con esta RFC responderán con un RST a cualquier paquete que no contenga un flag SYN, RST o ACK, mientras que no emitirán respuesta alguna si el puerto está abierto.

Según las respuestas obtenidas, Nmap clasifica los puertos en:
- Abiertos/Filtrados: Si no se recibe ninguna respuesta.
- Cerrados: Si se recibe un paquete RST.
- Filtrados: Si se recibe algún tipo de error ICMP inalcanzable.

