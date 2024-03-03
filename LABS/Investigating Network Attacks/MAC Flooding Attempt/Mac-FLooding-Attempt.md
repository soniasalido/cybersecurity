## Mac-FLooding-Attempt

"Mac-Flooding-Attempt" se refiere a un intento de inundación de direcciones MAC (Media Access Control). Es un tipo de ataque a redes que afecta a los switches. Los switches normalmente mantienen una tabla de direcciones MAC para saber a qué puerto enviar los paquetes de datos para una dirección MAC dada. En un ataque de inundación de MAC, el atacante satura la tabla de direcciones MAC del switch con direcciones falsas.

Esto se hace enviando una gran cantidad de paquetes de red con diferentes direcciones MAC de origen. Como resultado, la tabla de direcciones MAC del switch se llena rápidamente. Una vez que la tabla está llena, el switch no puede añadir nuevas entradas y comienza a comportarse como un hub, enviando paquetes a todos los puertos en lugar de solo al puerto que corresponde a la dirección MAC de destino. Esto puede permitir al atacante espiar el tráfico de la red o interrumpir la comunicación.

Los ataques de inundación de MAC pueden ser particularmente problemáticos en entornos de red donde la seguridad no es robusta, permitiendo que los atacantes exploten fácilmente esta vulnerabilidad. Para mitigar este tipo de ataques, los administradores de red pueden emplear varias técnicas, como la limitación del número de direcciones MAC que pueden aprender los puertos del switch, el uso de seguridad de puerto (port security) para restringir los dispositivos que pueden conectarse a un puerto de switch, o la implementación de sistemas de detección y prevención de intrusiones.

## Mac-FLooding-Attempt es igual Mac Poisoning?
No, "Mac-Flooding-Attempt" y "MAC Poisoning" no son lo mismo, aunque ambos son tipos de ataques a redes que involucran direcciones MAC.
- MAC Flooding: Es un ataque de inundación de MAC (MAC Flooding) busca saturar la tabla de direcciones MAC de un switch. En este ataque, el atacante envía una gran cantidad de paquetes con direcciones MAC de origen falsas. Esto puede hacer que la tabla de direcciones MAC del switch se llene y comience a enviar paquetes a todos los puertos indiscriminadamente, lo que potencialmente permite al atacante capturar tráfico de la red.

- MAC Poisoning: Por otro lado, el envenenamiento de MAC (MAC Poisoning) es un tipo de ataque más específico, comúnmente asociado con ataques como ARP poisoning (envenenamiento ARP). En este caso, el atacante envía mensajes ARP falsos a la red. Esto puede hacer que los dispositivos de la red asocien direcciones IP incorrectas con direcciones MAC, dirigiendo el tráfico de la red hacia el atacante en lugar de su destino legítimo. Este tipo de ataque es común en los ataques de "man-in-the-middle", donde el atacante intercepta y posiblemente altera la comunicación entre dos partes sin que ellas lo sepan.

