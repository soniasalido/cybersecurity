# Zerologon PCAP Overview
Hemos recopilado archivos PCAP de un exploit reciente de Windows Active Directory llamado Zerologon o CVE-2020-1472. El escenario dentro del archivo PCAP contiene un controlador de dominio de Windows con una IP privada de 192.168.100.6 y un atacante con una IP privada de 192.168.100.128. Repasemos los pasos para analizar el PCAP y llegar a una hipótesis de los eventos que sucedieron.

1[](https://assets.tryhackme.com/additional/wireshark101/49.png)


## Identificar al atacante
Inmediatamente al abrir el archivo PCAP vemos algunas cosas que pueden estar fuera de lo común. Primero, vemos algo de tráfico normal de OpenVPN, ARP, etc. Luego comenzamos a identificar lo que se conocería como protocolos desconocidos en este caso DCERPC y EPM.

Al observar los paquetes, vemos que 192.168.100.128 envía todas las solicitudes, por lo que podemos asumir que el dispositivo es el atacante. Podemos seguir buscando paquetes provenientes de esta IP para limitar nuestra búsqueda.

![](https://assets.tryhackme.com/additional/wireshark101/50.png)

### Análisis de Conexión POC de Zerologon
El "Análisis de Conexión POC de Zerologon" se refiere al análisis de una conexión utilizando una Prueba de Concepto (Proof of Concept, POC) para el exploit Zerologon. Zerologon es una vulnerabilidad crítica (CVE-2020-1472) en el protocolo Netlogon, que se utiliza en sistemas Windows Server para autenticar usuarios y máquinas en redes de dominio de Windows. Esta vulnerabilidad permite a un atacante con acceso a la red de una organización comprometer el controlador de dominio de Windows fácilmente, otorgándole privilegios de administrador de dominio sin necesidad de autenticación previa.

El "Análisis de Conexión POC de Zerologon" implica examinar cómo una conexión específica puede ser explotada o probada para vulnerabilidades utilizando una Prueba de Concepto de Zerologon. Esto incluiría observar el proceso de explotación, entender cómo se puede comprometer la seguridad del sistema mediante esta vulnerabilidad y evaluar las implicaciones de seguridad de utilizar el exploit en un entorno controlado. Este tipo de análisis es crucial para comprender la gravedad de la vulnerabilidad y para desarrollar medidas de mitigación adecuadas.

![](https://assets.tryhackme.com/additional/wireshark101/50.png)

Al analizar PCAPs, necesitamos estar conscientes de los IOC o Indicadores de Compromiso que los exploits particulares puedan tener asociados. Esto se conoce como Inteligencia de Amenazas. En este caso el exploit zerologon utiliza múltiples conexiones RPC y solicitudes DCERPC para cambiar la contraseña de la cuenta de la máquina, lo cual podría verificarse con el PCAP.


### Análisis de Secretsdump SMB
Al examinar más detenidamente el PCAP, podemos ver tráfico SMB2/3 y tráfico DRSUAPI, nuevamente, con conocimiento previo del ataque sabemos que utiliza secretsdump para volcar hashes. Secretsdump abusa de SMB2/3 y DRSUAPI para hacer esto, por lo tanto, podemos asumir que este tráfico es de secretsdump.

![](https://assets.tryhackme.com/additional/wireshark101/51.png)
