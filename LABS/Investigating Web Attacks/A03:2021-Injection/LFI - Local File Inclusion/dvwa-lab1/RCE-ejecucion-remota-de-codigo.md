# Ejecución remota de código (RCE) mediante Log Poisoning
Para realizar un ataque de ejecución remota de código aprovechando una vulnerabilidad de inclusión de archivos locales (LFI), es necesario encontrar una manera de introducir código malicioso en un archivo del sistema, de tal forma que este código pueda ejecutarse en un momento posterior cuando se acceda al archivo mediante LFI. Una estrategia para conseguir esto es mediante el "envenenamiento de registros" o "log poisoning".

Este enfoque se basa en dos requisitos principales:
- Primero, es esencial poder acceder a un archivo de registro (log) o cualquier otro archivo que documente eventos del sistema a través del LFI. Estos archivos son útiles porque suelen ser accesibles para leer y, a menudo, se almacenan en ubicaciones estándar conocidas.
- Segundo, es necesario tener la capacidad de añadir, o "escribir", el código malicioso deseado dentro de estos archivos de registro. Esto se puede lograr mediante acciones que generen entradas en los registros, como errores forzados o solicitudes específicas que el servidor web registre automáticamente.
  
La idea es manipular estos registros de forma que el código malicioso que se quiere ejecutar se inserte en ellos. Luego, al acceder al archivo de registro mediante LFI, el servidor web puede procesar el código malicioso como parte de su contenido, llevando a cabo la ejecución del código.

Una forma de lograrlo es envenenando el fichero /var/log/apache2/access.log de Apache. En este fichero se registran todos los accesos al servidor web con los siguientes datos: IP de origen, fecha de acceso, recursos solicitados, Estado HTTP, y User-Agent.

El Valor **User-Agent** es una cadena de texto que los navegadores web y otros clientes de internet envían a los servidores web al realizar una solicitud. Esta cadena contiene información sobre el navegador, su versión, el sistema operativo en el que está corriendo, y, en algunos casos, detalles sobre otros softwares o herramientas que están siendo utilizados. El propósito del valor User-Agent es identificar el tipo de cliente que hace la solicitud al servidor, permitiendo así que el servidor pueda ofrecer una respuesta optimizada para ese cliente específico.

Por ejemplo, un servidor web puede usar la información del User-Agent para decidir si debe enviar una página web diseñada para móviles o una versión para escritorio, o si necesita ofrecer contenido específico compatible con ciertas versiones de navegadores. Además, los desarrolladores web pueden usar esta información para realizar análisis y ajustes en sus sitios, asegurándose de que funcionen correctamente en diferentes navegadores y dispositivos.


Este dato se puede manipular a través de un proxy web como BurpSuite o ZAP. El ataque consiste en insertar código PHP malicioso que quedará registrado en el log. Realizamos un acceso normal a cualquier sitio web que tenga una LFI detectada y se intercepta la petición con BurpSuite. Una ver interceptada, se cambia el valor de la cabecera User_agent por código malicioso que interprete el servidor web atacado (PHP en este caso) para que su valor ae registre en un fichero de log ( en apache, access.log).
```
User-Agent: <?php system('uname -a'); ?>
```

**Proceso para el RCE:**

1º Es neceario insertar código malicioso en algún fichero del servidor; para ello, el mecanismo más sencillo y habitual es envenenando algún fichero de log (log poisoning): Se envía una petición modificada por el proxy al servidor cambiando el User-Agent → User-Agent: <?php system('uname -a'); ?>

2º Es necesario poder acceder al fichero invenenado y cargarlo en la web para que el código sea ejecutado por el servidor. Esto se condigue mediante LFI: Accedemos vía LFI al archivo /var/log/apache2/access.log. AL cargar este fichero, el servidor Apache ejecutará el contenido como código, interpretará el código PHP inyectado en la cabecera User-Agent.
![](capturas/ejecucion-remota-de-codigo.png)


Una vez que se ha conseguido la capacidad de lograr la ejecución de código remoto (RCE), es posible obtener una shell reversa en la víctima. [Shell Reversas](https://github.com/soniasalido/cybersecurity/blob/main/Documentation/Acciones%20en%20una%20m%C3%A1quina%20explotada/acciones-en-una-maquina-explotada.md)

**Otros ficheros interensantes para hacer log poisoing:**
- /var/log/auth.log → Es posible envenenarlo tratando de autenticarse con un usuario como:
  ```
  ssh <?  php system($_GET['cmd']);?>@ip_victima
- /var/log/vsftp.log → Si el servidor vsftp está instalado, se puede acceder al servidor FTP poniendo como nombre de usuario un código FTP.
- /var/log/apache2/error.log
- /proc/self/environ → Se puede escribir en el haciendo solicitudes HTTP y modificando la cabecera User-Agent para escribir código PHP.
- /proc/self/fd → Se puede intentar escribir en él modificando la cabecera Referer.

