La Inclusión de Archivos Remotos (RFI) es una versión de la Inclusión de Archivos Locales (LFI) que extiende su alcance. En RFI, un atacante logra hacer que la aplicación web, que se está ejecutando en el servidor, establezca una conexión con un servidor externo para cargar e incluir un archivo de este, en lugar de usar un archivo que ya esté en el propio servidor como sucede con LFI.

En cuanto a las dificultades asociadas con el envenenamiento de registros (log poisoning) al explotar LFI:
- La cuenta bajo la cual se ejecuta la aplicación web en el servidor necesita tener los derechos suficientes para leer los archivos de registro (logs) que el atacante desea manipular.
- Es necesario descubrir una forma de insertar código dañino en esos archivos de registro locales, lo cual podría lograrse mediante acciones como enviar ciertas cabeceras HTTP o generar errores intencionadamente.

Si fuera posible incluir archivos alojados en un servidor controlado por el atacante o en otra ubicación bajo su control, estas limitaciones se eliminarían, lo que haría mucho más sencilla la ejecución de código malicioso.

La vulnerabilidad de RFI surge principalmente por dos razones:
- La falta de una limpieza adecuada de las entradas proporcionadas por el usuario, lo que permite la introducción de URLs externas.
- Una configuración insegura o por defecto tanto en el servidor web como en las aplicaciones, que admite este tipo de inclusión de archivos. Un ejemplo claro de esto es tener habilitada la opción allow_url_include en la configuración de PHP, que permite la inclusión de archivos de fuentes externas.

Lenguajes susceptibles a estos ataques: PHP, ASP, JSP, Python...

Con un ataque RFI se puede conseguir:
- Defacement de Sitios Web: El "defacement" se refiere a la alteración visual de un sitio web, donde el contenido original se reemplaza con contenido creado por el atacante. Esto suele hacerse por motivos de vandalismo, para promover una agenda política o social, o simplemente para demostrar la vulnerabilidad del sitio. Con un ataque RFI, un atacante puede incluir un archivo remoto que contenga HTML, JavaScript u otro código que cambie la apariencia del sitio web o muestre un mensaje específico del atacante. Dado que el archivo está siendo incluido y ejecutado por el servidor web como parte de la página web, el contenido del archivo remoto se renderizará en el navegador del usuario, efectivamente cambiando la apariencia del sitio.

- Ejecución Remota de Comandos: Aún más peligroso es la capacidad de ejecutar comandos de forma remota en el servidor web a través de un ataque RFI. Esto puede lograrse si el atacante logra incluir un script PHP (o cualquier otro lenguaje de servidor que se esté ejecutando) desde un servidor remoto que el servidor web víctima ejecutará como suyo. Este script puede contener código que ejecute comandos en el servidor, lo que podría permitir al atacante tomar el control total del servidor web, acceder a bases de datos sensibles, modificar archivos del sistema, instalar malware, crear backdoors para acceso futuro, entre otras acciones maliciosas. La ejecución remota de comandos abre la puerta a una amplia gama de actividades perjudiciales que pueden comprometer la seguridad y la funcionalidad del servidor y de los datos alojados en él.

Ejemplo: Pagina 258 de hacking etico de J.L.Berenguel
