# HTPP

El Protocolo de Transferencia de Hipertexto (HTTP) es el protocolo de comunicación que se utiliza para transferir información en la World Wide Web. Es la base de cualquier intercambio de datos en la web, y **funciona como un protocolo de solicitud-respuesta entre un cliente y un servidor**.

**Es un protocolo de la capa de aplicación.** Originalmente diseñado para el intercambio de hipertexto. Un hipertexto es un sistema de organización de la información en formato digital que permite establecer conexiones no lineales entre diferentes documentos o secciones de un mismo documento. La World Wide Web es el ejemplo más conocido y extenso de hipertexto, donde las páginas web están interconectadas mediante enlaces, formando una vasta red de información. 

## Es un protocolo cliente-servidor
En el que se realizan peticiones (HTTP request) de recursos por parte de un cliente, y que generan las correspondientes respuestas (HTTP response) por parte del servidor.

En la version 1.1, estas peticiones y respuestas se transmiten en texto plano. Las peticiones y respuestas entre el servidor y el cliente en el protocolo HTTP tradicional se transmiten en texto plano, sin encriptación. Esto significa que la información enviada y recibida puede ser leída fácilmente si es interceptada, lo cual plantea problemas de seguridad, especialmente cuando se trata de información sensible como contraseñas, datos personales, o información financiera. Para abordar este problema, se desarrolló HTTPS (HTTP Secure), una extensión de HTTP. HTTPS utiliza el protocolo SSL/TLS para encriptar las comunicaciones entre el cliente y el servidor. Esto asegura que, incluso si los datos son interceptados, estarían cifrados y, por lo tanto, serían incomprensibles para el interceptor.

## HTTP se usa para:
- Intercambio de contenido HTML.
- Intercambio de datos entre aplicaciones distribuidas, como por ejemplo:
  - REST.
  - SOAP
  - ...

## HTTP es un protocolo sin estado:
Está basado en un modelo solcitus-respuesta. El cliente hace una solicitud (HHTP request) y el servidor constesta con una respuesta (HTTP response).

**Sin estado significa** que no mantiene información sobre las transacciones anteriores. En el contexto de HTTP, cada solicitud y respuesta es independiente. El servidor no guarda un registro o estado de las interacciones previas con un cliente en particular.

**Independencia de las Solicitud-Respuesta:** En HTTP, cada par de solicitud-respuesta es tratado como un evento completamente independiente. El servidor procesa cada solicitud sin referencia a las solicitudes anteriores.

**Implicaciones para la Interacción Usuario-Servidor:** Debido a esta característica, el servidor web no reconoce a los usuarios de una solicitud a otra. Por ejemplo, si navegas por diferentes páginas de un sitio web, el servidor HTTP no tiene una forma incorporada de saber que todas esas solicitudes provienen del mismo navegador o usuario.

**Manejo de Sesiones y Cookies:** Para superar esta limitación, se utilizan tecnologías como las cookies y el manejo de sesiones. Las cookies son pequeños archivos de datos que se guardan en el navegador del cliente y pueden llevar información como identificadores de sesión o preferencias del usuario. De esta manera, aunque HTTP como protocolo no mantiene el estado, las aplicaciones web pueden "recordar" usuarios y sesiones a través de las cookies.

**Ventajas y Desventajas:** La naturaleza sin estado de HTTP lo hace simple y eficiente para transacciones básicas de la web, pero también significa que cualquier funcionalidad adicional que requiera "recordar" el estado necesita ser manejada a un nivel superior (a través de aplicaciones web, por ejemplo).

## HTTP cookies
Para superar esta limitación, se utilizan tecnologías como las cookies y el manejo de sesiones. Las cookies se gestionan mediante el uso de cabeceras HTTP en las comunicaciones entre el navegador del cliente y el servidor web:
- **Estableciendo Cookies**:
  - Desde el Servidor: Cuando visitas un sitio web, el servidor puede enviar una o más cookies al navegador del cliente. Esto se hace mediante la cabecera "Set-Cookie" en la respuesta HTTP del servidor. Por ejemplo, después de iniciar sesión en un sitio web, el servidor puede enviar una cookie con un identificador de sesión.
  - Formato de la Cabecera "Set-Cookie": La cabecera incluye el nombre de la cookie, su valor, y otros atributos opcionales como la fecha de expiración, el dominio, la ruta, y directivas de seguridad (como "Secure" y "HttpOnly").
- **Enviando Cookies de Vuelta al Servidor:**
  - Desde el Cliente: Una vez que el navegador recibe una cookie y la almacena, la incluirá en todas las solicitudes HTTP posteriores al mismo servidor. Esto se hace mediante la cabecera "Cookie".
- **Gestión y Seguridad de las Cookies:**
  - Atributos de Seguridad: Las cookies pueden tener atributos que definen cómo se deben manejar y cuán seguras deben ser. Por ejemplo, una cookie marcada como "Secure" solo se enviará a través de conexiones HTTPS.
  - HttpOnly: Este atributo impide que las cookies sean accesibles mediante scripts del lado del cliente, como JavaScript. Esto ayuda a mitigar ciertos tipos de ataques, como el Cross-Site Scripting (XSS).
- **Fecha de Expiración:** Indica cuando caduca la cookie. Cuando expira el cliente deja de enviarla al servidor.  La expiración de la cookie se maneja completamente en el lado del cliente. Tipos de cookies con respecto a su expiración:
  - Se sesión: No incluyen Expires o Max-age. Se eliminan tan pronto como el cliente se cierra.
  - Permanentes: No se eliminan al cerrar el cliente, sino cuando expira en la fecha indicada por el atributo Expires, o tras un peiodo de tiempo indicado en el atributo Max-Age.

- Formato de la cabecera:
  - nombre:valor.
  - Expires | Max-Age.
  - Domain: Especifica a qué dominios y subdominios debe el cliente enviar la cookie. Si no se especifica, el cliente la enviará sólo al dominio del que la recibirá. Si se especifica un dominio, se enviará a este y a sus subdominios.
  - Path: Si se incluye, es una ruta que debe existir en la URL de la petición para enviar la cookie.
  - Atributos de seguridad: Configuran aspectos relativos a la seguridad de las cookies:
    - Samesite.
    - HttpOnly.
    - Secure.
    
```
Set-Cookie: SessionID=abc123; Expires=Wed, 09 Jun 2024 10:18:14 GMT; Path=/; Secure; HttpOnly
```
Nombre y Valor: SessionID=abc123. Aquí, "SessionID" es el nombre de la cookie y "abc123" es su valor, que es un identificador único de la sesión del usuario.
Expires: Expires=Wed, 09 Jun 2024 10:18:14 GMT. Este atributo especifica una fecha y hora en la que la cookie expirará y será eliminada automáticamente. En este ejemplo, la cookie está configurada para expirar el 9 de junio de 2024 a las 10:18:14 GMT.
Path: Path=/. Esto limita la cookie al directorio raíz ("/") del servidor, lo que significa que la cookie se enviará en todas las solicitudes a cualquier ruta del mismo dominio.
Secure: Este atributo indica que la cookie solo debe enviarse a través de una conexión segura (HTTPS). Esto ayuda a proteger los datos de la cookie durante el tránsito entre el navegador y el servidor.
HttpOnly: El atributo HttpOnly incrementa la seguridad al restringir el acceso a la cookie por parte de scripts del lado del cliente, como JavaScript. Esto ayuda a prevenir ataques de tipo Cross-Site Scripting (XSS).
