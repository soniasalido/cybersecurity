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
- Nombre y Valor: SessionID=abc123. Aquí, "SessionID" es el nombre de la cookie y "abc123" es su valor, que es un identificador único de la sesión del usuario.
- Expires: Expires=Wed, 09 Jun 2024 10:18:14 GMT. Este atributo especifica una fecha y hora en la que la cookie expirará y será eliminada automáticamente. En este ejemplo, la cookie está configurada para expirar el 9 de junio de 2024 a las 10:18:14 GMT.
- Path: Path=/. Esto limita la cookie al directorio raíz ("/") del servidor, lo que significa que la cookie se enviará en todas las solicitudes a cualquier ruta del mismo dominio.
- Secure: Este atributo indica que la cookie solo debe enviarse a través de una conexión segura (HTTPS). Esto ayuda a proteger los datos de la cookie durante el tránsito entre el navegador y el servidor.
- HttpOnly: El atributo HttpOnly incrementa la seguridad al restringir el acceso a la cookie por parte de scripts del lado del cliente, como JavaScript. Esto ayuda a prevenir ataques de tipo Cross-Site Scripting (XSS).

# Seguridad en HTTP.
Principal iniciativa para la seguridad en HTTP es HTTPS (HTTP Secure). HTTPS es el mismo protocolo HTTP en el que se utiliza un túnel cifrado de extremo aextremo entre el cliente y el servidor web.

- HTTPS proporciona tres serivicios básicos:
  - Encripta la Información Enviada y Recibida: En lugar de enviar datos como texto que cualquiera puede leer, HTTPS los transforma en un código secreto. Esto es como si tus mensajes se convirtieran en un rompecabezas que solo tú y el sitio web al que estás accediendo pueden resolver. De esta manera, incluso si alguien logra interceptar lo que estás enviando o recibiendo, no podrá entenderlo.
  - Verifica Quién Está en el Otro Extremo de la Conexión: HTTPS actúa como un verificador de identidad para los sitios web. Utiliza algo llamado certificado digital para confirmar que el sitio web es realmente quien dice ser. Es como si el sitio web tuviera una identificación oficial que tú puedes verificar para asegurarte de que no estás hablando con un impostor.
  - Asegura que los Datos No se Han Modificado Durante la Transmisión: Garantiza que lo que envías y recibes llegue exactamente como se envió originalmente, sin cambios ni alteraciones por parte de terceros.

Para que el túnel cifrado sea posible se usa el protocolo TLS (Transport Layer Security). TLS es una evolución del protocolo SSL (Secure Socket Layer).

## TLS
TLS, que significa "Transport Layer Security" (Seguridad de la Capa de Transporte), es un protocolo de seguridad diseñado para proporcionar comunicaciones seguras en una red informática. Facilita la privacidad y la seguridad de los datos en las comunicaciones por Internet. 

- Usos:
  - Encripta las comunicaciones entre aplicaciones web y servidores.
  - Encriptar otras comunicaciones como:
    - El correo electrónico.
    - Los mensajes.
    - La voz sobre IP (VoIP).

- Encriptación de Datos: TLS es ampliamente utilizado para encriptar la transferencia de datos entre un usuario y un servidor, lo que asegura que la información intercambiada permanezca privada y segura. Esto es especialmente importante para actividades sensibles como transacciones bancarias en línea, compras, y el intercambio de información personal.

- Sucesor de SSL: TLS es el sucesor del protocolo Secure Sockets Layer (SSL), aunque a menudo los términos SSL y TLS se utilizan indistintamente. TLS proporciona mejoras y fortalece la seguridad comparado con SSL, que ya está en desuso debido a varias vulnerabilidades de seguridad descubiertas.

- TLS y SSL usan una PKI (Public Key Infraestructure), en la que el servidor posee un certificado TSL, firmado por una autoridad de certificaciñon, que contiene dos claves: una pública y una privada. Se trata de un esquema de cifrado híbrido en el que la clave pública se usa para compartir una clave de sesión entre el cliente y el servidor con la que se cifra la comunicación.

- Cómo Funciona TLS:
  - Negociación de Conexión: Cuando un cliente (como un navegador web) se conecta a un servidor que utiliza TLS (como un sitio web HTTPS), primero realizan un "apretón de manos" (handshake). Durante este proceso, acuerdan los detalles de cómo se cifrará la comunicación, incluyendo la selección de un protocolo de encriptación y el intercambio de claves de encriptación.
  - Autenticación y Certificados: TLS utiliza certificados digitales, emitidos por Autoridades de Certificación (CA), para autenticar la identidad del servidor. Esto asegura al cliente que está conectándose al servidor correcto y no a un impostor.
  - Encriptación: Una vez que se establece la conexión segura, los datos transmitidos están encriptados, lo que significa que aunque sean interceptados, no podrán ser leídos o alterados sin la clave de descifrado adecuada.
 

## Cómo actúa TLS tras la apertura de una conexión TCP para iniciar una conversación HTTP desde el cliente:
- Inicio de la Conexión TCP: Antes de que pueda comenzar cualquier intercambio de datos seguro utilizando TLS, primero se debe establecer una conexión básica entre el cliente (por ejemplo, tu navegador) y el servidor. Esta conexión se realiza a través del Protocolo de Control de Transmisión (TCP), que es un protocolo estándar para enviar datos por Internet. El TCP asegura que los paquetes de datos lleguen de manera íntegra y en orden.

- Negociación de TLS (El "Handshake"):
  - Una vez que la conexión TCP está establecida, el cliente y el servidor comienzan el proceso de "apretón de manos" de TLS. Este es el momento en que TLS realmente entra en juego.
  - Durante el "handshake", el cliente y el servidor acuerdan los detalles de cómo se cifrarán y verificarán las comunicaciones. Esto incluye seleccionar una versión de TLS, elegir algoritmos de cifrado, y autenticar al servidor (y en algunos casos al cliente) mediante certificados digitales.

- Intercambio de Claves: Parte del proceso de "handshake" implica el intercambio de claves de cifrado. Esto generalmente se hace utilizando un método de cifrado asimétrico para intercambiar una clave de sesión, que luego se utiliza para el cifrado simétrico de la comunicación durante esa sesión.

- Comunicación  Segura HTTP sobre TLS:
  - Una vez completado el "handshake", toda la comunicación entre el cliente y el servidor se cifra utilizando la clave de sesión acordada. Esto significa que cualquier dato enviado (como parte de una solicitud HTTP) está cifrado y solo puede ser descifrado por el receptor, que posee la clave correcta.
  - Esto convierte la conexión HTTP inicial, que es no segura por defecto, en una conexión HTTPS segura, donde "S" representa la capa de seguridad añadida por SSL/TLS.

- Finalización de la Sesión TLS:
  - Después de que la comunicación segura haya terminado, la sesión TLS se cierra de forma segura, y la conexión TCP subyacente también se puede cerrar si ya no es necesaria.

![ttps://www.cloudflare.com/es-es/learning/ssl/transport-layer-security-tls/](https://cf-assets.www.cloudflare.com/slt3lc6tev37/5aYOr5erfyNBq20X5djTco/3c859532c91f25d961b2884bf521c1eb/tls-ssl-handshake.png)

## ¿En qué se diferencian TLS y HTTPS?
HTTPS es una implementación de la encriptación TLS en el protocolo HTTP, usado por todos los sitios web así como otros servicios web. Todos los sitios web que usan HTTPS emplean por tanto la encriptación TLS.

## ¿Qué ocurre durante un protocolo de enlace TLS? | Protocolo de enlace SSL
El algoritmo de intercambio de claves RSA, aunque ahora se considera que no es seguro, se utilizaba en las versiones de TLS anteriores a la 1.3. A grandes rasgos es como sigue -->
https://www.cloudflare.com/es-es/learning/ssl/what-happens-in-a-tls-handshake/#:~:text=Durante%20un%20protocolo%20de%20enlace%20TLS%2C%20las%20dos%20partes%20que,acordar%20las%20claves%20de%20sesi%C3%B3n


## 1. Cabeceras de Seguridad en HTTP
Las cabeceras de seguridad en HTTP son una serie de ajustes en las cabeceras HTTP que proporcionan capas adicionales de seguridad a las aplicaciones web. Estas cabeceras, enviadas en las respuestas del servidor web al navegador del cliente, ayudan a mitigar una variedad de vulnerabilidades y ataques comunes.

Hay herramientas de análisis automático de vulnerabilidades que comprueban estas cabeceras de seguridad. Pero se recomienda que se realice un pentester manual:
- https://www.youtube.com/watch?v=064yDG7Rz80
- https://www.youtube.com/watch?v=x_FxJxKIXl8

**Cabeceras de seguridad:**
- **Content Security Policy (CSP):** Esta cabecera ayuda a prevenir ataques de Cross-Site Scripting (XSS) y otros ataques basados en inyección. Permite a los administradores de sitios web especificar desde qué fuentes puede el navegador cargar recursos (como scripts, hojas de estilo, imágenes, etc.). De este modo, se evita la carga de recursos maliciosos.

- **HTTP Strict Transport Security (HSTS):** Esta cabecera asegura que el navegador solo se comunique con el servidor mediante una conexión segura HTTPS. Si un sitio web ha sido visitado previamente, HSTS obliga a las conexiones futuras a realizarse a través de HTTPS, incluso si el usuario intenta acceder mediante HTTP.

- **X-Content-Type-Options:** nosniff: Esta cabecera evita que el navegador intente "adivinar" un tipo de contenido diferente al declarado en la cabecera Content-Type. Ayuda a prevenir ataques que se basan en la carga de archivos no seguros o maliciosos.

- **X-Frame-Options:** Esta cabecera puede ser usada para controlar si un navegador debe permitir que una página sea renderizada en un <frame>, <iframe>, <embed> o <object>. Ayuda a proteger contra ataques de clickjacking, en los cuales un atacante engaña a un usuario para que haga clic en algo diferente a lo que el usuario cree que está haciendo.
- **X-XSS-Protection:** Aunque en gran parte obsoleto y sustituido por CSP, esta cabecera estaba diseñada para habilitar el filtro de XSS incorporado en algunos navegadores web.

- **Referrer-Policy:** Esta cabecera controla la cantidad de información de referencia que se incluye con los enlaces. Ayuda a proteger la privacidad cuando se enlaza a otros sitios, controlando la información que se envía en los encabezados del Referer.

- **Feature-Policy:** Permite a los desarrolladores web especificar qué características y APIs pueden ser utilizadas por el navegador mientras se carga el contenido de la página, limitando así el riesgo de ciertos tipos de ataques.


## 2. Uso seguro de HTTP Cookies
```
Set-Cookie: SessionID=abc123; Expires=Wed, 09 Jun 2024 10:18:14 GMT; Path=/; Secure; HttpOnly; SameSite=Strict
```
- La primera línea de seguridad son los **atributos Path y Domain** ya que permiten restringir dónde se enviará la cookie.
- Atributo SameSite:
  - Antes de la introducción del atributo SameSite en las cookies, los navegadores web tenían un comportamiento predeterminado en cuanto al manejo de cookies que podía presentar riesgos de seguridad. Cuando un usuario visitaba un sitio web, el navegador almacenaba las cookies emitidas por ese sitio. Luego, cada vez que el usuario realizaba una solicitud a ese mismo sitio, independientemente de dónde se originara la solicitud (es decir, desde el mismo sitio o desde un dominio externo), el navegador enviaba automáticamente todas las cookies relevantes para ese dominio con la solicitud. Con este comportamiento se podían producir ataques
    - CSRF --> Si un usuario había iniciado sesión en su banco en línea y luego visitaba un sitio malicioso, ese sitio podría forzar al navegador del usuario a enviar una solicitud al sitio del banco con las cookies de sesión del usuario, efectuando potencialmente una transacción no deseada sin el conocimiento del usuario.
    - Problemas de privacidad, ya que se podía hacer un track del comportamiento de navegación del usuario.
  - La introducción del atributo SameSite permitió a los desarrolladores web tener más control sobre este comportamiento, ofreciendo la capacidad de restringir cuándo se envían las cookies con las solicitudes.
  - Valores que puede tomar SameSite:
    - Strict.
    - Lax.
    - None:
- Atributo Secure:
- Atributo HttpOnly:

## 3. HTTP Access Control (CORS)

### 4. Ataque a HTTP


## Inspecionando un Request HTTP


## Inspeccionando un Response HTTP