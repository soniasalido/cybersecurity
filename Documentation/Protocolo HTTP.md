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
Para superar esta limitación, se utilizan tecnologías como las cookies y el manejo de sesiones. Las cookies se gestionan mediante el uso de cabeceras HTTP:
- 
