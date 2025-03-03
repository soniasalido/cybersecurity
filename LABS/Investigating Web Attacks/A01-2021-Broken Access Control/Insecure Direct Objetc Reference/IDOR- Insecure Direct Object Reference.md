Pertenece a la categoría A01:2021 - Broken Access Control. La vulnerabilidad IDOR (Insecure Direct Object Reference), también conocida como BOLA (Broken Object Level Autorization), está catalogada con la categoría CWE-639 (Autprization Bypass Throuh User-Controlled Key).

La vulnerabilidad IDOR, o "Insecure Direct Object References" (Referencias Directas a Objetos Inseguras), es un tipo de vulnerabilidad de seguridad en aplicaciones web. Se produce cuando una aplicación proporciona acceso directo a objetos basándose en la entrada del usuario. En este contexto, un "objeto" puede referirse a varios elementos, como archivos, registros de bases de datos, directorios, o páginas web clave. Si no se implementa una política de control de acceso adecuada, un atacante podría manipular estas referencias para acceder a datos no autorizados.

### Cómo Funciona IDOR
Imaginemos una aplicación web que permite a los usuarios ver sus facturas mediante URLs que incluyen un identificador de factura, como http://ejemplo.com/facturas?id=1234. En un caso de IDOR, si los controles de acceso no están correctamente implementados, un atacante podría simplemente cambiar el valor del parámetro id en la URL a otro número, http://ejemplo.com/facturas?id=1235, para acceder a facturas de otros usuarios sin permiso.

### Por Qué es Peligroso
- La vulnerabilidad IDOR puede permitir a los atacantes:
  - Acceder y posiblemente modificar datos privados o sensibles de otros usuarios.
  - Realizar acciones con privilegios elevados si pueden referenciar objetos de control de acceso (como cambiar niveles de usuario o permisos).
  - Descubrir y explotar otros fallos de seguridad a través del acceso no autorizado a la información.
 

## IDOR en llamadas a API
El uso indebido de la vulnerabilidad IDOR (Insecure Direct Object References) para explotar el ID de usuario en llamadas a una API es un escenario común de ataque en aplicaciones web. Este tipo de ataque ocurre cuando un atacante manipula los identificadores (como el ID de usuario) que controlan el acceso a objetos específicos, como datos personales o de cuenta, con el fin de acceder a información que no debería estar disponible para ellos.

- Ejemplo de Ataque IDOR con ID de Usuario: Llamada API Normal: Una aplicación web utiliza una API para permitir a los usuarios acceder a su perfil mediante una llamada como GET /api/usuarios/1234, donde 1234 es el ID del usuario autenticado. La aplicación espera que el usuario solo pueda acceder a su propia información.

- Explotación de IDOR: Un atacante, que ha iniciado sesión en la aplicación y tiene su propio ID de usuario (por ejemplo, 5678), modifica la solicitud a GET /api/usuarios/1234 cambiando el ID 5678 por otro ID de usuario, como 1234. Si la API no implementa adecuadamente controles de acceso que verifiquen si el solicitante tiene permiso para acceder a los datos del usuario 1234, el atacante podría obtener acceso a información privada o sensible de ese usuario.

- Prevención de Ataques IDOR en APIs: Para prevenir ataques IDOR al usar IDs de usuario en llamadas a una API, considera implementar las siguientes medidas de seguridad:
  - Controles de Acceso Estrictos: Asegúrate de que cada llamada a la API que solicita datos sensibles implemente controles de acceso fuertes. Esto implica verificar que el ID del usuario que realiza la solicitud coincida con el ID del objeto que se solicita, o que el usuario tenga los permisos adecuados para acceder a dicho objeto.
  - Referencias Indirectas de Objetos (IDOR): En lugar de usar IDs directos y predecibles (como incrementos numéricos), utiliza tokens o identificadores aleatorios que no permitan a los atacantes adivinar o iterar fácilmente a través de ellos.
  - Autenticación y Autorización Robustas: Utiliza mecanismos de autenticación fuertes y asegúrate de que la autorización se verifique en cada llamada a la API. Frameworks y librerías modernas de seguridad como OAuth2 pueden proporcionar un manejo de autenticación y autorización seguro y estandarizado.

Un ejemplo de esto se puede ver en Owasp Juice Shop para cambiar el carrito de compra al de otro usurio.


## IDOR en acceso a ficheros estáticos
La vulnerabilidad de Referencia Directa a Objetos Inseguros (IDOR) también puede aplicarse al acceso a ficheros estáticos en aplicaciones web. Esto ocurre cuando un atacante puede acceder o manipular ficheros estáticos, como documentos PDF, imágenes, archivos de configuración, etc., a los que no debería tener acceso, simplemente cambiando un identificador en la URL o en la petición que se envía al servidor.

**Ejemplo de Explotación de IDOR en Ficheros Estáticos:**
Supongamos que una aplicación web almacena facturas de usuarios como ficheros PDF en un directorio accesible públicamente y utiliza un esquema predecible para nombrar estos archivos (por ejemplo, basado en el ID del usuario y el número de factura: factura-usuarioID-numeroFactura.pdf).

Un usuario legítimo puede recibir un enlace para descargar su factura:
```
https://ejemplo.com/facturas/factura-123-001.pdf
```
Si los controles de acceso no están correctamente implementados, un atacante podría modificar este enlace para acceder a las facturas de otros usuarios simplemente cambiando el usuarioID y/o numeroFactura en la URL:

```
https://ejemplo.com/facturas/factura-124-001.pdf
```

- Cómo Prevenir IDOR en el Acceso a Ficheros Estáticos
  - Implementar Controles de Acceso: Asegúrate de que solo los usuarios autenticados y autorizados puedan acceder a sus propios ficheros. Esto puede requerir una verificación de sesión y permisos antes de servir cualquier archivo estático solicitado.
  - Uso de Referencias Indirectas: En lugar de utilizar nombres de archivos predecibles o basados en información sensible del usuario, utiliza identificadores aleatorios o tokens únicos que no permitan adivinar o enumerar otros ficheros.
  - Servir Archivos a Través de un Controlador: En vez de permitir el acceso directo a archivos estáticos, utiliza un controlador o un script en tu backend que primero verifique la autenticación y autorización del usuario antes de servir el archivo. Esto añade una capa de seguridad adicional, ya que el controlador puede realizar comprobaciones específicas de seguridad antes de permitir el acceso al archivo.
  - Almacenamiento Seguro de Archivos: Evita almacenar archivos sensibles en directorios directamente accesibles a través de la web. Considera almacenarlos fuera del directorio raíz de la web o en un sistema de almacenamiento seguro con acceso controlado.


