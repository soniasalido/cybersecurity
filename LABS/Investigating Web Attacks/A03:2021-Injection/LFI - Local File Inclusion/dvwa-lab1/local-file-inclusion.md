## Local File Inclusion
Las vulnerabilidades de Inclusión de Archivos Local (LFI) y de Inclusión de Archivos Remotos (RFI) son problemas de seguridad muy similares y están estrechamente vinculadas. Ambas hacen posible que un atacante acceda o manipule archivos en el sistema de la víctima. La LFI, específicamente, permite a los atacantes leer o ejecutar archivos que se encuentran en el servidor de la aplicación web.

**Estas vulnerabilidades surgen principalmente por dos razones:**
- Falta de validación o insuficiente control sobre los datos introducidos por los usuarios: Esto no se limita solo a la información que se envía a través de formularios web, sino que también incluye cualquier método que permita al usuario enviar información al servidor, como son los parámetros en métodos GET y POST, entre otros.
- La capacidad de los lenguajes de programación del lado del servidor, como PHP, ASP o JSP, de incluir e interpretar archivos de manera dinámica: Esto significa que si un atacante puede manipular las referencias a los archivos que estos lenguajes están procesando, podría forzar la aplicación a ejecutar o revelar el contenido de archivos no destinados a ser accesibles.

En esencia, estos problemas de seguridad ocurren cuando una **aplicación web no verifica adecuadamente los datos suministrados por el usuario**, permitiendo así que los atacantes inserten rutas de archivos maliciosos. Esto puede conducir a la lectura no autorizada de archivos del sistema o, en el caso de RFI, al ejecutar código malicioso desde un servidor remoto. La prevención efectiva de estos ataques implica asegurarse de que todas las entradas de los usuarios sean rigurosamente validadas y limpiadas, y restringir estrictamente los archivos que pueden ser incluidos o ejecutados por la aplicación web.

En las versiones más recientes del OWASP Top 10, LFI pertenece a la categoría "A03:2021-Injection". La categoría de Inyección incluye una variedad de ataques donde los atacantes envían datos maliciosos a un intérprete como parte de un comando o consulta, con la intención de hacer ejecutar o interpretar estos datos de manera no intencionada. 

## Análisis de la web víctima
### 1. Reconocimiento y Mapeo
Antes de intentar cualquier prueba de LFI, debemos realizar una fase de reconocimiento para entender la estructura de la aplicación web, identificar los puntos de entrada (como parámetros de URL, campos de formulario, etc.) y comprender cómo procesa la entrada la aplicación. Esto puede incluir:
- Revisar el código fuente: Si tenemos acceso, revisar el código puede revelar directamente dónde se podrían incluir archivos basados en la entrada del usuario.
- Si no tenemos acceso --> Mapear la aplicación: Utilizar herramientas como Burp Suite para automatizar la navegación y mapear todas las funcionalidades y parámetros de la aplicación.
![](capturas/local-file-inclusion-lab1.png)


### 2. Análisis
- Identificar patrones de inclusión de archivos: Busca patrones en la aplicación donde se cargan archivos o se incluyen basados en la entrada del usuario. Por ejemplo, parámetros que cambian el contenido de la página basándose en un valor específico pueden ser un indicio.
- Identificación de puntos de entrada: Primero, debemos identificar los puntos de la aplicación web donde se incluyen archivos basados en la entrada del usuario. Comúnmente, esto ocurre en funcionalidades como la carga de páginas, documentos, o scripts a través de parámetros GET o POST.
![](capturas/local-file-inclusion-lab1-2.png)

### 3. Pruebas Focalizadas
En lugar de probar a ciegas, podemos probar de manera focalizada:
- Pruebas dirigidas con listas de archivos sensibles: Basado en el tipo de servidor y la configuración conocida, crea o utiliza listas de rutas de archivos que son comúnmente accesibles y sensibles en esos entornos.
- Encodings y técnicas de evasión: Si sospechamos de la presencia de filtros o validaciones, aplicaremos técnicas de encoding de manera dirigida basándonos en cómo creemos que la aplicación está manejando la entrada.

### 4. Pruebas manuales:
Manipulación de parámetros: Una vez identificado un punto de entrada, intentaremos manipular el parámetro para incluir archivos locales del sistema. Esto se hace modificando la URL o los parámetros POST para apuntar a archivos del sistema.

Lista de rutas de archivos comunes: Utilizaremos listas de rutas de archivos comunes para probar la inclusión de archivos sensibles del sistema, como /etc/passwd, /var/www/html/config.php, entre otros. Ejemplos comunes de intento de inclusión serían:
- Acceder a archivos sensibles:
  ```
  ?page=../../../etc/passwd
  ?page=/etc/passwd
  ?page=/var/www/html/index.html
  ....
  ```
- Incluir archivos de configuración:
  ```
  ?config=../config/db.php
  ```
![](capturas/local-file-inclusion-lab1-3.png)

Uso de técnicas de encoding: Algunas aplicaciones usan técnicas para prevenir ataques LFI, como la validación de la ruta del archivo. En este caso, intentaremos evadir estas protecciones usando encoding URL o técnicas de codificación doble.

Explotación más allá de la lectura de archivos: En algunos entornos, una vulnerabilidad LFI puede llevar a la ejecución de código arbitrario. Esto se puede lograr a través de la inyección de PHP en archivos accesibles para la aplicación (como archivos de registro) y luego incluir esos archivos mediante LFI.

### 5. Scripts y herramientas automatizadas:
Existen herramientas específicas para automatizar la búsqueda de vulnerabilidades LFI, como LFISuite o dotdotpwn.

## Laboratorio LFI
Usamos DVWA, sección File Inclusión:
Enlace para instalar DVWA: xxxxxxxxxxxxxx



