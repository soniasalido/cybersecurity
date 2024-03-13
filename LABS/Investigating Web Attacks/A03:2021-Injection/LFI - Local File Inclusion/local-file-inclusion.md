## Local File Inclusion
Las vulnerabilidades de Inclusión de Archivos Local (LFI) y de Inclusión de Archivos Remotos (RFI) son problemas de seguridad muy similares y están estrechamente vinculadas. Ambas hacen posible que un atacante acceda o manipule archivos en el sistema de la víctima. La LFI, específicamente, permite a los atacantes leer o ejecutar archivos que se encuentran en el servidor de la aplicación web.

Estas vulnerabilidades surgen principalmente por dos razones:
- Falta de validación o insuficiente control sobre los datos introducidos por los usuarios: Esto no se limita solo a la información que se envía a través de formularios web, sino que también incluye cualquier método que permita al usuario enviar información al servidor, como son los parámetros en métodos GET y POST, entre otros.
- La capacidad de los lenguajes de programación del lado del servidor, como PHP, ASP o JSP, de incluir e interpretar archivos de manera dinámica: Esto significa que si un atacante puede manipular las referencias a los archivos que estos lenguajes están procesando, podría forzar la aplicación a ejecutar o revelar el contenido de archivos no destinados a ser accesibles.

En esencia, estos problemas de seguridad ocurren cuando una aplicación web no verifica adecuadamente los datos suministrados por el usuario, permitiendo así que los atacantes inserten rutas de archivos maliciosos. Esto puede conducir a la lectura no autorizada de archivos del sistema o, en el caso de RFI, al ejecutar código malicioso desde un servidor remoto. La prevención efectiva de estos ataques implica asegurarse de que todas las entradas de los usuarios sean rigurosamente validadas y limpiadas, y restringir estrictamente los archivos que pueden ser incluidos o ejecutados por la aplicación web.

En las versiones más recientes del OWASP Top 10, LFI pertenece a la categoría "A03:2021-Injection". La categoría de Inyección incluye una variedad de ataques donde los atacantes envían datos maliciosos a un intérprete como parte de un comando o consulta, con la intención de hacer ejecutar o interpretar estos datos de manera no intencionada. 

## Laboratorio LFI
Usamos DVWA, sección File Inclusión:
