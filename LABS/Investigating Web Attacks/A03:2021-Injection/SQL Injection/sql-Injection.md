## A3:2021 Injection
La vulnerabilidad SQLi está categorizada como CWE-89: Improper Neutralization of Special Elements used in an SQL command.

La inyección SQL es una técnica de inyección de código que podría permitir a un atacante ejecutar consultas maliciosas o manipular la base de datos de una aplicación web. Esta vulnerabilidad se explota insertando o "inyectando" una consulta SQL a través de la entrada del usuario o mediante la manipulación de parámetros de la aplicación.

## Qué se puede hacer con u  inyección SQL:
- Leer información sensible sin autorización.
- Modificar datos de la BBDD.
- Realizar tareas de administración de BBDD:
  - Paradas.
  - Reinicios
  - ...
- Acceder al sistema de ficheros para la lectura o modificación de archivos (LFI).
- Ejecución arbitraria de comandos en el servidor.

## Laboratorios sobre inyecciones SQL:
- Tryhackme:
  - https://tryhackme.com/room/sqlinjectionlm
  - https://tryhackme.com/r/room/sqlilab
- Lord of SQLi: https://los.rubiya.kr/
- Repostorio SQLi-Labs: https://github.com/Audi-1/sqli-labs


## Clasificación de las inyecciones SQL
La clasificación de las inyecciones SQL, en función de cómo se reciben los resultados de la inyección, ayuda a entender mejor las técnicas empleadas por los atacantes y las medidas preventivas necesarias. Las principales categorías son:

1. Inyección SQL de Banda Ciega (Blind SQL Injection): En una inyección SQL de banda ciega, el atacante no recibe un resultado directo de la consulta inyectada. Dado que la respuesta no incluye datos de la base de datos, el atacante debe hacer preguntas de sí o no y observar el comportamiento de la aplicación web para deducir la estructura de la base de datos, la presencia de ciertas tablas o columnas, o incluso extraer datos específicos de manera incremental.
  a. Basada en el Tiempo (Time-based Blind SQL Injection): El atacante realiza consultas que causan retrasos en la respuesta de la base de datos, utilizando funciones como SLEEP(). La diferencia en el tiempo de respuesta indica si la consulta inyectada devolvió verdadero o falso.
  b. Basada en el Comportamiento (Boolean-based Blind SQL Injection): El atacante modifica el contenido de la aplicación web a través de consultas que resultan en cambios visibles o en el comportamiento de la aplicación, dependiendo de si la consulta devuelve verdadero o falso, sin revelar datos directamente.

2. Inyección SQL Clásica (In-band SQL Injection): En este tipo de inyección SQL, el atacante es capaz de utilizar el mismo canal de comunicación para lanzar el ataque y recoger los resultados. Este tipo es más directo y puede ser muy peligroso, ya que permite al atacante obtener información detallada de la base de datos rápidamente.
  a. Basada en Errores (Error-based SQL Injection): El atacante provoca errores intencionales en las consultas SQL para extraer información de los mensajes de error devueltos por la base de datos, lo que puede revelar datos sensibles.

  b. Union-based SQL Injection: El atacante utiliza el operador UNION de SQL para combinar una consulta maliciosa con la consulta original de la aplicación. Esto permite al atacante extraer datos de la base de datos directamente en la respuesta de la página web.

3. Inyección Out-of-band: Sí devuelven el resultado, pero lo hacen en un canal distinto al usado para introducir la inyección. La inyección out-of-band se basa en la capacidad del atacante para obligar a la base de datos a realizar acciones que resulten en comunicaciones con un sistema controlado por el atacante. Estas acciones pueden incluir la realización de solicitudes DNS o HTTP hacia un servidor externo. A través de estas solicitudes, el atacante puede extraer información de la base de datos. Ejemplos de Inyección Out-of-Band:
  a. Solicitudes DNS: Un atacante podría explotar una vulnerabilidad SQL para hacer que la base de datos envíe una solicitud a un dominio controlado por el atacante. El nombre de dominio podría incluir información extraída de la base de datos, como un nombre de usuario o un ID de sesión.
  b. Solicitudes HTTP: De manera similar, el atacante podría hacer que la base de datos realice una solicitud HTTP a un servidor web bajo el control del atacante, incluyendo datos sensibles en la URL de la solicitud o en los parámetros.

La comprensión de estas categorías de inyección SQL es crucial para los profesionales de la seguridad y los desarrolladores de aplicaciones web, ya que cada tipo requiere diferentes estrategias de mitigación y detección. Las medidas preventivas comunes incluyen la validación de entradas del usuario, el uso de consultas preparadas (prepared statements), la implementación de listas de permisos para entrada de datos y el uso de tecnologías de escaneo de seguridad para identificar vulnerabilidades potenciales.


## Ténicas de Explotación para las inyecciones SQL:
### 1. Empleo de condiciones booleanas:


### 2. Uso del operador UNION:


### 3. Descubrir las estructura de la Base de Datos:

