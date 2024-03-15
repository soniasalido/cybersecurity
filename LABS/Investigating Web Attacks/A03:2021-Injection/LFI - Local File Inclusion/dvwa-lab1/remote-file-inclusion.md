RFI es una variante de LFI. Permite a un atacante acceder a una conexión desde el objetivo para incluir un fichero de un host externo en lugar de un fichero local como ocurría con LFI.

Limitaciones del uso de log poisoning con LFI:
- El usuario que ejecuta la aplicación que corre en el servidor debe terner permisos para leer los logs que se desea envenenar.
- Se ha de encontrar la manera de escribir código malicioso en esos ficheros de logs locales (envío de cabeceras HTTP, provocar errores, etc).

Si se pudieran incluir fichero remotos, por ejemplo alojados en la máquina atacante o en otro máquina bajo su controls, estas dos limitaciones desaparecerían facilitando la ejecución de código.

El origen de esta vulnerabilidad radica en:
- Entradas de usuario mal saneadas que permiten que se puedan introducir URL externas.
- Mala configuración: Una configuración incorrecta o predeterminada del servidor web o de aplicaciones que permite este comportamiento. Como por ejemplo, tener activada la directiva allow_url_include.
- 
