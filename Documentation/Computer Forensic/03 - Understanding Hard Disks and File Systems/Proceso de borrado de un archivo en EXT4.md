
### Proceso de borrado de un archivo en EXT4:
Cuando se borra un fichero en un sistema de archivos Ext4, ocurren varios procesos internos que involucran tanto la actualización de las estructuras de datos del sistema de archivos como la gestión del espacio en el disco:

  - Actualización de la Tabla de Inodos:
  Cada fichero y directorio en Ext4 está asociado con un inodo, que almacena metadatos y la ubicación de los bloques de datos del fichero en el disco.
  Al borrar un fichero, el sistema primero encuentra su inodo y actualiza la tabla de inodos para marcar ese inodo como libre. Esto implica actualizar varias estructuras internas, como las listas de inodos libres.

  - Liberación de Bloques de Datos:
  Los bloques de datos en el disco que fueron utilizados para almacenar el contenido del fichero también se liberan. Esto significa que el sistema marca estos bloques como disponibles para ser reescritos por otros ficheros en el futuro.
  En algunos casos, si el fichero es muy pequeño, su contenido puede almacenarse directamente en el inodo (en un espacio llamado "bloques de datos en línea"). En este caso, simplemente se limpia esta área.

  - Actualización del Directorio:
  El fichero también se elimina del directorio en el que residía. Los directorios en Ext4 son en realidad ficheros especiales que almacenan listas de ficheros y sus inodos correspondientes.
  Al eliminar un fichero, la entrada correspondiente en este fichero de directorio se elimina o se marca como no utilizada.

  - Manejo del Contador de Enlaces:
  Los inodos tienen un contador de enlaces que indica cuántas referencias (o nombres) hay para ese inodo. Un fichero puede existir en múltiples lugares a través de enlaces duros, cada uno incrementando este contador.
  Al borrar un fichero, se disminuye este contador. Si el contador llega a cero (lo que significa que no hay más referencias al fichero), entonces se procede a liberar el inodo y los bloques de datos.

  - No Borrado Inmediato de Datos:
  Es importante destacar que el borrado de un fichero generalmente no implica la eliminación inmediata de los datos del disco. El sistema simplemente marca el espacio como disponible. Los datos reales permanecen en el disco hasta que son sobreescritos por otros ficheros.

  - Journaling:
  Ext4 es un sistema de archivos con journaling. Esto significa que las operaciones, como borrar un fichero, se registran primero en un "journal" o diario. Esto ayuda a mantener la integridad del sistema de archivos en caso de una falla del sistema o un corte de energía.

