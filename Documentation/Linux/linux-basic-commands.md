 Linux

echo $SHELL
ls -la
more nombreFichero --> muestra el fichero poco a poco
less nombreFichero -->
w --> quien está logado en el sistema
cat fichero.txt | basse 64 > ficheroCodificado.txt
base64 -d nombreFicheroCodificado 
base64 -w 0 nombreFichero


### Running Multiple Commands

Comando que termina && Siguiente comando -->
true && echo 1
false && echo 1

Comando que falla || Siguiente Comando --> Sólo se ejecuta el segundo comando si el primero falla. Si no falla, entonces no se ejecuta.
false || echo 1

Correr un segundo comando independientemente de si falla o no el primer comando -->
comando1 ; comando2

Ejecución con backticks:
echo `echo 1`
Resultado: Primero ejecuta lo que está dentro de las comillas que es 1, y luego hace el echo 1, que es 1.


### Control Secuences:
ctrl +c --> mata el proceso
ctrl +d --> envia "end of file".
ctrl +z --> Para el proceso. No lo mata. Sólo lo para. Para volver al proceso, escribimos fg
ctrl +l --> limpia pantalla
ctrl +r --> ver el historico de comandos que se escribieron. Pulsamos ESC y queda el comando que buscamos.


### Command Composition
Conectar al salida estandar de un comando con la entrada estandar de otro comando:
cat /etc/password | grep root

cat /etc/passwd | grep root | cut -d':' -f 3 
| cut -d':' -f 3: Este comando procesa la entrada recibida del comando grep y la divide en campos basándose en el delimitador especificado por -d, que en este caso es ':'. Luego, selecciona el campo indicado por -f 3, que sería el tercer campo. En el formato estándar del archivo /etc/passwd, el tercer campo corresponde al ID de usuario (UID) del usuario.



```
find / -name  .bashrc -exec grep export {} \;
```


diferencia entre estos comandos: 
```
find / -name  .bashrc -exec grep export {} \;
find / -name  .bashrc |  grep -l export 
```
| grep -l export intentaría leer la lista de nombres de archivos como si fuera el contenido a examinar, lo cual no es el caso. Para que este enfoque funcione como se pretende (buscar dentro del contenido de los archivos .bashrc), debemos pasar los nombres de los archivos a un comando que pueda abrir y leer esos archivos, como xargs grep -l export.


Alternativa usando el pipe |:
```
find / -name .bashrc | xargs grep -l 'export'
```
Este comando realiza lo siguiente:

find / -name .bashrc busca en todo el sistema de archivos por archivos que se llaman .bashrc.
La salida de find (los nombres de los archivos .bashrc encontrados) se pasa a xargs.
xargs toma esa lista de nombres de archivos y los pasa como argumentos al comando grep -l 'export'.
grep -l 'export' busca dentro de los archivos pasados por xargs por la cadena "export" y lista solo los nombres de los archivos que contienen esa cadena.
El uso de -l con grep hace que solo se impriman los nombres de los archivos que contienen al menos una coincidencia, sin mostrar las líneas específicas. Si lo que deseas es ver las líneas que contienen "export" dentro de esos archivos, simplemente elimina el argumento -l:


### Sticky Bit
El "sticky bit" es un permiso especial que se puede establecer en directorios en sistemas de archivos UNIX y Linux. Cuando el sticky bit está configurado en un directorio, **solo el propietario de un archivo puede eliminar o renombrar los archivos dentro de ese directorio**. Esto es particularmente útil en directorios donde varios usuarios tienen permiso de escritura, como /tmp, para evitar que los usuarios borren o renombren archivos que no les pertenecen.

En los sistemas de archivos tradicionales UNIX, el sticky bit también tenía un propósito diferente para los archivos ejecutables, indicando al sistema que mantuviera el texto del programa en la memoria incluso después de terminar su ejecución, para acelerar reinicios subsiguientes del mismo programa. Sin embargo, esta funcionalidad ha quedado obsoleta en la mayoría de los sistemas modernos.

Para ver si un directorio tiene el sticky bit establecido, puedes usar el comando
```
ls -ld nombreDirectorio
drwxrwxrwt .......
```
Si el sticky bit está establecido, verás una "t" al final de los permisos del directorio, como en **drwxrwxrwt**.

Para establecer el sticky bit en un directorio, puedes usar el comando:
```
chmod +t nombreDirectorio
```
Para removerlo:
```
chmod -t nombreDirectorio
```

### Importancia del sticky bit en un ataque a un sistema linux:
El sticky bit juega un papel importante en la seguridad de un sistema Linux, especialmente como medida preventiva contra ciertos tipos de ataques. Su relevancia en la seguridad de un sistema puede entenderse desde varias perspectivas:
- Prevención contra la manipulación de archivos: En directorios compartidos donde múltiples usuarios tienen permisos de escritura, como /tmp, un usuario malicioso podría eliminar o renombrar archivos que pertenecen a otros usuarios o al sistema. El sticky bit previene este tipo de comportamiento al restringir la eliminación y el renombramiento de archivos solo a los propietarios de los archivos y al root del sistema. Esto ayuda a proteger contra ataques que buscan desestabilizar aplicaciones o servicios mediante la manipulación de archivos temporales o compartidos.

- Limitación del espacio para ataques de escritura: Los directorios con permisos de escritura amplios, si no están protegidos por el sticky bit, podrían ser explotados por atacantes para colocar archivos maliciosos, scripts, o ejecutables que podrían ser ejecutados por otros usuarios o procesos, elevando potencialmente los privilegios del atacante o comprometiendo la integridad del sistema. El sticky bit minimiza este riesgo al limitar quién puede eliminar o mover archivos dentro de estos directorios compartidos.

- Mejora de la gestión de archivos temporales: Muchos programas y servicios en sistemas Linux crean y utilizan archivos temporales en directorios como /tmp. El sticky bit es crucial para asegurar que estos archivos temporales solo puedan ser gestionados por sus respectivos propietarios, lo que previene posibles ataques de interceptación o suplantación mediante la manipulación de estos archivos temporales.

- Defensa contra ataques de denegación de servicio (DoS): Sin el sticky bit, un atacante podría fácilmente llenar un directorio compartido con archivos innecesarios, impidiendo a otros usuarios o servicios crear los archivos temporales necesarios. Esto podría utilizarse para realizar un ataque de denegación de servicio (DoS) al agotar el espacio disponible en el disco. Con el sticky bit, esta táctica es mucho más difícil de ejecutar, ya que solo el propietario de un archivo (o el administrador del sistema) puede eliminar archivos en el directorio protegido.


### Comprimir
- gzip: Comprime archivo.txt a archivo.txt.gz y elimina el original.
  ```
  gzip archivo.txt
  ```

- Comprimir varios archivos: Primero, debemo empaquetarlos con tar y luego comprimir. Este comando empaqueta y comprime los archivos especificados en paquete.tar.gz:
  ```
  tar cvf - archivos | gzip > paquete.tar.gz
  ```

- bzip2: Comprime archivo.txt a archivo.txt.bz2 y elimina el original.
  ```
  bzip2 archivo.txt
  ```
- xz: Esto comprime archivo.txt a archivo.txt.xz y elimina el original.
  ```
  xz archivo.txt
  ```
- zip: Comprimir varios archivos en un archivo .zip. Esto crea un archivo paquete.zip que contiene archivo1.txt y archivo2.txt:
  ```
  zip paquete.zip archivo1.txt archivo2.txt
  ```
- zip: Comprimir un directorio. Esto comprime el directorio y todos sus contenidos en paquete.zip:
  ```
  zip -r paquete.zip directorio/
  ```

- tar con compresión: Comprimir un directorio con gzip. Esto crea un archivo paquete.tar.gz que contiene todos los archivos y directorios dentro de directorio, usando compresión gzip:
  ```
  tar czvf paquete.tar.gz directorio/
  ```

- Comprimir un directorio con bzip2. Usa compresión bzip2:
  ```
  tar cjvf paquete.tar.bz2 directorio/
  ```

- Comprimir un directorio con xz. Usa compresión xz:
  ```
  tar cJvf paquete.tar.xz directorio/
  ```

