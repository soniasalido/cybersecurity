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



