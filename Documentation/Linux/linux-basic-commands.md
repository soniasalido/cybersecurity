# Linux

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


