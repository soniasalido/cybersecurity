# Marshal in the Middle - Hackthebox
https://app.hackthebox.com/challenges/Marshal%20in%20the%20Middle

### CHALLENGE DESCRIPTION
The security team was alerted to suspicous network activity from a production web server.&lt;br&gt;Can you determine if any data was stolen and what it was?

Filtros que dan respuestas interesantes:
http contains "<script>" -->

Vemos que introduce un script a través de jQUERY:
return document.title||a||!1},N:function(a){var b=document.body,c=this.a("BODY")[0],e=this.a("HEAD")[0];b&&b.contains(a)?b.removeChild(a):c&&c.contains(a)?c.removeChild(a):e&&e.contains(a)&&e.removeChild(a);return a},D:function(a){var b=this,c=document.createElement("script");c.type="text/javascript";c.setAttribute("async",!0);c.setAttribute("name","spr");c.setAttribute("id","spr-script");c.src=a;f.info(a);this.C(function(){setTimeout(function(){b.a("HEAD")[0].appendChild(c)},
1)});return c},b:[],ready:/loaded|interactive|complete/.test(document.readyState),flush:function(){var a=this.b.shift();for(this.ready=!0;a;)a(),a=this.b.shift()},C:function(a){this.ready?(this.b.push(a),this.flush()):document.documentElement.doScroll?window.self===window.top?function c(){if(!document.uniqueID&&document.expando)return this.b.push(a);try{document.documentElement.doScroll("left"),a()}catch(e){setTimeout(c,0)}}():this.b.push(a):this.b.push(a)},B:function(a,b,c){a.addEventListener?a.addEventListener(b,
c,!1):a.attachEvent("on"+b,c);return a},L:function(a,b,c){a.addEventListener?a.removeEventListener(b,c,!1):a.detachEvent("on"+b,c);return a},P:function(){return(window.pageYOffset?window.pageYOffset:document.documentElement?document.documentElement.scrollTop:0)-this.g},a:function(a){var b=[],c=0,e;if(!a)return[];if("string"!==typeof a)return[a];switch(a.charAt(0)){case "#":b.push(document.getElementById(a.substring(1)));break;case ".":var d=document.getElementsByTagName("*");for(e=" "+a.substring(1)+
" ";c<d.length;c+=1)a=(" "+d[c].className+" ").replace(/[\n\t\r]/g," "),-1<a.indexOf(e)&&b.push(d[c]);break;default:b=document.getElementsByTagName(a)}return b}};return{fetchContainer:function(a){h.h("//edge.simplereach.com/x?"+a,"x")}}}();

</script> <script> SPR.fetchContainer(window.location.search.substring(1)); </script>




http.file_data contains ".pdf"

http.file_data contains ".jpg"
GRAD711A-GovExecDef300x250.jpg
GRAD711A-GovExecDef300x250.jpg



(ip.dst == 104.16.24.235) and (http.request or tls.handshake.type eq 1) and !(ssdp)



Analizar el tráfico HTTP: Mostar solo las solicitudes HTTP.
http.request.uri

host: i.imgur.com


MIIFrTCCA5WgAwIBAgIUFHWEs92j/6b3twM03DJozrSlvQowDQYJKoZIhvcNAQEN



Buscar Cadenas de Texto Comunes en Base64:
http contains "=="
A menudo, las cadenas en base64 terminan con == o =, que son rellenos utilizados en la codificación. Puedes buscar estos patrones con un filtro como http contains "==" o http contains "=". Sin embargo, este enfoque puede dar muchos falsos positivos, ya que = también se utiliza ampliamente en URL y otros contextos.


----------------------
El archivo secrets.log contiene lo que parece ser una serie de registros relacionados con claves de sesión TLS. Cada línea sigue un formato específico que empieza con "CLIENT_RANDOM", seguido de un largo número hexadecimal (que parece ser un identificador de sesión aleatorio del cliente) y luego otro largo número hexadecimal, que probablemente es la clave maestra de sesión asociada con esa conexión TLS.

Este tipo de archivo se utiliza a menudo para almacenar claves de sesión TLS que pueden ser utilizadas luego para descifrar tráfico TLS capturado, permitiendo a alguien que posea tanto las capturas de tráfico como este archivo de claves ver los contenidos cifrados de las comunicaciones TLS.

Dada la naturaleza sensible de este archivo (contiene claves que pueden descifrar tráfico de red cifrado), es crucial manejarlo con extrema precaución y asegurarse de que esté protegido y accesible solo para personas autorizadas. Si este archivo cayese en manos equivocadas, podría comprometer la seguridad de las comunicaciones cifradas que pertenecen a esas sesiones TLS. ​

-------------------------
Para ver los contenidos cifrados de las comunicaciones TLS utilizando Wireshark, necesitas tanto las capturas de tráfico como el archivo de claves de sesión TLS, como el secrets.log que mencionaste. Aquí te explico los pasos a seguir:

Prepara tus Capturas de Tráfico y el Archivo de Claves TLS:

Asegúrate de tener las capturas de tráfico (generalmente archivos .pcap o .pcapng) y tu archivo de claves de sesión TLS (como secrets.log).
Configura Wireshark para Utilizar el Archivo de Claves TLS:

Abre Wireshark.
Ve a Edit > Preferences (o Edit > Options dependiendo de tu versión de Wireshark).
Dentro de Preferences, busca Protocols y luego desplázate hacia abajo hasta TLS (puede aparecer como SSL dependiendo de la versión de Wireshark).
En la configuración de TLS/SSL, verás un campo para (Pre)-Master-Secret log filename. Haz clic en Browse y selecciona tu archivo secrets.log.
Asegúrate de que todas las demás configuraciones sean las correctas y luego cierra las Preferences.
Abre la Captura de Tráfico:

Abre la captura de tráfico (archivo .pcap/.pcapng) en Wireshark.
Analiza el Tráfico Descifrado:

Una vez que el archivo de claves TLS está en su lugar y has abierto tu captura de tráfico, Wireshark debería ser capaz de usar las claves de sesión TLS para descifrar automáticamente el tráfico TLS correspondiente.
Busca los paquetes TLS en tu captura y verifica si el contenido descifrado es visible. Puedes usar filtros como tls o ssl para encontrar rápidamente este tráfico.
Los detalles descifrados estarán disponibles en el panel de detalles de Wireshark cuando seleccionas un paquete TLS descifrado.
Revisa la Información de Seguridad:

Asegúrate de revisar la información con cuidado y considera la seguridad y la privacidad de la información que estás manejando. El descifrado de tráfico TLS puede revelar datos sensibles, por lo que debes cumplir con todas las leyes y políticas relevantes de privacidad y seguridad de datos.
----------------------------

Filtro:
tls || ssl

(tls || ssl) && (ip.src == 10.10.100.43)

(tls || ssl) && (http contains "==")

ip.src == 10.10.100.0/24

http contains "<script>" 

http.request.method == "POST"

(tls || ssl) &&  http.request.method == "POST"

http.file_data contains "select" 
http.file_data matches "select" <-- Case insensitive

