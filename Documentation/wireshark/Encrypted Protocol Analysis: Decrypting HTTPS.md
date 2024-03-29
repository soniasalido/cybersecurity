
# Descifrando Tráfico HTTPS

Al investigar el tráfico web, los analistas a menudo se encuentran con tráfico encriptado. Esto se debe al uso del protocolo Hypertext Transfer Protocol Secure (HTTPS) para una mayor seguridad contra ataques de suplantación de identidad, interceptación y escucha. HTTPS utiliza el protocolo TLS para encriptar las comunicaciones, por lo que es imposible descifrar el tráfico y ver los datos transferidos sin tener los pares de claves de encriptación/desencriptación. Dado que este protocolo proporciona un buen nivel de seguridad para la transmisión de datos sensibles, los atacantes y los sitios web maliciosos también utilizan HTTPS. Por lo tanto, un analista de seguridad debe saber cómo utilizar archivos de claves para descifrar el tráfico encriptado e investigar la actividad del tráfico.

Los paquetes aparecerán en diferentes colores ya que el tráfico HTTP está encriptado. Además, los detalles del protocolo e información (dirección URL real y datos devueltos por el servidor) no serán completamente visibles.

## Filtros Wireshark:
- HTTPS Parameters:
  - Request: Listing all requests:
    ```
    http.request
    ```
  - TLS: Global TLS search:
    ```
    tls
    ```
  - TLS Client Request:
    ```
    tls.handshake.type == 1
    ```
  - TLS Server response:
    ```
    tls.handshake.type == 2
    ```
  - Local Simple Service Discovery Protocol (SSDP):
    ```
    ssdp
    ```
    Note: SSDP is a network protocol that provides advertisement and discovery of network services.


La primera imagen a continuación muestra los paquetes HTTP encriptados con el protocolo TLS. La segunda y tercera imágenes demuestran cómo filtrar paquetes HTTP sin utilizar un archivo de registro de claves:

![](capturas/wireshark-https.png)



Similar al proceso de establecimiento de conexión de tres vías de TCP, el protocolo TLS tiene su propio proceso de handshake (saludo inicial). Los primeros dos pasos contienen los mensajes "Client Hello" (Hola Cliente) y "Server Hello" (Hola Servidor). Los filtros proporcionados muestran los paquetes de saludo inicial en un archivo de captura. Estos filtros son útiles para identificar qué direcciones IP están involucradas en el handshake de TLS:
- Client Hello:
  ```
  (http.request or tls.handshake.type == 1) and !(ssdp)
  ```
- Server Hello:
  ```
  (http.request or tls.handshake.type == 2) and !(ssdp)
  ```

![](capturas/wireshark-https-2.png)
![](capturas/wireshark-https-3.png)

Un archivo de registro de claves de encriptación es un archivo de texto que contiene pares de claves únicos para descifrar la sesión de tráfico encriptado. Estos pares de claves se crean automáticamente (por sesión) cuando se establece una conexión con una página web habilitada para SSL/TLS. Dado que estos procesos se realizan todos en el navegador, necesitas configurar tu sistema y usar un navegador adecuado (Chrome y Firefox soportan esto) para guardar estos valores como un archivo de registro de claves. Para hacer esto, necesitarás **configurar una variable de entorno y crear el SSLKEYLOGFILE**, y el navegador volcará las claves a este archivo mientras navegas por la web. Los pares de claves SSL/TLS se crean por sesión en el momento de la conexión, por lo tanto, es importante volcar las claves durante la captura de tráfico. De lo contrario, no es posible crear/generar un archivo de registro de claves adecuado para descifrar el tráfico capturado. Puedes usar el menú de "clic derecho" o el menú "Editar --> Preferencias --> Protocolos --> TLS" para añadir/quitar archivos de registro de claves.


**Adding key log files with the "right-click" menu:**
![](capturas/wireshark-https-4.png)
![](capturas/wireshark-https-5.png)


**Viewing the traffic with/without the key log files:**
![](capturas/wireshark-https-6.png)

La imagen anterior muestra que los detalles del tráfico son visibles después de usar el archivo de registro de claves. Cabe destacar que el panel de detalles de paquetes y bytes proporciona los datos en diferentes formatos para la investigación. La información del encabezado descomprimido y los detalles de los paquetes HTTP2 están disponibles después de descifrar el tráfico. Dependiendo de los detalles del paquete, también puedes tener los siguientes formatos de datos:
- Frame (Marco).
- Decrypted TLS (TLS Descifrado).
- Decompressed Header (Encabezado Descomprimido).
- Reassembled TCP (TCP Reensamblado).
- Reassembled SSL (SSL Reensamblado).

