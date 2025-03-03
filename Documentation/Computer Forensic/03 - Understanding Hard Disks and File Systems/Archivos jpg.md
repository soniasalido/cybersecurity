
# A JPEG bit stream contains a sequence of data chunks:
El formato de imagen JPEG (Joint Photographic Experts Group) es un método comúnmente utilizado para la compresión y codificación de imágenes digitales. JPEG es especialmente eficaz para imágenes con transiciones de color suaves, como fotografías. La secuencia de un archivo JPEG consiste en varios segmentos o "chunks" de datos, cada uno con un propósito específico. Aquí hay un desglose de la secuencia típica de estos segmentos:

  - Start of Image (SOI) Marker:
  Cada archivo JPEG comienza con un marcador SOI (Start of Image), que señala el inicio del archivo. Este marcador consiste en dos bytes: 0xFFD8.

  - Headers/App Segments:
    - Tras el SOI, hay varios encabezados que proporcionan información sobre la imagen. Estos incluyen segmentos de aplicación (App0, App1, etc.), que pueden contener metadatos como la información Exif y la miniatura de la imagen.
    - Los encabezados comienzan con un marcador (0xFFE0 para App0, 0xFFE1 para App1, etc.) y son seguidos por la longitud del segmento y los datos específicos del segmento.

  - Quantization Tables (DQT):
    - Las tablas de cuantización definen cómo se cuantifican los valores de los píxeles durante la compresión. Estos segmentos empiezan con el marcador DQT (0xFFDB) y contienen los valores de la tabla de cuantización.

  - Start of Frame (SOF) Marker:
    - El marcador SOF (0xFFC0 para SOF0, que es el más común en JPEG estándar) indica el comienzo del marco de la imagen. Contiene detalles como la precisión de la muestra, la altura y la anchura de la imagen, y el número de componentes de color.

  - Huffman Tables (DHT):
    - Las tablas de Huffman, marcadas por 0xFFC4, se utilizan para la codificación de Huffman en el proceso de compresión. Estas tablas son esenciales para la descompresión y reconstrucción de la imagen.

  - Start of Scan (SOS) Marker:
    - El marcador SOS (0xFFDA) señala el inicio del escaneo de datos de la imagen. Indica qué parte de la imagen se está describiendo y cómo se deben interpretar los datos siguientes.

  - Imagen Data (Datos Codificados):
    - Tras el marcador SOS, vienen los datos de la imagen codificados. Estos datos están comprimidos utilizando la codificación de Huffman y la cuantificación definida por las tablas anteriores.

  - End of Image (EOI) Marker:
    - El archivo JPEG termina con un marcador EOI (End of Image), 0xFFD9, que indica el final del archivo.

Cada uno de estos segmentos tiene un propósito específico y juntos forman la estructura completa de un archivo JPEG. Esta estructura permite una compresión eficiente manteniendo una calidad de imagen razonablemente alta, lo que hace que el formato JPEG sea muy popular para el almacenamiento y la transmisión de imágenes digitales.


En un archivo JPEG, el nombre del archivo no se almacena dentro de los datos del archivo JPEG en sí. En cambio, el nombre del archivo se maneja a nivel del sistema de archivos del dispositivo de almacenamiento. Esto significa que el nombre de la foto, como "imagen.jpg", es mantenido por el sistema de archivos y no es parte de la secuencia de datos interna del archivo JPEG.

Cuando guardas una imagen en formato JPEG en tu computadora, unidad USB, o cualquier otro medio de almacenamiento, el sistema de archivos de ese medio es el que registra el nombre del archivo, su ubicación, tamaño, y otros metadatos relacionados con el sistema de archivos (como la fecha de creación y modificación).

