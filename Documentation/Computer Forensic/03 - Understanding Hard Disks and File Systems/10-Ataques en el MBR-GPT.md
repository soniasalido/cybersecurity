Dado que el MBR juega un papel crucial en el arranque del sistema operativo, se convierte en un objetivo atractivo para los atacantes. Los 512 bytes totales del MBR tienen una importancia extrema para todo el sistema. Cualquiera que pueda manipular estos 512 bytes puede secuestrar el sistema completo. Existen varios tipos de malware diseñados específicamente para atacar el MBR.

## Ejemplos comunes de malware que aprovechan el MBR para cumplir sus objetivos

### Bootkits (kits de arranque)
Los bootkits son un tipo de malware muy peligroso. Como el MBR se ejecuta antes de que arranque el sistema operativo, los bootkits se insertan en el MBR para burlar los mecanismos de seguridad del sistema operativo. Incluso si se elimina el malware o se reinstala el sistema operativo, el bootkit sigue allí, porque reside en el propio MBR.


### Ransomware
El MBR es lo primero que se ejecuta en el disco durante el arranque, por lo que el proceso de inicio depende fuertemente de él. En lugar de cifrar archivos individuales del sistema, los atacantes modifican y cifran el MBR para interrumpir el arranque y mostrar sus notas de rescate (ransom note).

Ejemplos:
- Petya (2016): encripta el MBR en lugar de los archivos del disco.
- Bad Rabbit: sobrescribe el MBR con un código malicioso que muestra una nota de rescate tras reiniciar.


### Wiper Malware (Malware destructivo)
Este tipo de malware corrompe el MBR para hacer que el sistema sea inarrancable. Cualquier alteración del MBR puede inutilizar el sistema por completo.

Ejemplo:
- Shamoon: sobrescribe el MBR con caracteres aleatorios para impedir que el sistema arranque.
