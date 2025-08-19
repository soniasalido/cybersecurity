## Text Commands

| Comando                    | ¿Qué hace?                              | Ejemplos rápidos                                                         |               |
| -------------------------- | --------------------------------------- | ------------------------------------------------------------------------ | ------------- |
| `cat`                      | Imprime/concatena archivos.             | `cat file.txt` · `cat a b > c`                                           |               |
| `tac`                      | Como `cat` pero al revés (líneas).      | `tac log.txt`                                                            |               |
| `nl`                       | Numera líneas.                          | `nl -ba file.txt`                                                        |               |
| `wc`                       | Cuenta líneas/palabras/bytes.           | `wc -l file.txt` · `wc -w *`                                             |               |
| `head`                     | Primeras líneas.                        | `head -n 20 file.txt`                                                    |               |
| `tail`                     | Últimas líneas; seguimiento.            | `tail -f /var/log/syslog`                                                |               |
| `less`                     | Paginador interactivo.                  | `less -N file.txt`                                                       |               |
| `grep`                     | Filtra por patrón (regex).              | `grep -i "error" log` · `grep -R "foo" .`                                |               |
| `cut`                      | Extrae columnas/campos.                 | `cut -d, -f1,3 data.csv` · `cut -c1-10 file`                             |               |
| `paste`                    | Combina columnas de archivos.           | `paste -d, col1 col2`                                                    |               |
| `tr`                       | Traduce/elimina caracteres.             | `tr '[:lower:]' '[:upper:]' < f` · `tr -d '\r'`                          |               |
| `sort`                     | Ordena líneas.                          | `sort -u nombres.txt` · `sort -t, -k2,2n data.csv`                       |               |
| `uniq`                     | Colapsa duplicados (adyacentes).        | \`sort file                                                              | uniq -c\`     |
| `sed`                      | Editor de flujo (sustituciones/borra).  | `sed 's/foo/bar/g' file` · `sed -n '10,20p' file`                        |               |
| `awk`                      | Procesa columnas/formatos.              | `awk -F, '{print $2,$1}' data.csv` · `awk 'NR>1{sum+=$3}END{print sum}'` |               |
| `column`                   | Alinea en columnas.                     | `column -t -s, data.csv`                                                 |               |
| `fmt`                      | Reajusta ancho de párrafos.             | `fmt -w 72 texto.md`                                                     |               |
| `fold`                     | Envuelve líneas largas.                 | `fold -s -w 80 file`                                                     |               |
| `expand` / `unexpand`      | Convierte tabs↔espacios.                | `expand -t4 in > out` · `unexpand -a file`                               |               |
| `join`                     | Une por clave común.                    | `join -1 1 -2 1 a.txt b.txt`                                             |               |
| `comm`                     | Compara dos listas ordenadas.           | `comm -12 A B`                                                           |               |
| `diff`                     | Diferencias entre archivos.             | `diff -u viejo nuevo`                                                    |               |
| `patch`                    | Aplica parches de `diff`.               | `patch < cambio.patch`                                                   |               |
| `od` / `xxd`               | Vuelca en octal/hex.                    | `xxd -g1 file` · `od -An -tx1 -v file`                                   |               |
| `strings`                  | Extrae texto imprimible de binarios.    | \`strings bin                                                            | grep URL\`    |
| `iconv`                    | Convierte codificaciones.               | `iconv -f ISO-8859-1 -t UTF-8 in > out`                                  |               |
| `base64`                   | Codifica/decodifica Base64.             | `base64 file` · `base64 -d enc.b64`                                      |               |
| `tee`                      | Duplica a archivo y stdout.             | \`cmd                                                                    | tee out.txt\` |
| `xargs`                    | Construye/ejecuta comandos desde stdin. | \`grep -l foo \*.txt                                                     | xargs rm\`    |
| `pr`                       | Paginado para impresión.                | `pr -n -w 80 file`                                                       |               |
| `zcat` / `zgrep` / `zless` | Trabaja con `.gz` sin descomprimir.     | `zgrep -i error logs.gz`                                                 |               |
| `dos2unix` / `unix2dos`    | Cambia finales de línea.                | `dos2unix file.txt`                                                      |               |


## more

| Opción / Uso | Qué hace                                                          | Nota útil                              |
| ------------ | ----------------------------------------------------------------- | -------------------------------------- |
| `+n`         | Empieza mostrando desde la línea `n`.                             | Ej.: `more +200 archivo.log`           |
| `+/patrón`   | Empieza en la primera coincidencia de `patrón`.                   | Ej.: `more +/ERROR archivo.log`        |
| `-d`         | Muestra mensajes de ayuda para continuar/salir en vez de pitidos. | “Press space to continue, ‘q’ to quit” |
| `-c`         | Repinta página limpiando la pantalla (no hace scroll).            | Útil para logs que cambian             |
| `-s`         | “Aplasta” múltiples líneas en blanco en una sola.                 | Legible en archivos con muchos huecos  |
| `-f`         | Cuenta líneas “lógicas” (no corta líneas largas).                 | Sin plegado por ancho                  |
| `-l`         | Ignora saltos de página (`^L`) al paginar.                        | No pausa en form feeds                 |
| `-u`         | Suprime subrayados/retrocesos (backspace underline).              | Evita artefactos en texto antiguo      |
| `-V`         | Muestra la versión.                                               | —                                      |



## less
| Opción / Uso | Qué hace                                                           | Nota útil                                               |
| ------------ | ------------------------------------------------------------------ | ------------------------------------------------------- |
| `-N`         | Muestra números de línea.                                          | Ideal para código y logs                                |
| `-S`         | No envuelve líneas largas (las corta a la vista).                  | Navega con flechas → ←                                  |
| `-F`         | Sale si el contenido cabe en una pantalla.                         | Combinable con `-X`                                     |
| `-X`         | No “resetea” la terminal al salir (deja el contenido en pantalla). | Útil para copiar/pegar                                  |
| `-R`         | Interpreta códigos ANSI “seguros” (colores).                       | Para logs coloreados                                    |
| `-i` / `-I`  | Búsqueda insensible a mayús.; `-I` siempre insensible.             | `-i` respeta mayús. si usas letras grandes en el patrón |
| `-g` / `-G`  | Resalta solo la coincidencia actual / no resalta ninguna.          | Control del highlight                                   |
| `-m` / `-M`  | Prompt “largo” (info extra); `-M` aún más detallado.               | % leído, posición, etc.                                 |
| `-s`         | “Aplasta” múltiples líneas en blanco.                              | Como en `more`                                          |
| `-p patrón`  | Abre posicionado en la primera coincidencia de `patrón`.           | Ej.: `less -p ERROR app.log`                            |
| `+n`         | Empieza en la línea `n`.                                           | Ej.: `less +200 app.log`                                |
| `+/patrón`   | Empieza en la primera coincidencia de `patrón`.                    | Ej.: `less +/FATAL app.log`                             |
| `-e` / `-E`  | Sale al final de archivo en el segundo / primer EOF.               | Para “leer y salir”                                     |
| `-x N`       | Tabs cada `N` espacios.                                            | Ej.: `less -x4 file.txt`                                |
| `-P PROMPT`  | Personaliza el prompt (cabecera).                                  | Avanzado                                                |
