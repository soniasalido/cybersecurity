# Estándar de jerarquía del sistema de archivos de Linux (FHS)

El FHS (Filesystem Hierarchy Standard) define qué directorios existen en un sistema Linux, para qué sirven y qué va dentro. Su objetivo es que software, admins y scripts encuentren las cosas en los mismos lugares, independientemente de la distro.

## Ideas clave
- Separación por función: binarios, libs, configuración, datos variables, etc.
- Estático vs. variable:
  - Estático: no cambia sin actualización (/usr, binarios, libs).
  - Variable: cambia mientras el sistema corre (/var, logs, colas, BD).
- Compartible vs. específico de máquina:
  - Compartible por red: /usr, /home.
  - Específico de máquina: /etc, /var, /run.
- Tendencia usr-merge: muchas distros enlazan /bin → /usr/bin, /sbin → /usr/sbin, /lib → /usr/lib.

## Directorios principales
| Directorio                | Qué contiene                                      | Notas típicas                                 |
| ------------------------- | ------------------------------------------------- | --------------------------------------------- |
| `/`                       | Raíz; punto de inicio                             | Solo lo mínimo para arrancar.                 |
| `/bin`                    | Binarios esenciales para **todos**                | En varias distros es enlace a `/usr/bin`.     |
| `/sbin`                   | Binarios de administración del sistema            | A menudo enlace a `/usr/sbin`.                |
| `/usr`                    | Software **de solo lectura** y datos compartibles | “Userland” instalable por el sistema; grande. |
| `/usr/bin`                | La mayoría de programas de usuario                |                                               |
| `/usr/sbin`               | Herramientas de admin no esenciales para arranque |                                               |
| `/usr/lib` (`/usr/lib64`) | Bibliotecas para `/usr/bin` y `/usr/sbin`         |                                               |
| `/usr/local`              | Software instalado **localmente** (manual)        | No gestionado por el gestor de paquetes.      |
| `/etc`                    | **Configuración** del sistema (texto)             | Específico de la máquina; editable.           |
| `/var`                    | Datos **variables**: logs, colas, cachés          | Ej.: `/var/log`, `/var/spool`, `/var/cache`.  |
| `/home`                   | Directorios de usuarios                           | Datos y config de usuario.                    |
| `/root`                   | Home del superusuario                             | No confundir con `/`.                         |
| `/tmp`                    | Ficheros temporales (cualquiera)                  | Puede vaciarse al reiniciar.                  |
| `/run`                    | Datos de runtime en RAM (tmpfs)                   | PIDs, sockets, locks: `/run/*`.               |
| `/dev`                    | Dispositivos (nodos)                              | Udev los crea dinámicamente.                  |
| `/proc`                   | **Pseudofs** con info del kernel/procesos         | Ej.: `/proc/cpuinfo`, `/proc/PID`.            |
| `/sys`                    | **Sysfs**: vista de dispositivos/driver           | Ajustes del kernel y hardware.                |
| `/lib` (`/lib64`)         | Librerías esenciales para arrancar                | A menudo enlace a `/usr/lib`.                 |
| `/boot`                   | Kernel, initramfs, gestor de arranque             | No lo montes en solo-lectura durante updates. |
| `/opt`                    | Apps “grandes” de terceros                        | Cada app en `/opt/<vendor>` o `/opt/<app>`.   |
| `/srv`                    | Datos servidos por este host                      | Ej.: `/srv/www`, `/srv/ftp`.                  |
| `/media`                  | Montajes automáticos (USB, CD)                    | Udisks/DE los usa.                            |
| `/mnt`                    | Punto de **montaje temporal** manual              | Para pruebas.                                 |
| `/lost+found`             | Recuperación de fs (ext\*)                        | Lo crea el fs.                                |



## ¿Dónde pongo cada cosa?
- Binario propio para todos: /usr/local/bin (y libs en /usr/local/lib).
- Config de tu servicio: /etc/<app>/…
- Datos cambiantes de tu servicio: /var/lib/<app>/…
- Logs: /var/log/<app>.log
- Sockets/PIDs runtime: /run/<app>/…
- Contenido a servir: /srv/<servicio>/… (si sigues FHS “puro”); muchas distros usan /var/www.

## Cosas que suelen confundir
- /bin vs /usr/bin: hoy, casi todo está en /usr/bin; /bin suele ser un enlace.
- /sbin: ejecutables de administración; en sistemas modernos ya están en $PATH del usuario con sudo.
- /opt vs /usr/local: ambos son “no empaquetados”, pero /opt se usa para paquetes completos de un tercero; /usr/local para herramientas sueltas instaladas manualmente.

## Cómo explorarlo rápido
- Árbol compacto: sudo tree -L 1 -d /
- Tamaños por dir: sudo du -h -d1 /usr | sort -h
- Dónde está un binario: type -a ls ; which ls
- A qué paquete pertenece (Debian/Ubuntu): dpkg -S /bin/ls

## Comandos útiles para explorar y trabajar con la jerarquía FHS en Linux
| Comando                                          | Para qué (ámbito FHS)                                               | Ejemplo / Uso típico                                         |           |
| ------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------ | --------- |
| `pwd`                                            | Ver en qué punto del árbol estás                                    | `pwd`                                                        |           |
| `ls`, `ls -l`, `ls -a`                           | Listar contenido de directorios estándar                            | `ls -l /etc /usr /var`                                       |           |
| `tree -d -L 2`                                   | Ver la estructura de directorios (solo carpetas)                    | `sudo tree -d -L 2 /usr/local`                               |           |
| `find`                                           | Localizar archivos por nombre/tipo dentro de rutas FHS              | `sudo find /etc -type f -name "ssh*"`                        |           |
| `grep -R`                                        | Buscar texto en configs bajo `/etc`                                 | `sudo grep -R "ListenAddress" /etc/ssh`                      |           |
| `file`                                           | Identificar tipo de archivo (binario, texto, script)                | `file /bin/ls /etc/hosts`                                    |           |
| `stat`                                           | Metadata/fechas/permisos de un archivo                              | `stat /var/log/syslog`                                       |           |
| `du -h -d1`                                      | Tamaño por subdir (datos variables en `/var`, software en `/usr`)   | \`sudo du -h -d1 /var                                        | sort -h\` |
| `df -hT`                                         | Uso de disco y tipo de FS (¿/boot separado?, ¿/home?)               | `df -hT`                                                     |           |
| `findmnt` / `mount`                              | Ver puntos de montaje (ej. `/proc`, `/sys`, `/boot`)                | `findmnt -t proc,sysfs,ext4`                                 |           |
| `lsblk -f`                                       | Discos/particiones y dónde están montadas                           | `lsblk -f`                                                   |           |
| `readlink -f` / `realpath`                       | Resolver enlaces (útil con `usr-merge`)                             | `readlink -f /bin`                                           |           |
| `which` / `type -a` / `whereis`                  | Dónde vive un binario dentro de FHS                                 | `type -a bash` · `whereis sshd`                              |           |
| `dpkg -S FILE` *(Deb)*                           | Qué paquete instaló un archivo                                      | `dpkg -S /usr/bin/rsync`                                     |           |
| `rpm -qf FILE` *(RHEL)*                          | Qué paquete instaló un archivo                                      | `rpm -qf /usr/bin/curl`                                      |           |
| `pacman -Qo FILE` *(Arch)*                       | Qué paquete instaló un archivo                                      | `pacman -Qo /usr/bin/sed`                                    |           |
| `dpkg -L PKG` / `rpm -ql PKG` / `pacman -Ql PKG` | Listar archivos de un paquete (ver rutas FHS)                       | `dpkg -L openssh-server`                                     |           |
| `apt-file search NAME` *(Deb)*                   | Encontrar qué paquete provee un archivo                             | `apt-file search bin/fio`                                    |           |
| `install -D -m 0755`                             | Instalar binarios propios en `/usr/local` con permisos              | `sudo install -D -m 0755 app /usr/local/bin/app`             |           |
| `ln -s`                                          | Exponer binarios desde `/opt` a `/usr/local/bin`                    | `sudo ln -s /opt/app/bin/app /usr/local/bin/app`             |           |
| `mkdir -p`, `chown`, `chmod`                     | Preparar jerarquías y permisos en `/srv`, `/var/lib`, etc.          | `sudo mkdir -p /srv/www && sudo chown -R www-data: /srv/www` |           |
| `lsof +D PATH` / `fuser -m PATH`                 | Ver procesos que usan rutas (bloqueos en `/var`, `/srv`)            | `sudo lsof +D /var/log`                                      |           |
| `systemctl cat`                                  | Ver dónde está una unidad (`/etc/systemd/system` vs `/usr/lib/...`) | `systemctl cat ssh.service`                                  |           |
| `journalctl -u`                                  | Logs (almacenados en `/var/log/journal` si está habilitado)         | `sudo journalctl -u ssh --since today`                       |           |
| `tar -C DIR`                                     | Empaquetar/desempaquetar respetando destinos FHS                    | `sudo tar -C /usr/local -xzf tool.tgz`                       |           |
| `getfacl` / `setfacl`                            | ACLs finas en árboles como `/srv` o `/var/lib`                      | `getfacl /srv/data`                                          |           |
