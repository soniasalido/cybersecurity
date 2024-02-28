
+ Testdisk:
https://www.cgsecurity.org/wiki/TestDisk_Paso_A_Paso


+ FOREMOST:
The U.S. Air Force Office of Special Investigations and the Center for Information Systems Security Studies and Research developed another specialized freeware tool called Foremost (see http://foremost.sourceforge.net).
https://github.com/korczis/foremost

+ cat << EOF > stream.txt

+ El comando
dpkg -l | grep -c '^ii'
en sistemas basados en Debian (como Ubuntu) se utiliza para contar el número total de paquetes instalados. Aquí está lo que hace cada parte del comando:
dpkg -l: Lista todos los paquetes disponibles y su estado actual.
grep -c '^ii': Filtra y cuenta solo las líneas que comienzan con 'ii'. En la salida de dpkg -l, 'ii' indica que un paquete está instalado correctamente.



+ sudo smartctl -a /dev/nvme0n1

+ Reiniciar servicio KWIN de kde: systemctl --user kill --signal=KILL plasma-kwin_x11.service && systemctl --user start plasma-kwin_x11.service

+ strings -n 5 fileName --> Encuentra secuencias de al menos 5 caracteres.
+ strings -ef fileName --> Encuentra cadenas de unicode.
+ yara [OPTIONS] -C RULES_FILE TARGET
+ yara [OPTIONS] RULES_FILE1 RULES_FILE2 .... TARGET
+ yara /my/files/rules . --> Aplica las reglas que se encuentra en la carpeta rules a todos los fichero del directorio actual. Los subdirectorios no son escaneados.
+ yara /my/files/rules -r /mydirectory --> Escanea todos los fichero del directorio mydirectory y los subdirectorios tambien.

# Compilar YARA
Para compilar YARA, necesitarás seguir una serie de pasos que incluyen descargar el código fuente y usar herramientas de compilación. A continuación, te proporciono una guía general sobre cómo hacerlo en sistemas Unix/Linux y Windows:

En Unix/Linux
Instalar Dependencias: Antes de compilar YARA, asegúrate de tener las herramientas de compilación y las dependencias necesarias. En sistemas basados en Debian/Ubuntu, puedes instalarlas usando:
```
sudo apt-get install automake libtool make gcc pkg-config libssl-dev libjansson-dev libmagic-dev
```
Descargar el Código Fuente: Puedes obtener el código fuente de YARA desde su repositorio en GitHub. Esto se puede hacer clonando el repositorio:
```
git clone https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure
make
## (Opcional) Para instalar YARA en el sistema:
sudo make install
yara -v
yara -h
```

# File Structures
## Header
Information about the file and type
Magic Numbers: The magic number are the first few bytes of a file, and it's a unique number thar represents that particular type of file. Las extensiones de los ficheros pueden cambiarse. Sin embargo si miramos a los magic number, identificaremos el tipo de fichero.
- Algunos magic number de ficheros:
  - Windows Executable files: 4D 5A
  - Docx Documents: 50 4B 03 04
  - Doc Documents: D0 CF 11 E0 A1 B1 1A E1
  - BMP images: 42 4D
  - JPG images: FF D8
  - PNG images: 89 50 4E 47

## Body


# The Process for writing YARA Rules:
- Analyze Files.
- Look for patterns and indicators of compromise.
- Encode patterns and contional logic.
- Test rules.


# Estructura de una Yara Rule:
```
/*
  Comments
*/
rule signature_name : tag_name {
  meta:
      author = ""
      description = ""
      version = ""
  strings:
    $s1 = ""
    $s2 = ""
  condition:
    $s1 = "" nocase

}
```

## meta
Data definition for the rule. The meta data section of the rule defines name/value pairs that contain information about the rule. It does not contain the rule itself.

## strings
- List of strings the rule will potentially match on. In the strings area of the rule, values are defined to represent the patterns and indicators of compromise that we're looking for.
- To define a tring within a rule, the string needs to be declared as a variable: $s1 = "mystring"
- Modifiers can fine-tune the matching:
  - Modifier to match against an exact word: $s1 = "mystring" fullword
  - Modifier to match the string regardless of case: $s1 = "MyString" nocase
  - Modifier to match on unicode and ascii characters: $s1 = "mystring" wide ascii


- Naming Convention:
Variable      Meaning          Example        Usage
a              Application      $a1,$a2...    $a1="sc.exe"
c              Command          $c1           $c1="open"
f              File             $f1           $f1="wsock32.dll"
ip             IP Adrress       $ip
p              Process          $p1           $p1="SmtpClient"
r              Registry         $r1           $r1="CurrentVersion\Run"
s              String           $s1           $s1="exploit"



## condition
The condition on wich a rule should be considered a match and trigger.
Adding processing logic is done in the condition portion of a rule. This allow for the rule to trigger a match when certain conditions are met.
- A file can be matched against a size: (filesize>1MB)
- A condition can state a file must be a windows executable:
  ```
  $s1 = {4D 5A}
  $s1 at 0
  ```
- You can customize how many matches are need to trigger a match:
  ```
  $s1
  Ss1 and $s2
  $s1 and not $s2
  all of them
  any of them
  ```

# Scanning with YARA
Use this script to download and merge all the yara malware rules from github: https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9
Create the rules directory and execute it. This will create a file called malware_rules.yar which contains all the yara rules for malware.

## Volatility 2:
```
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```

## Volatility 3:
```
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
