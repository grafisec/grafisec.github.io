---
title: Mi experencia con la eJPTv2 y consejos para aprobarla
categories: [Hacking]
tags: []
pin: false
math: true
mermaid: true
---

¡Hola! En esta oportunidad les contaré mi experiencia con la certificación eJPT, con el objetivo de que sirva de ayuda para todos aquellos que quieran rendir la certificación y estén un poco perdidos.

![](/imagenes/ejpt/ejptfoto.png)


## Mi experiencia

Para resumir, mi experiencia fue buena y consecuente con los temas del curso oficial, aunque tuve algunos problemas técnicos.

**Hablemos antes un poco respecto al examen:**

Como se nos informa al momento de rendirlo, es Browsed Based y todo lo que necesitas está integrado en el laboratorio del examen. Por ello, no puedes subir scripts ni nada por el estilo, por ejemplo, no podrás subir el LinPEAS ni tampoco podrás hacer pivoting con chisel, así que es algo que debes tener en cuenta.

Nos enfrentaremos a una DMZ, así que aprender pivoting es necesario. Si leemos la **Letter Of Engagement**, tenemos un ejemplo:

![](/imagenes/ejpt/dmz.png)

Por lo tanto, tener claro los conceptos de redes es clave.

El examen consta de diferentes preguntas relacionadas a la máquina, algunas son de selección múltiple y otras son flags, en caso de que tengas problemas en el laboratorio puedes reiniciarlo, pero debes leer el **Lab Guidelines** donde se te explica todo.

**¿Es tan fácil como todos dicen?**

No es cualquier cosa, si no tienes la práctica y los conocimientos necesarios vas a reprobar seguro, pero las máquinas en sí son fáciles. Cabe destacar que encontrarás tanto máquinas Linux como Windows.

**¿La explotación y escalada es muy difícil?**

El mayor desafío de esta certificación es enumerar más que explotar y escalar, así que no. 

En los documentos nos mencionan que **no es un CTF**, así que no nos encontraremos los típicos desafíos de CTF o cosas demasiado rebuscadas. Con respecto a la explotación, poco que decir al respecto, tienen el nivel de una máquina fácil. Recomiendo manejar metasploit perfectamente, está bien querer hacer las cosas a mano, yo también lo hago, pero en caso de que algo no funcione como esperan él será su amigo, pues este examen está hecho para que se utilice metasploit.

Personalmente, las escaladas estuvieron sencillas, te encontrarás con las típicas de siempre, pero debes saber buscar.

**Problemas técnicos**

Desgraciadamente, tuve varios problemas a lo largo del examen, a pesar de que lo terminé relativamente rápido (unas 6 horas creo). 

Vamos a partir diciendo que soy de Latinoamérica (Chile), mi internet sinceramente es bueno, sin embargo, el laboratorio se me desconectó unas 5 o 6 veces diría yo, lo cual era simplemente molesto porque el progreso no se pierde ni nada por el estilo (también existía un delay horrible). El problema grave fue en el pivoting, pues hice el procedimiento del pivoting correctamente pero los escaneos demoraban demasiado tiempo, era ridículo, aproximadamente se demoraba de 3 a 5 min en escanear **un** solo puerto para saber si estaba abierto o no. Luego de estar bastante tiempo encontré una web, la cual demoraba aproximadamente 10 minutos en cargar y a veces daba time out, por lo que me fue imposible reconocer las tecnologías por detrás y tuve 2 o 3 preguntas erradas por ello. Fue lamentable, pero entregué el examen porque sabía que ya había aprobado aunque fallara en el pivoting.

Espero que esto no les ocurra.

**¿Otras dificultades?**

Tuve algunos problemas a la hora de ganar acceso, así que tuve utilizar diferentes métodos, desde el típico payload de msfvenom, pasando por el oneline de bash, hasta el shell_exec del típico archivo php. Por lo tanto, recomiendo manejar diferentes formas de ganar acceso a una máquina y no desesperarse porque algo no funciona a la primera.

También, ligado a lo anterior de que no son cosas tan rebuscadas, entré en un "rabbit hole" y lo que estaba haciendo estaba bien difícil, así que recomiendo siempre pensar bien antes de intentar explotar algo.


En síntesis, la certificación me gustó bastante, la dificultad es como todos dicen pero no hay que relajarse, siempre hay que ir preparado para lo que sea. A pesar de los problemas técnicos recomiendo bastante esta certificación, sobretodo para probarte a tí mismo que puedes hacerlo.

## ¿Donde estudiar?

Les haré una pequeña lista de los recursos que utilicé para estudiar, la idea es que investiguen cada una de las siguientes opciones que expondré a continuación y elijan la que más les guste.

- **El curso oficial del INE (**[Penetration Testing Student](https://my.ine.com/CyberSecurity/learning-paths/61f88d91-79ff-4d8f-af68-873883dbbd8c/penetration-testing-student-v2)**)**

Buen curso, trata todas las temáticas evaluadas en el examen (obviamente). Lo completé y fue la opción que me ha dejado más conforme. Cabe destacar que el curso es en inglés, pero tiene subtítulos al español en caso de que el inglés no sea precisamente tu fuerte.

- **Introducción al hacking (**[Hack4u](https://hack4u.io/cursos/introduccion-al-hacking/)**)**

Como no hablar del gran curso del tito savitar, si tienes la oportunidad de suscribirte a la academia y hacer el curso lo recomiendo completamente. De hecho, recomendaría hacer este curso primero, más que el curso oficial del INE, porque savitar explica desde 0 (redes) y el curso del INE asume que sabes ciertas cosas y si eres totalmente novato puede que se te dificulte un poco. 

Siendo sincero, para la certificación es suficiente llegar hasta antes de OWASP el resto queda para otras certificaciones más complicadas.


- **TryHackme (**[Jr Penetration Tester](https://tryhackme.com/hacktivities)**)**

Muy útil, personalmente no llegué a terminarlo pero si he hecho varias máquinas de TryHackMe y me sirvieron bastante. Buena opción para los que no tienen dinero para pagar los cursos, además tiene un sistema de preguntas sobre la máquina similar al examen del eJPT, por lo que sirve para practicar.


- **Resolución de máquinas en youtube de savitar (**[S4viOnLive](https://www.youtube.com/@S4viOnLive)**)**

Esto va de la mano con la opción anterior, decenas y decenas de máquinas resultas en youtube, no hay excusa para no estudiar. La única desventaja de esta opción es que las máquinas de Hack the Box estarán retiradas, por lo que si no tienes una suscripción vip no podrás resolverlas por ti mismo, pero tienes otras plataformas como VulnHub. Adicionalmente, para no estar perdido puedes utilizar el [buscador](https://infosecmachines.io) de savitar, filtrar por ejpt y así encontrar máquinas que puedan servirte en tu estudio.


----

Estos son todos los cursos/recursos que utilicé para estudiar y recomiendo.


## Herramientas necesarias

- nmap
- metasploit
- dirb
- wfuzz
- crackmapexec
- ftp
- wpscan
- hydra
- msfvenom
- john
- searchsploit
- smbmap

Aquí hay un listado de herramientas que deben manejar al revés y al derecho, y deben saber todo lo que ofrecen. Pero no son las únicas, existen muchas más así que deben investigar.

## Máquinas recomendadas

Dejaré un listado de máquinas que les servirán para practicar:

- Friendly (HackMyVM)
- Root me (TryHackMe)
- Lame (HackTheBox) VIP
- Blog (TryHackme)
- Basic pentesting (TryHackMe)
- Vulnet: Internal (TryHackMe)
- Pickle Rick (TryHackMe)
- Dark Hole 1 (VulnHub)
- Symfonos (VulnHub)

Todas estas máquinas son gratis, menos Lame.

## Consejos y recomendaciones

- La enumeración es la clave, enumera todo lo que puedas con todas las herramientas que conozcas y tengas disponibles en el examen.
- Lee atentamente la Letter of Engagement y Lab Guidelines.
- Evita hacer fuerza bruta de primera opción, analiza siempre todos los posibles vectores.
- Evita reventar los servicios, recuerda que no es un CTF, te pueden bloquear por mucho tráfico o puedes botar el servicio.
- No todo lo que brilla es oro, que no te ciege un método e impida que pienses en otras vías.
- Ten tu propia herramienta para tomar notas en tu equipo, debes ir anotando toda la información lo más ordenado posible, el orden es la clave.
- No te desesperes porque tu idea no funcionó, sigue buscando.
- Evita leer las preguntas al iniciar el examen porque podrían confundirte, leelas una vez estés demasiado perdido.



## Recursos útiles 

- [Buscador de máquinas de savitar](https://infosecmachines.io)
- [Simulación de laboratorio](https://youtu.be/l6tHH2qQmQ8)
- [Pivoting con metasploit](https://youtu.be/4c8J-vkAWV4)


------

Y bien, esto es todo lo que tenía para decirles, espero que les sirva para estar más seguros a la hora de preparar el examen.

**¡Exito!**

