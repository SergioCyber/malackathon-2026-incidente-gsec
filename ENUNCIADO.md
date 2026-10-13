# Incidente en el GSEC — Enunciado del reto

> Te invitamos a participar en el **IV Malackathon**, en el reto «Incidente en el GSEC», diseñado
> para aplicar tus habilidades en un problema real de respuesta a incidentes.

En esta edición os incorporáis como **equipo de refuerzo de respuesta a incidentes del GSEC de
Málaga (Google Safety Engineering Center)**, en un escenario completamente ficticio. La madrugada
del día 0, el equipo de guardia detecta que el **portal de intercambio de muestras con socios** no
responde y que han aparecido ficheros extraños en el servidor de ficheros del **laboratorio de
análisis de malware**. La dirección sospecha un incidente de seguridad y teme que se haya filtrado
la **base de datos de inteligencia** del centro: informes TLP:RED compartidos por socios e
identidades de las personas objetivo de las campañas investigadas. Vuestro trabajo es averiguar
**qué ha pasado, cómo, desde cuándo, qué datos se han visto afectados y qué hay que hacer
ahora**… sabiendo que el atacante puede seguir dentro.

Trabajaréis con **30 días de telemetría de la red de laboratorio** (datos sintéticos generados
para este reto: cortafuegos y VPN del laboratorio, proxy web, DNS, pasarela de correo, telemetría
de procesos de las estaciones de análisis, registros de seguridad de Windows, auditoría de la base
de datos de inteligencia y el registro de detonaciones del *sandbox farm*, más el inventario de
usuarios y equipos, los tickets de IT, los accesos físicos al edificio y un feed de inteligencia de
amenazas). Son unos 9 millones de eventos (≈ 300 MB comprimidos): se descargan desde este
repositorio y se cargan en un portátil en menos de un minuto con el kit de arranque.
Estos datos se proporcionan exclusivamente para su uso en este reto y no podrán ser publicados ni
difundidos para otros fines.

El reto básico consiste en cargar y modelar la telemetría en **la base de datos que elijáis**
(relacional, analítica o de búsqueda), construir una **consola de analista** web que permita
explorarla, e **investigar el incidente**. El resto de herramientas, frameworks y plataformas de
despliegue es de libre elección.

> ⚠️ **Los datos del reto son hostiles.** Contienen cadenas diseñadas para romper analizadores y
> visores y para confundir a asistentes automáticos. Tratadlos como lo que son: datos controlados
> por un atacante. Verificad siempre con evidencia. Y recordad dónde estáis: en un laboratorio de
> malware **no todo el tráfico malicioso es un ataque**; parte es trabajo legítimo del centro.

> ℹ️ **Sobre el escenario.** Este reto es una obra de ficción con fines docentes. La red, los
> sistemas, las personas, los dominios y los datos son inventados. La arquitectura corresponde a
> una red de laboratorio aislada y deliberadamente clásica (Windows, VPN, SMB), **no** a la
> infraestructura real de Google ni del GSEC.

**¿Qué aprenderás participando?**

- **Ingeniería de datos de seguridad:** ingesta, normalización y correlación de fuentes
  heterogéneas a escala (millones de eventos en un portátil).
- **Modelado de datos de seguridad:** esquemas normalizados, consultas recursivas o de grafo para
  rutas de movimiento lateral, protección de datos sensibles.
- **Threat hunting y respuesta a incidentes:** reconstrucción de la cadena de ataque, MITRE
  ATT&CK, indicadores de compromiso, informe de incidente.
- **Desarrollo seguro:** una consola SOC que no pueda ser atacada con los propios logs que muestra.
- **Detección en tiempo real:** construir detecciones que funcionen mientras el ataque avanza.
- **Marco legal y ético:** RGPD (notificación en 72 h), NIS2, obligaciones con los socios (TLP) y
  con las personas cuyos datos figuran en la inteligencia.
- **Pensamiento crítico ante datos hostiles**, incluidas las herramientas de IA que uséis.

## Cómo se entrega todo

Cada equipo dispone de un **repositorio privado de entrega** en GitHub (lo crea la organización;
solo vuestro equipo y el jurado tienen acceso). Todo lo que se evalúa vive ahí:

| Fichero | Qué es | Reto |
|---|---|---|
| `ENTREGA.md` | Accesos, URLs, credenciales de los roles, tecnologías, capturas y diagrama | 1 y 2 |
| `respuestas.json` | Cuestionario de 12 preguntas cerradas (formato en `starter-kit/FORMATO_ENTREGA_ES.md`) | 3 |
| `oleada1.json`, `oleada2.json`, `oleada3.json` | Un reporte por oleada publicada | A |
| `BITACORA.md` | Bitácora de investigación desde el primer día (los *commits* son vuestra marca temporal) | 3 |
| `informe/` | Informe técnico (máx. 6 páginas) + resumen ejecutivo (1 página) + plan de respuesta (2 páginas) | 3 y C |

Los ficheros JSON tienen **formato obligatorio** y se corrigen automáticamente. Antes de hacer
*push*, validadlos con `python3 starter-kit/validar_respuestas.py respuestas.json`: el repositorio
de entrega ejecuta la misma comprobación en cada *push* y os avisa si el formato no es válido.
El cierre del cuestionario y de los reportes de oleada es el **jueves 29/10/2026 20:00 (hora peninsular)**; los
*commits* posteriores a esa hora no se tienen en cuenta.

## RETOS BÁSICOS

### 1.- Reto Base de Datos

Deberás crear un repositorio de datos en el motor que consideres (PostgreSQL, DuckDB, ClickHouse,
SQLite, OpenSearch/Elastic, Oracle…) e importar **todas** las fuentes de telemetría proporcionadas.
En él se definen los usuarios que consideres y, al menos, un usuario llamado `malackathon` con
contraseña `Mlk.2026_xxxxxxx` **de solo lectura**.

Se valorará:

- Un **modelo normalizado** (inspirado en esquemas estándar como OCSF o ECS) que relacione los
  eventos con el inventario (usuarios, equipos, grupos de trabajo, guardias, casos) y con el
  registro de detonaciones del *sandbox farm*. En `docs/esquema_canonico.sql` tenéis un esquema
  canónico de referencia (no es obligatorio usarlo).
- Que el modelo **aguante el volumen**: particionado o índices por tiempo, consultas recursivas
  (CTE) o de grafo para rutas host→host y usuario→host, manejo de eventos semiestructurados (JSON).
- **Proteger el repositorio como si fuera el del propio GSEC:** separación de roles (`malackathon`
  solo lectura), **enmascaramiento de las columnas con identidades de las personas objetivo y de
  los socios (TLP:RED)** (vistas enmascaradas, privilegios por columna, seguridad a nivel de fila
  o cifrado), registro de consultas si el motor lo permite y ningún secreto en el repositorio de
  código. *El jurado comprobará qué ve exactamente el usuario `malackathon`.*
- Enriquecimiento con **datos abiertos**: GeoIP/ASN, nodos de salida Tor, feeds públicos de IOCs
  (ThreatFox, URLhaus), CISA KEV, MITRE ATT&CK (STIX), calendario laboral.

Para evaluar el reto se debe indicar en `ENTREGA.md`:

- Forma de acceso para el usuario `malackathon`: URL de una consola SQL web (Adminer, pgweb,
  CloudBeaver…) o conexión directa protegida; como alternativa, evaluación presencial en la mesa
  del equipo.
  - El usuario tendrá acceso a las tablas con los datos del reto y los datos abiertos adicionales.
  - Diagrama del modelo de datos con las tablas y sus relaciones (imagen o PDF en el repositorio).
- El esquema deberá tener una vista (solo una) que muestre alguna información muy interesante
  sobre el modelo creado. La vista deberá llamarse `VISTA_MUY_INTERESANTE` y en `ENTREGA.md` se
  debe describir su contenido en un texto breve, claro y directo. Si el motor no es SQL, el
  equivalente (consulta guardada o visualización) con el mismo nombre.
  *(Ejemplos: sesiones con «viaje imposible»; usuarios cuyo acceso lógico no coincide con su
  acceso físico; consultas a la base de inteligencia sin caso asignado; tráfico «malicioso» que
  no se explica por ninguna detonación del sandbox.)*
- Un párrafo con las medidas de seguridad aplicadas al propio repositorio.

### 2.- Reto Desarrollo Web

El grupo deberá desarrollar una **consola de analista** web que acceda a la base de datos del
Reto 1 e incluya, como mínimo: línea temporal de eventos con filtros (usuario, equipo, origen,
rango temporal), gráficas de volumen y anomalías, lista de alertas con estados de triaje
(nueva / en investigación / cerrada) y notas de caso. Se valorará un mapa de calor de técnicas
MITRE ATT&CK y una visualización en grafo del movimiento lateral.

La aplicación debe incluir **autenticación con al menos dos roles** (analista y responsable) y
aplicar **buenas prácticas de desarrollo seguro**: consultas parametrizadas, escapado de todo
contenido procedente de los logs, control de acceso por objeto, secretos fuera del código
(variables de entorno o gestor de secretos), HTTPS, dependencias actualizadas. *El jurado probará
la consola con los propios datos del reto: si un user-agent malicioso o el nombre de una muestra
ejecuta JavaScript en vuestro visor, o un filtro admite inyección SQL, restará puntos.*

Se valorará la aplicación de buenas prácticas de Ingeniería del Software: repositorio con
historial de commits real, pruebas automatizadas, integración continua, README de despliegue y un
modelo de amenazas breve (STRIDE) de la propia consola.

La aplicación debe estar **desplegada y accesible para el jurado durante la ventana de
evaluación**. Plataforma libre: free tiers (Render, Fly.io, Railway, Vercel…), máquina virtual de
la universidad o túnel desde el portátil del equipo (Cloudflare Tunnel, ngrok) si se garantiza la
disponibilidad.

Para solicitar la evaluación de este hito se debe indicar en `ENTREGA.md`:

- Breve enumeración de las tecnologías utilizadas.
- Acceso al repositorio del código del proyecto.
- URL de acceso a la aplicación y credenciales de acceso para los roles implementados.
- Enumeración de las funcionalidades implementadas.
- Capturas de pantalla de las visualizaciones implementadas.

### 3.- Reto Análisis de Datos: investigación del incidente

El grupo deberá **reconstruir el incidente** a partir de la telemetría: paciente cero (primer
equipo infectado) y vector de entrada, cuentas y equipos comprometidos, ruta de movimiento
lateral, escalada de privilegios, **qué registros de la base de inteligencia se consultaron y
exfiltraron (y cuántos)**, canal de exfiltración, indicadores de compromiso y línea temporal
completa, mapeada a MITRE ATT&CK. También deberá **descartar razonadamente las falsas alarmas**
(incluido el tráfico legítimo del *sandbox farm*) y detectar cualquier otra actividad anómala que
no forme parte del ataque principal.

Se valorará el uso de técnicas analíticas (detección de anomalías, análisis de entropía,
correlación físico-lógica, modelos de detección de anomalías).

Entregables:

- **Cuestionario de respuestas cerradas** (`respuestas.json`, 12 preguntas: hashes, cuentas,
  horas UTC, recuentos, dominios). Corrección automática: **+1 por acierto, 0 si se deja en
  blanco (`null`), −1 si la respuesta es una pista falsa plantada en los datos**; máximo 10
  puntos. Si no estáis seguros, es mejor dejar la pregunta en blanco que adivinar.
- **Informe técnico de incidente** (máx. 6 páginas) con evidencia reproducible (consultas,
  identificadores de evento) + **resumen ejecutivo** de 1 página para la dirección del centro,
  en la carpeta `informe/`.
- **Bitácora de investigación** (`BITACORA.md`) desde el primer día: hipótesis, evidencia,
  conclusiones y callejones sin salida. Los *commits* son vuestras marcas temporales.

## RETOS AVANZADOS

### A.- «El ataque continúa» · Detección en vivo *(reto bandera)*

Durante el evento, la organización publicará **tres oleadas de nueva telemetría** en momentos
anunciados pero con contenido desconocido (miércoles 28/10/2026 17:00 (hora peninsular), jueves 29/10/2026 09:00 (hora peninsular) y
jueves 29/10/2026 15:00 (hora peninsular)). Cada oleada aparece como una *release* de este repositorio y se descarga con
`python3 starter-kit/fetch_dataset.py --wave N`. Los equipos deberán detectar y reportar la
actividad maliciosa (qué, cuándo, dónde, técnica ATT&CK, evidencia) en el fichero `oleadaN.json`
de su repositorio de entrega; **la hora del *push* es la hora de detección**. Se puntúa el
**tiempo hasta la detección**, la **cobertura** y la **precisión**; los falsos positivos restan
(no toda oleada contiene un ataque). En la práctica exige detecciones automatizadas (trabajos
programados, reglas SQL/Sigma, alertas en la consola) y triaje humano.

### C.- Respuesta, contención y marco legal · *Tabletop*

Plan de respuesta priorizado (contención, erradicación, recuperación), análisis de impacto,
borrador de notificación a la AEPD (72 h) y a INCIBE-CERT, plan de comunicación a los socios
cuyos informes se han visto afectados y, si procede, a las personas cuyos datos figuran en ellos
(2 páginas máximo, en `informe/`). Se defiende **dentro de la presentación final**: en el turno
de preguntas el jurado hace de dirección del GSEC e introduce dos o tres giros. Se evalúa el
juicio, no la retórica.

## Presentación final

Cada equipo dispone de **10 minutos de presentación y 10 minutos de defensa** ante el jurado.
Debe cubrir el modelo de datos, la consola, la reconstrucción del incidente, las detecciones en
vivo y el plan de respuesta. El resumen ejecutivo se expone como si la audiencia fuera la
dirección del centro.
