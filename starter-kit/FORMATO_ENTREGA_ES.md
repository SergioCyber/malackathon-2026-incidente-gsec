# Formato de entrega — «Incidente en el GSEC» (v1)

Dos tipos de fichero se corrigen automáticamente. Los dos van en la **raíz del repositorio
privado de entrega** de vuestro equipo y los dos se validan con el mismo script:

| Fichero | Qué es | Formato (`formato`) |
|---|---|---|
| `respuestas.json` | Cuestionario de 12 preguntas (reto 3) | `incidente-gsec/respuestas/v1` |
| `oleada1.json`, `oleada2.json`, `oleada3.json` | Un reporte por oleada publicada (reto A) | `incidente-gsec/oleada/v1` |

```bash
python3 starter-kit/validar_respuestas.py respuestas.json oleada1.json      # salida 0 = válido
```

El repositorio de entrega repite esa validación en cada *push*. **Un fichero que no valida no
puntúa**, así que validad siempre antes de subir. Las plantillas `starter-kit/respuestas.plantilla.json`
y `starter-kit/oleada.plantilla.json` ya son válidas: copiadlas y rellenadlas.

## 1. Reglas de corrección (resumen)

- Cuestionario: **+1** por pregunta acertada, **0** si está en blanco (`"respuesta": null`, o todos
  sus campos `null`, o la pregunta no aparece), **−1** si la respuesta coincide con una pista falsa
  plantada en los datos. En las preguntas con dos campos corregibles, **0,5** por campo acertado.
  Total máximo 10. *En blanco nunca resta: si no estáis seguros, no adivinéis.*
- La comparación es tolerante con la forma, no con el fondo: mayúsculas/minúsculas, acentos,
  comillas, espacios, punto final de un dominio, `https://` y rutas en dominios, prefijo de dominio
  (`GSECLAB\usuario`), separadores de miles (`12.345`, `12,345`, `12 345`), unidades de volumen
  (`B`, `KB`, `MB`, `GB`, `TB` en base 10; `KiB`, `MiB`, `GiB` en base 2), coma decimal y zona horaria
  en las fechas (`Z`, `+02:00`) se normalizan. Un valor fuera de tolerancia es simplemente incorrecto.
- Oleadas: se corrige la **primera versión válida** de cada `oleadaN.json` (podéis corregirla
  después, pero el tiempo de detección es el del primer *push* válido). Reportar como ataque una
  oleada que no lo es resta; cada entidad acusada que no tenga nada que ver con el ataque también.
- Cuenta la hora del *push* registrada por GitHub. No reescribáis el historial del repositorio de
  entrega (`push --force`): se trata como entrega inválida.

## 2. `respuestas.json`

### 2.1 Estructura general

```json
{
  "formato": "incidente-gsec/respuestas/v1",
  "equipo": "nombre-del-equipo",
  "generado": "2026-01-31T10:15:00Z",
  "respuestas": {
    "q01": {
      "respuesta": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
      "confianza": "media",
      "evidencia": ["SELECT ... FROM edr WHERE ...", "edr_2026-01-31.jsonl.gz línea 12"],
      "comentario": "opcional, máx. 500 caracteres"
    },
    "q02": { "respuesta": null }
  },
  "iocs": [ { "tipo": "dominio", "valor": "malo.example", "contexto": "C2 observado en proxy" } ],
  "mitre": ["T1566.002"],
  "enlaces": { "repositorio": "https://github.com/...", "consola": "https://..." }
}
```

- `equipo`: 1–60 caracteres (letras, dígitos, espacio, `.`, `-`, `_`), empieza y termina en letra o dígito.
- `generado`: fecha-hora ISO-8601 con zona, o `null`.
- `respuestas`: una entrada por pregunta (`q01` … `q12`). Cada entrada lleva `respuesta`
  (objeto con los campos de la pregunta, o `null`) y, opcionalmente, `confianza`
  (`alta`/`media`/`baja`), `evidencia` (hasta 10 textos de 300 caracteres) y `comentario` (500).
- `iocs` (opcional, hasta 200): indicadores que atribuís al atacante; `tipo` ∈ `dominio` · `ip` · `sha256` · `url` · `correo` · `fichero`.
  Se calcula su precisión y cobertura, y se listan los que son señuelos.
- `mitre` (opcional): técnicas ATT&CK observadas (`T1234` o `T1234.001`).
- `enlaces` (opcional): URL `https` de `repositorio`, `consola`, `informe`, `video`.
- No se admiten propiedades fuera de las descritas (ni `_ayuda`, ni comentarios): el validador las rechaza.

### 2.2 Las 12 preguntas y sus campos

Todos los campos de `respuesta` son obligatorios pero admiten `null` (campo sin responder). Los
valores de los ejemplos son **ficticios**.

### q01 — ¿Cuál es el SHA-256 del binario del ransomware (Malaka Locker)?

| Campo | Tipo | Qué poner |
|---|---|---|
| `sha256` | cadena hexadecimal de 64 caracteres | SHA-256 del binario, 64 caracteres hexadecimales |

```json
"q01": {"respuesta": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}
```

### q02 — ¿Qué usuario y qué equipo son el «paciente cero» (primer equipo infectado)?

| Campo | Tipo | Qué poner |
|---|---|---|
| `usuario` | texto: nombre de cuenta, sin dominio ni `@` | nombre de cuenta tal y como aparece en users.csv (sin dominio) |
| `equipo` | texto: nombre corto del equipo (como en `hosts.csv`) | nombre corto del equipo tal y como aparece en hosts.csv |

Puntuación parcial: 0,5 por cada uno de los 2 campos corregibles acertados.

```json
"q02": {"respuesta": {"usuario": "jdoe", "equipo": "ws-xxx-000"}}
```

### q03 — ¿Cuál es el dominio del C2 y la hora UTC del primer beacon?

| Campo | Tipo | Qué poner |
|---|---|---|
| `dominio` | texto: nombre de dominio, sin `https://` ni ruta | nombre de dominio del C2 (sin esquema ni ruta) |
| `primer_beacon_utc` | fecha-hora ISO-8601 **con zona horaria** (`2026-01-31T10:15:00Z`) | fecha-hora UTC ISO-8601 del primer beacon, p. ej. 2026-01-31T10:15:00Z |

Puntuación parcial: 0,5 por cada uno de los 2 campos corregibles acertados.

```json
"q03": {"respuesta": {"dominio": "malo.example", "primer_beacon_utc": "2026-01-31T10:15:00Z"}}
```

### q04 — ¿Qué cuenta de administrador local se usó para el movimiento lateral y la propagación, y cómo se obtuvo?

| Campo | Tipo | Qué poner |
|---|---|---|
| `cuenta` | texto: nombre de cuenta, sin dominio ni `@` | cuenta de administrador local (sin dominio) |
| `como_se_obtuvo` | texto libre (se buscan los términos técnicos habituales) (máx. 500 caracteres) | texto libre: cómo consiguió el atacante esa cuenta |

Puntuación parcial: 0,5 por cada uno de los 2 campos corregibles acertados.

```json
"q04": {"respuesta": {"cuenta": "jdoe", "como_se_obtuvo": "…"}}
```

### q05 — ¿Qué cuenta de servicio de BD se abusó y en qué fichero estaban sus credenciales?

| Campo | Tipo | Qué poner |
|---|---|---|
| `cuenta` | texto: nombre de cuenta, sin dominio ni `@` | cuenta de servicio de la base de datos |
| `fichero` | texto: ruta o nombre de fichero (máx. 300 caracteres) | ruta o nombre del fichero que contenía las credenciales |

Puntuación parcial: 0,5 por cada uno de los 2 campos corregibles acertados.

```json
"q05": {"respuesta": {"cuenta": "jdoe", "fichero": "\\\\servidor\\carpeta\\fichero.ext"}}
```

### q06 — ¿Cuántos registros de la base de inteligencia (intel.case_intel) consultó el atacante?

| Campo | Tipo | Qué poner |
|---|---|---|
| `registros` | número entero (también como texto con separadores de miles: `"12.345"`) | número entero de registros (se admiten separadores de miles) |

```json
"q06": {"respuesta": {"registros": 12345}}
```

### q07 — ¿Qué volumen (bytes) se exfiltró y a qué destino?

| Campo | Tipo | Qué poner |
|---|---|---|
| `bytes` | número entero de bytes, o texto con unidad (`"12.3 MB"`, `"1.2 GiB"`) | volumen en bytes (entero) o con unidad: 1.5 GB, 1.4 GiB… |
| `destino` | texto: dominio o dirección IP | dominio o IP de destino de la exfiltración |

Puntuación parcial: 0,5 por cada uno de los 2 campos corregibles acertados.

```json
"q07": {"respuesta": {"bytes": "12.3 MB", "destino": "destino.example"}}
```

### q08 — ¿Cuántos equipos ejecutaron el ransomware antes de la contención?

| Campo | Tipo | Qué poner |
|---|---|---|
| `equipos` | número entero (también como texto con separadores de miles: `"12.345"`) | número entero de equipos |

```json
"q08": {"respuesta": {"equipos": 12345}}
```

### q09 — ¿Quién consultó a la persona objetivo T-2048771 sin tener el caso asignado y desde qué puesto?

| Campo | Tipo | Qué poner |
|---|---|---|
| `usuario` | texto: nombre de cuenta, sin dominio ni `@` | nombre de cuenta (sin dominio) |
| `equipo` | texto: nombre corto del equipo (como en `hosts.csv`) | nombre corto del puesto |

Puntuación parcial: 0,5 por cada uno de los 2 campos corregibles acertados.

```json
"q09": {"respuesta": {"usuario": "jdoe", "equipo": "ws-xxx-000"}}
```

### q10 — ¿Cuál fue el vector de entrada real?

| Campo | Tipo | Qué poner |
|---|---|---|
| `vector` | uno de: `spear-phishing` · `vpn-sin-mfa` · `usb` · `servicio-expuesto` · `insider` · `cadena-de-suministro` · `otro` | vector de entrada (valor cerrado) |
| `detalle` | texto libre (máx. 500 caracteres) | texto libre: qué, quién, cuándo (no se corrige automáticamente) *(no se corrige automáticamente)* |

```json
"q10": {"respuesta": {"vector": "otro", "detalle": "…"}}
```

### q11 — ¿Fue malicioso el escaneo del 14/09 desde 10.10.99.50?

| Campo | Tipo | Qué poner |
|---|---|---|
| `es_ataque` | `true` / `false` | true si fue actividad maliciosa, false si no |
| `justificacion` | texto libre (máx. 500 caracteres) | texto libre: en qué os basáis (no se corrige automáticamente) *(no se corrige automáticamente)* |

```json
"q11": {"respuesta": {"es_ataque": null, "justificacion": "…"}}
```

### q12 — ¿Es maliciosa la IP 203.0.113.77 que aparece en el feed de IOCs?

| Campo | Tipo | Qué poner |
|---|---|---|
| `es_maliciosa` | `true` / `false` | true si la IP es maliciosa, false si no |
| `justificacion` | texto libre (máx. 500 caracteres) | texto libre: en qué os basáis (no se corrige automáticamente) *(no se corrige automáticamente)* |

```json
"q12": {"respuesta": {"es_maliciosa": null, "justificacion": "…"}}
```

## 3. `oleadaN.json` (reto A)

Un fichero por oleada, con su número en el nombre: `oleada1.json`, `oleada2.json`, `oleada3.json`.

```json
{
  "formato": "incidente-gsec/oleada/v1",
  "equipo": "nombre-del-equipo",
  "oleada": 1,
  "detectado_en": "2026-01-31T10:15:00Z",
  "es_ataque": true,
  "resumen": "Qué ha pasado, en vuestras palabras (máx. 1000 caracteres).",
  "entidades": {
    "usuarios": ["jdoe"],
    "equipos": ["ws-xxx-000"],
    "ips": ["192.0.2.1"],
    "dominios": ["malo.example"]
  },
  "evidencia": ["SELECT ... FROM wave1.vpn WHERE ...", "winsec 4624 tipo 10 en ws-xxx-000"],
  "mitre": ["T1078"],
  "regla_de_deteccion": "SQL, Sigma o descripción (opcional, máx. 4000 caracteres)"
}
```

| Campo | Tipo | Qué poner |
|---|---|---|
| `oleada` | entero 1, 2 o 3 | número de la oleada que reportáis |
| `detectado_en` | fecha-hora ISO-8601 con zona, o `null` | cuándo la detectasteis (informativo: la hora oficial es la del *push*) |
| `es_ataque` | `true` / `false` | si la oleada contiene actividad maliciosa. **No toda oleada es un ataque.** |
| `resumen` | texto (máx. 1000) | obligatorio aunque descartéis la oleada: explicad por qué |
| `entidades` | 4 listas de texto (máx. 50 cada una) | usuarios, equipos, IP y dominios **implicados en el ataque** (nombres cortos; se admiten alias razonables) |
| `evidencia` | lista de texto (máx. 20 × 300) | consultas, identificadores de evento, ficheros |
| `mitre` | lista opcional | técnicas ATT&CK |
| `regla_de_deteccion` | texto opcional (máx. 4000) | la regla/consulta que la detecta |

Puntuación de cada oleada: veredicto correcto (`es_ataque`) + cobertura de las entidades
implicadas + bonificación por rapidez (minutos desde la publicación de la oleada hasta vuestro
primer *push* válido). Las entidades sin relación con el ataque restan; una oleada que **no** es
un ataque puntúa íntegra si la descartáis con un `resumen` razonado, y resta si la reportáis como ataque.
Si no entregáis el fichero de una oleada, esa oleada puntúa 0 (nunca negativo).

## 4. Validación

```bash
python3 starter-kit/validar_respuestas.py respuestas.json oleada1.json oleada2.json
python3 starter-kit/validar_respuestas.py --all .          # todos los *.json de la carpeta
python3 starter-kit/validar_respuestas.py --json respuestas.json   # salida para integrar en vuestra CI
```

Solo necesita Python 3.10+ (biblioteca estándar). Código de salida `0` = todo válido, `1` = algún
fichero con errores (se listan con su ruta JSON, p. ej. `$.respuestas.q03.respuesta.dominio`),
`2` = error de uso. Los **avisos** no bloquean (campos en blanco, nombre de equipo sin cambiar…).

Límites duros: UTF-8, 1 MiB por fichero, 10 niveles de anidamiento, sin `NaN`/`Infinity`, sin
claves repetidas, objeto JSON en la raíz.

## 5. Preguntas frecuentes

- **¿Puedo dejar una pregunta a medias?** Sí: los campos que no sepáis, a `null`. Una pregunta con
  todos los campos `null` cuenta como en blanco.
- **¿Formato de los números?** Entero JSON (`12345`) o texto (`"12.345"`, `"12,345"`, `"12 345"`).
  Para volúmenes, también con unidad (`"12.3 MB"`): `KB/MB/GB/TB` son potencias de 10 y
  `KiB/MiB/GiB` potencias de 2.
- **¿Hora local o UTC?** Cualquiera, siempre con zona (`Z`, `+02:00`). Sin zona se interpreta
  como UTC. Las preguntas que piden UTC se corrigen con tolerancia de unos minutos.
- **¿Qué pasa si subo un fichero inválido?** El repositorio de entrega marca el *push* en rojo y
  ese fichero no se corrige hasta que subáis una versión válida. Para las oleadas, la primera
  versión válida fija la hora de detección.
