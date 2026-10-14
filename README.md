# Incidente en el GSEC · IV Malackathon

Repositorio público del reto **«Incidente en el GSEC»**: aquí está el enunciado, el conjunto de
datos (como *releases*), las oleadas de telemetría que se publican durante el evento y el kit de
arranque. Todo es gratuito y no requiere más que Python 3.10+ y un portátil normal.

> ℹ️ Obra de ficción con fines docentes. La red, las personas, los sistemas y los datos son
> inventados; nada describe la infraestructura real de Google ni del GSEC de Málaga. Los datos se
> entregan **exclusivamente** para este reto (ver [NORMAS.md](NORMAS.md)).

## Empezar en 3 pasos

```bash
git clone https://github.com/SergioCyber/malackathon-2026-incidente-gsec.git && cd $(basename SergioCyber/malackathon-2026-incidente-gsec)
python3 starter-kit/fetch_dataset.py            # descarga y verifica el dataset (≈ 300 MB) en output/public
python3 starter-kit/load_duckdb.py              # lo carga en un fichero DuckDB en ~20 s
```

- `fetch_dataset.py` descarga los ficheros de la *release* `dataset-v1.1`, comprueba su SHA-256
  y los extrae. Sin GitHub a mano (o si la wifi falla), funciona también desde el pendrive de la
  acreditación: `--from-dir /Volumes/MALACKATHON`.
- `load_duckdb.py` es solo un atajo: podéis usar el motor que queráis (PostgreSQL, ClickHouse,
  Elastic…). El formato de cada fuente está descrito en `README_DATASET_ES.md` dentro del dataset
  y en [starter-kit/README_ES.md](starter-kit/README_ES.md).
- Esquema canónico de referencia (opcional): [docs/esquema_canonico.sql](docs/esquema_canonico.sql).

## Documentos

| Documento | Para qué |
|---|---|
| [ENUNCIADO.md](ENUNCIADO.md) | El reto completo: contexto, retos básicos 1–3 y avanzados A y C, entregables |
| [starter-kit/FORMATO_ENTREGA_ES.md](starter-kit/FORMATO_ENTREGA_ES.md) | Formato obligatorio de `respuestas.json` y `oleadaN.json` (corrección automática) |
| [NORMAS.md](NORMAS.md) | Reglas del reto, uso de los datos, plazos y penalizaciones |
| [starter-kit/README_ES.md](starter-kit/README_ES.md) | Kit de arranque: descarga, carga, validación de entregas |

## Calendario

| Cuándo | Qué |
|---|---|
| Apertura del evento | Dataset disponible en la *release* `dataset-v1.1` |
| jueves 15/10/2026 10:15 (hora peninsular) | **Oleada 1** (`python3 starter-kit/fetch_dataset.py --wave 1`) |
| jueves 15/10/2026 13:15 (hora peninsular) | **Oleada 2** (`--wave 2`) |
| jueves 15/10/2026 16:15 (hora peninsular) | **Oleada 3** (`--wave 3`) |
| jueves 15/10/2026 19:30 (hora peninsular) | Cierre de `respuestas.json` y de los reportes de oleada |
| Final del evento | Presentación: 10 min + 10 min de defensa |

Las oleadas se publican como *releases* `oleada-1`, `oleada-2` y `oleada-3` a la hora indicada
(hora peninsular española). Suscribíos a las *releases* del repositorio («Watch → Custom →
Releases») para recibir el aviso.

## Entregas

Cada equipo entrega en **su propio repositorio privado de GitHub**: se crea desde
`https://github.com/SergioCyber/entrega-plantilla` con *Use this template* (visibilidad **Private**), se añade a `SergioCyber` y `alegp-google`
como colaboradores en *Settings → Collaborators* y se envía la URL a la organización (detalle en
`ENUNCIADO.md`, «Cómo se entrega todo»). Ahí van
`ENTREGA.md`, `respuestas.json`, `oleadaN.json`, `BITACORA.md` e `informe/`. Los JSON tienen
formato obligatorio: validadlos antes de subirlos.

```bash
python3 starter-kit/validar_respuestas.py respuestas.json oleada1.json
```

El repositorio de entrega repite esa validación en cada *push*. Un fichero con formato inválido
no puntúa. **La hora del *push* es la que cuenta** (reportes de oleada y cierre).

## Integridad y soporte

- Todos los ficheros del dataset van acompañados de `SHA256SUMS`; `fetch_dataset.py` lo comprueba
  automáticamente. Si descargáis a mano, verificad: `shasum -a 256 -c SHA256SUMS`.
- Dudas sobre el enunciado o los datos: el canal de la organización del Malackathon (por confirmar). No se responden preguntas sobre la solución.
- Si encontráis un error en el dataset (no una trampa: un error), avisad; se publicará una
  corrección para todos los equipos.
