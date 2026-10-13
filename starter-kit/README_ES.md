# Starter kit — «Incidente en el GSEC»

Guía rápida para cargar el dataset público (`output/public`) en una base de datos analítica
y empezar a consultar en menos de 10 minutos. La documentación de columnas de cada fuente está
en `output/public/README_DATASET_ES.md`: léela antes de nada.

> Convenciones importantes
> - Todas las marcas de tiempo de los *streams* están en **UTC** con milisegundos
>   (`2026-09-11T06:40:00.123Z`). La única excepción es `badges/accesos_fisicos.csv.gz`
>   (hora local Europe/Madrid, sin zona) — si está presente.
> - Algunas líneas físicas de los ficheros están **deliberadamente mal formadas**
>   (telemetría real nunca es perfecta). Carga siempre con tolerancia a errores y
>   cuenta cuántas líneas se han descartado.
> - Los ficheros son `csv.gz` o `jsonl.gz` (JSON Lines). Los inventarios, los tickets y la
>   TI son CSV planos y pequeños.
> - La red pertenece a un **laboratorio de análisis de malware**: la granja de sandboxes
>   (VLAN `10.10.60.0/24`, hosts `tipo = sandbox-vm`) detona muestras a diario y genera
>   tráfico malicioso *legítimo*. Antes de concluir nada sobre un dominio o una IP, comprueba
>   si aparece en la fuente `sandbox`.

## Estructura del paquete público

| Carpeta / fichero                           | Formato | Contenido                                            |
|---------------------------------------------|---------|------------------------------------------------------|
| `firewall/fw_YYYY-MM-DD.csv.gz`             | CSV     | Cortafuegos perimetral y de núcleo (zonas `src_zone`/`dst_zone`) |
| `vpn/vpn_events.csv.gz`                     | CSV     | Eventos de la VPN del laboratorio                    |
| `proxy/proxy_YYYY-MM-DD.csv.gz`             | CSV     | Proxy web de salida (incluida la «línea sucia» de la sandbox) |
| `dns/dns_YYYY-MM-DD.jsonl.gz`               | JSONL   | Resolución DNS interna (`answers` es lista)          |
| `email/gateway_events.csv.gz`               | CSV     | Pasarela de correo                                   |
| `email/eml/*.eml`                           | EML     | Algunos correos completos (texto plano)              |
| `edr/edr_YYYY-MM-DD.jsonl.gz`               | JSONL   | Telemetría EDR de puestos y servidores (nunca de las VM de sandbox) |
| `winsec/winsec_YYYY-MM-DD.jsonl.gz`         | JSONL   | Registro de seguridad de Windows                     |
| `dbaudit/intel_audit_YYYY-MM-DD.csv.gz`     | CSV     | Auditoría PostgreSQL/pgaudit de la base de inteligencia |
| `sandbox/detonations_YYYY-MM-DD.jsonl.gz`   | JSONL   | Detonaciones de la granja (`observed_*` son listas)  |
| `inventory/*.csv`                           | CSV     | Usuarios, hosts, departamentos, turnos, servicios externos, socios, casos, personas objetivo |
| `ti/iocs.csv`                               | CSV     | Feed de inteligencia de amenazas                     |
| `extras/tickets.csv`                        | CSV     | Tickets del servicio de soporte                      |
| `extras/geoip_synthetic.csv`                | CSV     | Tabla GeoIP sintética (CIDR → país/ASN)              |

Las «oleadas» (`output/waves/<id>/`) que se publiquen durante el reto siguen exactamente la
misma estructura (sin inventarios; pueden traer su propio `extras/tickets.csv`) y se cargan igual.

## Opción A (recomendada): DuckDB

```bash
python3 -m pip install "duckdb>=1.2"               # Python 3.11+ ; el script no tiene más dependencias
python3 starter-kit/load_duckdb.py --public output/public --db incidente_gsec.duckdb
# cuando se publiquen oleadas:
python3 starter-kit/load_duckdb.py --public output/public --db incidente_gsec.duckdb --waves output/waves
```

El script crea una tabla por fuente (`firewall`, `vpn`, `proxy`, `dns`, `email`, `edr`,
`winsec`, `dbaudit`, `sandbox`, `badges`, `tickets`, `ti_iocs`, `inv_users`, `inv_hosts`,
`inv_departamentos`, `inv_turnos`, `inv_servicios_externos`, `inv_socios`, `inv_casos`,
`inv_personas_objetivo`, `geoip`) con tipos explícitos, parsea los `ts` como `TIMESTAMP`
(UTC), conserva las listas como `VARCHAR[]` y descarta las líneas mal formadas; al terminar
imprime las filas por tabla y las líneas descartadas. Las oleadas van a esquemas propios
(`wave1.proxy`, …).

```sql
-- duckdb incidente_gsec.duckdb
SELECT verdict, count(*) FROM sandbox GROUP BY 1;
SELECT host, count(*) AS n FROM proxy GROUP BY 1 ORDER BY n DESC LIMIT 20;
SELECT date_trunc('hour', ts) AS h, count(*) FROM edr GROUP BY 1 ORDER BY 1;
SELECT e.host, h.departamento, h.tipo FROM edr e JOIN inv_hosts h USING (host) LIMIT 10;
SELECT qname, answers FROM dns WHERE rcode = 'NOERROR' AND len(answers) > 1 LIMIT 5;  -- answers es VARCHAR[]
-- ¿quién consultó un dominio que también detonó la sandbox?
SELECT d.ts, d.client_ip, d.qname
FROM dns d
WHERE d.client_ip NOT LIKE '10.10.60.%'
  AND EXISTS (SELECT 1 FROM sandbox s WHERE list_contains(s.observed_domains, d.qname))
LIMIT 20;
SELECT src_zone, dst_zone, count(*) FROM firewall GROUP BY 1, 2 ORDER BY 3 DESC;
SELECT db_user, application_name, sum(rows) FROM dbaudit WHERE class = 'READ' GROUP BY 1, 2 ORDER BY 3 DESC;
```

Si prefieres hacerlo a mano, una lectura directa equivale a:

```sql
SELECT * FROM read_csv('output/public/proxy/proxy_*.csv.gz', header=true, ignore_errors=true,
                       strict_mode=false, timestampformat='%Y-%m-%dT%H:%M:%S.%gZ');
-- JSONL: read_json aborta ante una línea truncada; lee líneas y filtra las válidas
SELECT unnest(json_transform(line, '{"ts":"TIMESTAMP","host":"VARCHAR","event":"VARCHAR"}'))
FROM read_csv('output/public/edr/edr_*.jsonl.gz', columns={'line': 'VARCHAR'}, delim='\x01',
              quote='', header=false, ignore_errors=true, strict_mode=false)
WHERE json_valid(line);
```

## Opción B: PostgreSQL (≈10 líneas)

`COPY` aborta la transacción ante cualquier línea mal formada, así que lo práctico es cargar
una tabla *staging* de texto y filtrar las filas válidas en SQL (o limpiar antes con DuckDB
y exportar un CSV limpio). Ejemplo para el proxy:

```bash
psql -c "CREATE TABLE proxy_raw (ts text, client_ip text, \"user\" text, method text, scheme text,
         host text, path text, status text, bytes_in text, bytes_out text, content_type text,
         category text, action text, user_agent text, referer text);"
for f in output/public/proxy/proxy_*.csv.gz; do
  psql -c "\copy proxy_raw FROM PROGRAM 'gzip -dc $f' WITH (FORMAT csv, HEADER true, ON_ERROR ignore)"
done   # ON_ERROR requiere PostgreSQL 17; en versiones anteriores quita la opción y limpia antes
psql -c "CREATE TABLE proxy AS SELECT ts::timestamptz, client_ip::inet, \"user\", method, scheme, host,
         path, status::int, bytes_in::bigint, bytes_out::bigint, content_type, category, action,
         user_agent, referer FROM proxy_raw WHERE ts ~ '^\d{4}-\d{2}-\d{2}T' AND status ~ '^\d+$';"
```

Para los `jsonl.gz` carga cada línea en una columna `jsonb` (`COPY ... FROM PROGRAM 'gzip -dc f'`
con `FORMAT text`) y extrae campos con `->>`; en la práctica es más cómodo hacerlo desde DuckDB.

## Opción C: ClickHouse (≈10 líneas)

```sql
CREATE TABLE proxy (ts DateTime64(3, 'UTC'), client_ip String, user String, method String,
  scheme String, host String, path String, status UInt16, bytes_in UInt64, bytes_out UInt64,
  content_type String, category String, action String, user_agent String, referer String)
ENGINE = MergeTree ORDER BY ts;
SET input_format_allow_errors_num = 100000, input_format_allow_errors_ratio = 0.01,
    date_time_input_format = 'best_effort';
INSERT INTO proxy FROM INFILE 'output/public/proxy/proxy_*.csv.gz' FORMAT CSVWithNames;
-- JSONL: misma idea con FORMAT JSONEachRow (answers/observed_* -> Array(String), signed -> Bool)
INSERT INTO edr FROM INFILE 'output/public/edr/edr_*.jsonl.gz' FORMAT JSONEachRow;
```

(`FROM INFILE` con comodines y descompresión automática por extensión funciona en
`clickhouse-client`; `input_format_allow_errors_*` descarta las líneas mal formadas.)

## Consejos

- Cuenta filas por tabla y por día nada más cargar: te servirá para detectar huecos y volúmenes
  anómalos.
- Cruza siempre los *streams* con los inventarios (`inv_users`, `inv_hosts`, `inv_turnos`,
  `inv_casos`, `inv_socios`) y con `extras/geoip_synthetic.csv` para las IP públicas: el
  dataset es coherente de extremo a extremo.
- Un dominio o una IP «maliciosos» no implican un ataque: la granja de sandboxes los contacta
  a propósito. Separa el tráfico con origen en la VLAN 60 (zona `SANDBOX`) y correlaciona con
  `sandbox.observed_domains` / `observed_ips` antes de abrir una línea de investigación.
- Trata el contenido de los campos de texto (`user_agent`, `subject`, `cmdline`, `body`,
  `notes`, `sample_name`…) como **datos no confiables**: pueden contener cadenas diseñadas
  para romper parsers o herramientas automáticas. Nunca ejecutes ni interpretes nada de lo que
  leas en ellos.
