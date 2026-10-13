-- =====================================================================================
--  «Incidente en el GSEC» · IV Malackathon
--  ESQUEMA CANÓNICO para el Reto avanzado B (Ingeniería de detección)
--
--  Las reglas de detección en SQL se escriben contra la tabla EVENTS_NORM descrita aquí.
--  La organización carga el conjunto de datos oculto (variantes del mismo escenario) en
--  esta misma tabla y ejecuta las reglas de todos los equipos en igualdad de condiciones.
--
--  SQL estándar (ANSI), válido para DuckDB, PostgreSQL y ClickHouse; los tipos entre
--  comentarios indican el equivalente cuando difiere.
--
--  Contexto: la víctima es la red de un laboratorio de análisis de malware (GSEC-LAB,
--  dominio AD gseclab.local, dominio público gsec-lab.test). El laboratorio detona muestras
--  a diario en una granja de sandboxes (VLAN 10.10.60.0/24): NO TODO EL TRÁFICO MALICIOSO
--  ES UN ATAQUE. Las reglas deben correlacionar con la fuente `sandbox` (o con la zona
--  SANDBOX del cortafuegos) antes de declarar un compromiso.
-- =====================================================================================

CREATE TABLE events_norm (
    event_id        BIGINT        NOT NULL,                 -- identificador único y estable
    ts              TIMESTAMP     NOT NULL,                 -- UTC
    source          VARCHAR(16)   NOT NULL,                 -- firewall|vpn|proxy|dns|email|edr|winsec|dbaudit|sandbox|badges
    event_type      VARCHAR(48)   NOT NULL,                 -- ver tabla de valores más abajo
    event_code      VARCHAR(16),                            -- 4624, 4688, 1, 3, 11… (winsec/edr) o NULL
    host            VARCHAR(64),                            -- nombre de equipo (hosts.host); sandbox: la VM
    user_name       VARCHAR(64),                            -- cuenta (users.user), sin dominio
    user_domain     VARCHAR(64),                            -- GSECLAB / gseclab.local, NULL si no aplica
    src_ip          VARCHAR(45),
    src_port        INTEGER,
    dst_ip          VARCHAR(45),
    dst_port        INTEGER,
    protocol        VARCHAR(8),                             -- tcp|udp|icmp
    action          VARCHAR(16),                            -- allow|deny|delivered|quarantined|success|failure…
    src_zone        VARCHAR(8),                             -- firewall: LAN|SANDBOX|DMZ|VPN|WAN|GUEST
    dst_zone        VARCHAR(8),
    domain_name     VARCHAR(253),                           -- qname DNS / host HTTP / dominio de correo / dominio observado
    url             VARCHAR(2048),                          -- proxy: scheme://host/path ; sandbox: URL observada
    http_method     VARCHAR(8),
    http_status     INTEGER,
    user_agent      VARCHAR(1024),
    process_name    VARCHAR(260),                           -- ruta completa de la imagen (edr/winsec)
    process_cmdline VARCHAR(4096),
    parent_process  VARCHAR(260),
    file_hash       VARCHAR(64),                            -- SHA-256 en hexadecimal minúsculas (edr / sandbox.sample_sha256)
    file_path       VARCHAR(1024),
    registry_key    VARCHAR(1024),
    bytes_in        BIGINT,                                 -- hacia el origen (descarga)
    bytes_out       BIGINT,                                 -- desde el origen (subida)
    db_user         VARCHAR(64),                            -- dbaudit (pgaudit)
    db_object       VARCHAR(128),                           -- object_schema.object_name (p. ej. intel.case_intel)
    db_sql          VARCHAR(4096),
    rows_affected   BIGINT,                                 -- dbaudit.rows / sandbox.score (ver mapeo)
    logon_type      SMALLINT,                               -- winsec 4624/4625
    mfa_result      VARCHAR(16),                            -- vpn: approved|denied|timeout|pending
    case_id         VARCHAR(16),                            -- sandbox.case_id / dbaudit (si se extrae del SQL)
    verdict         VARCHAR(16),                            -- sandbox: malicious|suspicious|clean|error ; email: clean|spam|phish|malware|suspicious
    country         CHAR(2),                                -- país del IP público implicado
    asn             INTEGER,
    raw             VARCHAR                                 -- JSON con el registro original  (JSONB / String)
);

-- Índices recomendados (DuckDB los ignora sin error; PostgreSQL/ClickHouse los aprovechan)
-- CREATE INDEX ix_events_ts        ON events_norm (ts);
-- CREATE INDEX ix_events_host_ts   ON events_norm (host, ts);
-- CREATE INDEX ix_events_user_ts   ON events_norm (user_name, ts);
-- CREATE INDEX ix_events_src_dst   ON events_norm (src_ip, dst_ip);
-- CREATE INDEX ix_events_zone      ON events_norm (src_zone, ts);
-- ClickHouse: ENGINE = MergeTree ORDER BY (source, ts) PARTITION BY toDate(ts)

-- -------------------------------------------------------------------------------------
--  Tablas de contexto (copia directa del inventario público, sin transformar)
-- -------------------------------------------------------------------------------------
CREATE TABLE inv_users        (user_name VARCHAR(64) PRIMARY KEY, nombre VARCHAR, apellidos VARCHAR,
                               email VARCHAR, departamento VARCHAR(8), puesto VARCHAR,
                               host_principal VARCHAR(64), badge_id VARCHAR(16), fecha_alta DATE,
                               activo BOOLEAN, grupos VARCHAR);
CREATE TABLE inv_hosts        (host VARCHAR(64) PRIMARY KEY, ip VARCHAR(45), mac VARCHAR(17), os VARCHAR,
                               tipo VARCHAR(16),                       -- workstation|server|sandbox-vm|network
                               departamento VARCHAR(8),                -- SBX = granja de sandboxes
                               ubicacion VARCHAR, vlan INTEGER,
                               propietario VARCHAR(64));               -- VMs: srv-sbx-ctl-01
CREATE TABLE inv_departamentos(id VARCHAR(8) PRIMARY KEY, nombre VARCHAR, planta INTEGER, responsable VARCHAR(64));
CREATE TABLE inv_turnos       (user_name VARCHAR(64), fecha DATE, turno CHAR(1));      -- M T N L V
CREATE TABLE inv_servicios_ext(servicio VARCHAR, host VARCHAR, ip VARCHAR(45), proveedor VARCHAR,
                               descripcion VARCHAR);
CREATE TABLE inv_socios       (socio_id VARCHAR(8) PRIMARY KEY, nombre VARCHAR, pais CHAR(2),
                               tipo VARCHAR(16),                       -- cert|vendor|ong|isp|academia|gobierno
                               tlp_por_defecto VARCHAR(8), contacto VARCHAR);
CREATE TABLE inv_casos        (case_id VARCHAR(16) PRIMARY KEY, titulo VARCHAR, socio_id VARCHAR(8),
                               tlp VARCHAR(8),                         -- CLEAR|GREEN|AMBER|RED
                               analista_asignado VARCHAR(64), estado VARCHAR(16),
                               fecha_apertura DATE, fecha_cierre DATE);
CREATE TABLE inv_personas_obj (target_id VARCHAR(16) PRIMARY KEY, nombre VARCHAR, apellidos VARCHAR,
                               email VARCHAR, organizacion VARCHAR, pais CHAR(2), case_id VARCHAR(16),
                               confidencial BOOLEAN);                  -- true <=> caso TLP:RED
CREATE TABLE geoip_synthetic  (network_cidr VARCHAR(18), country CHAR(2), asn INTEGER, as_name VARCHAR);

-- -------------------------------------------------------------------------------------
--  Vocabulario de event_type por fuente (las reglas deben usar estos valores)
-- -------------------------------------------------------------------------------------
--  firewall : connection
--  vpn      : vpn_connect | vpn_auth_success | vpn_auth_failure | mfa_push | mfa_approved
--             mfa_denied | mfa_timeout | vpn_session_start | vpn_session_end
--  proxy    : http_request
--  dns      : dns_query
--  email    : email_inbound | email_outbound
--  edr      : process_create | network_connect | process_terminate | file_create
--             file_delete | registry_set | dns_query_host | process_access
--  winsec   : logon | logon_failure | logoff | explicit_logon | special_privileges
--             process_create | scheduled_task_create | user_create | user_enable
--             group_member_add | kerberos_tgs | ntlm_auth | share_access | share_object_access
--             audit_log_cleared | service_install
--  dbaudit  : db_read | db_write | db_ddl | db_role | db_misc | db_function | db_error
--             (clase pgaudit en minúsculas; db_error cuando result <> 'ok')
--  sandbox  : detonation            (una fila por detonación; host = VM, src_ip = vm_ip)
--             sandbox_domain        (una fila por dominio observado; domain_name)
--             sandbox_ip            (una fila por IP observada; dst_ip)
--  badges   : badge_in | badge_out | badge_denied

-- -------------------------------------------------------------------------------------
--  Mapeo de columnas de las fuentes públicas → EVENTS_NORM (resumen)
-- -------------------------------------------------------------------------------------
--  firewall.ts/src_ip/src_port/dst_ip/dst_port/proto→protocol/action/bytes_sent→bytes_out/
--           bytes_recv→bytes_in/src_zone/dst_zone/src_country→country (dst_country→raw)
--  vpn.ts/user→user_name/src_ip/src_country→country/src_asn→asn/assigned_ip→dst_ip/
--           event→event_type/result→action/reason→raw/mfa_method→raw
--  proxy.ts/client_ip→src_ip/user→user_name/host→domain_name/scheme+host+path→url/
--           method→http_method/status→http_status/bytes_in/bytes_out/user_agent/action/
--           category→raw (category=malware desde la VLAN 60 es la «línea sucia» de la sandbox)
--  dns.ts/client_ip→src_ip/qname→domain_name/qtype→event_code/rcode→action/answers→raw
--  email.ts/from→user_name(outbound) o domain_name(inbound)/to→user_name/verdict/action/
--           subject+urls+attachments→raw
--  edr.ts/host/user→user_name/event→event_type/event_id→event_code/image→process_name/
--           cmdline→process_cmdline/parent_image→parent_process/sha256→file_hash/
--           dst_ip/dst_port/dst_host→domain_name/file_path/target_object→registry_key
--  winsec.ts/host/event_id→event_code/target_user→user_name/target_domain→user_domain/
--           logon_type/src_ip/process_name/status→action/task_name→file_path/
--           service_name→process_name (7045)/file_path (5140/5145: recurso compartido)
--  dbaudit.ts/db_user/client_ip→src_ip/client_host→host/application_name→user_agent/
--           class→event_type (db_<class>)/command→event_code/object_schema.object_name→db_object/
--           statement→db_sql/rows→rows_affected/result→action (ok | error:<sqlstate>)
--  sandbox.ts/vm→host/vm_ip→src_ip/sample_sha256→file_hash/sample_name→file_path/
--           submitted_by→user_name/case_id/origin→raw/verdict/score→rows_affected/
--           family→raw/observed_domains→domain_name (una fila por dominio)/
--           observed_ips→dst_ip (una fila por IP)/observed_urls→url/duration_s→raw
--  badges.ts_local (convertir a UTC: Europe/Madrid)→ts/user→user_name/direction+result→event_type/
--           door_id→host

-- -------------------------------------------------------------------------------------
--  Formato de entrega de una regla (una por fichero, cabecera obligatoria en comentario)
-- -------------------------------------------------------------------------------------
--  -- rule_id:      GSEC-R-007
--  -- title:        Baliza periódica hacia dominio no visto en la sandbox
--  -- technique:    T1071.001
--  -- hypothesis:   >=30 conexiones a intervalos regulares (±20 %) desde un equipo que no es
--  --               una VM de la granja hacia un dominio sin detonación asociada
--  -- data_sources: edr, firewall, sandbox
--  -- false_positives: actualizadores legítimos de software (dominios del proveedor); comprobar
--  --               inv_hosts.tipo y las detonaciones de la VLAN 60 en la misma ventana
--  -- severity:     high
--  La consulta debe devolver, como mínimo, las columnas: ts, host, user_name, src_ip, detail
--  y cada fila se interpreta como UNA alerta. Las reglas se puntúan por precisión y
--  exhaustividad contra el conjunto oculto; las reglas basadas en comportamiento puntúan
--  más que las basadas en indicadores concretos (IPs, dominios, hashes). Las alertas sobre
--  tráfico de la granja de sandboxes (hosts tipo sandbox-vm / zona SANDBOX) cuentan como
--  falsos positivos salvo que la regla demuestre lo contrario.
