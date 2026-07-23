// ============================================================
//  CollarGPS Server v3 — Node.js + PostgreSQL
//  Render.com · Puerto 3000
//
//  Endpoints:
//  POST /gps          — recibe posición + datos IMU del gateway
//  GET  /geovallas    — devuelve geovalla activa al gateway
//  POST /geovallas    — crea o actualiza una geovalla
//  GET  /historial    — historial de posiciones de un collar
//  GET  /config       — configuraciones de intensidad por collar
//  POST /config       — actualiza intensidad de shock de un collar
//  GET  /alertas      — últimas alertas (cruces y avisos)
//  GET  /actividad    — métricas de actividad por collar (IMU)
//  GET  /health       — health check para Render
// ============================================================

require('dotenv').config();
const express = require('express');
const { Pool }  = require('pg');
const cors      = require('cors');
const crypto    = require('crypto');   // nativo de Node, para hash de contraseñas

const app  = express();
const port = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// ── Secretos (fail-closed en producción) ─────────────────────
//  En producción TOKEN_SIGNING_KEY y ADMIN_PASSWORD son OBLIGATORIOS: si
//  faltan, el server NO arranca. Esto elimina el default público anterior
//  ('lindero-admin-2026') que permitía forjar tokens de cualquier usuario.
//  En desarrollo se generan valores efímeros y se imprimen en consola.
function requireSecret(name, minLen = 16) {
  const v = process.env[name];
  if (v && v.length >= minLen) return v;
  if (IS_PROD) {
    console.error(`FATAL: ${name} no definida o demasiado corta (mín. ${minLen} caracteres). El server no arrancará por seguridad.`);
    process.exit(1);
  }
  const gen = crypto.randomBytes(24).toString('hex');
  console.warn(`⚠️  ${name} no definida (dev): usando valor efímero → ${gen}`);
  return gen;
}
// La clave de firma debe ser larga/aleatoria (≥32); la contraseña de admin es humana (≥8).
const TOKEN_SIGNING_KEY = requireSecret('TOKEN_SIGNING_KEY', 32);
const ADMIN_PASSWORD    = requireSecret('ADMIN_PASSWORD', 8);
// Caducidad del token de sesión y tope de seguridad de la intensidad de estímulo.
const TOKEN_TTL_MS  = (Number(process.env.TOKEN_TTL_DAYS) || 30) * 24 * 60 * 60 * 1000;
const SHOCK_PWR_MAX = Math.min(255, Math.max(0, Number(process.env.SHOCK_PWR_MAX) || 255));
const RETENCION_DIAS = Number(process.env.RETENCION_DIAS) || 0;   // 0 = sin purga automática
// Clave de dispositivo (gateway/collar) para /gps y /salud. Si NO está definida, la
// validación se OMITE (rollout seguro: desplegar código → flashear gateway con la clave
// → setear esta variable en Render para ACTIVAR la exigencia sin romper el gateway).
const DEVICE_API_KEY = process.env.DEVICE_API_KEY || '';

app.set('trust proxy', 1);   // detrás del proxy de Render: obtener la IP real
app.use(cors());
app.use(express.json({ limit: '256kb' }));

// Cabeceras de seguridad (equivalente ligero a helmet, sin dependencias).
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});

// ── PostgreSQL ───────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
  max: Number(process.env.PG_POOL_MAX) || 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
// Una desconexión del Postgres de Render NO debe tumbar el proceso.
pool.on('error', (err) => {
  console.error('⚠️  Error inesperado en el pool de PostgreSQL:', err.message);
});

// Responde 500 sin filtrar detalles internos (err.message) al cliente.
function fail500(res, err) {
  console.error(err);
  return res.status(500).json({ error: 'error interno del servidor' });
}

// Rate-limit simple en memoria (Render free = 1 instancia).
// La IP viene de req.ip (correcto con trust proxy=1); NO se lee X-Forwarded-For
// crudo porque su primer elemento es falsificable por el cliente.
function rateLimit({ max, windowMs, msg, keyFn }) {
  const hits = new Map();
  // Barrido temporal de expiradas (no depende del tamaño); unref para no
  // mantener vivo el proceso por sí solo.
  const t = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (now - v.start > windowMs) hits.delete(k);
  }, windowMs);
  if (t.unref) t.unref();
  return (req, res, next) => {
    const now = Date.now();
    if (hits.size > 20000) hits.clear();   // tope duro anti-OOM bajo abuso
    const key = keyFn ? keyFn(req) : (req.ip || 'anon');
    const rec = hits.get(key);
    if (!rec || now - rec.start > windowMs) hits.set(key, { start: now, count: 1 });
    else if (++rec.count > max) return res.status(429).json({ error: msg || 'demasiados intentos, espera un momento' });
    next();
  };
}
// Solo el login se limita (fuerza bruta). Los endpoints de dispositivo (/gps, /salud)
// hacen polling frecuente y NO se limitan. Llave = IP + correo: no penaliza a varios
// usuarios legítimos tras una misma IP (NAT/CGNAT rural), pero sí frena el ataque por cuenta.
const loginLimiter = rateLimit({
  max: 30, windowMs: 15 * 60 * 1000,
  msg: 'demasiados intentos de inicio de sesión; espera unos minutos',
  keyFn: (req) => (req.ip || 'anon') + '|' + String(req.body && req.body.correo || '').toLowerCase().trim(),
});

// Purga opcional de datos crudos antiguos (RETENCION_DIAS; 0 = desactivada).
async function purgaRetencion() {
  if (RETENCION_DIAS <= 0) return;
  try {
    const a = await pool.query(`DELETE FROM posiciones     WHERE ts < NOW() - ($1 || ' days')::interval`, [RETENCION_DIAS]);
    const b = await pool.query(`DELETE FROM salud_collares WHERE ts < NOW() - ($1 || ' days')::interval`, [RETENCION_DIAS]);
    console.log(`🧹 Retención ${RETENCION_DIAS}d: -${a.rowCount} posiciones, -${b.rowCount} salud`);
  } catch (e) { console.error('purgaRetencion:', e.message); }
}

// ─────────────────────────────────────────────────────────────
//  AUTENTICACIÓN — hash de contraseñas y tokens de sesión
// ─────────────────────────────────────────────────────────────
// Hash de contraseña con scrypt (incluido en Node, seguro).
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(test));
}
// Token de sesión: userId + timestamp + firma HMAC (clave dedicada), con caducidad.
function crearToken(userId) {
  const payload = userId + '.' + Date.now();
  const firma = crypto.createHmac('sha256', TOKEN_SIGNING_KEY).update(payload).digest('hex');
  return Buffer.from(payload + '.' + firma).toString('base64');
}
// Comparación de cadenas en tiempo constante (evita canal lateral de temporización).
function safeEqual(a, b) {
  const ba = Buffer.from(String(a)), bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
function verificarToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString();
    const [userId, ts, firma] = decoded.split('.');
    if (!userId || !ts || !firma) return null;
    const payload = userId + '.' + ts;
    const esperada = crypto.createHmac('sha256', TOKEN_SIGNING_KEY).update(payload).digest('hex');
    if (!safeEqual(firma, esperada)) return null;
    if (Date.now() - Number(ts) > TOKEN_TTL_MS) return null;   // token caducado
    return userId;
  } catch(e) {}
  return null;
}
// Middleware: extrae el usuario del header Authorization
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  const userId = verificarToken(token);
  if (!userId) return res.status(401).json({ error: 'no autorizado' });
  req.userId = userId;
  next();
}
// Middleware: verifica la contraseña de admin (header x-admin-password)
function requireAdmin(req, res, next) {
  if (!safeEqual(req.headers['x-admin-password'] || '', ADMIN_PASSWORD)) {
    return res.status(403).json({ error: 'admin requerido' });
  }
  next();
}
// Autenticación de dispositivo (gateway) para la ingesta /gps y /salud.
// Gated por DEVICE_API_KEY: sin ella definida es no-op (no rompe el gateway durante
// el rollout); con ella, exige el header X-Device-Key (comparación en tiempo constante).
function requireDevice(req, res, next) {
  if (!DEVICE_API_KEY) return next();
  if (!safeEqual(req.headers['x-device-key'] || '', DEVICE_API_KEY)) {
    return res.status(401).json({ error: 'dispositivo no autorizado' });
  }
  next();
}
// Obtener el correo (dueño) a partir del id de usuario del token
async function correoDeUsuario(userId) {
  const { rows } = await pool.query('SELECT correo FROM usuarios WHERE id=$1', [userId]);
  return rows.length ? rows[0].correo : null;
}

// ── Distancia entre dos coordenadas en metros (Haversine) ─────
function distanciaMetros(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = d => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat/2)**2 +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

// ── v6: ¿el punto está dentro del polígono? (ray casting) ─────
function puntoEnPoligonoSrv(lat, lng, poly) {
  if (!Array.isArray(poly) || poly.length < 3) return false;
  let dentro = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const yi = poly[i].lat, xi = poly[i].lng;
    const yj = poly[j].lat, xj = poly[j].lng;
    if (((yi > lat) !== (yj > lat)) &&
        (lng < (xj - xi) * (lat - yi) / (yj - yi) + xi)) dentro = !dentro;
  }
  return dentro;
}

// ── v6: arreo vigente del dueño (o null), con expiración en el servidor ──
async function arreoVigente(dueno) {
  const { rows } = await pool.query(`
    SELECT * FROM modo_arreo
    WHERE dueno = $1 AND activo = true
    ORDER BY id DESC LIMIT 1
  `, [dueno]);
  if (!rows.length) return null;
  const a = rows[0];
  const venceEn = new Date(a.inicio).getTime() + a.duracion_min * 60000;
  if (Date.now() > venceEn) {
    await pool.query(
      'UPDATE modo_arreo SET activo=false, terminado_en=NOW() WHERE id=$1', [a.id]);
    console.log(`🐄 Arreo de ${dueno} EXPIRÓ en el servidor (${a.duracion_min} min).`);
    return null;
  }
  return a;
}

// ── v6: ¿este collar debe estar en arreo AHORA? ───────────────
// Regla Nofence: con destino, la contención del collar "se activa" en
// cuanto ese collar registra posición DENTRO del potrero destino. Su
// flag se apaga individualmente (los que llegaron quedan contenidos,
// los que van en camino siguen libres de estímulo).
async function flagArreoParaDevice(device, dueno) {
  const a = await arreoVigente(dueno);
  if (!a) return 0;
  if (!a.destino_valla_id) return 1;   // arreo simple por tiempo
  const v = await pool.query(
    'SELECT poligono FROM geovallas WHERE id=$1', [a.destino_valla_id]);
  if (!v.rows.length) return 1;
  const p = await pool.query(`
    SELECT lat, lng FROM posiciones
    WHERE device = $1 AND historico IS NOT TRUE
    ORDER BY ts DESC LIMIT 1
  `, [device]);
  if (!p.rows.length) return 1;
  return puntoEnPoligonoSrv(p.rows[0].lat, p.rows[0].lng, v.rows[0].poligono) ? 0 : 1;
}

// ── Inicializar tablas al arrancar ───────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posiciones (
      id          SERIAL PRIMARY KEY,
      device      TEXT NOT NULL,
      lat         DOUBLE PRECISION,
      lng         DOUBLE PRECISION,
      speed       REAL DEFAULT 0,
      sats        INT  DEFAULT 0,
      rssi        INT  DEFAULT 0,
      estado      TEXT DEFAULT 'ok',
      dist_borde  REAL DEFAULT 0,
      movimiento  BOOLEAN DEFAULT false,
      aceleracion REAL    DEFAULT 0,
      actividad_s BIGINT  DEFAULT 0,
      shock_pwr   INT     DEFAULT 200,
      bateria     INT     DEFAULT 100,
      carga       INT     DEFAULT 0,
      ts          TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE posiciones ADD COLUMN IF NOT EXISTS bateria INT DEFAULT 100;
    ALTER TABLE posiciones ADD COLUMN IF NOT EXISTS carga   INT DEFAULT 0;

    CREATE TABLE IF NOT EXISTS geovallas (
      id            SERIAL PRIMARY KEY,
      nombre        TEXT    NOT NULL DEFAULT 'potrero principal',
      tipo          TEXT    NOT NULL DEFAULT 'permanente',
      poligono      JSONB   NOT NULL,
      activa        BOOLEAN DEFAULT true,
      warn_dist_m   REAL    DEFAULT 10,
      color         TEXT    DEFAULT '#1D9E75',
      collares      JSONB   DEFAULT '[]',
      expira_en     TIMESTAMPTZ,
      creada_por    TEXT    DEFAULT 'app',
      created       TIMESTAMPTZ DEFAULT NOW(),
      updated       TIMESTAMPTZ DEFAULT NOW(),
      dueno         TEXT    DEFAULT 'default'
    );

    CREATE TABLE IF NOT EXISTS historial_cercas (
      id         SERIAL PRIMARY KEY,
      valla_id   INT REFERENCES geovallas(id) ON DELETE CASCADE,
      accion     TEXT NOT NULL,
      detalle    JSONB,
      ts         TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS alertas (
      id      SERIAL PRIMARY KEY,
      device  TEXT NOT NULL,
      tipo    TEXT NOT NULL,
      lat     DOUBLE PRECISION,
      lng     DOUBLE PRECISION,
      mensaje TEXT,
      leida   BOOLEAN DEFAULT false,
      ts      TIMESTAMPTZ DEFAULT NOW(),
      ts_fin  TIMESTAMPTZ DEFAULT NOW(),
      conteo  INT DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS config_collares (
      id        SERIAL PRIMARY KEY,
      device    TEXT NOT NULL UNIQUE,
      shock_pwr INT  NOT NULL DEFAULT 200,
      notas     TEXT,
      updated   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS lotes (
      id      BIGINT PRIMARY KEY,
      nombre  TEXT NOT NULL,
      color   TEXT DEFAULT '#4ade80',
      dueno   TEXT DEFAULT 'default',
      updated TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS animales (
      id      BIGINT PRIMARY KEY,
      nombre  TEXT NOT NULL,
      collar  TEXT,
      arete   TEXT,
      peso    INT DEFAULT 0,
      edad    INT DEFAULT 0,
      raza    TEXT,
      sexo    TEXT,
      lote    BIGINT,
      notas   TEXT,
      dueno   TEXT DEFAULT 'default',
      updated TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS usuarios (
      id       SERIAL PRIMARY KEY,
      correo   TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      rancho   TEXT NOT NULL,
      creado   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS collar_dueno (
      device TEXT PRIMARY KEY,
      dueno  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS aguajes (
      id      SERIAL PRIMARY KEY,
      dueno   TEXT NOT NULL,
      nombre  TEXT NOT NULL DEFAULT 'Aguaje',
      lat     DOUBLE PRECISION NOT NULL,
      lng     DOUBLE PRECISION NOT NULL,
      radio_m REAL DEFAULT 20,
      created TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS visitas_aguaje (
      id        SERIAL PRIMARY KEY,
      aguaje_id INT NOT NULL,
      device    TEXT NOT NULL,
      ts        TIMESTAMPTZ DEFAULT NOW(),
      ts_fin    TIMESTAMPTZ DEFAULT NOW()
    );

    -- v6: salud reportada por cada collar (paquete "sl":1 vía gateway)
    CREATE TABLE IF NOT EXISTS salud_collares (
      id         SERIAL PRIMARY KEY,
      device     TEXT NOT NULL,
      uptime_min BIGINT DEFAULT 0,
      bateria    INT DEFAULT 0,
      bateria_mv INT DEFAULT 0,
      carga      INT DEFAULT 0,
      pulsos     INT DEFAULT 0,
      avisos     INT DEFAULT 0,
      bloqueado  BOOLEAN DEFAULT false,
      reinicios  INT DEFAULT 0,
      reinicios_anormales INT DEFAULT 0,
      entrega_pct INT DEFAULT 0,
      respaldo   INT DEFAULT 0,
      rssi       INT DEFAULT 0,
      ts         TIMESTAMPTZ DEFAULT NOW()
    );

    -- v6: modo arreo por rancho. La expiración se calcula en el servidor
    -- al leer (inicio + duracion_min); nunca se confía en que alguien
    -- apague el botón. destino_valla_id opcional: con destino, el flag
    -- de cada collar se apaga solo cuando ese collar entra al potrero.
    CREATE TABLE IF NOT EXISTS modo_arreo (
      id               SERIAL PRIMARY KEY,
      dueno            TEXT NOT NULL,
      activo           BOOLEAN DEFAULT true,
      destino_valla_id INT,
      inicio           TIMESTAMPTZ DEFAULT NOW(),
      duracion_min     INT DEFAULT 120,
      terminado_en     TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_pos_device ON posiciones(device);
    CREATE INDEX IF NOT EXISTS idx_pos_ts     ON posiciones(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_visitas_ts ON visitas_aguaje(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_salud_ts   ON salud_collares(ts DESC);
  `);

  // ── Migraciones: agregar columnas que falten en tablas ya creadas ──
  // Si la base se creó con una versión vieja de la tabla geovallas,
  // estas líneas agregan las columnas nuevas sin borrar datos.
  const migraciones = [
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS tipo TEXT NOT NULL DEFAULT 'permanente'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS warn_dist_m REAL DEFAULT 10`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS color TEXT DEFAULT '#1D9E75'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS collares JSONB DEFAULT '[]'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS expira_en TIMESTAMPTZ`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS creada_por TEXT DEFAULT 'app'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS updated TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS dueno TEXT DEFAULT 'default'`,
    // Alertas: agrupar por episodio (ts = inicio, ts_fin = última vez visto)
    `ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ts_fin TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE alertas ADD COLUMN IF NOT EXISTS conteo INT DEFAULT 1`,
    // v6: bienestar, diagnóstico, históricos y arreo por posición
    `ALTER TABLE posiciones ADD COLUMN IF NOT EXISTS bloqueado BOOLEAN DEFAULT false`,
    `ALTER TABLE posiciones ADD COLUMN IF NOT EXISTS reinicios_anormales INT DEFAULT 0`,
    `ALTER TABLE posiciones ADD COLUMN IF NOT EXISTS historico BOOLEAN DEFAULT false`,
    `ALTER TABLE posiciones ADD COLUMN IF NOT EXISTS hace_s BIGINT DEFAULT 0`,
    `ALTER TABLE posiciones ADD COLUMN IF NOT EXISTS arreo BOOLEAN DEFAULT false`,
    // Fase 3: índices creados DESPUÉS de agregar columnas (dueno/collares ya existen).
    // Cada uno es su propia sentencia con try/catch en el loop: un fallo aislado no
    // arrastra a los demás ni aborta las migraciones. Idempotentes (IF NOT EXISTS).
    `CREATE INDEX IF NOT EXISTS idx_pos_device_ts     ON posiciones(device, ts DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_salud_device_ts   ON salud_collares(device, ts DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_alertas_device_ts ON alertas(device, ts DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_geovallas_dueno   ON geovallas(dueno)`,
    `CREATE INDEX IF NOT EXISTS idx_geovallas_activa  ON geovallas(activa)`,
    `CREATE INDEX IF NOT EXISTS idx_geovallas_collares_gin ON geovallas USING GIN (collares)`,
    `CREATE INDEX IF NOT EXISTS idx_histcercas_valla  ON historial_cercas(valla_id)`,
    `CREATE INDEX IF NOT EXISTS idx_visitas_aguaje    ON visitas_aguaje(aguaje_id, ts_fin DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_aguajes_dueno     ON aguajes(dueno)`,
    `CREATE INDEX IF NOT EXISTS idx_animales_dueno    ON animales(dueno)`,
    `CREATE INDEX IF NOT EXISTS idx_lotes_dueno       ON lotes(dueno)`,
    `CREATE INDEX IF NOT EXISTS idx_collardueno_dueno ON collar_dueno(dueno)`,
    `CREATE INDEX IF NOT EXISTS idx_arreo_dueno_activo ON modo_arreo(dueno, activo)`
  ];
  for (const m of migraciones) {
    try { await pool.query(m); }
    catch (e) { console.log('migración:', e.message); }
  }

  console.log('✅ Tablas inicializadas y migradas');
}

// ─────────────────────────────────────────────────────────────
//  GET /health  — Render lo usa para saber si el server vive
// ─────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'ok', version: '3.1', ts: new Date().toISOString() });
  } catch (err) {
    console.error('health: la BD no responde:', err.message);
    res.status(503).json({ status: 'degraded', db: 'down', ts: new Date().toISOString() });
  }
});

// ─────────────────────────────────────────────────────────────
//  POST /gps
//  Body: { device, lat, lng, speed, sats, rssi, estado,
//          dist_borde, movimiento, aceleracion, actividad_s,
//          shock_pwr }
// ─────────────────────────────────────────────────────────────
app.post('/gps', requireDevice, async (req, res) => {
  const {
    device, lat, lng,
    speed       = 0,
    sats        = 0,
    rssi        = 0,
    estado      = 'ok',
    dist_borde  = 0,
    movimiento  = false,
    aceleracion = 0,
    actividad_s = 0,
    shock_pwr   = 200,
    bateria     = 100,
    carga       = 0,
    // v6: bienestar, diagnóstico, históricos y arreo
    bloqueado   = false,
    reinicios_anormales = 0,
    historico   = false,
    hace_s      = 0,
    arreo       = false
  } = req.body;

  const latNum = Number(lat), lngNum = Number(lng);
  if (!device || lat == null || lng == null ||
      !Number.isFinite(latNum) || !Number.isFinite(lngNum) ||
      latNum < -90 || latNum > 90 || lngNum < -180 || lngNum > 180) {
    return res.status(400).json({ error: 'device y lat/lng numéricos en rango son requeridos' });
  }

  try {
    // v6: una posición histórica se guarda con SU hora real (ahora - hace_s),
    // no con la hora en que por fin llegó. Así el mapa y los reportes ven
    // el recorrido verdadero, en orden.
    const haceSeg = historico ? Math.max(0, parseInt(hace_s) || 0) : 0;
    await pool.query(`
      INSERT INTO posiciones
        (device, lat, lng, speed, sats, rssi, estado,
         dist_borde, movimiento, aceleracion, actividad_s, shock_pwr, bateria, carga,
         bloqueado, reinicios_anormales, historico, hace_s, arreo, ts)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
              $15,$16,$17,$18,$19, NOW() - make_interval(secs => $20))
    `, [device, lat, lng, speed, sats, rssi, estado,
        dist_borde, movimiento, aceleracion, actividad_s, shock_pwr, bateria, carga,
        !!bloqueado, parseInt(reinicios_anormales) || 0, !!historico, haceSeg, !!arreo, haceSeg]);

    // ── Alertas por EPISODIO (no una nueva cada 5 segundos) ──
    // Si el collar sigue en el mismo estado (warn/shock), en vez de crear
    // una alerta nueva, actualizamos la última de ese tipo extendiendo su
    // hora de fin. Así una sola alerta muestra cuánto duró el episodio.
    // Solo se crea una alerta NUEVA si pasaron más de 5 minutos desde la
    // última del mismo tipo (= el animal salió de ese estado un rato).
    if (estado === 'shock' || estado === 'warn') {
      const VENTANA_MIN = 5;  // minutos sin reportar para considerar episodio nuevo
      const mensaje = estado === 'shock'
        ? `${device} cruzó la cerca`
        : `${device} se acercó al límite (${dist_borde.toFixed(0)}m)`;

      // ¿Hay un episodio reciente del mismo tipo aún "vivo"?
      const reciente = await pool.query(`
        SELECT id FROM alertas
        WHERE device = $1 AND tipo = $2
          AND ts_fin > NOW() - INTERVAL '${VENTANA_MIN} minutes'
        ORDER BY ts_fin DESC
        LIMIT 1
      `, [device, estado]);

      if (reciente.rows.length > 0) {
        // Mismo episodio: extender la duración (ts_fin) y sumar al conteo.
        await pool.query(`
          UPDATE alertas
          SET ts_fin = NOW(), conteo = conteo + 1,
              lat = $2, lng = $3, mensaje = $4
          WHERE id = $1
        `, [reciente.rows[0].id, lat, lng, mensaje]);
      } else {
        // Episodio nuevo: crear alerta (ts = inicio, ts_fin = ahora).
        await pool.query(`
          INSERT INTO alertas (device, tipo, lat, lng, mensaje)
          VALUES ($1, $2, $3, $4, $5)
        `, [device, estado, lat, lng, mensaje]);
      }
    }

    // ── v6: Alerta de BLOQUEO DE BIENESTAR (episodio de 60 min) ──
    // El collar alcanzó su límite de estímulos y pasó a solo-buzzer.
    // Es la alerta más importante para el ranchero: ese animal requiere
    // atención presencial.
    if (bloqueado) {
      const rb = await pool.query(`
        SELECT id FROM alertas
        WHERE device = $1 AND tipo = 'bloqueo'
          AND ts_fin > NOW() - INTERVAL '60 minutes'
        ORDER BY ts_fin DESC LIMIT 1
      `, [device]);
      if (rb.rows.length > 0) {
        await pool.query(`
          UPDATE alertas SET ts_fin = NOW(), conteo = conteo + 1, lat = $2, lng = $3
          WHERE id = $1
        `, [rb.rows[0].id, lat, lng]);
      } else {
        await pool.query(`
          INSERT INTO alertas (device, tipo, lat, lng, mensaje)
          VALUES ($1, 'bloqueo', $2, $3, $4)
        `, [device, lat, lng,
            `${device} alcanzó el límite de estímulos — bloqueo de bienestar activo (solo buzzer)`]);
      }
    }

    // ── Conteo de VISITAS A AGUAJES ──────────────────────────
    // Si el collar está dentro del radio de un aguaje de su dueño y no
    // tenía una visita "viva" (últimos 10 min) a ese aguaje, se registra
    // una visita nueva. Si ya estaba, solo se extiende. Así contamos
    // visitas reales (no una por cada reporte de GPS).
    // v6: las posiciones HISTÓRICAS no cuentan visitas (su hora real es
    // pasada y corromperían la lógica de episodios que usa NOW()).
    if (!historico) try {
      const og = await pool.query('SELECT dueno FROM collar_dueno WHERE device = $1', [device]);
      if (og.rows.length) {
        const ags = await pool.query('SELECT id, lat, lng, radio_m FROM aguajes WHERE dueno = $1', [og.rows[0].dueno]);
        for (const ag of ags.rows) {
          const d = distanciaMetros(lat, lng, ag.lat, ag.lng);
          if (d <= (ag.radio_m || 20)) {
            const v = await pool.query(`
              SELECT id FROM visitas_aguaje
              WHERE aguaje_id = $1 AND device = $2
                AND ts_fin > NOW() - INTERVAL '10 minutes'
              ORDER BY ts_fin DESC LIMIT 1
            `, [ag.id, device]);
            if (v.rows.length) {
              await pool.query('UPDATE visitas_aguaje SET ts_fin = NOW() WHERE id = $1', [v.rows[0].id]);
            } else {
              await pool.query('INSERT INTO visitas_aguaje (aguaje_id, device) VALUES ($1, $2)', [ag.id, device]);
            }
            break;  // contar solo el aguaje más cercano en el que está
          }
        }
      }
    } catch(e) { console.log('visita aguaje:', e.message); }

    res.json({ ok: true });
  } catch (err) {
    console.error('POST /gps error:', err.message);
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  GET /geovallas
//  Sin params       → todas activas (gateway)
//  ?device=collar_01 → solo las que aplican a ese collar
//  ?todas=true       → incluye inactivas (dashboard)
// ─────────────────────────────────────────────────────────────
app.get('/geovallas', async (req, res) => {
  const { device, todas } = req.query;
  // Si el dashboard manda token, filtrar por su dueño
  const auth = req.headers.authorization || '';
  const userId = verificarToken(auth.replace('Bearer ', ''));
  try {
    // Expirar cercas temporales vencidas automáticamente
    await pool.query(`
      UPDATE geovallas SET activa = false
      WHERE tipo = 'temporal' AND expira_en IS NOT NULL
        AND expira_en < NOW() AND activa = true
    `);

    let query = 'SELECT * FROM geovallas';
    const params = [];

    if (userId) {
      // Dashboard autenticado: solo las cercas de su rancho
      const dueno = await correoDeUsuario(userId);
      params.push(dueno);
      query += ' WHERE dueno = $1';
      if (!todas) query += ' AND activa = true';
      query += ' ORDER BY id DESC';
      const { rows } = await pool.query(query, params);
      return res.json(rows);
    }
    // Gateway (sin token): si manda ?device, acotar SOLO al dueño de ese
    // collar. Antes devolvía TODAS las cercas activas de todos los ranchos,
    // y el gateway las mezclaba en un polígono deforme → falsos "fuera".
    if (device) {
      const og = await pool.query('SELECT dueno FROM collar_dueno WHERE device = $1', [device]);
      if (og.rows.length > 0) {
        const { rows } = await pool.query(`
          SELECT * FROM geovallas
          WHERE dueno = $1 AND activa = true AND tipo <> 'simbolica'
            AND (collares = '[]'::jsonb OR collares @> $2::jsonb)
          ORDER BY tipo DESC, id DESC
        `, [og.rows[0].dueno, JSON.stringify([device])]);
        // v6: incluir el flag de modo arreo en cada cerca. El gateway lo
        // detecta buscando "arreo":1 en el texto de la respuesta y se lo
        // renueva al collar en cada intercambio LoRa.
        const ar = await flagArreoParaDevice(device, og.rows[0].dueno);
        return res.json(rows.map(r => ({ ...r, arreo: ar })));
      }
      // Si el collar no tiene dueño asignado, cae al comportamiento viejo.
    }
    if (todas !== 'true') {
      query += ' WHERE activa = true';
    }
    if (device) {
      const cond = todas !== 'true' ? ' AND' : ' WHERE';
      query += `${cond} (collares = '[]'::jsonb OR collares @> $1::jsonb)`;
      params.push(JSON.stringify([device]));
    }
    query += ' ORDER BY tipo DESC, id DESC';
    const { rows } = await pool.query(query, params);
    // v6: si es el gateway preguntando por un collar sin dueño asignado,
    // usar el arreo del rancho 'default'.
    if (device) {
      const ar = await flagArreoParaDevice(device, 'default');
      return res.json(rows.map(r => ({ ...r, arreo: ar })));
    }
    res.json(rows);
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  POST /geovallas
//  { nombre, tipo, poligono, warn_dist_m, color,
//    collares, horas, expira_en }
//  tipo: "permanente" | "temporal" | "exclusion"
// ─────────────────────────────────────────────────────────────
// Valida que un polígono sea un array de ≥3 vértices {lat,lng} numéricos y en rango.
function validarPoligono(poly) {
  if (!Array.isArray(poly) || poly.length < 3) return false;
  return poly.every(p => p &&
    Number.isFinite(Number(p.lat)) && Number(p.lat) >= -90  && Number(p.lat) <= 90 &&
    Number.isFinite(Number(p.lng)) && Number(p.lng) >= -180 && Number(p.lng) <= 180);
}
app.post('/geovallas', requireAuth, async (req, res) => {
  const {
    nombre      = 'potrero',
    tipo        = 'permanente',
    poligono,
    warn_dist_m = 10,
    color       = '#1D9E75',
    collares    = [],
    horas,
    expira_en
  } = req.body;

  if (!validarPoligono(poligono))
    return res.status(400).json({ error: 'poligono necesita ≥3 vértices {lat,lng} numéricos y en rango' });
  if (!['permanente','temporal','exclusion','simbolica'].includes(tipo))
    return res.status(400).json({ error: 'tipo invalido' });

  let expiraCalc = null;
  if (tipo === 'temporal') {
    if (horas)      expiraCalc = new Date(Date.now() + horas * 3600000).toISOString();
    else if (expira_en) expiraCalc = new Date(expira_en).toISOString();
    else return res.status(400).json({ error: 'cercas temporales requieren horas o expira_en' });
  }

  try {
    // El dueño se deriva SIEMPRE del token (requireAuth ya validó la sesión).
    const dueno = await correoDeUsuario(req.userId);

    const { rows } = await pool.query(`
      INSERT INTO geovallas
        (nombre,tipo,poligono,activa,warn_dist_m,color,collares,expira_en,creada_por,dueno)
      VALUES ($1,$2,$3,true,$4,$5,$6,$7,'app',$8) RETURNING *
    `, [nombre, tipo, JSON.stringify(poligono),
        warn_dist_m, color, JSON.stringify(collares), expiraCalc, dueno]);

    await pool.query(
      'INSERT INTO historial_cercas (valla_id,accion,detalle) VALUES ($1,$2,$3)',
      [rows[0].id, 'creada', JSON.stringify({tipo, horas, expiraCalc})]
    );
    console.log(`🗺️  Cerca "${nombre}" [${tipo}] dueño:${dueno}`);
    res.json({ ok: true, valla: rows[0] });
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  PATCH /geovallas/:id — mover polígono, extender tiempo, etc.
// ─────────────────────────────────────────────────────────────
app.patch('/geovallas/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const { nombre, poligono, activa, warn_dist_m, color,
          collares, horas_extra, expira_en } = req.body;
  if (poligono !== undefined && !validarPoligono(poligono))
    return res.status(400).json({ error: 'poligono necesita ≥3 vértices {lat,lng} numéricos y en rango' });
  try {
    // Solo la cerca del dueño autenticado (evita mover/editar cercas ajenas).
    const dueno = await correoDeUsuario(req.userId);
    const { rows: cur } = await pool.query('SELECT * FROM geovallas WHERE id=$1 AND dueno=$2',[id, dueno]);
    if (!cur.length) return res.status(404).json({ error: 'cerca no encontrada' });
    const v = cur[0];

    let nuevaExp = v.expira_en;
    if (horas_extra && v.tipo === 'temporal') {
      const base = v.expira_en ? new Date(v.expira_en) : new Date();
      nuevaExp = new Date(base.getTime() + horas_extra * 3600000).toISOString();
    } else if (expira_en) {
      nuevaExp = new Date(expira_en).toISOString();
    }

    const { rows } = await pool.query(`
      UPDATE geovallas SET
        nombre=$1, poligono=COALESCE($2,poligono), activa=COALESCE($3,activa),
        warn_dist_m=COALESCE($4,warn_dist_m), color=COALESCE($5,color),
        collares=COALESCE($6,collares), expira_en=$7, updated=NOW()
      WHERE id=$8 RETURNING *
    `, [nombre||v.nombre,
        poligono?JSON.stringify(poligono):null,
        activa!==undefined?activa:null,
        warn_dist_m||null, color||null,
        collares?JSON.stringify(collares):null,
        nuevaExp, id]);

    await pool.query(
      'INSERT INTO historial_cercas (valla_id,accion,detalle) VALUES ($1,$2,$3)',
      [id,'modificada',JSON.stringify(req.body)]
    );
    res.json({ ok: true, valla: rows[0] });
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  DELETE /geovallas/:id — desactivar (no borra el registro)
// ─────────────────────────────────────────────────────────────
app.delete('/geovallas/:id', requireAuth, async (req, res) => {
  try {
    // Solo desactiva si la cerca pertenece al dueño autenticado.
    const dueno = await correoDeUsuario(req.userId);
    const r = await pool.query('UPDATE geovallas SET activa=false,updated=NOW() WHERE id=$1 AND dueno=$2',[req.params.id, dueno]);
    if (!r.rowCount) return res.status(404).json({ error: 'cerca no encontrada' });
    await pool.query('INSERT INTO historial_cercas (valla_id,accion) VALUES ($1,$2)',[req.params.id,'desactivada']);
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ═════════════════════════════════════════════════════════════
//  AGUAJES (puntos de agua: lago, tanque, pozo)
// ═════════════════════════════════════════════════════════════
app.get('/aguajes', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query(
      'SELECT * FROM aguajes WHERE dueno = $1 ORDER BY id DESC', [dueno]);
    res.json(rows);
  } catch (err) { fail500(res, err); }
});

app.post('/aguajes', requireAuth, async (req, res) => {
  const { nombre = 'Aguaje', lat, lng, radio_m = 20 } = req.body;
  if (lat == null || lng == null) return res.status(400).json({ error: 'lat y lng requeridos' });
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query(
      'INSERT INTO aguajes (dueno,nombre,lat,lng,radio_m) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [dueno, nombre, lat, lng, radio_m]);
    res.json({ ok: true, aguaje: rows[0] });
  } catch (err) { fail500(res, err); }
});

app.delete('/aguajes/:id', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    await pool.query('DELETE FROM aguajes WHERE id = $1 AND dueno = $2', [req.params.id, dueno]);
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ═════════════════════════════════════════════════════════════
//  GET /reporte-diario — resumen del día para el rancho
// ═════════════════════════════════════════════════════════════
app.get('/reporte-diario', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    // Collares del rancho
    const cols = await pool.query('SELECT device FROM collar_dueno WHERE dueno = $1', [dueno]);
    const devices = cols.rows.map(r => r.device);

    // Alertas de hoy (cruces y avisos)
    let cruces = 0, avisos = 0;
    if (devices.length) {
      const al = await pool.query(`
        SELECT tipo, COUNT(*)::int AS n FROM alertas
        WHERE device = ANY($1) AND ts >= CURRENT_DATE
        GROUP BY tipo
      `, [devices]);
      al.rows.forEach(r => {
        if (r.tipo === 'shock') cruces = r.n;
        if (r.tipo === 'warn')  avisos = r.n;
      });
    }

    // Visitas a aguajes hoy, por aguaje
    const visitas = await pool.query(`
      SELECT a.nombre, COUNT(v.id)::int AS visitas
      FROM aguajes a
      LEFT JOIN visitas_aguaje v
        ON v.aguaje_id = a.id AND v.ts >= CURRENT_DATE
      WHERE a.dueno = $1
      GROUP BY a.id, a.nombre
      ORDER BY visitas DESC
    `, [dueno]);

    // Última batería y estado por collar
    let collares = [];
    if (devices.length) {
      const ult = await pool.query(`
        SELECT DISTINCT ON (device) device, estado, shock_pwr, ts
        FROM posiciones
        WHERE device = ANY($1)
        ORDER BY device, ts DESC
      `, [devices]);
      collares = ult.rows;
    }

    res.json({
      fecha: new Date().toISOString().slice(0,10),
      cruces, avisos,
      aguajes: visitas.rows,
      collares
    });
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  GET /geovallas/historial?valla_id=1
// ─────────────────────────────────────────────────────────────
app.get('/geovallas/historial', async (req, res) => {
  const { valla_id } = req.query;
  try {
    const { rows } = await pool.query(`
      SELECT h.*,g.nombre FROM historial_cercas h
      JOIN geovallas g ON h.valla_id=g.id
      ${valla_id?'WHERE h.valla_id=$1':''} ORDER BY h.ts DESC LIMIT 50
    `, valla_id?[valla_id]:[]);
    res.json(rows);
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  GET /historial?device=collar_01&limit=100
//  Devuelve las últimas N posiciones de un collar
// ─────────────────────────────────────────────────────────────
app.get('/historial', requireAuth, async (req, res) => {
  const { device, limit = 100 } = req.query;
  if (!device) return res.status(400).json({ error: 'device requerido' });

  try {
    const { rows } = await pool.query(`
      SELECT lat, lng, ts, estado, sats FROM posiciones
      WHERE device = $1
      ORDER BY ts DESC
      LIMIT $2
    `, [device, Math.min(parseInt(limit), 1000)]);
    res.json(rows);
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  GET /config
//  Devuelve la tabla de configuraciones de todos los collares.
//  El gateway la descarga cada 30s para saber qué pwr enviar.
//  Respuesta: [{ device: "collar_01", pwr: 180 }, ...]
// ─────────────────────────────────────────────────────────────
app.get('/config', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT device, shock_pwr AS pwr, notas, updated FROM config_collares ORDER BY device'
    );
    res.json(rows);
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  POST /config
//  Crea o actualiza la configuración de intensidad de un collar.
//  Body: { device: "collar_01", pwr: 150, notas: "becerro joven" }
//
//  El gateway descargará el cambio en máximo 30s y lo enviará
//  al collar en el próximo ciclo LoRa.
// ─────────────────────────────────────────────────────────────
app.post('/config', requireAuth, async (req, res) => {
  const { device, pwr, notas } = req.body;

  if (!device) {
    return res.status(400).json({ error: 'device es requerido' });
  }
  const pwrNum = Number(pwr);
  if (pwr == null || !Number.isFinite(pwrNum) || pwrNum < 0 || pwrNum > 255) {
    return res.status(400).json({ error: 'pwr debe ser un entero entre 0 y 255' });
  }
  // Tope de seguridad configurable (SHOCK_PWR_MAX): acota la intensidad de estímulo.
  const pwrSafe = Math.min(Math.round(pwrNum), SHOCK_PWR_MAX);

  try {
    // El device debe pertenecer al dueño autenticado (evita fijar estímulo ajeno).
    const dueno = await correoDeUsuario(req.userId);
    const owns = await pool.query('SELECT 1 FROM collar_dueno WHERE device=$1 AND dueno=$2',[device, dueno]);
    if (!owns.rowCount) return res.status(404).json({ error: 'collar no encontrado' });
    // UPSERT — si ya existe el device lo actualiza, si no lo crea
    const { rows } = await pool.query(`
      INSERT INTO config_collares (device, shock_pwr, notas, updated)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (device)
      DO UPDATE SET
        shock_pwr = EXCLUDED.shock_pwr,
        notas     = COALESCE(EXCLUDED.notas, config_collares.notas),
        updated   = NOW()
      RETURNING *
    `, [device, pwrSafe, notas || null]);

    console.log(`⚙️  Config actualizada: ${device} pwr=${pwrSafe}${pwrSafe !== pwrNum ? ` (limitado desde ${pwrNum})` : ''}`);
    res.json({ ok: true, config: rows[0] });
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  GET /alertas?limit=50&device=collar_01&no_leidas=true
//  Devuelve alertas recientes para el dashboard
// ─────────────────────────────────────────────────────────────
app.get('/alertas', requireAuth, async (req, res) => {
  const { device, limit = 50, no_leidas } = req.query;
  try {
    const dueno = await correoDeUsuario(req.userId);
    // Solo alertas de los collares que pertenecen a este rancho
    let query = `
      SELECT a.* FROM alertas a
      JOIN collar_dueno cd ON cd.device = a.device
      WHERE cd.dueno = $1
    `;
    const params = [dueno];

    if (device) {
      params.push(device);
      query += ` AND a.device = $${params.length}`;
    }
    if (no_leidas === 'true') {
      query += ' AND a.leida = false';
    }
    params.push(Math.min(parseInt(limit), 500));
    query += ` ORDER BY a.ts_fin DESC LIMIT $${params.length}`;

    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  POST /alertas/:id/leer  — marcar alerta como leída
// ─────────────────────────────────────────────────────────────
app.post('/alertas/:id/leer', async (req, res) => {
  try {
    await pool.query('UPDATE alertas SET leida=true WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  GET /actividad?device=collar_01&dias=7
//  Métricas de actividad del acelerómetro — útil para el
//  dashboard de bienestar animal y heatmaps
// ─────────────────────────────────────────────────────────────
app.get('/actividad', async (req, res) => {
  const { device, dias = 7 } = req.query;
  if (!device) return res.status(400).json({ error: 'device requerido' });

  try {
    const { rows } = await pool.query(`
      SELECT
        DATE_TRUNC('hour', ts)      AS hora,
        AVG(aceleracion)::REAL      AS accel_avg,
        MAX(aceleracion)::REAL      AS accel_max,
        SUM(CASE WHEN movimiento THEN 1 ELSE 0 END)::INT AS muestras_mov,
        COUNT(*)::INT               AS total_muestras,
        ROUND(
          100.0 * SUM(CASE WHEN movimiento THEN 1 ELSE 0 END) / COUNT(*)
        )::INT                      AS pct_movimiento
      FROM posiciones
      WHERE device = $1
        AND ts > NOW() - INTERVAL '1 day' * $2
      GROUP BY DATE_TRUNC('hour', ts)
      ORDER BY hora DESC
    `, [device, parseInt(dias)]);
    res.json(rows);
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  GET /collares  — lista todos los devices con su última pos.
// ─────────────────────────────────────────────────────────────
app.get('/collares', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query(`
      SELECT DISTINCT ON (p.device)
        p.device, p.lat, p.lng, p.estado, p.movimiento,
        p.aceleracion, p.shock_pwr, p.sats, p.rssi, p.dist_borde, p.bateria, p.carga,
        p.bloqueado, p.arreo, p.ts
      FROM posiciones p
      JOIN collar_dueno cd ON cd.device = p.device
      WHERE cd.dueno = $1
      ORDER BY p.device, p.ts DESC
    `, [dueno]);
    res.json(rows);
  } catch (err) {
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  ANIMALES — guardar y leer perfiles (permanente)
// ─────────────────────────────────────────────────────────────
app.get('/animales', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query('SELECT * FROM animales WHERE dueno=$1 ORDER BY id', [dueno]);
    res.json(rows);
  } catch (err) { fail500(res, err); }
});

// Crear o actualizar un animal (upsert por id)
app.post('/animales', requireAuth, async (req, res) => {
  const a = req.body;
  if (!a || !a.id) return res.status(400).json({ error: 'falta id' });
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query(`
      INSERT INTO animales (id,nombre,collar,arete,peso,edad,raza,sexo,lote,notas,dueno,updated)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
      ON CONFLICT (id) DO UPDATE SET
        nombre=$2, collar=$3, arete=$4, peso=$5, edad=$6,
        raza=$7, sexo=$8, lote=$9, notas=$10, updated=NOW()
      WHERE animales.dueno=$11
      RETURNING *
    `, [a.id, a.nombre||'Sin nombre', a.collar||'', a.arete||'',
        a.peso||0, a.edad||0, a.raza||'', a.sexo||'', a.lote||null, a.notas||'', dueno]);
    res.json({ ok: true, animal: rows[0] });
  } catch (err) { fail500(res, err); }
});

app.delete('/animales/:id', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    await pool.query('DELETE FROM animales WHERE id=$1 AND dueno=$2', [req.params.id, dueno]);
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  LOTES — guardar y leer (permanente, por dueño)
// ─────────────────────────────────────────────────────────────
app.get('/lotes', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query('SELECT * FROM lotes WHERE dueno=$1 ORDER BY id', [dueno]);
    res.json(rows);
  } catch (err) { fail500(res, err); }
});

app.post('/lotes', requireAuth, async (req, res) => {
  const l = req.body;
  if (!l || !l.id) return res.status(400).json({ error: 'falta id' });
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query(`
      INSERT INTO lotes (id,nombre,color,dueno,updated)
      VALUES ($1,$2,$3,$4,NOW())
      ON CONFLICT (id) DO UPDATE SET nombre=$2, color=$3, updated=NOW()
      WHERE lotes.dueno=$4
      RETURNING *
    `, [l.id, l.nombre||'Lote', l.color||'#4ade80', dueno]);
    res.json({ ok: true, lote: rows[0] });
  } catch (err) { fail500(res, err); }
});

app.delete('/lotes/:id', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    await pool.query('DELETE FROM lotes WHERE id=$1 AND dueno=$2', [req.params.id, dueno]);
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  v6 · POST /salud — el gateway sube el paquete de salud del collar
//  (sin auth: es un endpoint de dispositivo, igual que /gps)
// ─────────────────────────────────────────────────────────────
app.post('/salud', requireDevice, async (req, res) => {
  const {
    device,
    uptime_min = 0, bateria = 0, bateria_mv = 0, carga = 0,
    pulsos = 0, avisos = 0, bloqueado = false,
    reinicios = 0, reinicios_anormales = 0,
    entrega_pct = 0, respaldo = 0, rssi = 0
  } = req.body;
  if (!device) return res.status(400).json({ error: 'device requerido' });
  try {
    await pool.query(`
      INSERT INTO salud_collares
        (device, uptime_min, bateria, bateria_mv, carga, pulsos, avisos,
         bloqueado, reinicios, reinicios_anormales, entrega_pct, respaldo, rssi)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    `, [device, uptime_min, bateria, bateria_mv, carga, pulsos, avisos,
        !!bloqueado, reinicios, reinicios_anormales, entrega_pct, respaldo, rssi]);
    console.log(`💚 Salud ${device}: bat ${bateria}% | entrega ${entrega_pct}% | reinicios ${reinicios} (${reinicios_anormales} anormales)`);
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /salud error:', err.message);
    fail500(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
//  v6 · GET /salud — dashboard: última salud de cada collar del rancho
//  ?device=collar_01&limit=20 → historial de ese collar
// ─────────────────────────────────────────────────────────────
app.get('/salud', requireAuth, async (req, res) => {
  const { device, limit = 20 } = req.query;
  try {
    const dueno = await correoDeUsuario(req.userId);
    if (device) {
      const { rows } = await pool.query(`
        SELECT s.* FROM salud_collares s
        JOIN collar_dueno cd ON cd.device = s.device
        WHERE s.device = $1 AND cd.dueno = $2
        ORDER BY s.ts DESC LIMIT $3
      `, [device, dueno, Math.min(parseInt(limit), 500)]);
      return res.json(rows);
    }
    const { rows } = await pool.query(`
      SELECT DISTINCT ON (s.device) s.*
      FROM salud_collares s
      JOIN collar_dueno cd ON cd.device = s.device
      WHERE cd.dueno = $1
      ORDER BY s.device, s.ts DESC
    `, [dueno]);
    res.json(rows);
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  v6 · MODO ARREO — mover ganado entre potreros sin estímulo
//
//  GET  /arreo          → estado actual + progreso por collar
//  POST /arreo          → iniciar { duracion_min, destino_valla_id? }
//  POST /arreo/terminar → terminar manualmente
//
//  El gateway NO usa estos endpoints: lee el flag "arreo" que
//  /geovallas agrega a su respuesta. La expiración vive aquí.
// ─────────────────────────────────────────────────────────────
app.get('/arreo', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    const a = await arreoVigente(dueno);
    if (!a) return res.json({ activo: false });

    const restanteMin = Math.max(0, Math.round(
      (new Date(a.inicio).getTime() + a.duracion_min * 60000 - Date.now()) / 60000));

    let destino = null;
    const progreso = [];
    if (a.destino_valla_id) {
      const v = await pool.query(
        'SELECT id, nombre, poligono FROM geovallas WHERE id=$1', [a.destino_valla_id]);
      if (v.rows.length) {
        destino = { id: v.rows[0].id, nombre: v.rows[0].nombre };
        const cds = await pool.query(
          'SELECT device FROM collar_dueno WHERE dueno=$1 ORDER BY device', [dueno]);
        for (const cd of cds.rows) {
          const p = await pool.query(`
            SELECT lat, lng, ts, arreo FROM posiciones
            WHERE device = $1 AND historico IS NOT TRUE
            ORDER BY ts DESC LIMIT 1
          `, [cd.device]);
          progreso.push({
            device: cd.device,
            dentro: p.rows.length
              ? puntoEnPoligonoSrv(p.rows[0].lat, p.rows[0].lng, v.rows[0].poligono)
              : false,
            confirmado: p.rows.length ? !!p.rows[0].arreo : false,
            ultima_pos: p.rows.length ? p.rows[0].ts : null
          });
        }
      }
    }
    res.json({
      activo: true, inicio: a.inicio, duracion_min: a.duracion_min,
      restante_min: restanteMin, destino, progreso
    });
  } catch (err) { fail500(res, err); }
});

app.post('/arreo', requireAuth, async (req, res) => {
  const { duracion_min = 120, destino_valla_id = null } = req.body;
  const dur = parseInt(duracion_min);
  if (!dur || dur < 5 || dur > 480) {
    return res.status(400).json({ error: 'duracion_min debe estar entre 5 y 480' });
  }
  try {
    const dueno = await correoDeUsuario(req.userId);
    if (destino_valla_id) {
      const v = await pool.query(
        'SELECT id FROM geovallas WHERE id=$1 AND dueno=$2 AND activa=true', [destino_valla_id, dueno]);
      if (!v.rows.length) {
        return res.status(400).json({ error: 'el potrero destino no existe o no está activo' });
      }
    }
    // Cerrar cualquier arreo previo del rancho antes de abrir el nuevo
    await pool.query(
      'UPDATE modo_arreo SET activo=false, terminado_en=NOW() WHERE dueno=$1 AND activo=true', [dueno]);
    const { rows } = await pool.query(`
      INSERT INTO modo_arreo (dueno, activo, destino_valla_id, duracion_min)
      VALUES ($1, true, $2, $3) RETURNING *
    `, [dueno, destino_valla_id || null, dur]);
    console.log(`🐄 ARREO iniciado por ${dueno}: ${dur} min${destino_valla_id ? ' → valla ' + destino_valla_id : ' (sin destino)'}`);
    res.json({ ok: true, arreo: rows[0] });
  } catch (err) { fail500(res, err); }
});

app.post('/arreo/terminar', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    await pool.query(
      'UPDATE modo_arreo SET activo=false, terminado_en=NOW() WHERE dueno=$1 AND activo=true', [dueno]);
    console.log(`🐄 Arreo de ${dueno} terminado manualmente.`);
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  AUTENTICACIÓN — login y administración de cuentas
// ─────────────────────────────────────────────────────────────

// Login: correo + password → devuelve token y datos del rancho
app.post('/login', loginLimiter, async (req, res) => {
  const { correo, password } = req.body;
  if (!correo || !password) return res.status(400).json({ error: 'faltan datos' });
  try {
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE correo=$1', [correo.toLowerCase().trim()]);
    if (!rows.length) return res.status(401).json({ error: 'correo o contraseña incorrectos' });
    const u = rows[0];
    if (!verifyPassword(password, u.password)) {
      return res.status(401).json({ error: 'correo o contraseña incorrectos' });
    }
    const token = crearToken(u.id);
    res.json({ ok: true, token, rancho: u.rancho, correo: u.correo });
  } catch (err) { fail500(res, err); }
});

// ADMIN: crear una cuenta de rancho (requiere contraseña de admin)
app.post('/admin/usuarios', requireAdmin, async (req, res) => {
  const { correo, password, rancho } = req.body;
  if (!correo || !password || !rancho) return res.status(400).json({ error: 'faltan datos' });
  try {
    const hash = hashPassword(password);
    const { rows } = await pool.query(
      'INSERT INTO usuarios (correo,password,rancho) VALUES ($1,$2,$3) RETURNING id,correo,rancho',
      [correo.toLowerCase().trim(), hash, rancho]
    );
    res.json({ ok: true, usuario: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'ese correo ya existe' });
    fail500(res, err);
  }
});

// ADMIN: listar cuentas
app.get('/admin/usuarios', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id,correo,rancho,creado FROM usuarios ORDER BY id');
    res.json(rows);
  } catch (err) { fail500(res, err); }
});

// ADMIN: borrar una cuenta (y liberar sus collares para reasignarlos)
app.delete('/admin/usuarios/:id', requireAdmin, async (req, res) => {
  try {
    // Buscar el correo del usuario para liberar sus collares asignados
    const u = await pool.query('SELECT correo FROM usuarios WHERE id=$1', [req.params.id]);
    if (u.rows.length) {
      const correo = u.rows[0].correo;
      // Liberar collares: quedan sin dueño y se pueden reasignar a otro cliente
      await pool.query('DELETE FROM collar_dueno WHERE dueno=$1', [correo]);
    }
    await pool.query('DELETE FROM usuarios WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ADMIN: asignar un collar (device) a un rancho (correo del dueño)
app.post('/admin/asignar-collar', requireAdmin, async (req, res) => {
  const { device, dueno } = req.body;
  if (!device || !dueno) return res.status(400).json({ error: 'faltan datos' });
  try {
    await pool.query(
      'INSERT INTO collar_dueno (device,dueno) VALUES ($1,$2) ON CONFLICT (device) DO UPDATE SET dueno=$2',
      [device, dueno.toLowerCase().trim()]
    );
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  GET /admin/collares-asignados — lista todas las asignaciones
// ─────────────────────────────────────────────────────────────
app.get('/admin/collares-asignados', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT cd.device, cd.dueno, u.rancho
      FROM collar_dueno cd
      LEFT JOIN usuarios u ON u.correo = cd.dueno
      ORDER BY cd.device
    `);
    res.json(rows);
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
//  DELETE /admin/asignar-collar/:device — quitar una asignación
// ─────────────────────────────────────────────────────────────
app.delete('/admin/asignar-collar/:device', requireAdmin, async (req, res) => {
  const { device } = req.params;
  try {
    await pool.query('DELETE FROM collar_dueno WHERE device = $1', [device]);
    res.json({ ok: true });
  } catch (err) { fail500(res, err); }
});

// ─────────────────────────────────────────────────────────────
// Manejo global de errores de Express (rutas que lanzan de forma síncrona).
app.use((err, req, res, next) => {
  console.error('Error no controlado:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'error interno del servidor' });
});
// No morir en silencio ante promesas/excepciones sin capturar.
process.on('unhandledRejection', (reason) => console.error('unhandledRejection:', reason));
process.on('uncaughtException', (err) => console.error('uncaughtException:', err));

const server = app.listen(port, async () => {
  try { await initDB(); } catch (e) { console.error('initDB falló:', e); }
  if (RETENCION_DIAS > 0) { purgaRetencion(); setInterval(purgaRetencion, 6 * 60 * 60 * 1000); }
  console.log(`\n🚀 CollarGPS Server v3 en puerto ${port}`);
  console.log('   Endpoints disponibles:');
  console.log('   POST /gps          — posición + IMU');
  console.log('   GET  /geovallas    — geovalla activa');
  console.log('   POST /geovallas    — crear geovalla');
  console.log('   GET  /historial    — historial de posiciones');
  console.log('   GET  /config       — configuraciones de collares');
  console.log('   POST /config       — actualizar intensidad shock');
  console.log('   GET  /alertas      — alertas de cruce/aviso');
  console.log('   POST /alertas/:id/leer — marcar alerta leída');
  console.log('   GET  /actividad    — métricas IMU por hora');
  console.log('   GET  /collares     — estado actual de todos');
  console.log('   POST /salud        — salud del collar (v6)');
  console.log('   GET  /salud        — última salud por collar (v6)');
  console.log('   GET/POST /arreo    — modo arreo (v6)');
  console.log('   GET  /health       — health check\n');
});

// Apagado ordenado: Render envía SIGTERM en cada deploy.
process.on('SIGTERM', () => {
  console.log('SIGTERM recibido: cerrando servidor...');
  server.close(() => pool.end().finally(() => process.exit(0)));
});
