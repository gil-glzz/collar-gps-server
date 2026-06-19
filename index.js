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

// Contraseña de admin (para crear cuentas). Cámbiala con una variable de entorno.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'lindero-admin-2026';

app.use(cors());
app.use(express.json());

// ── PostgreSQL ───────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

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
// Token de sesión simple: id de usuario + firma. No expira (piloto).
function crearToken(userId) {
  const payload = userId + '.' + Date.now();
  const firma = crypto.createHmac('sha256', ADMIN_PASSWORD).update(payload).digest('hex');
  return Buffer.from(payload + '.' + firma).toString('base64');
}
function verificarToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString();
    const [userId, ts, firma] = decoded.split('.');
    const payload = userId + '.' + ts;
    const esperada = crypto.createHmac('sha256', ADMIN_PASSWORD).update(payload).digest('hex');
    if (firma === esperada) return userId;
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
  if (req.headers['x-admin-password'] !== ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'admin requerido' });
  }
  next();
}
// Obtener el correo (dueño) a partir del id de usuario del token
async function correoDeUsuario(userId) {
  const { rows } = await pool.query('SELECT correo FROM usuarios WHERE id=$1', [userId]);
  return rows.length ? rows[0].correo : null;
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
      ts          TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS geovallas (
      id            SERIAL PRIMARY KEY,
      nombre        TEXT    NOT NULL DEFAULT 'potrero principal',
      tipo          TEXT    NOT NULL DEFAULT 'permanente',
      poligono      JSONB   NOT NULL,
      activa        BOOLEAN DEFAULT true,
      warn_dist_m   REAL    DEFAULT 12,
      color         TEXT    DEFAULT '#1D9E75',
      collares      JSONB   DEFAULT '[]',
      expira_en     TIMESTAMPTZ,
      creada_por    TEXT    DEFAULT 'app',
      created       TIMESTAMPTZ DEFAULT NOW(),
      updated       TIMESTAMPTZ DEFAULT NOW()
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
      ts      TIMESTAMPTZ DEFAULT NOW()
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

    CREATE INDEX IF NOT EXISTS idx_pos_device ON posiciones(device);
    CREATE INDEX IF NOT EXISTS idx_pos_ts     ON posiciones(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas(ts DESC);
  `);

  // ── Migraciones: agregar columnas que falten en tablas ya creadas ──
  // Si la base se creó con una versión vieja de la tabla geovallas,
  // estas líneas agregan las columnas nuevas sin borrar datos.
  const migraciones = [
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS tipo TEXT NOT NULL DEFAULT 'permanente'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS warn_dist_m REAL DEFAULT 12`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS color TEXT DEFAULT '#1D9E75'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS collares JSONB DEFAULT '[]'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS expira_en TIMESTAMPTZ`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS creada_por TEXT DEFAULT 'app'`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS updated TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE geovallas ADD COLUMN IF NOT EXISTS dueno TEXT DEFAULT 'default'`
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
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '3.0', ts: new Date().toISOString() });
});

// ─────────────────────────────────────────────────────────────
//  POST /gps
//  Body: { device, lat, lng, speed, sats, rssi, estado,
//          dist_borde, movimiento, aceleracion, actividad_s,
//          shock_pwr }
// ─────────────────────────────────────────────────────────────
app.post('/gps', async (req, res) => {
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
    shock_pwr   = 200
  } = req.body;

  if (!device || lat == null || lng == null) {
    return res.status(400).json({ error: 'device, lat y lng son requeridos' });
  }

  try {
    await pool.query(`
      INSERT INTO posiciones
        (device, lat, lng, speed, sats, rssi, estado,
         dist_borde, movimiento, aceleracion, actividad_s, shock_pwr)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    `, [device, lat, lng, speed, sats, rssi, estado,
        dist_borde, movimiento, aceleracion, actividad_s, shock_pwr]);

    // Registrar alerta si es cruce o aviso
    if (estado === 'shock' || estado === 'warn') {
      await pool.query(`
        INSERT INTO alertas (device, tipo, lat, lng, mensaje)
        VALUES ($1, $2, $3, $4, $5)
      `, [
        device,
        estado,
        lat,
        lng,
        estado === 'shock'
          ? `${device} cruzó la cerca`
          : `${device} se acercó al límite (${dist_borde.toFixed(0)}m)`
      ]);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('POST /gps error:', err.message);
    res.status(500).json({ error: err.message });
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
    if (todas !== 'true') {
      query += ' WHERE activa = true';
    }
    if (device) {
      const cond = toda !== 'true' ? ' AND' : ' WHERE';
      query += `${cond} (collares = '[]'::jsonb OR collares @> $1::jsonb)`;
      params.push(JSON.stringify([device]));
    }
    query += ' ORDER BY tipo DESC, id DESC';
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────
//  POST /geovallas
//  { nombre, tipo, poligono, warn_dist_m, color,
//    collares, horas, expira_en }
//  tipo: "permanente" | "temporal" | "exclusion"
// ─────────────────────────────────────────────────────────────
app.post('/geovallas', async (req, res) => {
  const {
    nombre      = 'potrero',
    tipo        = 'permanente',
    poligono,
    warn_dist_m = 12,
    color       = '#1D9E75',
    collares    = [],
    horas,
    expira_en
  } = req.body;

  if (!poligono || !Array.isArray(poligono) || poligono.length < 3)
    return res.status(400).json({ error: 'poligono necesita al menos 3 puntos' });
  if (!['permanente','temporal','exclusion'].includes(tipo))
    return res.status(400).json({ error: 'tipo invalido' });

  let expiraCalc = null;
  if (tipo === 'temporal') {
    if (horas)      expiraCalc = new Date(Date.now() + horas * 3600000).toISOString();
    else if (expira_en) expiraCalc = new Date(expira_en).toISOString();
    else return res.status(400).json({ error: 'cercas temporales requieren horas o expira_en' });
  }

  try {
    // El dueño viene del token del dashboard
    const auth = req.headers.authorization || '';
    const userId = verificarToken(auth.replace('Bearer ', ''));
    const dueno = userId ? await correoDeUsuario(userId) : 'default';

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
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────
//  PATCH /geovallas/:id — mover polígono, extender tiempo, etc.
// ─────────────────────────────────────────────────────────────
app.patch('/geovallas/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { nombre, poligono, activa, warn_dist_m, color,
          collares, horas_extra, expira_en } = req.body;
  try {
    const { rows: cur } = await pool.query('SELECT * FROM geovallas WHERE id=$1',[id]);
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─────────────────────────────────────────────────────────────
//  DELETE /geovallas/:id — desactivar (no borra el registro)
// ─────────────────────────────────────────────────────────────
app.delete('/geovallas/:id', async (req, res) => {
  try {
    await pool.query('UPDATE geovallas SET activa=false,updated=NOW() WHERE id=$1',[req.params.id]);
    await pool.query('INSERT INTO historial_cercas (valla_id,accion) VALUES ($1,$2)',[req.params.id,'desactivada']);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─────────────────────────────────────────────────────────────
//  GET /historial?device=collar_01&limit=100
//  Devuelve las últimas N posiciones de un collar
// ─────────────────────────────────────────────────────────────
app.get('/historial', async (req, res) => {
  const { device, limit = 100 } = req.query;
  if (!device) return res.status(400).json({ error: 'device requerido' });

  try {
    const { rows } = await pool.query(`
      SELECT * FROM posiciones
      WHERE device = $1
      ORDER BY ts DESC
      LIMIT $2
    `, [device, Math.min(parseInt(limit), 1000)]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
app.post('/config', async (req, res) => {
  const { device, pwr, notas } = req.body;

  if (!device) {
    return res.status(400).json({ error: 'device es requerido' });
  }
  if (pwr == null || pwr < 0 || pwr > 255) {
    return res.status(400).json({ error: 'pwr debe ser un entero entre 0 y 255' });
  }

  try {
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
    `, [device, pwr, notas || null]);

    console.log(`⚙️  Config actualizada: ${device} pwr=${pwr}`);
    res.json({ ok: true, config: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────
//  GET /alertas?limit=50&device=collar_01&no_leidas=true
//  Devuelve alertas recientes para el dashboard
// ─────────────────────────────────────────────────────────────
app.get('/alertas', async (req, res) => {
  const { device, limit = 50, no_leidas } = req.query;

  let query = 'SELECT * FROM alertas WHERE 1=1';
  const params = [];

  if (device) {
    params.push(device);
    query += ` AND device = $${params.length}`;
  }
  if (no_leidas === 'true') {
    query += ' AND leida = false';
  }

  params.push(Math.min(parseInt(limit), 500));
  query += ` ORDER BY ts DESC LIMIT $${params.length}`;

  try {
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
        p.aceleracion, p.shock_pwr, p.sats, p.rssi, p.dist_borde, p.ts
      FROM posiciones p
      JOIN collar_dueno cd ON cd.device = p.device
      WHERE cd.dueno = $1
      ORDER BY p.device, p.ts DESC
    `, [dueno]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/animales/:id', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    await pool.query('DELETE FROM animales WHERE id=$1 AND dueno=$2', [req.params.id, dueno]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─────────────────────────────────────────────────────────────
//  LOTES — guardar y leer (permanente, por dueño)
// ─────────────────────────────────────────────────────────────
app.get('/lotes', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    const { rows } = await pool.query('SELECT * FROM lotes WHERE dueno=$1 ORDER BY id', [dueno]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/lotes/:id', requireAuth, async (req, res) => {
  try {
    const dueno = await correoDeUsuario(req.userId);
    await pool.query('DELETE FROM lotes WHERE id=$1 AND dueno=$2', [req.params.id, dueno]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─────────────────────────────────────────────────────────────
//  AUTENTICACIÓN — login y administración de cuentas
// ─────────────────────────────────────────────────────────────

// Login: correo + password → devuelve token y datos del rancho
app.post('/login', async (req, res) => {
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    res.status(500).json({ error: err.message });
  }
});

// ADMIN: listar cuentas
app.get('/admin/usuarios', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id,correo,rancho,creado FROM usuarios ORDER BY id');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ADMIN: borrar una cuenta
app.delete('/admin/usuarios/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM usuarios WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─────────────────────────────────────────────────────────────
app.listen(port, async () => {
  await initDB();
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
  console.log('   GET  /health       — health check\n');
});
