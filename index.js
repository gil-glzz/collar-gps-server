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

const app  = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ── PostgreSQL ───────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

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
      id       SERIAL PRIMARY KEY,
      nombre   TEXT NOT NULL DEFAULT 'valla principal',
      poligono JSONB NOT NULL,
      activa   BOOLEAN DEFAULT true,
      created  TIMESTAMPTZ DEFAULT NOW()
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

    CREATE INDEX IF NOT EXISTS idx_pos_device ON posiciones(device);
    CREATE INDEX IF NOT EXISTS idx_pos_ts     ON posiciones(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas(ts DESC);
  `);
  console.log('✅ Tablas inicializadas');
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
//  GET /geovallas  — el gateway descarga la geovalla activa
// ─────────────────────────────────────────────────────────────
app.get('/geovallas', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM geovallas WHERE activa = true ORDER BY id DESC LIMIT 1'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────
//  POST /geovallas  — el dashboard crea o actualiza la geovalla
//  Body: { nombre, poligono: [{lat, lng}, ...] }
// ─────────────────────────────────────────────────────────────
app.post('/geovallas', async (req, res) => {
  const { nombre = 'valla principal', poligono } = req.body;

  if (!poligono || !Array.isArray(poligono) || poligono.length < 3) {
    return res.status(400).json({ error: 'poligono debe tener al menos 3 puntos' });
  }

  try {
    // Desactivar vallas anteriores
    await pool.query('UPDATE geovallas SET activa = false');
    // Insertar la nueva
    const { rows } = await pool.query(
      'INSERT INTO geovallas (nombre, poligono, activa) VALUES ($1,$2,true) RETURNING *',
      [nombre, JSON.stringify(poligono)]
    );
    res.json({ ok: true, valla: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
app.get('/collares', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT DISTINCT ON (device)
        device, lat, lng, estado, movimiento,
        aceleracion, shock_pwr, sats, ts
      FROM posiciones
      ORDER BY device, ts DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
