# CollarGPS Server v3

Node.js + PostgreSQL desplegado en Render.com.

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/gps` | Recibe posición + datos IMU del gateway |
| GET | `/geovallas` | Geovalla activa (la descarga el gateway) |
| POST | `/geovallas` | Crear/actualizar geovalla desde el dashboard |
| GET | `/historial` | Historial de posiciones `?device=collar_01&limit=100` |
| GET | `/config` | Configuraciones de intensidad de shock por collar |
| POST | `/config` | Actualizar intensidad de un collar |
| GET | `/alertas` | Alertas recientes `?device=&limit=&no_leidas=true` |
| POST | `/alertas/:id/leer` | Marcar alerta como leída |
| GET | `/actividad` | Métricas IMU por hora `?device=&dias=7` |
| GET | `/collares` | Estado actual de todos los collares |

## POST /gps — payload completo v3

```json
{
  "device":      "collar_01",
  "lat":         25.123456,
  "lng":         -100.654321,
  "speed":       3.2,
  "sats":        8,
  "rssi":        -85,
  "estado":      "ok",
  "dist_borde":  45.2,
  "movimiento":  true,
  "aceleracion": 234,
  "actividad_s": 3600,
  "shock_pwr":   200
}
```

## GET /config — respuesta

```json
[
  { "device": "collar_01", "pwr": 200, "notas": null, "updated": "..." },
  { "device": "collar_02", "pwr": 150, "notas": "becerro joven", "updated": "..." }
]
```

## POST /config — actualizar intensidad

```json
{ "device": "collar_01", "pwr": 150, "notas": "ajustado en campo" }
```

`pwr` debe ser un entero entre 0 y 255.
El gateway lo descarga en máximo 30s y lo envía al collar vía LoRa.

## Deploy en Render.com

1. Sube este directorio a un repositorio GitHub
2. En Render → New Web Service → conecta el repo
3. Build command: `npm install`
4. Start command: `npm start`
5. En Environment Variables agrega:
   - `DATABASE_URL` — la URL de tu PostgreSQL en Render
   - `NODE_ENV` = `production`
6. Las tablas se crean automáticamente al primer arranque

## Base de datos

Render ofrece PostgreSQL gratis (plan Free: 256MB, suficiente para el piloto).
Al crear el servicio de base de datos en Render, copia la "Internal Database URL"
y pégala en la variable `DATABASE_URL` del web service.
