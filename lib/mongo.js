let MongoClient;
try {
  ({ MongoClient } = require('mongodb'));
} catch (e) {
  MongoClient = null;
}

const DEFAULT_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const DEFAULT_DB = process.env.MONGO_DB || 'oidc';
const DEFAULT_COLLECTION = process.env.MONGO_COLLECTION || 'events';

const MONGO_ENABLED = (process.env.MONGO_ENABLED ?? 'true').toLowerCase() !== 'false';
let _warnedNoDriver = false;

let _client = null;
let _clientPromise = null;

async function getClient() {
  if (!MONGO_ENABLED) return null;
  if (!MongoClient) {
    if (!_warnedNoDriver) {
      console.warn('⚠️ Mongo logging disabled: mongodb driver not installed. Run: npm i mongodb');
      _warnedNoDriver = true;
    }
    return null;
  }
  if (_client) return _client;
  if (_clientPromise) return _clientPromise;

  const uri = DEFAULT_URI;
  _clientPromise = (async () => {
    try {
      const client = new MongoClient(uri, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 3000,
      });
      await client.connect();
      _client = client;
      return client;
    } catch (err) {
      _client = null;
      _clientPromise = null;
      throw err;
    }
  })();

  try {
    return await _clientPromise;
  } catch (err) {
    _clientPromise = null;
    throw err;
  }
}

function getDbName() {
  return DEFAULT_DB;
}

function getCollectionName() {
  return DEFAULT_COLLECTION;
}

function maskToken(token) {
  if (!token || typeof token !== 'string') return token;
  if (token.length <= 12) return token.replace(/.(?=.{4})/g, '*');
  return token.slice(0, 6) + '…' + token.slice(-4);
}

function safePick(obj, keys) {
  const out = {};
  for (const k of keys) {
    if (obj && Object.prototype.hasOwnProperty.call(obj, k)) out[k] = obj[k];
  }
  return out;
}

async function logEvent(eventType, req, payload = {}) {
  if (!MongoClient) {
    if (!logEvent._warned) {
      console.warn('⚠️ Mongo logging disabled: install dependency `mongodb` to enable (npm i mongodb).');
      logEvent._warned = true;
    }
    return;
  }

  try {
    const client = await getClient();
    if (!client) return;

    const db = client.db(getDbName());
    const col = db.collection(getCollectionName());

    const ip =
      (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() ||
      req.socket?.remoteAddress ||
      req.ip;

    const doc = {
      eventType,
      createdAt: new Date(),
      path: req.originalUrl,
      method: req.method,
      ip,
      userAgent: req.get('user-agent') || null,
      req: {
        query: safePick(req.query, ['code', 'state', 'error', 'error_description']),
      },
      payload,
    };

    if (payload && typeof payload === 'object' && payload.user && typeof payload.user === 'object') {
      const u = payload.user;
      doc.name = u.name ?? null;
      doc.email = u.email ?? null;
      doc.citizen_id = u.citizen_id ?? null;
      doc.sub = u.sub ?? null;
    }

    if (process.env.STORE_TOKENS === 'true' && payload && typeof payload === 'object') {
      if (payload.tokens && typeof payload.tokens === 'object') {
        doc.payload.tokens = {
          ...payload.tokens,
          access_token: maskToken(payload.tokens.access_token),
          id_token: maskToken(payload.tokens.id_token),
          refresh_token: maskToken(payload.tokens.refresh_token),
        };
      }
    } else {
      if (doc.payload && doc.payload.tokens) delete doc.payload.tokens;
    }

    await col.insertOne(doc);
  } catch (err) {
    console.warn('⚠️ Mongo logEvent failed:', err?.message || err);
  }
}

async function closeMongo() {
  if (_client) {
    try {
      await _client.close();
    } catch {}
    _client = null;
    _clientPromise = null;
  }
}

module.exports = { logEvent, closeMongo };
