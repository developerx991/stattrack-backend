console.log("⏳ Пытаюсь запустить сервер...");
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

const BOT_TOKEN = (process.env.BOT_TOKEN || '').trim();
const RAW_MONGO_URI = (process.env.MONGODB_URI || '').trim();

let dbConnecting = null;
let lastDbError = '';

// Резервный обход ошибки querySrv ENODATA через защищенный HTTPS-запрос к Google DNS
async function resolveMongoUri(uri) {
  if (!uri || !uri.startsWith('mongodb+srv://')) return uri;

  try {
    const parsed = new URL(uri);
    const srvHost = parsed.hostname;
    console.log(`🔍 Ищу серверы кластера ${srvHost} через Google DoH...`);

    const srvRes = await fetch(`https://dns.google/resolve?name=_mongodb._tcp.${srvHost}&type=SRV`);
    const srvJson = await srvRes.json();

    if (!srvJson.Answer || srvJson.Answer.length === 0) {
      console.error(`⚠️ У домена ${srvHost} нет активных SRV-записей в DNS!`);
      return uri;
    }

    const hosts = srvJson.Answer
      .filter(a => a.type === 33)
      .map(a => {
        const parts = a.data.trim().split(/\s+/);
        const port = parts[2];
        const target = parts[3].replace(/\.$/, '');
        return `${target}:${port}`;
      });

    const txtRes = await fetch(`https://dns.google/resolve?name=${srvHost}&type=TXT`);
    const txtJson = await txtRes.json();
    const extraParams = new URLSearchParams(parsed.search);
    extraParams.set('ssl', 'true');
    if (!extraParams.has('authSource')) extraParams.set('authSource', 'admin');

    if (txtJson.Answer && txtJson.Answer.length > 0) {
      const txtData = txtJson.Answer[0].data.replace(/"/g, '');
      const txtParams = new URLSearchParams(txtData);
      for (const [k, v] of txtParams.entries()) {
        if (!extraParams.has(k)) extraParams.set(k, v);
      }
    }

    const auth = parsed.username
      ? `${parsed.username}:${parsed.password}@`
      : '';
    const dbName = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : '/stattrack';

    const directUri = `mongodb://${auth}${hosts.join(',')}${dbName}?${extraParams.toString()}`;
    console.log(`✅ Прямой адрес получен (${hosts.length} узла), подключаюсь...`);
    return directUri;
  } catch (e) {
    console.error('Ошибка при разрешении SRV через HTTPS:', e.message);
    return uri;
  }
}

async function connectDB() {
  if (mongoose.connection.readyState === 1) return true;
  if (dbConnecting) return dbConnecting;

  dbConnecting = (async () => {
    if (!RAW_MONGO_URI) {
      lastDbError = 'MONGODB_URI не задан в переменных окружения';
      console.error('❌ ' + lastDbError);
      return false;
    }

    const opts = {
      serverSelectionTimeoutMS: 8000,
      connectTimeoutMS: 10000,
      socketTimeoutMS: 20000
    };

    // Сначала пробуем прямое подключение (на Render работает быстрее и стабильнее)
    try {
      await mongoose.connect(RAW_MONGO_URI, opts);
      lastDbError = '';
      console.log('✅ Успешное подключение к MongoDB Atlas!');
      return true;
    } catch (err) {
      console.warn('⚠️ Прямое подключение не удалось:', err.message);
      if (/ENODATA|ENOTFOUND|querySrv/i.test(err.message) && RAW_MONGO_URI.startsWith('mongodb+srv://')) {
        try {
          const directUri = await resolveMongoUri(RAW_MONGO_URI);
          await mongoose.connect(directUri, opts);
          lastDbError = '';
          console.log('✅ Успешное подключение к MongoDB Atlas через DoH!');
          return true;
        } catch (err2) {
          lastDbError = err2.message;
          console.error('❌ Ошибка подключения к БД (DoH):', err2.message);
          return false;
        }
      }
      lastDbError = err.message;
      console.error('❌ Ошибка подключения к БД:', err.message);
      return false;
    }
  })().finally(() => {
    dbConnecting = null;
  });

  return dbConnecting;
}

connectDB();

const userSchema = new mongoose.Schema({
  telegramId: { type: Number, required: true, unique: true },
  data: { type: Object, default: null }
});
const User = mongoose.model('User', userSchema);

function verifyTelegramWebAppData(telegramInitData) {
  if (!telegramInitData || !BOT_TOKEN) return false;
  try {
    const urlParams = new URLSearchParams(telegramInitData);
    const hash = urlParams.get('hash');
    if (!hash) return false;
    urlParams.delete('hash');
    urlParams.sort();

    let dataCheckString = '';
    for (const [key, value] of urlParams.entries()) {
      dataCheckString += `${key}=${value}\n`;
    }
    dataCheckString = dataCheckString.slice(0, -1);

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    return calculatedHash === hash;
  } catch (e) {
    return false;
  }
}

function extractTelegramUserId(telegramInitData, fallbackId) {
  try {
    const rawUser = new URLSearchParams(telegramInitData).get('user');
    if (rawUser) {
      const parsed = JSON.parse(rawUser);
      if (parsed && parsed.id) return Number(parsed.id);
    }
  } catch (e) {}
  return Number(fallbackId);
}

// Быстрая проверка состояния сервера и БД: откройте https://stattrack-backend.onrender.com/api/health
app.get(['/', '/api/health'], (req, res) => {
  res.json({
    ok: true,
    dbConnected: mongoose.connection.readyState === 1,
    hasBotToken: Boolean(BOT_TOKEN),
    hasMongoUri: Boolean(RAW_MONGO_URI),
    dbError: lastDbError || undefined
  });
});

app.post('/api/load', async (req, res) => {
  const { initData, user_id } = req.body || {};
  if (!BOT_TOKEN) {
    return res.status(500).json({ error: 'На сервере не задан BOT_TOKEN (проверь Environment Variables на Render)' });
  }
  if (!verifyTelegramWebAppData(initData)) {
    return res.status(403).json({ error: 'Подпись Telegram не прошла проверку (проверь BOT_TOKEN на Render)' });
  }

  const tgId = extractTelegramUserId(initData, user_id);
  if (!Number.isFinite(tgId)) {
    return res.status(400).json({ error: 'Некорректный user_id' });
  }

  const connected = await connectDB();
  if (!connected) {
    return res.status(503).json({ error: 'Нет подключения к MongoDB: ' + (lastDbError || 'проверь MONGODB_URI и Network Access 0.0.0.0/0 в Atlas') });
  }

  try {
    let user = await User.findOne({ telegramId: tgId });
    if (!user) {
      user = new User({ telegramId: tgId, data: null });
      await user.save();
    }
    res.json(user.data);
  } catch (error) {
    console.error('Ошибка /api/load:', error.message);
    res.status(500).json({ error: 'Ошибка БД: ' + error.message });
  }
});

app.post('/api/save', async (req, res) => {
  const { initData, user_id, state } = req.body || {};
  if (!BOT_TOKEN) {
    return res.status(500).json({ error: 'На сервере не задан BOT_TOKEN' });
  }
  if (!verifyTelegramWebAppData(initData)) {
    return res.status(403).json({ error: 'Доступ запрещен' });
  }

  const tgId = extractTelegramUserId(initData, user_id);
  if (!Number.isFinite(tgId)) {
    return res.status(400).json({ error: 'Некорректный user_id' });
  }

  const connected = await connectDB();
  if (!connected) {
    return res.status(503).json({ error: 'Нет подключения к MongoDB' });
  }

  try {
    await User.findOneAndUpdate(
      { telegramId: tgId },
      { data: state },
      { upsert: true }
    );
    res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Ошибка /api/save:', error.message);
    res.status(500).json({ error: 'Ошибка сохранения: ' + error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
