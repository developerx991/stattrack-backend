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

const visitorSchema = new mongoose.Schema({
  visitorId: { type: String, required: true, unique: true },
  user_id: { type: Number, default: null },
  username: { type: String, default: '' },
  firstName: { type: String, default: '' },
  mode: { type: String, default: 'guest' },
  nick: { type: String, default: '' },
  studyMin: { type: Number, default: 0 },
  workouts: { type: Number, default: 0 },
  streak: { type: Number, default: 0 },
  lastSeen: { type: Number, default: Date.now },
  visits: { type: Number, default: 0 }
});
const Visitor = mongoose.model('Visitor', visitorSchema);

function verifyTelegramWebAppData(telegramInitData) {
  if (!telegramInitData || !BOT_TOKEN) return { ok: false, reason: !BOT_TOKEN ? 'no_token' : 'empty_initData' };
  try {
    let raw = String(telegramInitData).trim().replace(/^[?#]/, '');
    if (raw.startsWith('tgWebAppData=')) {
      raw = new URLSearchParams(raw).get('tgWebAppData') || raw;
    }

    const check = (str) => {
      const urlParams = new URLSearchParams(str);
      const hash = urlParams.get('hash');
      if (!hash) return { ok: false, reason: 'no_hash' };
      const pairs = [];
      for (const [key, value] of urlParams.entries()) {
        if (key !== 'hash') pairs.push([key, value]);
      }
      pairs.sort((a, b) => a[0].localeCompare(b[0]));
      const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join('\n');
      const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
      const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
      if (calculatedHash === hash) return { ok: true };
      return { ok: false, reason: 'hash_mismatch', keys: pairs.map(p => p[0]).join(',') };
    };

    let res = check(raw);
    if (!res.ok && raw.includes('%3D')) {
      try { res = check(decodeURIComponent(raw)); } catch (e) {}
    }
    if (!res.ok) {
      const botId = BOT_TOKEN.split(':')[0];
      console.warn(`⚠️ Telegram auth failed (${res.reason}), botId=${botId}, keys=[${res.keys || ''}]`);
    }
    return res;
  } catch (e) {
    return { ok: false, reason: 'exception: ' + e.message };
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
  const auth = verifyTelegramWebAppData(initData);
  if (!auth.ok) {
    return res.status(403).json({ error: `Подпись не совпала (${auth.reason}; botId=${BOT_TOKEN.split(':')[0]})` });
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
  const auth = verifyTelegramWebAppData(initData);
  if (!auth.ok) {
    return res.status(403).json({ error: `Доступ запрещен (${auth.reason})` });
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

// 1. Приём пинга при каждом входе (и Telegram, и гости)
app.post('/api/ping', async (req, res) => {
  const { visitorId, user_id, username, firstName, mode, nick, studyMin, workouts, streak, ts } = req.body || {};
  if (!visitorId) return res.status(400).json({ ok: false });

  const connected = await connectDB();
  if (!connected) return res.status(503).json({ ok: false });

  try {
    await Visitor.findOneAndUpdate(
      { visitorId: String(visitorId) },
      {
        $set: {
          visitorId: String(visitorId),
          user_id: Number.isFinite(Number(user_id)) ? Number(user_id) : null,
          username: String(username || '').slice(0, 64),
          firstName: String(firstName || '').slice(0, 64),
          mode: mode === 'telegram' ? 'telegram' : 'guest',
          nick: String(nick || '').slice(0, 64),
          studyMin: Number(studyMin) || 0,
          workouts: Number(workouts) || 0,
          streak: Number(streak) || 0,
          lastSeen: Number(ts) || Date.now()
        },
        $inc: { visits: 1 }
      },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('Ошибка /api/ping:', error.message);
    res.status(500).json({ error: error.message });
  }
});

function getCurrentWeekDayKeys() {
  const now = new Date();
  const day = (now.getDay() + 6) % 7; // 0 = Пн .. 6 = Вс
  const mon = new Date(now.getFullYear(), now.getMonth(), now.getDate() - day);
  const keys = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(mon.getTime() + i * 86400000);
    keys.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`);
  }
  return keys;
}

// 2. Отдача общего рейтинга (все время + текущая неделя Пн–Вс) и списка визитов (для админа)
app.post('/api/leaderboard', async (req, res) => {
  const connected = await connectDB();
  if (!connected) {
    return res.status(503).json({ error: 'Нет подключения к MongoDB' });
  }

  try {
    const isAdmin = Boolean(req.body?.admin);
    const weekKeys = getCurrentWeekDayKeys();
    const [users, visitors] = await Promise.all([
      User.find({}).lean(),
      Visitor.find({}).sort({ lastSeen: -1 }).limit(150).lean()
    ]);

    const usernameByTgId = new Map();
    for (const v of visitors) {
      if (v.user_id && v.username) usernameByTgId.set(Number(v.user_id), v.username);
    }

    const leaderboard = users
      .map(u => {
        const st = u.data || {};
        const daily = st.daily || {};
        let weekStudyMin = 0;
        let weekWorkouts = 0;
        for (const k of weekKeys) {
          if (daily[k]) {
            weekStudyMin += Number(daily[k].min) || 0;
            weekWorkouts += Number(daily[k].wk) || 0;
          }
        }
        return {
          user_id: u.telegramId,
          username: usernameByTgId.get(Number(u.telegramId)) || '',
          nick: st?.profile?.nick || 'Игрок',
          studyMin: st?.stats?.min || 0,
          workouts: st?.stats?.wk || 0,
          weekStudyMin,
          weekWorkouts,
          streak: st?.streak?.cur || 0
        };
      })
      .filter(u => u.studyMin > 0 || u.workouts > 0 || u.streak > 0 || u.weekStudyMin > 0 || u.weekWorkouts > 0);

    res.json({ leaderboard, visitors: isAdmin ? visitors : [] });
  } catch (error) {
    console.error('Ошибка /api/leaderboard:', error.message);
    res.status(500).json({ error: 'Ошибка загрузки рейтинга: ' + error.message });
  }
});


// ==========================================================================
// TELEGRAM BOT: КОМАНДЫ, КРАСИВОЕ МЕНЮ И ЖИВАЯ СТАТИСТИКА ИЗ MONGODB
// ==========================================================================
const WEBAPP_URL = (process.env.WEBAPP_URL || '').trim();
const RENDER_URL = (process.env.RENDER_EXTERNAL_URL || 'https://stattrack-backend.onrender.com').replace(/\/+$/, '');

async function tgApi(method, payload) {
  if (!BOT_TOKEN) return null;
  try {
    const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return await res.json();
  } catch (e) {
    console.error(`Telegram API ${method} error:`, e.message);
    return null;
  }
}

function buildMainKeyboard() {
  const rows = [];
  if (WEBAPP_URL) {
    rows.push([{ text: '🔥 Открыть StatTrack', web_app: { url: WEBAPP_URL } }]);
  }
  rows.push([
    { text: '📊 Моя статистика', callback_data: 'stats' },
    { text: '❓ Как играть', callback_data: 'help' }
  ]);
  return { inline_keyboard: rows };
}

async function formatUserStats(telegramId) {
  const connected = await connectDB();
  if (!connected) return '⚠️ База данных сейчас недоступна. Попробуй через минуту.';
  const user = await User.findOne({ telegramId });
  const st = user?.data;
  if (!st || !st.stats) {
    return '📭 Профиль пока пуст.\n\nОткрой <b>StatTrack</b>, пройди быструю настройку — и здесь появится твоя статистика!';
  }
  const nick = st.profile?.nick || 'Игрок';
  const hrs = ((st.stats.min || 0) / 60).toFixed(1);
  const wk = st.stats.wk || 0;
  const streak = st.streak?.cur || 0;
  const bestStreak = st.streak?.best || 0;
  const keys = st.stats.keyBalance || 0;
  const chests = st.stats.chests || 0;
  const pend = Math.round(st.bank?.pend || 0).toLocaleString('ru-RU');
  const paid = Math.round(st.bank?.paid || 0).toLocaleString('ru-RU');
  const habitsCount = Array.isArray(st.habits) ? st.habits.length : 0;

  return [
    `⚔️ <b>Профиль: ${nick}</b>`,
    ``,
    `📚 <b>Учёба:</b> ${hrs} ч`,
    `🏋️ <b>Тренировки:</b> ${wk}`,
    `🔥 <b>Серия:</b> ${streak} дн. (рекорд: ${bestStreak})`,
    `🔑 <b>Ключи:</b> ${keys}${chests ? ` • 📦 <b>Кейсы:</b> ${chests}` : ''}`,
    `✅ <b>Привычек в трекере:</b> ${habitsCount}`,
    `💰 <b>Банк:</b> ${pend} ₽ к выплате (всего выплачено: ${paid} ₽)`
  ].join('\n');
}

const WELCOME_TEXT = [
  `🔥 <b>Добро пожаловать в StatTrack</b>`,
  ``,
  `Твоя система геймификации учёбы, спорта и ежедневных привычек:`,
  `• 📚 <b>Лабиринт учёбы</b> — 10 врат разного риска, таймер и ключи`,
  `• 🏋️ <b>Спорт и журнал весов</b> — тренировки, подходы и рекорды`,
  `• 🎯 <b>Цели и Привычки</b> — календарь дисциплины и контроль дней`,
  `• 📦 <b>Магазин и Кейсы</b> — тактические предметы за ключи`,
  ``,
  `Прогресс автоматически синхронизируется между телефоном и ПК.`,
  WEBAPP_URL ? `Жми кнопку ниже, чтобы начать 👇` : `Нажми кнопку <b>«Открыть» / «Поиграть»</b> слева внизу 👇`
].join('\n');

const HELP_TEXT = [
  `📖 <b>Как работает StatTrack</b>`,
  ``,
  `1️⃣ <b>Учёба:</b> выбираешь план в минутах и открываешь врата. Каждые 90 минут учёбы дают 🔑 1 ключ, а из дверей могут выпасть отдых, катка, кейс или тайный выход.`,
  `2️⃣ <b>Спорт:</b> отмечай тренировки, записывай рабочие веса в журнале и следи за личными рекордами.`,
  `3️⃣ <b>Привычки и Цели:</b> добавляй ежедневные или кастомные привычки и отслеживай прогресс в календаре (красный / жёлтый / зелёный день).`,
  `4️⃣ <b>Синхронизация:</b> всегда открывай приложение через этого бота — на телефоне и ПК будет один и тот же аккаунт.`,
  ``,
  `Команды бота: /start • /stats • /help`
].join('\n');

app.post('/api/webhook', async (req, res) => {
  res.sendStatus(200);
  const update = req.body;
  if (!update) return;

  try {
    if (update.message && update.message.chat) {
      const chatId = update.message.chat.id;
      const userId = update.message.from?.id;
      const text = (update.message.text || '').trim().split(/\s+/)[0].toLowerCase();

      if (text === '/start' || text === '/menu') {
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: WELCOME_TEXT,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else if (text === '/stats') {
        const statsMsg = await formatUserStats(userId);
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: statsMsg,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else if (text === '/help') {
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: HELP_TEXT,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else {
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: 'Используй команды /start, /stats, /help или открой приложение 👇',
          reply_markup: buildMainKeyboard()
        });
      }
    } else if (update.callback_query) {
      const cq = update.callback_query;
      const chatId = cq.message?.chat?.id;
      const userId = cq.from?.id;
      await tgApi('answerCallbackQuery', { callback_query_id: cq.id });
      if (!chatId) return;

      if (cq.data === 'stats') {
        const statsMsg = await formatUserStats(userId);
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: statsMsg,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else if (cq.data === 'help') {
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: HELP_TEXT,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      }
    }
  } catch (e) {
    console.error('Webhook error:', e.message);
  }
});

async function setupTelegramBot() {
  if (!BOT_TOKEN) return;
  await tgApi('setMyCommands', {
    commands: [
      { command: 'start', description: '🔥 Запустить StatTrack' },
      { command: 'stats', description: '📊 Моя статистика и баланс' },
      { command: 'help', description: '❓ Как всё работает' }
    ]
  });
  await tgApi('setWebhook', {
    url: `${RENDER_URL}/api/webhook`,
    allowed_updates: ['message', 'callback_query']
  });
  console.log(`🤖 Telegram-бот настроен (webhook: ${RENDER_URL}/api/webhook)`);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  setupTelegramBot();
});
