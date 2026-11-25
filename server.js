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

const weeklyResultSchema = new mongoose.Schema({
  weekKey: { type: String, required: true, unique: true },
  weekRange: { type: String, default: '' },
  finalizedAt: { type: Number, default: Date.now },
  summarySent: { type: Boolean, default: false },
  studyTop: { type: Array, default: [] },
  workTop: { type: Array, default: [] }
});
const WeeklyResult = mongoose.model('WeeklyResult', weeklyResultSchema);

const scheduledTimerSchema = new mongoose.Schema({
  telegramId: { type: Number, required: true, unique: true },
  endAt: { type: Number, required: true },
  label: { type: String, default: 'Таймер завершён' },
  kind: { type: String, default: 'study' }
});
const ScheduledTimer = mongoose.model('ScheduledTimer', scheduledTimerSchema);

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

function getWeekDayKeys(weekOffset = 0) {
  const now = new Date(Date.now() - 3 * 3600 * 1000); // Игровой день обновляется в 03:00
  const day = (now.getDay() + 6) % 7; // 0 = Пн .. 6 = Вс
  const mon = new Date(now.getFullYear(), now.getMonth(), now.getDate() - day + weekOffset * 7);
  const keys = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(mon.getTime() + i * 86400000);
    keys.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`);
  }
  const sun = new Date(mon.getTime() + 6 * 86400000);
  const fmtDM = d => `${String(d.getDate()).padStart(2, '0')}.${String(d.getMonth() + 1).padStart(2, '0')}`;
  return { weekKey: keys[0], keys, range: `${fmtDM(mon)} – ${fmtDM(sun)}` };
}

async function ensurePrevWeekResult(users, usernameByTgId, prevWeekInfo) {
  let prevWeek = await WeeklyResult.findOne({ weekKey: prevWeekInfo.weekKey }).lean();
  if (prevWeek) return prevWeek;

  const prevRows = users.map(u => {
    const st = u.data || {};
    const daily = st.daily || {};
    let studyMin = 0;
    let workouts = 0;
    for (const k of prevWeekInfo.keys) {
      if (daily[k]) {
        studyMin += Number(daily[k].min) || 0;
        workouts += Number(daily[k].wk) || 0;
      }
    }
    return {
      user_id: u.telegramId,
      username: usernameByTgId.get(Number(u.telegramId)) || '',
      nick: st?.profile?.nick || 'Игрок',
      nickStyle: st?.profile?.nickStyle || '',
      frame: st?.profile?.frame || '',
      badge: st?.profile?.badge || '',
      ava: st?.profile?.ava || 'crown',
      studyMin,
      workouts
    };
  });

  const studyTop = prevRows.filter(x => x.studyMin > 0).sort((a, b) => b.studyMin - a.studyMin).slice(0, 20);
  const workTop = prevRows.filter(x => x.workouts > 0).sort((a, b) => b.workouts - a.workouts).slice(0, 20);

  try {
    prevWeek = await WeeklyResult.findOneAndUpdate(
      { weekKey: prevWeekInfo.weekKey },
      {
        $setOnInsert: {
          weekKey: prevWeekInfo.weekKey,
          weekRange: prevWeekInfo.range,
          finalizedAt: Date.now(),
          summarySent: false,
          studyTop,
          workTop
        }
      },
      { upsert: true, new: true }
    ).lean();
  } catch (e) {
    prevWeek = await WeeklyResult.findOne({ weekKey: prevWeekInfo.weekKey }).lean();
  }
  return prevWeek;
}

// 2. Отдача общего рейтинга (все время + текущая неделя + замороженные итоги прошлой недели + косметика и короны чемпионов)
app.post('/api/leaderboard', async (req, res) => {
  const connected = await connectDB();
  if (!connected) {
    return res.status(503).json({ error: 'Нет подключения к MongoDB' });
  }

  try {
    const isAdmin = Boolean(req.body?.admin);
    const curWeek = getWeekDayKeys(0);
    const prevWeekInfo = getWeekDayKeys(-1);

    const [users, visitors] = await Promise.all([
      User.find({}).lean(),
      Visitor.find({}).sort({ lastSeen: -1 }).limit(150).lean()
    ]);

    const usernameByTgId = new Map();
    for (const v of visitors) {
      if (v.user_id && v.username) usernameByTgId.set(Number(v.user_id), v.username);
    }

    const prevWeek = await ensurePrevWeekResult(users, usernameByTgId, prevWeekInfo);
    const champStudyId = prevWeek?.studyTop?.[0]?.user_id ? Number(prevWeek.studyTop[0].user_id) : null;
    const champWorkId = prevWeek?.workTop?.[0]?.user_id ? Number(prevWeek.workTop[0].user_id) : null;

    const leaderboard = users
      .map(u => {
        const st = u.data || {};
        const daily = st.daily || {};
        let weekStudyMin = 0;
        let weekWorkouts = 0;
        for (const k of curWeek.keys) {
          if (daily[k]) {
            weekStudyMin += Number(daily[k].min) || 0;
            weekWorkouts += Number(daily[k].wk) || 0;
          }
        }
        const uidNum = Number(u.telegramId);
        const champTitles = [];
        if (champStudyId && uidNum === champStudyId) champTitles.push('study');
        if (champWorkId && uidNum === champWorkId) champTitles.push('work');
        return {
          user_id: uidNum,
          username: usernameByTgId.get(uidNum) || '',
          nick: st?.profile?.nick || 'Игрок',
          nickStyle: st?.profile?.nickStyle || '',
          frame: st?.profile?.frame || '',
          badge: st?.profile?.badge || '',
          ava: st?.profile?.ava || 'crown',
          champTitles,
          studyMin: st?.stats?.min || 0,
          workouts: st?.stats?.wk || 0,
          weekStudyMin,
          weekWorkouts,
          streak: st?.streak?.cur || 0
        };
      })
      .filter(u => u.studyMin > 0 || u.workouts > 0 || u.streak > 0 || u.weekStudyMin > 0 || u.weekWorkouts > 0);

    res.json({ leaderboard, visitors: isAdmin ? visitors : [], prevWeek, champStudyId, champWorkId });
  } catch (error) {
    console.error('Ошибка /api/leaderboard:', error.message);
    res.status(500).json({ error: 'Ошибка загрузки рейтинга: ' + error.message });
  }
});


// ==========================================================================
// TELEGRAM BOT: ПРИВЕТСТВИЕ, ИНТЕРАКТИВНЫЙ ГИД, СТАТИСТИКА И ТОП НЕДЕЛИ
// ==========================================================================
const WEBAPP_URL = (process.env.WEBAPP_URL || '').trim();
const BANNER_URL = (process.env.BANNER_URL || '').trim();
const RENDER_URL = (process.env.RENDER_EXTERNAL_URL || 'https://stattrack-backend.onrender.com').replace(/\/+$/, '');
const ADMIN_IDS = new Set(
  String(process.env.ADMIN_IDS || '')
    .split(',')
    .map(s => Number(s.trim()))
    .filter(n => Number.isFinite(n) && n > 0)
);
const isAdminUser = userId => ADMIN_IDS.has(Number(userId));
const pendingAnnounces = new Map();

function cleanupPendingAnnounces() {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [k, v] of pendingAnnounces.entries()) {
    if (v.createdAt < cutoff) pendingAnnounces.delete(k);
  }
}

async function getAllRecipientIds() {
  const connected = await connectDB();
  if (!connected) return [];
  const [users, visitors] = await Promise.all([
    User.find({}, { telegramId: 1 }).lean(),
    Visitor.find({ user_id: { $ne: null } }, { user_id: 1 }).lean()
  ]);
  const ids = new Set();
  for (const u of users) {
    const id = Number(u.telegramId);
    if (Number.isFinite(id) && id > 0) ids.add(id);
  }
  for (const v of visitors) {
    const id = Number(v.user_id);
    if (Number.isFinite(id) && id > 0) ids.add(id);
  }
  return Array.from(ids);
}

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

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function formatHm(minutes) {
  const m = Math.round(Number(minutes) || 0);
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return h ? `${h} ч${rem ? ' ' + rem + ' мин' : ''}` : `${rem} мин`;
}

function buildMainKeyboard() {
  const rows = [];
  if (WEBAPP_URL) {
    rows.push([{ text: 'Открыть StatTrack', web_app: { url: WEBAPP_URL } }]);
  }
  rows.push([
    { text: 'Моя статистика', callback_data: 'stats' },
    { text: 'Топ недели', callback_data: 'top' }
  ]);
  rows.push([
    { text: 'Краткий гид', callback_data: 'guide_0' }
  ]);
  return { inline_keyboard: rows };
}

const WELCOME_TEXT = [
  `<b>StatTrack</b> — трекер учёбы, тренировок и привычек прямо в Telegram.`,
  ``,
  `Внутри лабиринт с таймером, журнал тренировок, календарь привычек и общий недельный рейтинг. Прогресс автоматически синхронизируется между телефоном и ПК.`
].join('\n');

const GUIDE_SLIDES = [
  {
    title: 'Шаг 1 из 6 — Учёба и Лабиринт',
    text: [
      'Учебное время разбивается на короткие блоки в формате лабиринта из 10 врат разной сложности.',
      '',
      '• <b>Ключи и награды:</b> каждые 90 минут учёбы приносят ключ, а за дверями могут попасться перерыв, кейс или тайный выход.',
      '',
      '• <b>Разминка и катки:</b> перед дверью может выпасть 1-минутная разминка. И катки, и разминки легко отключаются галочками перед стартом.'
    ].join('\n')
  },
  {
    title: 'Шаг 2 из 6 — Спорт и Журнал',
    text: [
      'Быстрый учёт тренировок без лишней рутины.',
      '',
      '• <b>Группы мышц:</b> отмечай тренировку и выбирай нужные группы мышц плюсиком. Подходы и рабочие веса — по желанию.',
      '',
      '• <b>Задним числом:</b> если забыл записать тренировку, её можно добавить за последние 2 дня текущей недели.'
    ].join('\n')
  },
  {
    title: 'Шаг 3 из 6 — Привычки и Цели',
    text: [
      'Ежедневные дела и крупные задачи всегда под рукой.',
      '',
      '• <b>Гибкие привычки:</b> на каждый день, по будням или в выбранные дни недели. Пропущенную отметку тоже можно закрыть за последние 2 дня.',
      '',
      '• <b>Цели:</b> разбивай задачи на чекбоксы или часы — после учёбы время можно распределять прямо по подцелям.'
    ].join('\n')
  },
  {
    title: 'Шаг 4 из 6 — Календарь прогресса',
    text: [
      'Вся дисциплина собирается в цветной календарь в разделе «Прогресс».',
      '',
      '• <b>Цвета дней:</b> красный — без активности, жёлтый — минимум выполнен, зелёный — отличный результат.',
      '',
      '• <b>Детали дня:</b> календарь переключается между общей активностью и привычками. Нажатие на любой день открывает его подробную сводку.'
    ].join('\n')
  },
  {
    title: 'Шаг 5 из 6 — Рейтинг и Чемпионы',
    text: [
      'Соревнуйся с другими участниками по учёбе и тренировкам.',
      '',
      '• <b>Два зачёта:</b> пьедестал и таблица лидеров за всё время или за текущую неделю (Пн–Вс).',
      '',
      '• <b>Итоги недели:</b> каждый понедельник чемпионы прошлой недели фиксируются в отдельном блоке и больше не меняются.'
    ].join('\n')
  },
  {
    title: 'Шаг 6 из 6 — Магазин, Банк и Синхронизация',
    text: [
      'Награды для самомотивации и единый профиль на всех устройствах.',
      '',
      '• <b>Магазин:</b> трать ключи на кейсы или полезные предметы для лабиринта (разведка, переброс, щит).',
      '',
      '• <b>Банк:</b> условия выплат за тренировки можно настроить позже или вообще не использовать.',
      '',
      '• <b>Синхронизация:</b> открывай приложение через этого бота — прогресс общий на телефоне и ПК.'
    ].join('\n')
  }
];

function buildGuideKeyboard(idx) {
  const nav = [];
  if (idx > 0) nav.push({ text: '← Назад', callback_data: `guide_${idx - 1}` });
  if (idx < GUIDE_SLIDES.length - 1) nav.push({ text: 'Дальше →', callback_data: `guide_${idx + 1}` });
  const rows = [];
  if (nav.length) rows.push(nav);
  if (WEBAPP_URL) rows.push([{ text: 'Открыть StatTrack', web_app: { url: WEBAPP_URL } }]);
  return { inline_keyboard: rows };
}

function formatGuideSlide(idx) {
  const safeIdx = Math.max(0, Math.min(GUIDE_SLIDES.length - 1, Number(idx) || 0));
  const slide = GUIDE_SLIDES[safeIdx];
  return {
    idx: safeIdx,
    text: `<b>${slide.title}</b>\n\n${slide.text}`,
    reply_markup: buildGuideKeyboard(safeIdx)
  };
}

async function sendStartMessage(chatId) {
  if (BANNER_URL) {
    const res = await tgApi('sendPhoto', {
      chat_id: chatId,
      photo: BANNER_URL,
      caption: WELCOME_TEXT,
      parse_mode: 'HTML',
      reply_markup: buildMainKeyboard()
    });
    if (res && res.ok) return;
  }
  await tgApi('sendMessage', {
    chat_id: chatId,
    text: WELCOME_TEXT,
    parse_mode: 'HTML',
    reply_markup: buildMainKeyboard()
  });
}

async function formatUserStats(telegramId) {
  const connected = await connectDB();
  if (!connected) return 'База данных сейчас недоступна. Попробуй через минуту.';
  const user = await User.findOne({ telegramId });
  const st = user?.data;
  if (!st || !st.stats) {
    return 'Профиль пока пуст.\n\nОткрой <b>StatTrack</b>, пройди быструю настройку — и здесь появится твоя статистика.';
  }
  const nick = escapeHtml(st.profile?.nick || 'Игрок');
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
    `<b>Профиль: ${nick}</b>`,
    ``,
    `Учёба: <b>${hrs} ч</b>`,
    `Тренировки: <b>${wk}</b>`,
    `Серия: <b>${streak} дн.</b> (рекорд: ${bestStreak})`,
    `Ключи: <b>${keys}</b>${chests ? ` • Кейсы: <b>${chests}</b>` : ''}`,
    `Привычек в трекере: <b>${habitsCount}</b>`,
    `Банк: <b>${pend} ₽</b> к выплате (выплачено: ${paid} ₽)`
  ].join('\n');
}

async function formatWeeklyTop() {
  const connected = await connectDB();
  if (!connected) return 'База данных сейчас недоступна. Попробуй через минуту.';

  const curWeek = getWeekDayKeys(0);
  const users = await User.find({}).lean();
  const rows = users.map(u => {
    const st = u.data || {};
    const daily = st.daily || {};
    let studyMin = 0;
    let workouts = 0;
    for (const k of curWeek.keys) {
      if (daily[k]) {
        studyMin += Number(daily[k].min) || 0;
        workouts += Number(daily[k].wk) || 0;
      }
    }
    return {
      nick: escapeHtml(st?.profile?.nick || 'Игрок'),
      studyMin,
      workouts
    };
  });

  const studyTop = rows.filter(r => r.studyMin > 0).sort((a, b) => b.studyMin - a.studyMin).slice(0, 5);
  const workTop = rows.filter(r => r.workouts > 0).sort((a, b) => b.workouts - a.workouts).slice(0, 5);

  const lines = [`<b>Топ недели (${curWeek.range})</b>`, ``];

  lines.push(`<b>Учёба:</b>`);
  if (studyTop.length) {
    studyTop.forEach((u, i) => lines.push(`${i + 1}. ${u.nick} — ${formatHm(u.studyMin)}`));
  } else {
    lines.push(`Пока нет записей за эту неделю.`);
  }

  lines.push(``);
  lines.push(`<b>Тренировки:</b>`);
  if (workTop.length) {
    workTop.forEach((u, i) => lines.push(`${i + 1}. ${u.nick} — ${u.workouts} тр.`));
  } else {
    lines.push(`Пока нет тренировок за эту неделю.`);
  }

  return lines.join('\n');
}

app.post('/api/webhook', async (req, res) => {
  res.sendStatus(200);
  const update = req.body;
  if (!update) return;

  try {
    if (update.message && update.message.chat) {
      const chatId = update.message.chat.id;
      const userId = update.message.from?.id;
      const text = (update.message.text || '').trim().split(/\s+/)[0].toLowerCase().split('@')[0];

      if (text === '/start' || text === '/menu') {
        await sendStartMessage(chatId);
      } else if (text === '/stats') {
        const statsMsg = await formatUserStats(userId);
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: statsMsg,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else if (text === '/top') {
        const topMsg = await formatWeeklyTop();
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: topMsg,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else if (text === '/help') {
        const slide = formatGuideSlide(0);
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: slide.text,
          parse_mode: 'HTML',
          reply_markup: slide.reply_markup
        });
      } else if (text === '/myid') {
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: `Твой Telegram ID: <code>${userId}</code>`,
          parse_mode: 'HTML'
        });
      } else if (text === '/announce') {
        if (!isAdminUser(userId)) {
          await tgApi('sendMessage', {
            chat_id: chatId,
            text: 'Используй команды /start, /stats, /top, /help или открой приложение ниже.',
            reply_markup: buildMainKeyboard()
          });
          return;
        }
        cleanupPendingAnnounces();
        const rawText = String(update.message.text || '');
        const bodyText = rawText.replace(/^\/announce(?:@\S+)?\s*/i, '').trim();
        const replyMsg = update.message.reply_to_message;

        if (!bodyText && !replyMsg) {
          await tgApi('sendMessage', {
            chat_id: chatId,
            text: [
              '<b>Как сделать рассылку:</b>',
              '',
              '1. Напиши <code>/announce Текст сообщения</code>',
              '2. Или ответь командой <code>/announce</code> на любой свой пост (можно с картинкой и форматированием) — бот разошлёт его копию всем.',
              '',
              'Перед отправкой бот покажет предпросмотр и спросит подтверждение.'
            ].join('\n'),
            parse_mode: 'HTML'
          });
          return;
        }

        const recipients = await getAllRecipientIds();
        const draftId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

        if (replyMsg && !bodyText) {
          pendingAnnounces.set(draftId, {
            mode: 'copy',
            fromChatId: chatId,
            sourceMessageId: replyMsg.message_id,
            createdAt: Date.now()
          });
          await tgApi('copyMessage', {
            chat_id: chatId,
            from_chat_id: chatId,
            message_id: replyMsg.message_id,
            reply_markup: WEBAPP_URL ? { inline_keyboard: [[{ text: 'Открыть StatTrack', web_app: { url: WEBAPP_URL } }]] } : undefined
          });
          await tgApi('sendMessage', {
            chat_id: chatId,
            text: `👆 <b>Предпросмотр рассылки</b>\nПолучателей в базе: <b>${recipients.length}</b>. Отправляем?`,
            parse_mode: 'HTML',
            reply_markup: {
              inline_keyboard: [[
                { text: `Отправить всем (${recipients.length})`, callback_data: `ann_send_${draftId}` },
                { text: 'Отмена', callback_data: `ann_cancel_${draftId}` }
              ]]
            }
          });
        } else {
          pendingAnnounces.set(draftId, {
            mode: 'text',
            text: bodyText,
            fromChatId: chatId,
            createdAt: Date.now()
          });
          await tgApi('sendMessage', {
            chat_id: chatId,
            text: `<b>Предпросмотр рассылки (${recipients.length} чел.):</b>\n\n${escapeHtml(bodyText)}`,
            parse_mode: 'HTML',
            reply_markup: {
              inline_keyboard: [[
                { text: `Отправить всем (${recipients.length})`, callback_data: `ann_send_${draftId}` },
                { text: 'Отмена', callback_data: `ann_cancel_${draftId}` }
              ]]
            }
          });
        }
      } else {
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: 'Используй команды /start, /stats, /top, /help или открой приложение ниже.',
          reply_markup: buildMainKeyboard()
        });
      }
    } else if (update.callback_query) {
      const cq = update.callback_query;
      const chatId = cq.message?.chat?.id;
      const messageId = cq.message?.message_id;
      const userId = cq.from?.id;
      const data = String(cq.data || '');
      await tgApi('answerCallbackQuery', { callback_query_id: cq.id });
      if (!chatId) return;

      if (data === 'stats') {
        const statsMsg = await formatUserStats(userId);
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: statsMsg,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else if (data === 'top') {
        const topMsg = await formatWeeklyTop();
        await tgApi('sendMessage', {
          chat_id: chatId,
          text: topMsg,
          parse_mode: 'HTML',
          reply_markup: buildMainKeyboard()
        });
      } else if (data.startsWith('ann_cancel_')) {
        if (!isAdminUser(userId)) return;
        const draftId = data.slice(11);
        pendingAnnounces.delete(draftId);
        if (messageId) {
          await tgApi('editMessageText', {
            chat_id: chatId,
            message_id: messageId,
            text: '❌ Рассылка отменена.'
          });
        }
      } else if (data.startsWith('ann_send_')) {
        if (!isAdminUser(userId)) return;
        const draftId = data.slice(9);
        const draft = pendingAnnounces.get(draftId);
        if (!draft) {
          if (messageId) {
            await tgApi('editMessageText', {
              chat_id: chatId,
              message_id: messageId,
              text: '⚠️ Черновик устарел или уже отправлен. Сформируй команду /announce заново.'
            });
          }
          return;
        }
        pendingAnnounces.delete(draftId);

        const recipients = await getAllRecipientIds();
        if (messageId) {
          await tgApi('editMessageText', {
            chat_id: chatId,
            message_id: messageId,
            text: `⏳ Отправляю рассылку (${recipients.length} чел.)…`
          });
        }

        const openMarkup = WEBAPP_URL
          ? { inline_keyboard: [[{ text: 'Открыть StatTrack', web_app: { url: WEBAPP_URL } }]] }
          : undefined;

        let okCount = 0;
        let failCount = 0;
        for (const targetId of recipients) {
          let r = null;
          if (draft.mode === 'copy') {
            r = await tgApi('copyMessage', {
              chat_id: targetId,
              from_chat_id: draft.fromChatId,
              message_id: draft.sourceMessageId,
              reply_markup: openMarkup
            });
          } else {
            r = await tgApi('sendMessage', {
              chat_id: targetId,
              text: escapeHtml(draft.text),
              parse_mode: 'HTML',
              reply_markup: openMarkup
            });
          }
          if (r && r.ok) okCount++;
          else failCount++;
          await new Promise(resolve => setTimeout(resolve, 60));
        }

        const report = [
          '✅ <b>Рассылка завершена!</b>',
          `Доставлено: <b>${okCount}</b> из <b>${recipients.length}</b>`,
          failCount ? `Не доставлено (бот заблокирован/удалён): <b>${failCount}</b>` : ''
        ].filter(Boolean).join('\n');

        if (messageId) {
          await tgApi('editMessageText', {
            chat_id: chatId,
            message_id: messageId,
            text: report,
            parse_mode: 'HTML'
          });
        } else {
          await tgApi('sendMessage', { chat_id: chatId, text: report, parse_mode: 'HTML' });
        }
      } else if (data.startsWith('guide_')) {
        const idx = parseInt(data.slice(6), 10) || 0;
        const slide = formatGuideSlide(idx);
        const isPhotoMsg = Boolean(cq.message?.photo);
        if (messageId && !isPhotoMsg) {
          const edited = await tgApi('editMessageText', {
            chat_id: chatId,
            message_id: messageId,
            text: slide.text,
            parse_mode: 'HTML',
            reply_markup: slide.reply_markup
          });
          if (!edited || !edited.ok) {
            await tgApi('sendMessage', {
              chat_id: chatId,
              text: slide.text,
              parse_mode: 'HTML',
              reply_markup: slide.reply_markup
            });
          }
        } else {
          await tgApi('sendMessage', {
            chat_id: chatId,
            text: slide.text,
            parse_mode: 'HTML',
            reply_markup: slide.reply_markup
          });
        }
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
      { command: 'start', description: 'Открыть StatTrack' },
      { command: 'stats', description: 'Моя статистика' },
      { command: 'top', description: 'Топ недели' },
      { command: 'help', description: 'Краткий гид по приложению' }
    ]
  });
  await tgApi('setWebhook', {
    url: `${RENDER_URL}/api/webhook`,
    allowed_updates: ['message', 'callback_query']
  });
  console.log(`🤖 Telegram-бот настроен (webhook: ${RENDER_URL}/api/webhook)`);
}


// 3. Планирование Telegram-уведомления по окончанию таймера (учёба / отдых / разминка)
app.post('/api/timer/schedule', async (req, res) => {
  const { initData, user_id, endAt, label, kind } = req.body || {};
  if (!BOT_TOKEN) return res.status(500).json({ ok: false });
  const auth = verifyTelegramWebAppData(initData);
  if (!auth.ok) return res.status(403).json({ ok: false });

  const tgId = extractTelegramUserId(initData, user_id);
  const endTs = Number(endAt);
  if (!Number.isFinite(tgId) || !Number.isFinite(endTs) || endTs <= Date.now()) {
    return res.status(400).json({ ok: false });
  }

  const connected = await connectDB();
  if (!connected) return res.status(503).json({ ok: false });

  try {
    await ScheduledTimer.findOneAndUpdate(
      { telegramId: tgId },
      {
        telegramId: tgId,
        endAt: endTs,
        label: String(label || 'Таймер завершён').slice(0, 120),
        kind: String(kind || 'study').slice(0, 24)
      },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('Ошибка /api/timer/schedule:', e.message);
    res.status(500).json({ ok: false });
  }
});

app.post('/api/timer/cancel', async (req, res) => {
  const { initData, user_id } = req.body || {};
  if (!BOT_TOKEN) return res.status(500).json({ ok: false });
  const auth = verifyTelegramWebAppData(initData);
  if (!auth.ok) return res.status(403).json({ ok: false });

  const tgId = extractTelegramUserId(initData, user_id);
  if (!Number.isFinite(tgId)) return res.status(400).json({ ok: false });

  const connected = await connectDB();
  if (!connected) return res.status(503).json({ ok: false });

  try {
    await ScheduledTimer.deleteOne({ telegramId: tgId });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

let timerPollBusy = false;
async function checkScheduledTimers() {
  if (timerPollBusy || !BOT_TOKEN || mongoose.connection.readyState !== 1) return;
  timerPollBusy = true;
  try {
    const now = Date.now();
    const due = await ScheduledTimer.find({ endAt: { $lte: now } }).limit(30).lean();
    for (const item of due) {
      const removed = await ScheduledTimer.findOneAndDelete({ _id: item._id, endAt: item.endAt });
      if (!removed) continue;
      const prefix = item.kind === 'rest' ? '🔥 Перерыв завершён!' : item.kind === 'warmup' ? '🧘 Разминка завершена!' : '⏰ Время вышло!';
      const msg = `<b>${prefix}</b>
${escapeHtml(item.label)}

Возвращайся в StatTrack, чтобы открыть следующие врата.`;
      await tgApi('sendMessage', {
        chat_id: item.telegramId,
        text: msg,
        parse_mode: 'HTML',
        reply_markup: WEBAPP_URL ? { inline_keyboard: [[{ text: 'Открыть StatTrack', web_app: { url: WEBAPP_URL } }]] } : undefined
      });
    }
  } catch (e) {
    console.error('Ошибка рассылки таймеров:', e.message);
  } finally {
    timerPollBusy = false;
  }
}
setInterval(checkScheduledTimers, 10000);


// 4. Авто-сводка в понедельник утром в 07:50 (по SUMMARY_TZ_OFFSET, по умолчанию UTC+3)
const SUMMARY_TZ_OFFSET = Number.isFinite(Number(process.env.SUMMARY_TZ_OFFSET)) ? Number(process.env.SUMMARY_TZ_OFFSET) : 3;
let mondaySummaryBusy = false;

async function checkMondaySummary() {
  if (mondaySummaryBusy || !BOT_TOKEN || mongoose.connection.readyState !== 1) return;
  const localNow = new Date(Date.now() + SUMMARY_TZ_OFFSET * 3600 * 1000);
  const dow = localNow.getUTCDay(); // 1 = Понедельник
  const minsOfDay = localNow.getUTCHours() * 60 + localNow.getUTCMinutes();
  // Запускаем в понедельник начиная с 07:50 (окно до 14:00 на случай сна сервера)
  if (dow !== 1 || minsOfDay < 7 * 60 + 50 || minsOfDay > 14 * 60) return;

  mondaySummaryBusy = true;
  try {
    const prevWeekInfo = getWeekDayKeys(-1);
    const existing = await WeeklyResult.findOne({ weekKey: prevWeekInfo.weekKey }).lean();
    if (existing && existing.summarySent) return;

    const [users, visitors] = await Promise.all([
      User.find({}).lean(),
      Visitor.find({}).lean()
    ]);
    const usernameByTgId = new Map();
    for (const v of visitors) {
      if (v.user_id && v.username) usernameByTgId.set(Number(v.user_id), v.username);
    }

    const prevWeek = await ensurePrevWeekResult(users, usernameByTgId, prevWeekInfo);
    if (!prevWeek) return;

    // Атомарная блокировка, чтобы сводка ушла ровно 1 раз
    const locked = await WeeklyResult.findOneAndUpdate(
      { weekKey: prevWeekInfo.weekKey, summarySent: { $ne: true } },
      { $set: { summarySent: true } },
      { new: true }
    ).lean();
    if (!locked) return;

    const studyAll = users.map(u => {
      const daily = u.data?.daily || {};
      let min = 0, wk = 0;
      for (const k of prevWeekInfo.keys) {
        if (daily[k]) {
          min += Number(daily[k].min) || 0;
          wk += Number(daily[k].wk) || 0;
        }
      }
      return { id: Number(u.telegramId), min, wk };
    });

    const studyRankList = studyAll.filter(x => x.min > 0).sort((a, b) => b.min - a.min);
    const workRankList = studyAll.filter(x => x.wk > 0).sort((a, b) => b.wk - a.wk);
    const champStudy = prevWeek.studyTop?.[0] || null;
    const champWork = prevWeek.workTop?.[0] || null;

    let sentCount = 0;
    for (const u of users) {
      const tgId = Number(u.telegramId);
      if (!Number.isFinite(tgId) || !u.data) continue;

      const myStat = studyAll.find(x => x.id === tgId) || { min: 0, wk: 0 };
      const sPos = studyRankList.findIndex(x => x.id === tgId) + 1;
      const wPos = workRankList.findIndex(x => x.id === tgId) + 1;
      const isChamp = (champStudy && Number(champStudy.user_id) === tgId) || (champWork && Number(champWork.user_id) === tgId);

      const lines = [
        `<b>Итоги прошлой недели (${prevWeekInfo.range})</b>`,
        ``,
        `Учёба: <b>${formatHm(myStat.min)}</b>${sPos ? ` (#${sPos} в топе)` : ''}`,
        `Тренировки: <b>${myStat.wk}</b>${wPos ? ` (#${wPos} в топе)` : ''}`,
        ``,
        `<b>Чемпионы недели:</b>`,
        `• Учёба: ${champStudy ? `<b>${escapeHtml(champStudy.nick)}</b> — ${formatHm(champStudy.studyMin)}` : 'нет лидера'}`,
        `• Спорт: ${champWork ? `<b>${escapeHtml(champWork.nick)}</b> — ${champWork.workouts} тр.` : 'нет лидера'}`
      ];

      if (isChamp) {
        lines.push(``);
        lines.push(`👑 Поздравляем! Ты чемпион прошлой недели — временная корона уже закреплена рядом с твоим ником на всю неделю.`);
      }

      await tgApi('sendMessage', {
        chat_id: tgId,
        text: lines.join('\n'),
        parse_mode: 'HTML',
        reply_markup: WEBAPP_URL ? { inline_keyboard: [[{ text: 'Открыть StatTrack', web_app: { url: WEBAPP_URL } }]] } : undefined
      });
      sentCount++;
      await new Promise(r => setTimeout(r, 60));
    }
    console.log(`📨 Понедельничная сводка за ${prevWeekInfo.range} отправлена (${sentCount} польз.)`);
  } catch (e) {
    console.error('Ошибка понедельничной сводки:', e.message);
  } finally {
    mondaySummaryBusy = false;
  }
}
setInterval(checkMondaySummary, 60000);
setTimeout(checkMondaySummary, 8000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  setupTelegramBot();
});
