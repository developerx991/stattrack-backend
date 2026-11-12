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

// Функция обхода ошибки querySrv ENODATA через защищенный HTTPS-запрос к Google DNS
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
      console.error(`👉 Проверь сайт MongoDB Atlas (вкладка Database/Clusters): возможно, кластер ещё создаётся, поставлен на паузу (Paused) или его адрес изменился.`);
      return uri;
    }

    // Собираем прямые адреса нод (шардов)
    const hosts = srvJson.Answer
      .filter(a => a.type === 33)
      .map(a => {
        const parts = a.data.trim().split(/\s+/);
        const port = parts[2];
        const target = parts[3].replace(/\.$/, '');
        return `${target}:${port}`;
      });

    // Получаем дополнительные параметры (replicaSet и authSource) из TXT-записи
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

// Подключение к базе данных
(async () => {
  const finalUri = await resolveMongoUri(process.env.MONGODB_URI);
  mongoose.connect(finalUri)
    .then(() => console.log('✅ Успешное подключение к MongoDB Atlas!'))
    .catch(err => console.error('❌ Ошибка подключения к БД:', err.message));
})();

const userSchema = new mongoose.Schema({
  telegramId: { type: Number, required: true, unique: true },
  data: { type: Object, default: {} }
});
const User = mongoose.model('User', userSchema);

function verifyTelegramWebAppData(telegramInitData) {
  if (!telegramInitData) return false;
  const urlParams = new URLSearchParams(telegramInitData);
  const hash = urlParams.get('hash');
  urlParams.delete('hash');
  urlParams.sort();
  
  let dataCheckString = '';
  for (const [key, value] of urlParams.entries()) {
    dataCheckString += `${key}=${value}\n`;
  }
  dataCheckString = dataCheckString.slice(0, -1);
  
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(process.env.BOT_TOKEN).digest();
  const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  return calculatedHash === hash;
}

app.post('/api/load', async (req, res) => {
  const { initData, user_id } = req.body;
  if (!verifyTelegramWebAppData(initData)) return res.status(403).json({ error: 'Доступ запрещен' });
  
  try {
    let user = await User.findOne({ telegramId: user_id });
    if (!user) {
      user = new User({ telegramId: user_id, data: null });
      await user.save();
    }
    res.json(user.data);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка БД' });
  }
});

app.post('/api/save', async (req, res) => {
  const { initData, user_id, state } = req.body;
  if (!verifyTelegramWebAppData(initData)) return res.status(403).json({ error: 'Доступ запрещен' });
  
  try {
    await User.findOneAndUpdate({ telegramId: user_id }, { data: state }, { upsert: true });
    res.status(200).send('Сохранено');
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сохранения' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));