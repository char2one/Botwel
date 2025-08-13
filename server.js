import express from 'express';
import crypto from 'crypto';
import axios from 'axios';

const app = express();
const PORT = process.env.PORT || 3000;

const PACHCA_TOKEN = process.env.PACHCA_TOKEN; // Bearer access_token бота
const PACHCA_SIGNING_SECRET = process.env.PACHCA_SIGNING_SECRET; // Signing secret исходящего вебхука

if (!PACHCA_TOKEN || !PACHCA_SIGNING_SECRET) {
  console.error('ENV error: set PACHCA_TOKEN and PACHCA_SIGNING_SECRET');
  process.exit(1);
}

// Отдельный raw‑парсер только для /webhook (для корректной подписи)
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const raw = req.body; // Buffer
    const signature = req.headers['pachca-signature'];
    if (!signature) return res.status(400).send('No signature');

    // Валидируем HMAC SHA256 по сырому телу
    const expected = crypto.createHmac('sha256', PACHCA_SIGNING_SECRET).update(raw).digest('hex');
    if (expected !== signature) return res.status(401).send('Invalid signature');

    const payload = JSON.parse(raw.toString('utf8'));

    // Защита от replay: вебхук считается свежим в пределах 60 сек
    const now = Math.floor(Date.now() / 1000);
    if (payload.webhook_timestamp && Math.abs(now - payload.webhook_timestamp) > 60) {
      return res.status(408).send('Webhook too old');
    }

    // Хелперы
    const api = axios.create({
      baseURL: 'https://api.pachca.com/api/shared/v1',
      headers: { Authorization: `Bearer ${PACHCA_TOKEN}` }
    });

    const sendMessage = async ({ entityType, entityId, content }) => {
      await api.post('/messages', {
        message: {
          entity_type: entityType, // 'discussion' | 'thread' | 'user'
          entity_id: entityId,
          content
        }
      });
    };

    const getUserAlias = async (id) => {
      try {
        const { data } = await api.get(`/users/${id}`);
        const u = data?.data || {};
        const nick = (u.nickname || '').trim();
        if (nick) return `@${nick}`; // упоминание по нику
        const name = [u.first_name, u.last_name].filter(Boolean).join(' ').trim();
        return name || 'коллега';
      } catch {
        return 'коллега';
      }
    };

    // Ваш текст приветствия (можно править как угодно)
    const WELCOME_TEXT = (
      alias => `${alias ? alias + ', ' : ''}Добро пожаловать в команду Академии Международного Бизнеса! 🎉\n\n` +
               `Мы очень рады, что ты с нами! \n` +
               `Желаем быстрой адаптации, интересных задач и крутых результатов в нашей дружной команде. Не стесняйся задавать вопросы – здесь всегда помогут и поддержат.\n\n` +
               `Важно для всех:\n` +
               `📌 В ветке отдела есть форма ежедневного отчёта, которую необходимо заполнять каждый день до 21:00. \n` +
               `Это помогает нам быть на одной волне и эффективно работать.\n\n` +
               `Давай настраиваться на продуктивную работу и отличное взаимодействие! 🚀\n\n` +
               `В общем чате АМБ тебя скоро поприветствуют и там ты увидишь всех нас. \n\n` +
               `В ветке "отчет отдела"- вся команда твоего отдела, знакомься!\n\n` +
               `P.S. Если что-то непонятно – обращайся, с радостью поможем! 😊`
    );

    // 1) Приветствуем при добавлении в чат/ветку
    if (payload.type === 'chat_member' && payload.event === 'add') {
      const chatId = payload.chat_id;
      const threadId = payload.thread_id || null;
      const entityType = threadId ? 'thread' : 'discussion';
      const entityId = threadId || chatId;

      // Берём первого добавленного пользователя (обычно это и есть новичок)
      const targetUserId = Array.isArray(payload.user_ids) && payload.user_ids.length ? payload.user_ids[0] : null;
      const alias = targetUserId ? await getUserAlias(targetUserId) : '';

      await sendMessage({ entityType, entityId, content: WELCOME_TEXT(alias) });
      return res.sendStatus(200);
    }

    // 2) (Опционально) личное приветствие, когда сотрудник подтвердил приглашение в пространство
    if (payload.type === 'company_member' && payload.event === 'confirm') {
      const targetUserId = Array.isArray(payload.user_ids) && payload.user_ids[0];
      if (targetUserId) {
        const alias = await getUserAlias(targetUserId);
        await sendMessage({ entityType: 'user', entityId: targetUserId, content: WELCOME_TEXT(alias) });
      }
      return res.sendStatus(200);
    }

    // Игнорим всё остальное
    return res.sendStatus(200);
  } catch (e) {
    console.error('Webhook error', e?.response?.data || e.message);
    return res.status(500).send('Internal error');
  }
});

// Healthcheck
app.get('/', (req, res) => res.send('OK'));

app.listen(PORT, () => console.log(`Welcome bot listening on :${PORT}`));