const express      = require("express");
const cors         = require("cors");
const twilio       = require("twilio");
const mysql        = require("mysql2/promise");
const jwt          = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto       = require("crypto");
 
// ---------------------------------------------------------------------------
// Configuration — fail fast instead of falling back to insecure defaults.
// GIFT_API_KEY protects /create-gift and /send-gift (generate a long random
// string and send it as the X-API-Key header from your app/backend).
// ---------------------------------------------------------------------------
const REQUIRED_ENV = ["ACCOUNT_SID", "AUTH_TOKEN", "JWT_SECRET", "DASHBOARD_PASSWORD", "DATABASE_URL", "GIFT_API_KEY"];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
  console.error("Missing required environment variables: " + missingEnv.join(", "));
  process.exit(1);
}
 
const accountSid    = process.env.ACCOUNT_SID;
const authToken     = process.env.AUTH_TOKEN;
const client        = twilio(accountSid, authToken);
const fromNumber    = "whatsapp:+966534864736";
const JWT_SECRET    = process.env.JWT_SECRET;
const DASH_PASS     = process.env.DASHBOARD_PASSWORD;
const GIFT_API_KEY  = process.env.GIFT_API_KEY;
const GIFT_BASE_URL = process.env.GIFT_BASE_URL || "https://gift.glamlysa.com";
const IS_PROD       = process.env.NODE_ENV === "production";
 
const app = express();
// Required behind a reverse proxy (Railway/Heroku/etc.) so Twilio signature
// validation and req.ip see the real request URL and client IP.
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
 
// CORS: the dashboard is served from this same server, so cross-origin access
// stays disabled unless you explicitly list origins in CORS_ORIGINS
// (comma-separated). Non-browser clients (your mobile app) are unaffected.
const corsOrigins = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: corsOrigins.length ? corsOrigins : false }));
 
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
 
// Constant-time string comparison (hash first so lengths always match).
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
 
// Accepts digits with optional +, spaces, dashes; returns bare digits or null.
function cleanPhone(raw) {
  const p = String(raw || "").replace(/[\s\-+]/g, "");
  return /^\d{8,15}$/.test(p) ? p : null;
}
 
// Cryptographically random 8-char code (Math.random is guessable and could
// produce short codes).
function makeGiftCode() {
  return crypto.randomBytes(4).toString("hex").toUpperCase();
}
 
let db;
async function connectDB() {
  try {
    db = await mysql.createPool({
      uri: process.env.DATABASE_URL,
      waitForConnections: true,
      connectionLimit: 10
    });
    await db.execute(`
      CREATE TABLE IF NOT EXISTS conversations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        phone VARCHAR(50) UNIQUE NOT NULL,
        status VARCHAR(20) DEFAULT 'bot',
        lang VARCHAR(5) DEFAULT 'ar',
        assigned_to VARCHAR(100),
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await db.execute(`
      CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        phone VARCHAR(50) NOT NULL,
        sender VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        media_url VARCHAR(512),
        media_type VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_messages_phone (phone)
      )
    `);
    await db.execute(`
      CREATE TABLE IF NOT EXISTS gifts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        gift_code VARCHAR(20) UNIQUE NOT NULL,
        sender_name VARCHAR(100) NOT NULL,
        recipient_phone VARCHAR(20) NOT NULL,
        service_name VARCHAR(200) NOT NULL,
        salon_name VARCHAR(200) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    // Lightweight migrations for databases created before these columns existed.
    const ensureColumn = async (table, ddl) => {
      try { await db.execute("ALTER TABLE " + table + " ADD COLUMN " + ddl); }
      catch (e) { if (e.code !== "ER_DUP_FIELDNAME") throw e; }
    };
    await ensureColumn("conversations", "lang VARCHAR(5) DEFAULT 'ar'");
    await ensureColumn("messages", "media_url VARCHAR(512)");
    await ensureColumn("messages", "media_type VARCHAR(100)");
    console.log("Database connected!");
  } catch (err) {
    console.error("Database connection failed:", err.message);
    process.exit(1);
  }
}
connectDB();
 
// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}
 
// API-key auth for server-to-server endpoints (gift sending). Your app's
// backend must send: X-API-Key: <GIFT_API_KEY>
function requireApiKey(req, res, next) {
  const key = req.headers["x-api-key"];
  if (!key || !safeEqual(key, GIFT_API_KEY)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}
 
// Simple in-memory rate limit for /login: 10 attempts per IP per 15 minutes.
const loginAttempts = new Map();
function loginLimiter(req, res, next) {
  const now = Date.now();
  const rec = loginAttempts.get(req.ip);
  if (rec && now < rec.resetAt && rec.count >= 10) {
    return res.status(429).json({ error: "Too many attempts, try again later" });
  }
  if (!rec || now >= rec.resetAt) {
    loginAttempts.set(req.ip, { count: 0, resetAt: now + 15 * 60 * 1000 });
  }
  next();
}
 
// ---------------------------------------------------------------------------
// Bot
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Bot FAQ — bilingual. The bot detects the customer's language per message
// and replies in that language only ('ar' is the default).
// Edit the answer texts below to match your real policies
// (especially payment methods and refund timelines).
// getBotReply always returns { reply, handoff }:
//   reply   -> text sent back to the customer
//   handoff -> true = also flag the conversation as 'pending' for an agent
// ---------------------------------------------------------------------------
const FAQ = {
  menu: {
    en: "1️⃣ Booking status 📅\n2️⃣ Cancel or reschedule 🔄\n3️⃣ Prices & services 💅\n4️⃣ Payment methods 💳\n5️⃣ Refunds 💸\n6️⃣ Gift cards 🎁\n7️⃣ Talk to an agent 💬",
    ar: "1️⃣ حالة الحجز 📅\n2️⃣ إلغاء أو تعديل الحجز 🔄\n3️⃣ الأسعار والخدمات 💅\n4️⃣ طرق الدفع 💳\n5️⃣ استرداد المبلغ 💸\n6️⃣ بطاقات الهدايا 🎁\n7️⃣ التحدث مع موظف 💬"
  },
  welcome: {
    en: "✨ Welcome to Glamly! ✨\nHow can we help you today?\n\n",
    ar: "✨ أهلاً بك في Glamly! ✨\nكيف نقدر نساعدك اليوم؟\n\n"
  },
  agent: {
    en: "💬 Connecting you to an agent now — one moment please! 🙏",
    ar: "💬 جاري تحويلك لموظف — لحظة من فضلك! 🙏"
  },
  status: {
    en: "📅 Please share your booking ID and an agent will check it for you right away! ⚡",
    ar: "📅 أرسل رقم حجزك وسيتحقق منه أحد الموظفين فوراً! ⚡"
  },
  cancel: {
    en: "🔄 To cancel or reschedule, please share your booking ID and an agent will assist you.\n\n💡 Cancellations made 24hrs before the appointment are fully refunded.",
    ar: "🔄 لإلغاء أو تعديل حجزك أرسل رقم الحجز وسيساعدك أحد الموظفين.\n\n💡 الإلغاء قبل 24 ساعة من الموعد يحصل على استرداد كامل."
  },
  prices: {
    en: "💅 Browse all services and prices in the Glamly app!\n\n🔗 glamlysa.com ✨",
    ar: "💅 تصفح جميع الخدمات والأسعار في تطبيق Glamly!\n\n🔗 glamlysa.com ✨"
  },
  payment: { // EDIT: confirm these match what you actually accept
    en: "💳 You can pay securely in the Glamly app using:\n\n• mada\n• Visa / Mastercard\n• Apple Pay 🍎",
    ar: "💳 يمكنك الدفع بأمان في تطبيق Glamly عبر:\n\n• مدى\n• فيزا / ماستركارد\n• Apple Pay 🍎"
  },
  refund: {
    en: "💸 Cancellations made 24hrs or more before the appointment are fully refunded.\n\n⏱️ Refunds are processed within 3-5 business days to your original payment method.",
    ar: "💸 الإلغاء قبل 24 ساعة أو أكثر من الموعد يحصل على استرداد كامل.\n\n⏱️ تتم معالجة الاسترداد خلال 3-5 أيام عمل إلى نفس وسيلة الدفع."
  },
  gift: {
    en: "🎁 You can gift any service from the Glamly app!\n\n💝 Your friend instantly receives their gift on WhatsApp with a link to book their appointment. ✨",
    ar: "🎁 يمكنك إهداء أي خدمة من تطبيق Glamly!\n\n💝 تصل الهدية فوراً عبر واتساب مع رابط لحجز الموعد. ✨"
  },
  thanks: {
    en: "You're most welcome! 💜\n\nGlamly ✨",
    ar: "على الرحب والسعة! 💜\n\nGlamly ✨"
  },
  fallback: {
    en: "🤔 Sorry, I didn't quite get that — an agent will follow up with you shortly. 💬\n\nMeanwhile, you can pick an option:\n\n",
    ar: "🤔 عذراً، لم أفهم رسالتك — سيتواصل معك أحد الموظفين قريباً. 💬\n\nيمكنك أيضاً اختيار أحد الخيارات:\n\n"
  }
};
 
// 'ar' if the message contains Arabic script, 'en' if it contains Latin
// letters, null if neither (e.g. "1") — caller falls back to the stored lang.
function detectLang(text) {
  if (/[؀-ۿ]/.test(text)) return "ar";
  if (/[a-z]/i.test(text)) return "en";
  return null;
}
 
function getBotReply(message, lang) {
  const t = key => FAQ[key][lang] || FAQ[key].ar;
  const msg = message.toLowerCase().trim();
  const has = (...words) => words.some(w => msg.includes(w));
 
  // 7 - Agent (checked first so "agent" requests always win)
  if (msg === "7" || has("agent", "human", "support", "staff", "موظف", "مساعدة", "خدمة العملاء"))
    return { reply: t("agent"), handoff: true };
  // 1 - Booking status
  if (msg === "1" || has("booking", "status", "appointment", "حجز", "حالة", "موعدي"))
    return { reply: t("status"), handoff: true };
  // 2 - Cancel / reschedule
  if (msg === "2" || has("cancel", "reschedule", "إلغاء", "الغ", "تعديل", "تأجيل"))
    return { reply: t("cancel"), handoff: true };
  // 3 - Prices ("كم" only as a whole word — substring of words like "عليكم")
  if (msg === "3" || has("price", "cost", "how much", "services", "سعر", "أسعار", "تكلفة") || msg.split(/\s+/).some(w => w === "كم" || w === "بكم"))
    return { reply: t("prices"), handoff: false };
  // 4 - Payment methods
  if (msg === "4" || has("pay", "payment", "mada", "apple pay", "دفع", "مدى", "فيزا", "بطاقة ائتمان"))
    return { reply: t("payment"), handoff: false };
  // 5 - Refunds
  if (msg === "5" || has("refund", "money back", "استرداد", "استرجاع"))
    return { reply: t("refund"), handoff: false };
  // 6 - Gift cards
  if (msg === "6" || has("gift", "هدية", "هدايا", "اهداء", "إهداء"))
    return { reply: t("gift"), handoff: false };
  // Greetings -> menu
  if (has("hello", "hi", "hey", "مرحبا", "هلا", "اهلا", "أهلا", "السلام"))
    return { reply: t("welcome") + t("menu"), handoff: false };
  // Thanks
  if (has("thank", "شكر"))
    return { reply: t("thanks"), handoff: false };
  // Fallback: didn't understand -> menu in their language AND flag an agent
  return { reply: t("fallback") + t("menu"), handoff: true };
}
 
// ---------------------------------------------------------------------------
// Twilio webhook — signature validated so only Twilio can call it.
// (To test locally with curl, temporarily set validate: false.)
// ---------------------------------------------------------------------------
// Set env var TWILIO_VALIDATE=false to temporarily skip signature validation
// while debugging (turn it back on afterwards!).
const validateTwilio = process.env.TWILIO_VALIDATE !== "false";
app.post("/webhook", (req, res, next) => {
  console.log("Webhook hit | From:", req.body.From || "(none)", "| signature:", req.headers["x-twilio-signature"] ? "present" : "MISSING", "| url seen as:", req.protocol + "://" + req.get("host") + req.originalUrl);
  next();
}, twilio.webhook({ validate: validateTwilio }, authToken), async (req, res) => {
  const from = req.body.From || "";
  const message = (req.body.Body || "").trim();
  // Media messages (images, voice notes): store the first attachment's URL
  // so the dashboard can display it via the /media proxy.
  const numMedia  = Number(req.body.NumMedia) || 0;
  const mediaUrl  = numMedia > 0 ? (req.body.MediaUrl0 || null) : null;
  const mediaType = numMedia > 0 ? (req.body.MediaContentType0 || null) : null;
 
  try {
    if (from && (message || mediaUrl)) {
      await db.execute(
        "INSERT INTO conversations (phone, status, last_seen) VALUES (?, 'bot', NOW()) ON DUPLICATE KEY UPDATE last_seen = NOW()",
        [from]
      );
      await db.execute(
        "INSERT INTO messages (phone, sender, message, media_url, media_type) VALUES (?, 'customer', ?, ?, ?)",
        [from, message, mediaUrl, mediaType]
      );
      const [existing] = await db.execute(
        "SELECT status, lang FROM conversations WHERE phone = ?",
        [from]
      );
      const currentStatus = existing.length ? existing[0].status : "bot";
 
      // Detect and remember the customer's language ('ar' default).
      const detected = detectLang(message);
      const lang = detected || (existing.length && existing[0].lang) || "ar";
      if (detected && existing.length && existing[0].lang !== detected) {
        await db.execute("UPDATE conversations SET lang = ? WHERE phone = ?", [detected, from]);
      }
 
      // If an agent is already handling this chat (or it's waiting for one),
      // the bot stays quiet — the message is just stored and re-flagged.
      if (currentStatus === "agent" || currentStatus === "pending") {
        await db.execute(
          "UPDATE conversations SET status = 'pending' WHERE phone = ?",
          [from]
        );
        if (currentStatus === "agent") notifyAgents(from, message || "[media]");
      } else {
        const bot = getBotReply(message, lang);
        await db.execute(
          "INSERT INTO messages (phone, sender, message) VALUES (?, 'bot', ?)",
          [from, bot.reply]
        );
        await db.execute(
          "UPDATE conversations SET status = ? WHERE phone = ?",
          [bot.handoff ? "pending" : "bot", from]
        );
        if (bot.handoff) notifyAgents(from, message || "[media]");
        // Awaited so send failures are logged instead of becoming
        // unhandled promise rejections.
        try {
          await client.messages.create({ from: fromNumber, to: from, body: bot.reply });
        } catch (sendErr) {
          console.error("Bot reply send failed:", sendErr.message);
        }
      }
      broadcast();
    }
  } catch (err) {
    console.error("Webhook error:", err.message);
  }
  // Twilio expects TwiML; an empty <Response> means "no additional reply".
  res.type("text/xml").send("<Response></Response>");
});
 
// ---------------------------------------------------------------------------
// Dashboard auth
// ---------------------------------------------------------------------------
app.post("/login", loginLimiter, (req, res) => {
  const { password } = req.body;
  if (!password || !safeEqual(password, DASH_PASS)) {
    const rec = loginAttempts.get(req.ip);
    if (rec) rec.count++;
    return res.status(401).json({ error: "Wrong password" });
  }
  loginAttempts.delete(req.ip);
  const token = jwt.sign({ role: "agent" }, JWT_SECRET, { expiresIn: "24h" });
  res.cookie("token", token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: "lax",
    maxAge: 86400000
  });
  res.json({ success: true, token });
});
 
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});
 
// ---------------------------------------------------------------------------
// Real-time updates (SSE): the dashboard listens on /events and reloads
// whenever broadcast() is called after a message or status change.
// ---------------------------------------------------------------------------
const sseClients = new Set();
function broadcast() {
  for (const clientRes of sseClients) {
    try { clientRes.write("data: update\n\n"); } catch { sseClients.delete(clientRes); }
  }
}
app.get("/events", requireAuth, (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no"
  });
  res.flushHeaders();
  res.write("data: connected\n\n");
  sseClients.add(res);
  const ping = setInterval(() => {
    try { res.write(": ping\n\n"); } catch { /* cleaned up on close */ }
  }, 25000);
  req.on("close", () => { clearInterval(ping); sseClients.delete(res); });
});
 
// Optional WhatsApp alert to agents when a chat needs a human.
// Set AGENT_ALERT_NUMBERS to comma-separated numbers, e.g. "9665xxxxxxxx,9665yyyyyyyy".
// Note: WhatsApp only delivers these if the agent messaged the business number
// within the last 24h — the dashboard sound/notification always works.
async function notifyAgents(from, preview) {
  const numbers = (process.env.AGENT_ALERT_NUMBERS || "").split(",").map(s => s.trim()).filter(Boolean);
  for (const n of numbers) {
    try {
      await client.messages.create({
        from: fromNumber,
        to: "whatsapp:+" + n.replace(/^\+/, ""),
        body: "Glamly: new chat waiting for an agent\n" + from.replace("whatsapp:", "") + ": " + String(preview).substring(0, 100)
      });
    } catch (e) {
      console.error("Agent alert failed:", e.message);
    }
  }
}
 
// ---------------------------------------------------------------------------
// Conversations — two fixed queries instead of one query per conversation.
// ---------------------------------------------------------------------------
app.get("/conversations", requireAuth, async (req, res) => {
  try {
    const [convs] = await db.execute("SELECT * FROM conversations ORDER BY last_seen DESC");
    const [msgs]  = await db.execute("SELECT id, phone, sender, message, media_url, media_type, created_at FROM messages ORDER BY created_at ASC, id ASC");
    const byPhone = {};
    for (const m of msgs) {
      (byPhone[m.phone] = byPhone[m.phone] || []).push({
        id:        m.id,
        from:      m.sender,
        message:   m.message,
        time:      m.created_at,
        hasMedia:  !!m.media_url,
        mediaType: m.media_type
      });
    }
    const result = {};
    for (const conv of convs) {
      result[conv.phone] = {
        status:     conv.status,
        lang:       conv.lang || "ar",
        assignedTo: conv.assigned_to,
        lastSeen:   conv.last_seen,
        messages:   byPhone[conv.phone] || []
      };
    }
    res.json(result);
  } catch (err) {
    console.error("Conversations error:", err.message);
    res.status(500).json({ error: "Failed to load conversations" });
  }
});
 
app.post("/reply", requireAuth, async (req, res) => {
  const { to, message } = req.body;
  const phone = cleanPhone(to);
  if (!phone || !message || !String(message).trim()) {
    return res.status(400).json({ error: "Invalid phone number or empty message" });
  }
  const fullNumber = "whatsapp:+" + phone;
  try {
    await client.messages.create({ from: fromNumber, to: fullNumber, body: String(message).trim() });
    await db.execute(
      "INSERT INTO messages (phone, sender, message) VALUES (?, 'agent', ?)",
      [fullNumber, String(message).trim()]
    );
    // Replying keeps the conversation active ('agent'); agents mark it
    // resolved explicitly via the dashboard button.
    await db.execute(
      "UPDATE conversations SET status = 'agent', last_seen = NOW() WHERE phone = ?",
      [fullNumber]
    );
    broadcast();
    res.json({ success: true });
  } catch (err) {
    console.error("Reply error:", err.message);
    // 63016: outside WhatsApp's 24-hour session window — freeform messages
    // are rejected; a pre-approved template must be used instead.
    if (err.code === 63016) {
      return res.status(400).json({ error: "Cannot send: more than 24h since the customer's last message. Use an approved template instead." });
    }
    res.status(500).json({ error: "Failed to send message" });
  }
});
 
// Send a pre-approved template when the 24h WhatsApp window has closed.
// Create a re-engagement template in Twilio (Content Editor), get it approved
// for WhatsApp, then set SUPPORT_TEMPLATE_SID_EN / SUPPORT_TEMPLATE_SID_AR.
app.post("/send-template", requireAuth, async (req, res) => {
  const { to, language } = req.body;
  const phone = cleanPhone(to);
  if (!phone) return res.status(400).json({ error: "Invalid phone number" });
  const sid = language === "ar" ? process.env.SUPPORT_TEMPLATE_SID_AR : process.env.SUPPORT_TEMPLATE_SID_EN;
  if (!sid) return res.status(400).json({ error: "No support template configured. Create an approved template in Twilio and set SUPPORT_TEMPLATE_SID_EN / SUPPORT_TEMPLATE_SID_AR." });
  const fullNumber = "whatsapp:+" + phone;
  try {
    await client.messages.create({ from: fromNumber, to: fullNumber, contentSid: sid });
    await db.execute(
      "INSERT INTO messages (phone, sender, message) VALUES (?, 'agent', ?)",
      [fullNumber, "[template message sent]"]
    );
    await db.execute(
      "UPDATE conversations SET status = 'agent', last_seen = NOW() WHERE phone = ?",
      [fullNumber]
    );
    broadcast();
    res.json({ success: true });
  } catch (err) {
    console.error("Send-template error:", err.message);
    res.status(500).json({ error: "Failed to send template" });
  }
});
 
// Proxy Twilio media — Twilio media URLs require account auth, so the
// dashboard can't load them directly.
app.get("/media/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).send("Bad id");
  try {
    const [rows] = await db.execute("SELECT media_url, media_type FROM messages WHERE id = ?", [id]);
    if (!rows.length || !rows[0].media_url) return res.status(404).send("Not found");
    if (!/^https:\/\/api\.twilio\.com\//.test(rows[0].media_url)) return res.status(400).send("Invalid media source");
    const upstream = await fetch(rows[0].media_url, {
      headers: { Authorization: "Basic " + Buffer.from(accountSid + ":" + authToken).toString("base64") }
    });
    if (!upstream.ok) return res.status(502).send("Failed to fetch media");
    res.set("Content-Type", upstream.headers.get("content-type") || rows[0].media_type || "application/octet-stream");
    res.set("Cache-Control", "private, max-age=86400");
    res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (err) {
    console.error("Media proxy error:", err.message);
    res.status(500).send("Error loading media");
  }
});
 
const VALID_STATUSES = ["bot", "pending", "agent", "resolved"];
app.post("/status", requireAuth, async (req, res) => {
  const { number, status } = req.body;
  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }
  try {
    await db.execute("UPDATE conversations SET status = ? WHERE phone = ?", [status, number]);
    broadcast();
    res.json({ success: true });
  } catch (err) {
    console.error("Status error:", err.message);
    res.status(500).json({ error: "Failed to update status" });
  }
});
 
app.get("/booking/:id", requireAuth, async (req, res) => {
  res.json({
    id:       req.params.id,
    customer: "Connect to your Glamly database",
    service:  "to show real booking data",
    date:     "here",
    status:   "pending"
  });
});
 
// ---------------------------------------------------------------------------
// Gifts — both endpoints now require the API key so strangers can't send
// WhatsApp messages on your Twilio account.
// ---------------------------------------------------------------------------
function validateGiftInput(body) {
  const senderName  = String(body.senderName || "").trim();
  const serviceName = String(body.serviceName || "").trim();
  const salonName   = String(body.salonName || "").trim();
  const phone       = cleanPhone(body.recipientPhone);
  if (!phone) return { error: "Invalid recipient phone number" };
  if (!senderName || senderName.length > 100)   return { error: "Invalid sender name" };
  if (!serviceName || serviceName.length > 200) return { error: "Invalid service name" };
  if (!salonName || salonName.length > 200)     return { error: "Invalid salon name" };
  return { senderName, serviceName, salonName, phone };
}
 
app.post("/send-gift", requireApiKey, async (req, res) => {
  const input = validateGiftInput(req.body);
  if (input.error) return res.status(400).json({ error: input.error });
  const templateSid = req.body.language === "ar" ? process.env.TEMPLATE_SID_AR : process.env.TEMPLATE_SID_EN;
  if (!templateSid) return res.status(500).json({ error: "Template SID not configured" });
  try {
    await client.messages.create({
      from:             fromNumber,
      to:               "whatsapp:+" + input.phone,
      contentSid:       templateSid,
      contentVariables: JSON.stringify({ "1": input.senderName, "2": input.serviceName, "3": input.salonName })
    });
    res.json({ success: true });
  } catch (err) {
    console.error("Send-gift error:", err.message);
    res.status(500).json({ error: "Failed to send gift message" });
  }
});
 
app.post("/create-gift", requireApiKey, async (req, res) => {
  const input = validateGiftInput(req.body);
  if (input.error) return res.status(400).json({ error: input.error });
  const templateSid = req.body.language === "ar" ? process.env.TEMPLATE_SID_AR : process.env.TEMPLATE_SID_EN;
  if (!templateSid) return res.status(500).json({ error: "Template SID not configured" });
  try {
    // Retry on the (rare) duplicate-code collision.
    let giftCode = null;
    for (let attempt = 0; attempt < 5 && !giftCode; attempt++) {
      const candidate = makeGiftCode();
      try {
        await db.execute(
          "INSERT INTO gifts (gift_code, sender_name, recipient_phone, service_name, salon_name) VALUES (?, ?, ?, ?, ?)",
          [candidate, input.senderName, input.phone, input.serviceName, input.salonName]
        );
        giftCode = candidate;
      } catch (insertErr) {
        if (insertErr.code !== "ER_DUP_ENTRY") throw insertErr;
      }
    }
    if (!giftCode) throw new Error("Could not generate a unique gift code");
 
    // The link now actually points at this gift's page.
    const giftLink = GIFT_BASE_URL + "/gift/" + giftCode;
 
    await client.messages.create({
      from:             fromNumber,
      to:               "whatsapp:+" + input.phone,
      contentSid:       templateSid,
      contentVariables: JSON.stringify({
        "1": input.senderName,
        "2": input.serviceName,
        "3": input.salonName
      })
    });
    res.json({ success: true, giftCode: giftCode, giftLink: giftLink });
  } catch (err) {
    console.error("Create-gift error:", err.message);
    res.status(500).json({ error: "Failed to create gift" });
  }
});
 
// Generic landing page (no code) — deep-links into the app or shows store links.
app.get("/gift", (req, res) => {
  const appleUrl  = process.env.APPLE_STORE_URL || "https://apps.apple.com";
  const googleUrl = process.env.GOOGLE_PLAY_URL || "https://play.google.com";
  const lines = [];
  lines.push("<!DOCTYPE html>");
  lines.push("<html lang=\"ar\" dir=\"rtl\">");
  lines.push("<head>");
  lines.push("<meta charset=\"UTF-8\">");
  lines.push("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
  lines.push("<title>Glamly - your gift</title>");
  lines.push("<link href=\"https://fonts.googleapis.com/css2?family=Noto+Naskh+Arabic:wght@400;700&display=swap\" rel=\"stylesheet\">");
  lines.push("<style>");
  lines.push("*{margin:0;padding:0;box-sizing:border-box}");
  lines.push("body{font-family:'Noto Naskh Arabic',sans-serif;background:#0F0A28;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}");
  lines.push(".card{background:#1E1040;border-radius:24px;padding:36px 28px;max-width:380px;width:100%;text-align:center}");
  lines.push(".brand{color:#E8DEFF;font-size:24px;font-weight:700;letter-spacing:4px;font-family:sans-serif}");
  lines.push(".tagline{color:#C8A84B;font-size:11px;font-family:sans-serif;margin-bottom:24px}");
  lines.push(".spinner{width:36px;height:36px;border:3px solid #3D2580;border-top-color:#C8A84B;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}");
  lines.push("@keyframes spin{to{transform:rotate(360deg)}}");
  lines.push("h1{color:#FFFFFF;font-size:20px;margin-bottom:10px;line-height:1.5}");
  lines.push("p{color:#9F7FEA;font-size:14px;margin-bottom:24px;line-height:1.7}");
  lines.push(".btn{display:block;width:100%;padding:16px;border-radius:14px;font-size:16px;font-weight:700;text-decoration:none;margin-bottom:12px;font-family:'Noto Naskh Arabic',sans-serif}");
  lines.push(".btn-apple{background:#FFFFFF;color:#000000}");
  lines.push(".btn-android{background:#1D9E75;color:#FFFFFF}");
  lines.push(".footer{color:#3D2870;font-size:11px;margin-top:20px;font-family:sans-serif}");
  lines.push(".hidden{display:none}");
  lines.push("</style>");
  lines.push("</head>");
  lines.push("<body>");
  lines.push("<div class=\"card\">");
  lines.push("  <div class=\"brand\">GLAMLY</div>");
  lines.push("  <div class=\"tagline\">جمالك بكل سهولة</div>");
  lines.push("  <div id=\"loading\">");
  lines.push("    <div class=\"spinner\"></div>");
  lines.push("    <p>جاري فتح هديتك في التطبيق</p>");
  lines.push("  </div>");
  lines.push("  <div id=\"fallback\" class=\"hidden\">");
  lines.push("    <h1>هديتك بانتظارك في التطبيق</h1>");
  lines.push("    <p>يبدو ان التطبيق غير مثبت لديك. حملي Glamly الان لعرض هديتك:</p>");
  lines.push("    <a href=\"" + escapeHtml(appleUrl) + "\" class=\"btn btn-apple\">App Store</a>");
  lines.push("    <a href=\"" + escapeHtml(googleUrl) + "\" class=\"btn btn-android\">Google Play</a>");
  lines.push("  </div>");
  lines.push("  <div class=\"footer\">Glamly</div>");
  lines.push("</div>");
  lines.push("<script>");
  lines.push("var appOpened = false;");
  lines.push("window.addEventListener('blur', function(){ appOpened = true; });");
  lines.push("document.addEventListener('visibilitychange', function(){ if(document.hidden) appOpened = true; });");
  lines.push("window.location.href = 'glamly://gift';");
  lines.push("setTimeout(function(){");
  lines.push("  if(!appOpened){");
  lines.push("    document.getElementById('loading').classList.add('hidden');");
  lines.push("    document.getElementById('fallback').classList.remove('hidden');");
  lines.push("  }");
  lines.push("}, 1500);");
  lines.push("</script>");
  lines.push("</body>");
  lines.push("</html>");
  res.send(lines.join("\n"));
});
 
app.get("/gift/:code", async (req, res) => {
  const code = String(req.params.code || "");
  if (!/^[A-Za-z0-9]{4,20}$/.test(code)) {
    return res.status(404).send("Not found");
  }
  try {
    const [rows] = await db.execute(
      "SELECT * FROM gifts WHERE gift_code = ?",
      [code]
    );
    if (rows.length === 0) {
      return res.send([
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">",
        "<style>body{background:#0F0A28;color:#E8DEFF;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}</style>",
        "</head><body><h2>هذه الهدية غير موجودة</h2></body></html>"
      ].join("\n"));
    }
    const gift = rows[0];
    const appleUrl  = process.env.APPLE_STORE_URL || "https://apps.apple.com";
    const googleUrl = process.env.GOOGLE_PLAY_URL || "https://play.google.com";
    // All user-supplied values are escaped — sender/service/salon names come
    // from API input and would otherwise be stored XSS on a public page.
    const senderName  = escapeHtml(gift.sender_name);
    const serviceName = escapeHtml(gift.service_name);
    const salonName   = escapeHtml(gift.salon_name);
    const giftCodeSafe = escapeHtml(gift.gift_code);
    const html = [
      "<!DOCTYPE html>",
      "<html lang=\"ar\" dir=\"rtl\">",
      "<head>",
      "<meta charset=\"UTF-8\">",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
      "<title>Glamly - your gift</title>",
      "<link href=\"https://fonts.googleapis.com/css2?family=Noto+Naskh+Arabic:wght@400;700&display=swap\" rel=\"stylesheet\">",
      "<style>",
      "*{margin:0;padding:0;box-sizing:border-box}",
      "body{font-family:'Noto Naskh Arabic',sans-serif;background:#0F0A28;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}",
      ".card{background:#1E1040;border-radius:24px;padding:36px 28px;max-width:380px;width:100%;text-align:center}",
      ".brand{color:#E8DEFF;font-size:24px;font-weight:700;letter-spacing:4px;font-family:sans-serif}",
      ".tagline{color:#C8A84B;font-size:11px;font-family:sans-serif;margin-bottom:24px}",
      ".from{color:#9F7FEA;font-size:14px;margin-bottom:6px}",
      ".from span{color:#C8A84B;font-weight:700}",
      "h1{color:#FFFFFF;font-size:22px;margin-bottom:20px;line-height:1.5}",
      ".divider{width:80%;height:1px;background:#2D1B6E;margin:20px auto}",
      ".detail-box{background:#2D1B6E;border-radius:14px;padding:16px;margin-bottom:20px;text-align:right}",
      ".detail-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid #3D2580}",
      ".detail-row:last-child{border-bottom:none}",
      ".detail-label{color:#9F7FEA;font-size:13px}",
      ".detail-value{color:#E8DEFF;font-size:14px;font-weight:600}",
      ".btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:16px;border-radius:14px;font-size:16px;font-weight:700;text-decoration:none;margin-bottom:12px;font-family:'Noto Naskh Arabic',sans-serif;cursor:pointer;border:none}",
      ".btn-main{background:#C8A84B;color:#0F0A28}",
      ".btn-apple{background:#FFFFFF;color:#000000;font-size:14px}",
      ".btn-android{background:#1D9E75;color:#FFFFFF;font-size:14px}",
      ".status{display:inline-block;padding:4px 14px;border-radius:20px;font-size:12px;margin-bottom:16px}",
      ".status.pending{background:#C8A84B22;color:#C8A84B;border:1px solid #C8A84B}",
      ".status.used{background:#1D9E7522;color:#1D9E75;border:1px solid #1D9E75}",
      ".footer{color:#3D2870;font-size:11px;margin-top:20px;font-family:sans-serif}",
      ".divider-text{color:#534AB7;font-size:12px;margin-bottom:12px}",
      "</style>",
      "</head>",
      "<body>",
      "<div class=\"card\">",
      "  <div class=\"brand\">GLAMLY</div>",
      "  <div class=\"tagline\">جمالك بكل سهولة</div>",
      "  <div class=\"from\">أهدتك <span>" + senderName + "</span> هدية مميزة</div>",
      "  <h1>تجربة تجميل بانتظارك</h1>",
      "  <span class=\"status " + (gift.status === "used" ? "used" : "pending") + "\">" + (gift.status === "used" ? "تم الاستخدام" : "لم تستخدم بعد") + "</span>",
      "  <div class=\"divider\"></div>",
      "  <div class=\"detail-box\">",
      "    <div class=\"detail-row\"><span class=\"detail-value\">" + serviceName + "</span><span class=\"detail-label\">الخدمة</span></div>",
      "    <div class=\"detail-row\"><span class=\"detail-value\">" + salonName + "</span><span class=\"detail-label\">المكان</span></div>",
      "    <div class=\"detail-row\"><span class=\"detail-value\">" + new Date(gift.created_at).toLocaleDateString("ar-SA") + "</span><span class=\"detail-label\">تاريخ الهدية</span></div>",
      "  </div>",
      "  <a href=\"glamly://gift/" + giftCodeSafe + "\" class=\"btn btn-main\">احجزي موعدك الآن</a>",
      "  <div class=\"divider-text\">اذا لم يكن التطبيق مثبتا لديك، حملي من هنا:</div>",
      "  <a href=\"" + escapeHtml(appleUrl) + "\" class=\"btn btn-apple\">App Store</a>",
      "  <a href=\"" + escapeHtml(googleUrl) + "\" class=\"btn btn-android\">Google Play</a>",
      "  <div class=\"footer\">Glamly</div>",
      "</div>",
      "</body>",
      "</html>"
    ].join("\n");
    res.send(html);
  } catch (err) {
    console.error("Gift page error:", err.message);
    res.status(500).send("Error loading gift");
  }
});
 
// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
app.get("/dashboard", (req, res) => {
  const html = [
    "<!DOCTYPE html>",
    "<html lang=\"en\">",
    "<head>",
    "<meta charset=\"UTF-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>Glamly Support</title>",
    "<style>",
    "*{margin:0;padding:0;box-sizing:border-box}",
    "body{font-family:sans-serif;background:#f0eef8;height:100vh;overflow:hidden;display:flex;flex-direction:column}",
    ".login-screen{display:flex;align-items:center;justify-content:center;height:100vh;background:#1E1040}",
    ".login-box{background:#2D1B6E;padding:40px;border-radius:16px;width:320px;text-align:center}",
    ".login-box h2{color:#E8DEFF;font-size:22px;margin-bottom:6px}",
    ".login-box p{color:#9F7FEA;font-size:13px;margin-bottom:24px}",
    ".login-box input{width:100%;padding:10px 14px;border-radius:8px;border:1px solid #534AB7;background:#1E1040;color:#E8DEFF;font-size:14px;outline:none;margin-bottom:12px}",
    ".login-box button{width:100%;padding:11px;background:#C8A84B;color:#1A0E3D;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}",
    ".login-err{color:#F09595;font-size:12px;margin-top:8px}",
    ".app{display:none;flex-direction:column;height:100vh}",
    ".topbar{background:#1E1040;padding:10px 20px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}",
    ".brand{color:#E8DEFF;font-size:16px;font-weight:600;letter-spacing:1px}",
    ".top-right{display:flex;align-items:center;gap:12px}",
    ".lang-toggle{display:flex;gap:4px}",
    ".lang-btn{padding:4px 10px;border-radius:5px;font-size:12px;cursor:pointer;border:none;background:#3D2580;color:#B89FFF}",
    ".lang-btn.active{background:#C8A84B;color:#1A0E3D;font-weight:600}",
    ".logout-btn{padding:4px 12px;border-radius:5px;font-size:12px;cursor:pointer;border:none;background:#3D2580;color:#F09595}",
    ".stats-bar{background:#2D1B6E;padding:8px 20px;display:flex;gap:24px;flex-shrink:0}",
    ".stat{text-align:center}",
    ".stat-n{font-size:20px;font-weight:600;color:#E8DEFF}",
    ".stat-l{font-size:10px;color:#9F7FEA;margin-top:1px}",
    ".main{display:flex;flex:1;overflow:hidden}",
    ".sidebar{width:280px;background:#1A0D3B;display:flex;flex-direction:column;flex-shrink:0}",
    ".filter-row{padding:8px 12px;display:flex;gap:5px;flex-wrap:wrap;border-bottom:1px solid #2D1B6E}",
    ".f-btn{padding:4px 10px;border-radius:10px;font-size:11px;border:none;cursor:pointer;background:#2D1B6E;color:#9F7FEA}",
    ".f-btn.active{background:#7F77DD;color:#EEEDFE}",
    ".search-box{padding:8px 12px;border-bottom:1px solid #2D1B6E}",
    ".search-box input{width:100%;padding:6px 10px;border-radius:6px;border:none;background:#2D1B6E;color:#E8DEFF;font-size:12px;outline:none}",
    ".conv-list{flex:1;overflow-y:auto}",
    ".conv-item{padding:10px 14px;border-bottom:1px solid #2D1B6E;cursor:pointer}",
    ".conv-item:hover,.conv-item.active{background:#2D1B6E}",
    ".conv-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:3px}",
    ".conv-num{font-size:12px;font-weight:600;color:#E8DEFF}",
    ".conv-time{font-size:10px;color:#534AB7}",
    ".conv-prev{font-size:11px;color:#7C5FD4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
    ".badge{display:inline-block;padding:1px 8px;border-radius:8px;font-size:10px;font-weight:500;margin-top:4px}",
    ".badge.pending{background:#C8A84B22;color:#C8A84B;border:0.5px solid #C8A84B}",
    ".badge.bot{background:#1D9E7522;color:#1D9E75;border:0.5px solid #1D9E75}",
    ".badge.agent{background:#7F77DD22;color:#B89FFF;border:0.5px solid #7F77DD}",
    ".badge.resolved{background:#534AB722;color:#9F7FEA;border:0.5px solid #534AB7}",
    ".chat-area{flex:1;display:flex;flex-direction:column;background:#f0eef8}",
    ".chat-head{padding:12px 18px;background:white;border-bottom:1px solid #eee;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}",
    ".ch-left{display:flex;align-items:center;gap:10px}",
    ".avatar{width:38px;height:38px;border-radius:50%;background:#EEEDFE;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;color:#534AB7;flex-shrink:0}",
    ".ch-name{font-size:14px;font-weight:600;color:#1E1040}",
    ".ch-sub{font-size:11px;color:#888;margin-top:1px}",
    ".ch-actions{display:flex;gap:6px}",
    ".act-btn{padding:5px 12px;border-radius:6px;font-size:12px;border:1px solid #ddd;background:white;color:#555;cursor:pointer}",
    ".act-btn.success{background:#1D9E75;color:white;border-color:#1D9E75}",
    ".messages{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:8px}",
    ".msg-wrap{display:flex;flex-direction:column;max-width:65%}",
    ".msg-wrap.right{align-self:flex-end;align-items:flex-end}",
    ".msg-wrap.left{align-self:flex-start}",
    ".msg{padding:9px 13px;border-radius:10px;font-size:13px;line-height:1.55;white-space:pre-wrap;word-break:break-word}",
    ".msg.customer{background:white;border:1px solid #eee;border-radius:10px 10px 10px 2px;color:#333}",
    ".msg.bot{background:#EEEDFE;border-radius:10px 10px 2px 10px;color:#26215C}",
    ".msg.agent{background:#2D1B6E;border-radius:10px 10px 2px 10px;color:#E8DEFF}",
    ".msg-meta{font-size:10px;color:#aaa;margin-top:3px;padding:0 3px}",
    ".booking-card{background:#EEEDFE;border:1px solid #AFA9EC;border-radius:10px;padding:12px 16px;margin:8px 0;font-size:13px;color:#26215C}",
    ".booking-card h4{font-size:13px;font-weight:600;margin-bottom:8px;color:#3C3489}",
    ".booking-card table{width:100%}",
    ".booking-card td{padding:3px 0;font-size:12px}",
    ".booking-card td:first-child{color:#534AB7;width:100px}",
    ".quick-replies{padding:8px 16px;display:flex;gap:6px;flex-wrap:wrap;background:white;border-top:1px solid #eee;flex-shrink:0}",
    ".qr-label{font-size:10px;color:#aaa;width:100%;margin-bottom:2px}",
    ".qr{padding:5px 12px;border-radius:14px;font-size:11px;border:1px solid #ddd;background:white;color:#555;cursor:pointer;white-space:nowrap}",
    ".reply-box{padding:10px 14px;border-top:1px solid #eee;display:flex;gap:8px;align-items:center;background:white;flex-shrink:0}",
    ".reply-box textarea{flex:1;padding:8px 14px;border:1px solid #ddd;border-radius:10px;font-size:13px;background:#fafafa;color:#333;outline:none;resize:none;height:40px;font-family:sans-serif}",
    ".send-btn{padding:8px 18px;background:#2D1B6E;color:#E8DEFF;border:none;border-radius:10px;font-size:13px;cursor:pointer}",
    ".empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#aaa;gap:8px}",
    "</style>",
    "</head>",
    "<body>",
    "<div class=\"login-screen\" id=\"loginScreen\">",
    "  <div class=\"login-box\">",
    "    <h2>GLAMLY</h2>",
    "    <p>Support Dashboard</p>",
    "    <input type=\"password\" id=\"passInput\" placeholder=\"Password\" onkeydown=\"if(event.key==='Enter')doLogin()\">",
    "    <button onclick=\"doLogin()\">Login</button>",
    "    <div class=\"login-err\" id=\"loginErr\"></div>",
    "  </div>",
    "</div>",
    "<div class=\"app\" id=\"app\">",
    "  <div class=\"topbar\">",
    "    <div class=\"brand\">GLAMLY Support</div>",
    "    <div class=\"top-right\">",
    "      <div class=\"lang-toggle\">",
    "        <button class=\"lang-btn active\" onclick=\"setLang('en')\">EN</button>",
    "        <button class=\"lang-btn\" onclick=\"setLang('ar')\">AR</button>",
    "      </div>",
    "      <button class=\"logout-btn\" onclick=\"doLogout()\">Logout</button>",
    "    </div>",
    "  </div>",
    "  <div class=\"stats-bar\">",
    "    <div class=\"stat\"><div class=\"stat-n\" id=\"s-total\">0</div><div class=\"stat-l\">Total</div></div>",
    "    <div class=\"stat\"><div class=\"stat-n\" style=\"color:#C8A84B\" id=\"s-pending\">0</div><div class=\"stat-l\">Pending</div></div>",
    "    <div class=\"stat\"><div class=\"stat-n\" style=\"color:#1D9E75\" id=\"s-bot\">0</div><div class=\"stat-l\">Bot</div></div>",
    "    <div class=\"stat\"><div class=\"stat-n\" style=\"color:#9F7FEA\" id=\"s-resolved\">0</div><div class=\"stat-l\">Resolved</div></div>",
    "  </div>",
    "  <div class=\"main\">",
    "    <div class=\"sidebar\">",
    "      <div class=\"filter-row\">",
    "        <button class=\"f-btn active\" onclick=\"setFilter('all',this)\">All</button>",
    "        <button class=\"f-btn\" onclick=\"setFilter('pending',this)\">Pending</button>",
    "        <button class=\"f-btn\" onclick=\"setFilter('agent',this)\">Agent</button>",
    "        <button class=\"f-btn\" onclick=\"setFilter('bot',this)\">Bot</button>",
    "        <button class=\"f-btn\" onclick=\"setFilter('resolved',this)\">Resolved</button>",
    "      </div>",
    "      <div class=\"search-box\"><input id=\"searchInput\" placeholder=\"Search...\" oninput=\"renderList()\"></div>",
    "      <div class=\"conv-list\" id=\"convList\"></div>",
    "    </div>",
    "    <div class=\"chat-area\" id=\"chatArea\">",
    "      <div class=\"empty-state\"><p>Select a conversation</p></div>",
    "    </div>",
    "  </div>",
    "</div>",
    "<script>",
    "var conversations={};",
    "var activeNumber=null;",
    "var currentFilter='all';",
    "var currentLang='en';",
    "var authToken=localStorage.getItem('glamly_token')||'';",
    "var drafts={}; // unsent reply text per conversation, survives re-renders",
    "var lastPendingCount=-1;",
    "var eventSource=null;",
    "",
    "// Escape everything that goes into innerHTML — customer messages are",
    "// attacker-controlled and were previously stored XSS in this dashboard.",
    "function esc(s){",
    "  var d=document.createElement('div');",
    "  d.textContent=(s==null?'':String(s));",
    "  return d.innerHTML;",
    "}",
    "",
    "var quickReplies={",
    "  en:['Please share your booking ID so I can help you.','Cancellations made 24hrs before appointment are fully refunded.','Your refund will be processed within 3-5 business days.','Thank you for choosing Glamly!'],",
    "  ar:['من فضلك أرسل رقم حجزك حتى أتمكن من مساعدتك.','الإلغاء قبل 24 ساعة من الموعد يحصل على استرداد كامل.','سيتم معالجة استرداد المبلغ خلال 3-5 أيام عمل.','شكراً لاختيارك Glamly!']",
    "};",
    "",
    "function doLogin(){",
    "  var pass=document.getElementById('passInput').value;",
    "  fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pass})})",
    "    .then(function(res){ return res.json(); })",
    "    .then(function(data){",
    "      if(data.success){",
    "        authToken=data.token;",
    "        localStorage.setItem('glamly_token',authToken);",
    "        showApp();",
    "      } else {",
    "        document.getElementById('loginErr').textContent=data.error||'Wrong password';",
    "      }",
    "    });",
    "}",
    "",
    "function doLogout(){",
    "  if(eventSource){ eventSource.close(); eventSource=null; }",
    "  fetch('/logout',{method:'POST'});",
    "  authToken='';",
    "  localStorage.removeItem('glamly_token');",
    "  document.getElementById('app').style.display='none';",
    "  document.getElementById('loginScreen').style.display='flex';",
    "}",
    "",
    "function showApp(){",
    "  document.getElementById('loginScreen').style.display='none';",
    "  document.getElementById('app').style.display='flex';",
    "  loadConversations();",
    "  initSSE();",
    "  if(window.Notification && Notification.permission==='default') Notification.requestPermission();",
    "}",
    "",
    "// Real-time: reload whenever the server broadcasts a change.",
    "function initSSE(){",
    "  if(eventSource) return;",
    "  try{",
    "    eventSource=new EventSource('/events');",
    "    eventSource.onmessage=function(){ loadConversations(); };",
    "  }catch(e){ /* polling fallback still runs */ }",
    "}",
    "",
    "function playBeep(){",
    "  try{",
    "    var ctx=new (window.AudioContext||window.webkitAudioContext)();",
    "    var o=ctx.createOscillator(); var g=ctx.createGain();",
    "    o.connect(g); g.connect(ctx.destination);",
    "    o.frequency.value=880; g.gain.value=0.08;",
    "    o.start(); setTimeout(function(){ o.stop(); ctx.close(); },200);",
    "  }catch(e){}",
    "}",
    "",
    "function notifyNewPending(){",
    "  playBeep();",
    "  if(window.Notification && Notification.permission==='granted'){",
    "    try{ new Notification('Glamly Support',{body:'New chat waiting for an agent'}); }catch(e){}",
    "  }",
    "}",
    "",
    "function authHeaders(){",
    "  return {Authorization:'Bearer '+authToken,'Content-Type':'application/json'};",
    "}",
    "",
    "function setLang(lang){",
    "  currentLang=lang;",
    "  var btns=document.querySelectorAll('.lang-btn');",
    "  btns[0].classList.toggle('active', lang==='en');",
    "  btns[1].classList.toggle('active', lang==='ar');",
    "  renderList();",
    "  if(activeNumber) openConversation(activeNumber);",
    "}",
    "",
    "function setFilter(f,btn){",
    "  currentFilter=f;",
    "  document.querySelectorAll('.f-btn').forEach(function(b){ b.classList.remove('active'); });",
    "  btn.classList.add('active');",
    "  renderList();",
    "}",
    "",
    "function timeAgo(iso){",
    "  var d=Math.floor((Date.now()-new Date(iso))/1000);",
    "  if(d<0) d=0;",
    "  if(d<60) return d+'s';",
    "  if(d<3600) return Math.floor(d/60)+'m';",
    "  if(d<86400) return Math.floor(d/3600)+'h';",
    "  return Math.floor(d/86400)+'d';",
    "}",
    "",
    "var KNOWN_STATUSES=['pending','bot','agent','resolved'];",
    "",
    "function renderList(){",
    "  var list=document.getElementById('convList');",
    "  var search=document.getElementById('searchInput').value.toLowerCase();",
    "  list.innerHTML='';",
    "  var total=0,pending=0,bot=0,resolved=0;",
    "  for(var number in conversations){",
    "    var data=conversations[number];",
    "    total++;",
    "    if(data.status==='pending') pending++;",
    "    else if(data.status==='bot') bot++;",
    "    else if(data.status==='resolved') resolved++;",
    "    if(currentFilter!=='all' && data.status!==currentFilter) continue;",
    "    var last=data.messages[data.messages.length-1];",
    "    var preview=last?(last.message||(last.hasMedia?'[Media]':'')).substring(0,40):'';",
    "    if(search && number.indexOf(search)===-1 && preview.toLowerCase().indexOf(search)===-1) continue;",
    "    var div=document.createElement('div');",
    "    div.className='conv-item'+(number===activeNumber?' active':'');",
    "    var statusClass=KNOWN_STATUSES.indexOf(data.status)!==-1?data.status:'bot';",
    "    var badgeText=data.status==='pending'?'Pending':data.status==='bot'?'Bot':data.status==='agent'?'Agent':'Resolved';",
    "    div.innerHTML='<div class=\"conv-top\"><span class=\"conv-num\">'+esc(number.replace('whatsapp:+',''))+'</span><span class=\"conv-time\">'+esc(timeAgo(data.lastSeen))+'</span></div><div class=\"conv-prev\">'+esc(preview)+'</div><span class=\"badge '+statusClass+'\">'+esc(badgeText)+'</span>';",
    "    div.onclick=(function(num){ return function(){ openConversation(num); }; })(number);",
    "    list.appendChild(div);",
    "  }",
    "  document.getElementById('s-total').textContent=total;",
    "  document.getElementById('s-pending').textContent=pending;",
    "  document.getElementById('s-bot').textContent=bot;",
    "  document.getElementById('s-resolved').textContent=resolved;",
    "  if(lastPendingCount>=0 && pending>lastPendingCount) notifyNewPending();",
    "  lastPendingCount=pending;",
    "}",
    "",
    "function openConversation(number){",
    "  // Save the draft + focus state before the re-render wipes the textarea",
    "  var prevInput=document.getElementById('replyInput');",
    "  if(prevInput && activeNumber) drafts[activeNumber]=prevInput.value;",
    "  var keepFocus=prevInput && document.activeElement===prevInput && activeNumber===number;",
    "  activeNumber=number;",
    "  var data=conversations[number];",
    "  var num=number.replace('whatsapp:+','');",
    "",
    "  var msgsHtml='';",
    "  for(var i=0;i<data.messages.length;i++){",
    "    var m=data.messages[i];",
    "    var side=m.from==='customer'?'left':'right';",
    "    var who=m.from==='customer'?'Customer':m.from==='bot'?'Bot':'Agent';",
    "    var msgClass=m.from==='customer'?'customer':m.from==='bot'?'bot':'agent';",
    "    var content='';",
    "    if(m.hasMedia){",
    "      var mt=m.mediaType||'';",
    "      if(mt.indexOf('image/')===0) content+='<img src=\"/media/'+m.id+'\" style=\"max-width:200px;border-radius:8px;display:block;margin-bottom:4px\">';",
    "      else if(mt.indexOf('audio/')===0) content+='<audio controls src=\"/media/'+m.id+'\" style=\"display:block;margin-bottom:4px;max-width:220px\"></audio>';",
    "      else content+='<a href=\"/media/'+m.id+'\" target=\"_blank\">[Attachment]</a><br>';",
    "    }",
    "    content+=esc(m.message);",
    "    msgsHtml += '<div class=\"msg-wrap '+side+'\"><div class=\"msg '+msgClass+'\">'+content+'</div><div class=\"msg-meta\">'+who+' - '+esc(new Date(m.time).toLocaleTimeString())+'</div></div>';",
    "  }",
    "",
    "  var qrHtml='';",
    "  var qrList=quickReplies[currentLang];",
    "  for(var j=0;j<qrList.length;j++){",
    "    qrHtml += '<button class=\"qr\" onclick=\"setReply(this.textContent)\">'+esc(qrList[j])+'</button>';",
    "  }",
    "",
    "  document.getElementById('chatArea').innerHTML =",
    "    '<div class=\"chat-head\"><div class=\"ch-left\"><div class=\"avatar\">'+esc(num.slice(-2))+'</div><div><div class=\"ch-name\">+'+esc(num)+'</div><div class=\"ch-sub\">Status: '+esc(data.status)+' | Lang: '+esc((data.lang||'ar').toUpperCase())+'</div></div></div>'+",
    "    '<div class=\"ch-actions\"><button class=\"act-btn\" onclick=\"lookupBooking()\">Booking lookup</button><button class=\"act-btn success\" onclick=\"markResolved(\\''+esc(number)+'\\')\">Mark resolved</button></div></div>'+",
    "    '<div class=\"messages\" id=\"messages\">'+msgsHtml+'</div>'+",
    "    '<div class=\"quick-replies\"><div class=\"qr-label\">Quick replies:</div>'+qrHtml+'</div>'+",
    "    '<div class=\"reply-box\"><textarea id=\"replyInput\" placeholder=\"Type your reply...\" onkeydown=\"if(event.key===\\'Enter\\' && !event.shiftKey){event.preventDefault();sendReply();}\"></textarea><button class=\"act-btn\" onclick=\"sendTemplate()\" title=\"Use when the 24h WhatsApp window has closed\">Template</button><button class=\"send-btn\" onclick=\"sendReply()\">Send</button></div>';",
    "",
    "  // Restore the draft (and cursor) after the re-render",
    "  var newInput=document.getElementById('replyInput');",
    "  if(newInput){",
    "    newInput.value=drafts[number]||'';",
    "    if(keepFocus){ newInput.focus(); newInput.selectionStart=newInput.selectionEnd=newInput.value.length; }",
    "  }",
    "  document.getElementById('messages').scrollTop=99999;",
    "  renderList();",
    "}",
    "",
    "function setReply(text){",
    "  var i=document.getElementById('replyInput');",
    "  if(i) i.value=text;",
    "}",
    "",
    "function sendReply(){",
    "  var input=document.getElementById('replyInput');",
    "  var message=input.value.trim();",
    "  if(!message || !activeNumber) return;",
    "  input.value='';",
    "  drafts[activeNumber]='';",
    "  fetch('/reply',{method:'POST',headers:authHeaders(),body:JSON.stringify({to:activeNumber.replace('whatsapp:+',''),message:message})})",
    "    .then(function(res){ return res.json(); })",
    "    .then(function(data){",
    "      if(data && data.error){",
    "        alert(data.error);",
    "        drafts[activeNumber]=message;",
    "        var inp=document.getElementById('replyInput');",
    "        if(inp) inp.value=message; // restore so the agent doesn't lose the draft",
    "        return;",
    "      }",
    "      return loadConversations().then(function(){ openConversation(activeNumber); });",
    "    })",
    "    .catch(function(){ alert('Failed to send message'); drafts[activeNumber]=message; var inp=document.getElementById('replyInput'); if(inp) inp.value=message; });",
    "}",
    "",
    "// For chats outside the 24h window: send the approved re-engagement template.",
    "function sendTemplate(){",
    "  if(!activeNumber) return;",
    "  if(!confirm('Send the re-engagement template to this customer?')) return;",
    "  var lang=(conversations[activeNumber]&&conversations[activeNumber].lang)||'ar';",
    "  fetch('/send-template',{method:'POST',headers:authHeaders(),body:JSON.stringify({to:activeNumber.replace('whatsapp:+',''),language:lang})})",
    "    .then(function(res){ return res.json(); })",
    "    .then(function(data){",
    "      if(data && data.error){ alert(data.error); return; }",
    "      return loadConversations();",
    "    })",
    "    .catch(function(){ alert('Failed to send template'); });",
    "}",
    "",
    "function markResolved(number){",
    "  fetch('/status',{method:'POST',headers:authHeaders(),body:JSON.stringify({number:number,status:'resolved'})})",
    "    .then(function(){ return loadConversations(); })",
    "    .then(function(){ if(activeNumber===number) openConversation(number); });",
    "}",
    "",
    "function lookupBooking(){",
    "  var bookingId=prompt('Enter booking ID:');",
    "  if(!bookingId) return;",
    "  fetch('/booking/'+encodeURIComponent(bookingId),{headers:authHeaders()})",
    "    .then(function(res){ return res.json(); })",
    "    .then(function(data){",
    "      var msgs=document.getElementById('messages');",
    "      if(!msgs) return;",
    "      var card=document.createElement('div');",
    "      card.className='msg-wrap left';",
    "      card.innerHTML='<div class=\"booking-card\"><h4>Booking #'+esc(data.id)+'</h4><table><tr><td>Customer</td><td>'+esc(data.customer)+'</td></tr><tr><td>Service</td><td>'+esc(data.service)+'</td></tr><tr><td>Date</td><td>'+esc(data.date)+'</td></tr><tr><td>Status</td><td>'+esc(data.status)+'</td></tr></table></div>';",
    "      msgs.appendChild(card);",
    "      msgs.scrollTop=99999;",
    "    });",
    "}",
    "",
    "function loadConversations(){",
    "  if(!authToken) return Promise.resolve();",
    "  return fetch('/conversations',{headers:authHeaders()})",
    "    .then(function(res){",
    "      if(res.status===401){ doLogout(); return null; }",
    "      return res.json();",
    "    })",
    "    .then(function(data){",
    "      if(!data) return;",
    "      conversations=data;",
    "      renderList();",
    "      if(activeNumber && conversations[activeNumber]) openConversation(activeNumber);",
    "    })",
    "    .catch(function(err){ console.error('Failed to load:',err); });",
    "}",
    "",
    "if(authToken) showApp();",
    "// Polling is now just a fallback — SSE delivers updates instantly.",
    "setInterval(function(){ if(authToken) loadConversations(); }, 30000);",
    "</script>",
    "</body>",
    "</html>"
  ].join("\n");
  res.send(html);
});
 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Glamly webhook running on port " + PORT));
// v2.1 — draft preservation fix
 
