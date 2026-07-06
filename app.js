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
function getBotReply(message) {
  const msg = message.toLowerCase().trim();
  if (msg === "1" || msg.includes("booking") || msg.includes("status") || msg.includes("حجز") || msg.includes("حالة"))
    return "Please share your booking ID and we will check it for you!\n\nأرسل رقم حجزك وسنتحقق منه فوراً!";
  if (msg === "2" || msg.includes("cancel") || msg.includes("إلغاء") || msg.includes("الغ"))
    return "To cancel your booking please share your booking ID.\n\nCancellations made 24hrs before are fully refunded.\n\nلإلغاء حجزك أرسل رقم الحجز.\nالإلغاء قبل 24 ساعة يحصل على استرداد كامل.";
  if (msg === "3" || msg.includes("price") || msg.includes("سعر") || msg.includes("كم") || msg.includes("تكلفة"))
    return "Browse all prices in the Glamly app!\n\nglamlysa.com\n\nتصفح جميع الأسعار في تطبيق Glamly!\nglamlysa.com";
  if (msg === "4" || msg.includes("agent") || msg.includes("human") || msg.includes("موظف") || msg.includes("مساعدة"))
    return "Connecting you to an agent now. Please wait!\n\nجاري تحويلك لموظف. لحظة من فضلك!";
  if (msg.includes("hello") || msg.includes("hi") || msg.includes("مرحبا") || msg.includes("هلا") || msg.includes("اهلا") || msg.includes("السلام"))
    return "Welcome to Glamly!\nأهلاً بك في Glamly!\n\n1- Booking status\n2- Cancel booking\n3- Prices\n4- Talk to agent";
  if (msg.includes("thank") || msg.includes("شكر") || msg.includes("شكراً"))
    return "You're most welcome!\nعلى الرحب والسعة!\n\nGlamly";
  return null;
}
 
// ---------------------------------------------------------------------------
// Twilio webhook — signature validated so only Twilio can call it.
// (To test locally with curl, temporarily set validate: false.)
// ---------------------------------------------------------------------------
app.post("/webhook", twilio.webhook({ authToken: authToken, validate: true }), async (req, res) => {
  const from = req.body.From || "";
  let message = (req.body.Body || "").trim();
  // Media-only messages (images, voice notes) have no Body — store a
  // placeholder instead of crashing the INSERT with undefined.
  if (!message && Number(req.body.NumMedia) > 0) message = "[media message]";
 
  try {
    if (from && message) {
      await db.execute(
        "INSERT INTO conversations (phone, status, last_seen) VALUES (?, 'bot', NOW()) ON DUPLICATE KEY UPDATE last_seen = NOW()",
        [from]
      );
      await db.execute(
        "INSERT INTO messages (phone, sender, message) VALUES (?, 'customer', ?)",
        [from, message]
      );
      const botReply = getBotReply(message);
      if (botReply) {
        await db.execute(
          "INSERT INTO messages (phone, sender, message) VALUES (?, 'bot', ?)",
          [from, botReply]
        );
        await db.execute(
          "UPDATE conversations SET status = 'bot' WHERE phone = ?",
          [from]
        );
        // Awaited so send failures are logged instead of becoming
        // unhandled promise rejections.
        try {
          await client.messages.create({ from: fromNumber, to: from, body: botReply });
        } catch (sendErr) {
          console.error("Bot reply send failed:", sendErr.message);
        }
      } else {
        await db.execute(
          "UPDATE conversations SET status = 'pending' WHERE phone = ?",
          [from]
        );
      }
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
// Conversations — two fixed queries instead of one query per conversation.
// ---------------------------------------------------------------------------
app.get("/conversations", requireAuth, async (req, res) => {
  try {
    const [convs] = await db.execute("SELECT * FROM conversations ORDER BY last_seen DESC");
    const [msgs]  = await db.execute("SELECT phone, sender, message, created_at FROM messages ORDER BY created_at ASC, id ASC");
    const byPhone = {};
    for (const m of msgs) {
      (byPhone[m.phone] = byPhone[m.phone] || []).push({
        from: m.sender, message: m.message, time: m.created_at
      });
    }
    const result = {};
    for (const conv of convs) {
      result[conv.phone] = {
        status:     conv.status,
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
 
const VALID_STATUSES = ["bot", "pending", "agent", "resolved"];
app.post("/status", requireAuth, async (req, res) => {
  const { number, status } = req.body;
  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }
  try {
    await db.execute("UPDATE conversations SET status = ? WHERE phone = ?", [status, number]);
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
    "    var preview=last?last.message.substring(0,40):'';",
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
    "}",
    "",
    "function openConversation(number){",
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
    "    msgsHtml += '<div class=\"msg-wrap '+side+'\"><div class=\"msg '+msgClass+'\">'+esc(m.message)+'</div><div class=\"msg-meta\">'+who+' - '+esc(new Date(m.time).toLocaleTimeString())+'</div></div>';",
    "  }",
    "",
    "  var qrHtml='';",
    "  var qrList=quickReplies[currentLang];",
    "  for(var j=0;j<qrList.length;j++){",
    "    qrHtml += '<button class=\"qr\" onclick=\"setReply(this.textContent)\">'+esc(qrList[j])+'</button>';",
    "  }",
    "",
    "  document.getElementById('chatArea').innerHTML =",
    "    '<div class=\"chat-head\"><div class=\"ch-left\"><div class=\"avatar\">'+esc(num.slice(-2))+'</div><div><div class=\"ch-name\">+'+esc(num)+'</div><div class=\"ch-sub\">Status: '+esc(data.status)+'</div></div></div>'+",
    "    '<div class=\"ch-actions\"><button class=\"act-btn\" onclick=\"lookupBooking()\">Booking lookup</button><button class=\"act-btn success\" onclick=\"markResolved(\\''+esc(number)+'\\')\">Mark resolved</button></div></div>'+",
    "    '<div class=\"messages\" id=\"messages\">'+msgsHtml+'</div>'+",
    "    '<div class=\"quick-replies\"><div class=\"qr-label\">Quick replies:</div>'+qrHtml+'</div>'+",
    "    '<div class=\"reply-box\"><textarea id=\"replyInput\" placeholder=\"Type your reply...\" onkeydown=\"if(event.key===\\'Enter\\' && !event.shiftKey){event.preventDefault();sendReply();}\"></textarea><button class=\"send-btn\" onclick=\"sendReply()\">Send</button></div>';",
    "",
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
    "  fetch('/reply',{method:'POST',headers:authHeaders(),body:JSON.stringify({to:activeNumber.replace('whatsapp:+',''),message:message})})",
    "    .then(function(res){ return res.json(); })",
    "    .then(function(data){",
    "      if(data && data.error){",
    "        alert(data.error);",
    "        input.value=message; // restore so the agent doesn't lose the draft",
    "        return;",
    "      }",
    "      return loadConversations().then(function(){ openConversation(activeNumber); });",
    "    })",
    "    .catch(function(){ alert('Failed to send message'); input.value=message; });",
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
    "setInterval(function(){ if(authToken) loadConversations(); }, 8000);",
    "</script>",
    "</body>",
    "</html>"
  ].join("\n");
  res.send(html);
});
 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Glamly webhook running on port " + PORT));
 

