// ══════════════════════════════════════════════════════════════════════════
// الأمن السيبراني — وزارة الداخلية — ملف الموقع فقط (بدون بوت)
// البوت في ملف ثاني على استضافة ثانية، والاثنين يتكلمون عن طريق نفس قاعدة MongoDB.
// ══════════════════════════════════════════════════════════════════════════
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const mongoose = require("mongoose");
const { PermissionFlagsBits } = require("discord.js");   // لأسماء الصلاحيات فقط — الموقع ما يسجّل دخول بأي بوت

// ══════════════════════════════════════════════════════════════════════════
// 1) الإعدادات — من Environment Variables
//    MONGO_URI لازم يكون نفس اللي في البوت بالضبط
// ══════════════════════════════════════════════════════════════════════════
const CONFIG = {
    DISCORD_CLIENT_ID: process.env.DISCORD_CLIENT_ID || "",
    DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET || "",
    DISCORD_CALLBACK_URL: process.env.DISCORD_CALLBACK_URL || "",   // مثال: https://xxx.com/auth/discord/callback
    MONGO_URI: process.env.MONGO_URI || "",
    SESSION_SECRET: process.env.SESSION_SECRET || "غيّر_هذا_السر_2026",
    PORT: process.env.PORT || 7800,
    SITE_NAME: "الأمن السيبراني",
    SITE_SUB: "وزارة الداخلية",
};

// ══════════════════════════════════════════════════════════════════════════
// 2) قاعدة البيانات
// ══════════════════════════════════════════════════════════════════════════
mongoose.connect(CONFIG.MONGO_URI)
    .then(() => console.log("✅ MongoDB connected"))
    .catch(err => console.log("❌ MongoDB error:", err));

const EventSchema = new mongoose.Schema({
    kind: { type: String, default: "normal", index: true },     // normal | suspicious
    cat: { type: String, default: "other", index: true },       // join, leave, kick, ban, role, channel, message, bot, webhook, server, panel, everyone
    rule: { type: String, default: null },
    key: { type: String, default: null, index: true },
    title: String,
    details: String,
    severity: { type: String, default: "low" },                 // low | medium | high
    actorId: { type: String, default: null, index: true },
    actorTag: { type: String, default: null },
    targetId: { type: String, default: null },
    targetTag: { type: String, default: null },
    count: { type: Number, default: 1 },
    data: { type: mongoose.Schema.Types.Mixed, default: {} },
    remedy: { type: mongoose.Schema.Types.Mixed, default: null }, // { type, label, params }
    resolved: { type: Boolean, default: false },
    resolvedBy: String,
    resolvedAt: Date,
    createdAt: { type: Date, default: Date.now, index: true, expires: 60 * 60 * 24 * 60 },
    updatedAt: { type: Date, default: Date.now },
});
const Event = mongoose.model("CyberEvent", EventSchema);

const ImageSchema = new mongoose.Schema({
    eventId: { type: mongoose.Schema.Types.ObjectId, index: true },
    name: String,
    contentType: String,
    size: Number,
    data: Buffer,
    createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 60 },
});
const EventImage = mongoose.model("CyberEventImage", ImageSchema);

// تتبّع آخر دخول للوحة (وقت الدخول وآخر نشاط، لحساب مدة الجلسة)
const MemberSchema = new mongoose.Schema({
    _id: String, // آيدي ديسكورد
    tag: String,
    avatar: String,
    lastLoginAt: Date,
    lastSeenAt: Date,
});
const PanelMember = mongoose.model("CyberPanelMember", MemberSchema);

// لقطة يومية لعدد الأعضاء (بدون انتهاء — حجمها صغير) + نقطة بداية الأسابيع + أرشيف الأسابيع المكتملة
const DailyStat = mongoose.model("CyberDailyStat", new mongoose.Schema({ _id: String, members: Number, updatedAt: Date }));
const MsgLog = mongoose.model("CyberMsgLog", new mongoose.Schema({
    _id: String, channelId: { type: String, index: true }, authorId: String, authorTag: String, content: String, att: Number,
    at: { type: Date, index: true, expires: 60 * 60 * 24 * 5 },   // نحتفظ بالنسخة 5 أيام فقط
}));
const StatMeta = mongoose.model("CyberStatMeta", new mongoose.Schema({ _id: String, value: String }));
const WeekArchive = mongoose.model("CyberWeekArchive", new mongoose.Schema({
    _id: Number, start: String, end: String, total: Number, resolved: Number, unresolved: Number,
    byRule: mongoose.Schema.Types.Mixed, days: mongoose.Schema.Types.Mixed, savedAt: Date,
}));

// ── جداول الربط بين الموقع والبوت (لازم تكون نفسها بالضبط في ملف البوت) ──
const Job = mongoose.model("CyberJob", new mongoose.Schema({
    type: String,
    params: { type: mongoose.Schema.Types.Mixed, default: {} },
    status: { type: String, default: "pending", index: true },   // pending | running | done | error
    result: mongoose.Schema.Types.Mixed,
    error: String, errStatus: Number,
    createdAt: { type: Date, default: Date.now, index: true, expires: 60 * 30 },
    startedAt: Date, doneAt: Date,
}, { minimize: false }));
// استفسار "ليش عطيت الرتبة": الموقع ينشئه، والبوت يرسله بالخاص ويستقبل الرد ويرسل القرار
const Inquiry = mongoose.model("CyberInquiry", new mongoose.Schema({
    eventId: { type: mongoose.Schema.Types.ObjectId, index: true },   // عملية الرتبة اللي انفتح عليها الاستفسار
    dmId: { type: String, index: true }, dmTag: String,                // العضو اللي يوصله السؤال (اللي أعطى الرتبة)
    subjectTag: String,                                                // اللي انعطى الرتبة
    about: String,                                                     // وصف العملية (من اللوق)
    senderId: String, senderTag: String, senderAvatar: String,         // اللي ضغط الزر من اللوحة
    status: { type: String, default: "sent", index: true },            // sent | replied | covenant | investigation
    reason: String, repliedAt: Date,
    decidedBy: String, decidedById: String, decidedAvatar: String, decidedAt: Date,
    createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 60 },
}));
const Access = mongoose.model("CyberAccess", new mongoose.Schema({ _id: String, level: { type: String, default: null }, updatedAt: Date }));

// ── بث فوري للوحة (Server-Sent Events) — بدون أي تحديث كامل للصفحة ──
const sseClients = new Set();
function broadcastChanged() {
    const line = "event: changed\ndata: {}\n\n";
    for (const res of sseClients) { try { res.write(line); } catch { sseClients.delete(res); } }
}

// ══════════════════════════════════════════════════════════════════════════
// 3) الصلاحيات (أسماء عربية + تصنيف الخطورة)
// ══════════════════════════════════════════════════════════════════════════
const P = PermissionFlagsBits;
const PERM_AR = {
    Administrator: "مدير (كل الصلاحيات)", ManageGuild: "إدارة السيرفر", ManageRoles: "إدارة الرتب", ManageChannels: "إدارة القنوات",
    KickMembers: "طرد الأعضاء", BanMembers: "حظر الأعضاء", ManageWebhooks: "إدارة الويبهوكس", MentionEveryone: "منشن @everyone",
    ManageMessages: "إدارة الرسائل", ModerateMembers: "تقييد الأعضاء (تايم أوت)", ViewAuditLog: "عرض سجل التدقيق",
    ManageNicknames: "إدارة الألقاب", MuteMembers: "كتم الأعضاء", DeafenMembers: "تصميم الأعضاء", MoveMembers: "نقل الأعضاء",
    ManageGuildExpressions: "إدارة الإيموجي والملصقات", ManageEvents: "إدارة الفعاليات", ManageThreads: "إدارة الثريدات",
    CreateInstantInvite: "إنشاء دعوات", ViewChannel: "رؤية القناة", SendMessages: "إرسال الرسائل", SendMessagesInThreads: "الإرسال في الثريدات",
    CreatePublicThreads: "إنشاء ثريدات عامة", CreatePrivateThreads: "إنشاء ثريدات خاصة", EmbedLinks: "تضمين الروابط", AttachFiles: "إرفاق الملفات",
    AddReactions: "إضافة تفاعلات", UseExternalEmojis: "إيموجي خارجي", UseExternalStickers: "ملصقات خارجية", ReadMessageHistory: "قراءة سجل الرسائل",
    SendTTSMessages: "رسائل TTS", UseApplicationCommands: "أوامر التطبيقات", SendPolls: "إنشاء استطلاعات", SendVoiceMessages: "رسائل صوتية",
    Connect: "الاتصال بالصوت", Speak: "التحدث", Stream: "البث", UseVAD: "كشف الصوت", PrioritySpeaker: "أولوية التحدث",
    UseEmbeddedActivities: "الأنشطة", UseSoundboard: "لوحة الأصوات", RequestToSpeak: "طلب التحدث", ChangeNickname: "تغيير اللقب",
    ViewGuildInsights: "إحصائيات السيرفر", CreateGuildExpressions: "إنشاء إيموجي", CreateEvents: "إنشاء فعاليات",
};
// أسماء ناقصة كانت تطلع بالإنجليزي — الحين كلها عربي
Object.assign(PERM_AR, {
    UseExternalSounds: "أصوات خارجية", UseExternalApps: "تطبيقات خارجية", PinMessages: "تثبيت الرسائل", BypassSlowmode: "تجاوز الوضع البطيء",
    SetVoiceChannelStatus: "تعيين حالة الروم الصوتي", ViewCreatorMonetizationAnalytics: "تحليلات أرباح المنشئ",
});
// الاسم الأصلي في ديسكورد (يظهر جنب العربي كملاحظة رمادية)
const PERM_EN = {
    CreateInstantInvite: "Create Invite", KickMembers: "Kick Members", BanMembers: "Ban Members", Administrator: "Administrator",
    ManageChannels: "Manage Channels", ManageGuild: "Manage Server", AddReactions: "Add Reactions", ViewAuditLog: "View Audit Log",
    PrioritySpeaker: "Priority Speaker", Stream: "Video", ViewChannel: "View Channels", SendMessages: "Send Messages",
    SendTTSMessages: "Send Text-to-Speech Messages", ManageMessages: "Manage Messages", EmbedLinks: "Embed Links", AttachFiles: "Attach Files",
    ReadMessageHistory: "Read Message History", MentionEveryone: "Mention @everyone, @here, and All Roles", UseExternalEmojis: "Use External Emoji",
    ViewGuildInsights: "View Server Insights", Connect: "Connect", Speak: "Speak", MuteMembers: "Mute Members", DeafenMembers: "Deafen Members",
    MoveMembers: "Move Members", UseVAD: "Use Voice Activity", ChangeNickname: "Change Nickname", ManageNicknames: "Manage Nicknames",
    ManageRoles: "Manage Roles", ManageWebhooks: "Manage Webhooks", ManageGuildExpressions: "Manage Expressions",
    UseApplicationCommands: "Use Application Commands", RequestToSpeak: "Request to Speak", ManageEvents: "Manage Events",
    ManageThreads: "Manage Threads", CreatePublicThreads: "Create Public Threads", CreatePrivateThreads: "Create Private Threads",
    UseExternalStickers: "Use External Stickers", SendMessagesInThreads: "Send Messages in Threads", UseEmbeddedActivities: "Use Activities",
    ModerateMembers: "Timeout Members", ViewCreatorMonetizationAnalytics: "View Creator Monetization Analytics", UseSoundboard: "Use Soundboard",
    CreateGuildExpressions: "Create Expressions", CreateEvents: "Create Events", UseExternalSounds: "Use External Sounds",
    SendVoiceMessages: "Send Voice Messages", SendPolls: "Create Polls", UseExternalApps: "Use External Apps", PinMessages: "Pin Messages",
    BypassSlowmode: "Bypass Slowmode", SetVoiceChannelStatus: "Set Voice Channel Status",
};
const enOf = k => PERM_EN[k] || k.replace(/([a-z])([A-Z])/g, "$1 $2");
const CRITICAL = ["Administrator", "ManageGuild", "ManageRoles", "ManageChannels", "ManageWebhooks", "BanMembers", "KickMembers"].filter(n => P[n]);
const HIGH = ["MentionEveryone", "ManageMessages", "ModerateMembers", "ViewAuditLog", "ManageNicknames", "MuteMembers", "DeafenMembers", "MoveMembers", "ManageGuildExpressions", "ManageThreads", "ManageEvents"].filter(n => P[n]);
const DANGER_LEVEL = {}; CRITICAL.forEach(n => DANGER_LEVEL[n] = "critical"); HIGH.forEach(n => DANGER_LEVEL[n] = "high");
const isDanger = n => !!DANGER_LEVEL[n];
const ROLE_PERMS = Object.keys(P);
const CHANNEL_PERMS = ["CreateInstantInvite", "ManageChannels", "ManageRoles", "ManageWebhooks", "ViewChannel", "SendMessages", "SendMessagesInThreads",
    "CreatePublicThreads", "CreatePrivateThreads", "EmbedLinks", "AttachFiles", "AddReactions", "UseExternalEmojis", "UseExternalStickers", "MentionEveryone",
    "ManageMessages", "ManageThreads", "ReadMessageHistory", "SendTTSMessages", "UseApplicationCommands", "SendPolls", "SendVoiceMessages", "Connect", "Speak",
    "Stream", "UseVAD", "PrioritySpeaker", "MuteMembers", "DeafenMembers", "MoveMembers", "UseEmbeddedActivities", "UseSoundboard", "RequestToSpeak", "ManageEvents"].filter(n => P[n]);
const permMeta = list => list.map(k => ({ k, ar: PERM_AR[k] || enOf(k), en: enOf(k), danger: DANGER_LEVEL[k] || null }))
    .sort((a, b) => (b.danger ? 1 : 0) - (a.danger ? 1 : 0));

// ══════════════════════════════════════════════════════════════════════════
// 4) أدوات الموقع (بدل البوت: كل شي يجي من القاعدة)
// ══════════════════════════════════════════════════════════════════════════
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function logEvent(o) {
    try { const ev = await Event.create({ ...o, updatedAt: new Date() }); broadcastChanged(); return ev; }
    catch (e) { console.error("logEvent:", e.message); }
}
const LOGCAT = (o) => logEvent({ kind: "normal", severity: "low", ...o });

// البوت يكتب نبضة كل 30 ثانية — إذا انقطعت يعني البوت طافي
const readLastAlive = async () => { const m = await StatMeta.findById("lastAlive").lean(); return m ? Number(m.value) || 0 : 0; };
async function botAlive() { return Date.now() - (await readLastAlive()) < 100000; }

// يرسل طلب للبوت عن طريق القاعدة وينتظر النتيجة
async function callBot(type, params, timeoutMs) {
    if (!(await botAlive())) { const e = new Error("البوت غير متصل حالياً — تأكد إنه شغّال على استضافته"); e.status = 503; throw e; }
    const job = await Job.create({ type, params: params || {}, status: "pending" });
    const t0 = Date.now(), limit = timeoutMs || 25000;
    while (Date.now() - t0 < limit) {
        await sleep(300);
        const j = await Job.findById(job._id).lean();
        if (!j) break;
        if (j.status === "done") return j.result;
        if (j.status === "error") { const e = new Error(j.error || "فشل التنفيذ"); e.status = j.errStatus || 500; throw e; }
    }
    await Job.deleteOne({ _id: job._id, status: "pending" }).catch(() => {});
    const e = new Error("البوت ما رد بالوقت المناسب — حاول مرة ثانية"); e.status = 504; throw e;
}

let presenceCache = { v: true, t: 0 };
async function getPresence() {
    if (Date.now() - presenceCache.t < 30000) return presenceCache.v;
    const m = await StatMeta.findById("presence").lean();
    presenceCache = { v: !m || m.value !== "0", t: Date.now() };
    return presenceCache.v;
}
// آخر عدد أعضاء سجّله البوت (يتحدّث مع كل دخول/خروج)
async function liveMembers() { const d = await DailyStat.findOne().sort({ _id: -1 }).lean(); return d ? d.members : null; }

// ══════════════════════════════════════════════════════════════════════════
// 5) الموقع (Express) — تسجيل دخول ديسكورد + حماية بالرتبة
// ══════════════════════════════════════════════════════════════════════════
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(session({
    secret: CONFIG.SESSION_SECRET, resave: false, saveUninitialized: false,
    cookie: { maxAge: 7 * 864e5, httpOnly: true, sameSite: "lax", secure: "auto" },
}));
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(e => { console.error("❌", req.method, req.path, e.message); if (!res.headersSent) res.status(e.status || 500).json({ error: e.message || "صار خطأ بالسيرفر" }); });

// الصلاحية تجي من جدول CyberAccess اللي البوت يحدّثه لحظياً من رتب ديسكورد
const roleCheck = new Map();
async function stillAuthorized(uid) {
    const c = roleCheck.get(uid);
    if (c && Date.now() - c.t < 10000) return c;
    let level = null; // 'full' | 'view' | null
    try { const d = await Access.findById(uid).lean(); level = d && d.level ? d.level : null; } catch { level = null; }
    const res = { ok: !!level, level };
    roleCheck.set(uid, { ...res, t: Date.now() });
    return res;
}
// يرسل حدث فوري لكل صفحات هذا الشخص المفتوحة (فصل أو تغيّر صلاحيته)
function pushToUser(uid, event, data) {
    const line = "event: " + event + "\ndata: " + JSON.stringify(data || {}) + "\n\n";
    for (const res of sseClients) { if (res._uid === uid) { try { res.write(line); } catch { sseClients.delete(res); } } }
}
function applyAccess(uid, level) {
    roleCheck.set(uid, { ok: !!level, level, t: Date.now() });
    if (level) pushToUser(uid, "access", { level }); else pushToUser(uid, "dismissed");
}
const seenThrottle = new Map();
const auth = wrap(async (req, res, next) => {
    const u = req.session.user;
    if (!u) return res.status(401).json({ error: "سجّل دخولك" });
    const r = await stillAuthorized(u.id);
    if (!r.ok) { req.session.destroy(() => {}); return res.status(401).json({ error: "تم سحب صلاحيتك" }); }
    req.session.user.level = r.level;
    const last = seenThrottle.get(u.id) || 0;
    if (Date.now() - last > 30000) {
        seenThrottle.set(u.id, Date.now());
        PanelMember.updateOne({ _id: u.id }, { $set: { lastSeenAt: new Date() } }).catch(() => {});
    }
    next();
});
const full = wrap(async (req, res, next) => {
    if (req.session.user.level !== "full") return res.status(403).json({ error: "هذا الإجراء يحتاج صلاحية القائد أو النائب" });
    next();
});

app.get("/auth/discord", (req, res) => {
    const state = crypto.randomBytes(16).toString("hex");
    req.session.oauthState = state;
    const q = new URLSearchParams({ client_id: CONFIG.DISCORD_CLIENT_ID, redirect_uri: CONFIG.DISCORD_CALLBACK_URL, response_type: "code", scope: "identify", state });
    req.session.save(() => res.redirect("https://discord.com/oauth2/authorize?" + q));
});

app.get("/auth/discord/callback", wrap(async (req, res) => {
    const { code, state } = req.query;
    if (!code || !state || state !== req.session.oauthState) return res.redirect("/?err=1");
    delete req.session.oauthState;
    const tr = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: CONFIG.DISCORD_CLIENT_ID, client_secret: CONFIG.DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code: String(code), redirect_uri: CONFIG.DISCORD_CALLBACK_URL }),
    });
    if (!tr.ok) return res.redirect("/?err=1");
    const tok = await tr.json();
    const ur = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + tok.access_token } });
    if (!ur.ok) return res.redirect("/?err=1");
    const u = await ur.json();
    roleCheck.delete(u.id);
    const r0 = await stillAuthorized(u.id);
    const allowed = r0.ok;
    if (!allowed) {
        await LOGCAT({ cat: "panel", severity: "medium", title: "محاولة دخول مرفوضة للوحة", details: "ما معه رتبة الأمن السيبراني", actorId: u.id, actorTag: u.username, data: { act: "panel_denied" } });
        req.session.denied = true;
        return req.session.save(() => res.redirect("/?denied=1"));
    }
    const avatar = u.avatar ? "https://cdn.discordapp.com/avatars/" + u.id + "/" + u.avatar + ".png?size=64" : "https://cdn.discordapp.com/embed/avatars/0.png";
    req.session.user = { id: u.id, tag: u.global_name || u.username, level: r0.level, avatar };
    delete req.session.denied;
    const now = new Date();
    await PanelMember.findByIdAndUpdate(u.id, { _id: u.id, tag: u.global_name || u.username, avatar, lastLoginAt: now, lastSeenAt: now }, { upsert: true }).catch(() => {});
    await LOGCAT({ cat: "panel", title: "تسجيل دخول للوحة", details: "", actorId: u.id, actorTag: u.username, data: { act: "panel_login" } });
    req.session.save(() => res.redirect("/"));
}));
app.get("/auth/logout", (req, res) => req.session.destroy(() => res.redirect("/")));


// ── API: من أنا ──
app.get("/api/me", auth, wrap(async (req, res) => res.json({ user: req.session.user, presence: await getPresence() })));

// ── بث فوري (SSE): يخبر الموقع إنه فيه تحديث جديد باللوق، بدون أي ريفرش للصفحة ──
app.get("/api/events/stream", wrap(async (req, res) => {
    const u = req.session.user;
    if (!u) return res.status(401).end();
    const r = await stillAuthorized(u.id);
    if (!r.ok) return res.status(401).end();
    res.set({ "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.flushHeaders?.();
    res.write("retry: 3000\n\n");
    res._uid = u.id;
    sseClients.add(res);
    const hb = setInterval(() => { try { res.write(": ping\n\n"); } catch { } }, 25000);
    req.on("close", () => { clearInterval(hb); sseClients.delete(res); });
}));

// ── API: صورة مرفق محذوف (بيانات ثنائية حقيقية — بدون base64) ──
app.get("/api/images/:id", auth, wrap(async (req, res) => {
    const img = await EventImage.findById(req.params.id).lean();
    if (!img) return res.status(404).end();
    res.set({ "Content-Type": img.contentType || "image/png", "Cache-Control": "private, max-age=86400" });
    const bin = Buffer.isBuffer(img.data) ? img.data : Buffer.from(img.data?.buffer || img.data || []);
    res.send(bin);
}));

// ── API: اللوق ──
const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ── بحث اللوق بالوقت والتاريخ (عربي / إنجليزي) ──
const TZ_OFF = "+03:00";   // توقيت الرياض
const FILL = "\u0001";
const normQ = s => String(s || "")
    .replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, " ")
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660))
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x06F0))
    .replace(/[أإآٱ]/g, "ا").replace(/ى/g, "ي").replace(/ة/g, "ه").replace(/،/g, " ")
    .toLowerCase();
const MONTHS_Q = {
    يناير: 1, فبراير: 2, مارس: 3, ابريل: 4, مايو: 5, يونيو: 6, يونيه: 6, يوليو: 7, يوليه: 7, اغسطس: 8, سبتمبر: 9, اكتوبر: 10, نوفمبر: 11, ديسمبر: 12,
    شباط: 2, اذار: 3, نيسان: 4, ايار: 5, حزيران: 6, تموز: 7, ايلول: 9,
    january: 1, february: 2, march: 3, april: 4, may: 5, june: 6, july: 7, august: 8, september: 9, october: 10, november: 11, december: 12,
    jan: 1, feb: 2, apr: 4, jun: 6, jul: 7, aug: 8, sept: 9, sep: 9, oct: 10, nov: 11, dec: 12,
};
const DOW_Q = {   // 1 = الأحد (نفس ترقيم MongoDB)
    احد: 1, اثنين: 2, اتنين: 2, ثلاثاء: 3, ثلاثا: 3, اربعاء: 4, اربعا: 4, خميس: 5, جمعه: 6, سبت: 7,
    sunday: 1, monday: 2, tuesday: 3, wednesday: 4, thursday: 5, friday: 6, saturday: 7,
};
const altOf = o => Object.keys(o).sort((a, b) => b.length - a.length).join("|");
const PER = "am|pm|ص|م|صباحا|صباح|مساء|ظهرا|ظهر|عصرا|عصر|ليلا|ليل|فجرا|فجر";
const PFX = "(?:(?:الساعه|ساعه|at)\\s*)?";
const NB = "(?<![\\p{L}\\d:.\\/-])", NA = "(?![\\d:.\\/-])";
const SEP = "\\s*[-\\/.]\\s*";
const RE_ISO = new RegExp(NB + "(\\d{4})" + SEP + "(\\d{1,2})" + SEP + "(\\d{1,2})" + NA, "gu");
const RE_DMY = new RegExp(NB + "(\\d{1,2})" + SEP + "(\\d{1,2})" + SEP + "(\\d{4})" + NA, "gu");
const RE_YM = new RegExp(NB + "(\\d{4})\\s*[-\\/]\\s*(\\d{1,2})" + NA, "gu");
const RE_DM = new RegExp(NB + "(\\d{1,2})\\s*[-\\/]\\s*(\\d{1,2})" + NA, "gu");
const RE_TCOL = new RegExp(PFX + NB + "(\\d{1,2}):(\\d{2})(?::\\d{2})?(?:\\s*(" + PER + ")[\\u064B-\\u065F]*(?![\\p{L}]))?", "gu");
const RE_THOUR = new RegExp(PFX + NB + "(\\d{1,2})\\s*(" + PER + ")[\\u064B-\\u065F]*(?![\\p{L}])", "gu");
const RE_THPFX = new RegExp("(?:الساعه|ساعه|at)\\s*(\\d{1,2})(?![\\d:.\\/-])", "gu");
const RE_MONTH = new RegExp("(?:(?<![\\d:.\\/-])(\\d{1,2})\\s*)?(?<![\\p{L}])(" + altOf(MONTHS_Q) + ")(?![\\p{L}])(?:\\s*(\\d{1,2})(?![\\d:.\\/-]))?(?:\\s*(20\\d{2})(?!\\d))?", "gu");
const RE_DOW = new RegExp("(?<![\\p{L}\\d])(?:ال)?(" + altOf(DOW_Q) + ")(?![\\p{L}])", "gu");
const RE_YEAR = new RegExp(NB + "(20\\d{2})" + NA, "gu");
const REL_Q = [
    [/(?<![\p{L}\d])(?:اول\s+امس|قبل\s+امس|day\s+before\s+yesterday)(?![\p{L}])/gu, -2],
    [/(?<![\p{L}\d])(?:امس|البارحه|yesterday)(?![\p{L}])/gu, -1],
    [/(?<![\p{L}\d])(?:اليوم|today)(?![\p{L}])/gu, 0],
];
const STOP_Q = /^(في|شهر|يوم|بتاريخ|تاريخ|وقت|الوقت|ساعه|الساعه|ميلادي|عام|سنه|at|on|in|of|the|date|time|day|month|year)$/;
const perOf = p => (p[0] === "a" || p[0] === "ص" || p.startsWith("فجر")) ? "am" : (p[0] === "p" || p[0] === "م" || p[0] === "ع") ? "pm" : p[0] === "ظ" ? "noon" : "night";
function hoursFor(h, per) {
    if (h > 23) return null;
    if (per === "am") return [h === 12 ? 0 : h];
    if (per === "pm") return [h < 12 ? h + 12 : h];
    if (per === "noon") return [h >= 1 && h <= 5 ? h + 12 : h];
    if (per === "night") return [h === 12 ? 0 : (h >= 6 && h < 12 ? h + 12 : h)];
    if (h === 0 || h > 12) return [h];
    return [h, (h + 12) % 24];
}
// يحلّل نص البحث: يطلّع شروط الوقت/التاريخ، والباقي يبقى بحث بالاسم
function parseWhen(q) {
    const raw = String(q || "").trim();
    const none = { conds: [], rest: raw };
    if (!raw || /^\d{12,}$/.test(raw)) return none;
    const s = normQ(raw);
    if (s.length !== raw.length) return none;
    const G = {}; let any = false, w = s;
    const eat = (re, fn) => { w = w.replace(re, (m, ...g) => { if (!fn(g)) return m; any = true; return FILL.repeat(m.length); }); };
    const okD = v => v >= 1 && v <= 31, okM = v => v >= 1 && v <= 12, okY = v => v >= 2020 && v <= new Date().getFullYear() + 1;
    eat(RE_ISO, g => { const y = +g[0], m = +g[1], d = +g[2]; if (!okY(y) || !okM(m) || !okD(d)) return false; G.y = y; G.m = m; G.day = d; return true; });
    eat(RE_DMY, g => { const d = +g[0], m = +g[1], y = +g[2]; if (!okY(y) || !okM(m) || !okD(d)) return false; G.y = y; G.m = m; G.day = d; return true; });
    eat(RE_YM, g => { const y = +g[0], m = +g[1]; if (!okY(y) || !okM(m)) return false; G.y = y; G.m = m; return true; });
    eat(RE_DM, g => { let d = +g[0], m = +g[1]; if (m > 12 && d <= 12) [d, m] = [m, d]; if (!okM(m) || !okD(d)) return false; G.m = m; G.day = d; return true; });
    const setTime = (h, min, per) => { const hs = hoursFor(h, per ? perOf(per) : null); if (!hs || (min != null && min > 59)) return false; G.hours = hs; if (min != null) G.min = min; return true; };
    eat(RE_TCOL, g => setTime(+g[0], +g[1], g[2]));
    eat(RE_THOUR, g => setTime(+g[0], null, g[1]));
    eat(RE_THPFX, g => setTime(+g[0], null, null));
    for (const [re, back] of REL_Q) eat(re, () => {
        const k = dayKeyOf(Date.now() + back * DAY); G.y = +k.slice(0, 4); G.m = +k.slice(5, 7); G.day = +k.slice(8, 10); return true;
    });
    eat(RE_MONTH, g => {
        const m = MONTHS_Q[g[1].replace(/\s+/g, " ")]; const d = g[0] || g[2];
        if (!m || (d && !okD(+d))) return false;
        G.m = m; if (d) G.day = +d; if (g[3]) G.y = +g[3]; return true;
    });
    eat(RE_DOW, g => { G.dow = DOW_Q[g[0]]; return !!G.dow; });
    eat(RE_YEAR, g => { if (!okY(+g[0])) return false; G.y = +g[0]; return true; });
    if (!any) return none;
    let rest = "";
    for (let i = 0; i < raw.length; i++) rest += w[i] === FILL ? " " : raw[i];
    rest = rest.split(/\s+/).filter(t => t && !STOP_Q.test(normQ(t)) && !/^[\s،,.:;\-\/\\|]+$/.test(t)).join(" ");
    const part = op => ({ [op]: { date: "$createdAt", timezone: TZ_OFF } });
    const conds = [];
    if (G.y != null) conds.push({ $eq: [part("$year"), G.y] });
    if (G.m != null) conds.push({ $eq: [part("$month"), G.m] });
    if (G.day != null) conds.push({ $eq: [part("$dayOfMonth"), G.day] });
    if (G.dow != null) conds.push({ $eq: [part("$dayOfWeek"), G.dow] });
    if (G.hours) conds.push({ $in: [part("$hour"), G.hours] });
    if (G.min != null) conds.push({ $eq: [part("$minute"), G.min] });
    return { conds, rest };
}

// كاش لقائمة أعضاء السيرفر (من البوت) — لعرض اسم الشخص بالسيرفر ويوزره في تفاصيل العملية
let memCache = { t: 0, map: null }, memInflight = null;
async function getMemberMap() {
    if (memCache.map && Date.now() - memCache.t < 120000) return memCache.map;
    if (!memInflight) memInflight = (async () => {
        try {
            const r = await callBot("perm_members", {}, 60000);
            const map = new Map(); (r.members || []).forEach(m => map.set(String(m.id), m));
            memCache = { t: Date.now(), map };
            return map;
        } catch (e) { if (memCache.map) return memCache.map; throw e; }
        finally { memInflight = null; }
    })();
    return memInflight;
}
app.get("/api/events", auth, wrap(async (req, res) => {
    const { q, cat, unres, before, cu } = req.query;
    const f = {};
    if (cu === "1") f["data.catchup"] = true;
    if (cat === "sus") f.kind = "suspicious";
    else if (cat === "newacc") f.rule = "new_account";
    else if (cat === "probot") f["data.probot"] = true;
    else if (cat) f.cat = cat;
    if (unres === "1") { f.kind = "suspicious"; f.resolved = false; }
    if (before) f.createdAt = { $lt: new Date(Number(before)) };
    if (q && String(q).trim()) {
        const t = String(q).trim(), w = parseWhen(t);
        if (w.conds.length) f.$expr = { $and: w.conds };          // بحث بالوقت / التاريخ
        const nm = w.conds.length ? w.rest : t;                    // الباقي بحث بالاسم / الآيدي
        if (nm) { const re = new RegExp(escRe(nm), "i"); f.$or = [{ actorId: nm }, { targetId: nm }, { actorTag: re }, { targetTag: re }]; }
    }
    const list = await Event.find(f).sort({ createdAt: -1 }).limit(50).select("-data.messages").lean();
    const evIds = list.map(e => e._id);
    const inqIds = list.map(e => e.data && e.data.inqId).filter(x => x && mongoose.isValidObjectId(x));
    const inqs = evIds.length ? await Inquiry.find({ $or: [{ eventId: { $in: evIds } }, { _id: { $in: inqIds } }] }).select("eventId dmTag status reason").lean() : [];
    const byEv = {}, byId = {};
    inqs.forEach(i => { if (i.eventId) byEv[String(i.eventId)] = i; byId[String(i._id)] = i; });
    res.json({ events: list.map(e => {
        const i = (e.data && e.data.inqId && byId[String(e.data.inqId)]) || byEv[String(e._id)];
        return { ...e, hasMsgs: !!(e.data && (e.data.act === "bulk_delete" || e.data.act === "mass_msg_delete")), inq: i ? { id: String(i._id), status: i.status, dmTag: i.dmTag } : null };
    }) });
}));
// ── تفاصيل عملية وحدة (للفورم اللي يطلع لما تضغط على العملية) ──
app.get("/api/events/:id/info", auth, wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "عملية غير صحيحة" });
    const e = await Event.findById(req.params.id).select("-data.messages").lean();
    if (!e) return res.status(404).json({ error: "العملية غير موجودة" });
    const d = e.data || {};
    res.json({ event: {
        _id: String(e._id), title: e.title, details: e.details, cat: e.cat, rule: e.rule, kind: e.kind, severity: e.severity, count: e.count || 1,
        resolved: !!e.resolved, resolvedBy: e.resolvedBy || null, resolvedAt: e.resolvedAt || null, createdAt: e.createdAt,
        actorId: e.actorId || null, actorTag: e.actorTag || null, targetId: e.targetId || null, targetTag: e.targetTag || null,
        channel: d.channel || null, probot: !!d.probot, catchup: !!d.catchup,
        images: (Array.isArray(d.images) ? d.images : []).filter(i => i && i.id).map(i => ({ id: String(i.id) })),
        hasMsgs: d.act === "bulk_delete" || d.act === "mass_msg_delete",
    } });
}));
// اسم الشخص بالسيرفر + يوزره (من قائمة أعضاء البوت)
app.get("/api/people/lookup", auth, wrap(async (req, res) => {
    const ids = [...new Set(String(req.query.ids || "").split(",").map(x => x.trim()).filter(x => /^\d{5,25}$/.test(x)))].slice(0, 6);
    if (!ids.length) return res.json({ ok: true, people: {} });
    const map = await getMemberMap().catch(() => null);
    if (!map) return res.json({ ok: false, people: {} });
    const people = {};
    ids.forEach(id => { const m = map.get(id); if (m) people[id] = { server: m.server || null, global: m.global || null, username: m.username || null, avatar: m.avatar || null, bot: !!m.bot }; });
    res.json({ ok: true, people });
}));
app.get("/api/events/:id/messages", auth, wrap(async (req, res) => {
    const e = await Event.findById(req.params.id).lean();
    res.json({ messages: (e && e.data && e.data.messages) || [], channel: e?.data?.channel, probot: !!e?.data?.probot, title: e?.title });
}));

async function panelLog(req, title, details, extra = {}) {
    await LOGCAT({ cat: "panel", title, details, actorId: req.session.user.id, actorTag: req.session.user.tag, data: { act: "panel_action" }, ...extra });
}

// ── تنفيذ العلاج (الأزرار) — البوت هو اللي ينفّذ ──
app.post("/api/events/:id/remedy", auth, full, wrap(async (req, res) => {
    const e = await Event.findById(req.params.id);
    if (!e || !e.remedy) return res.status(404).json({ error: "ما فيه إجراء لهذي العملية" });
    const out = await callBot("remedy", { remedy: JSON.parse(JSON.stringify(e.remedy)), who: req.session.user.tag }, 90000);
    const msg = out.msg;
    if (!e.resolved) { e.resolved = true; e.resolvedBy = req.session.user.tag; e.resolvedAt = new Date(); e.updatedAt = new Date(); await e.save(); }   // لو كانت محلولة قبل نخلّي اللي حلّها كما هو
    await panelLog(req, "تنفيذ إجراء: " + e.remedy.label.replace(/^\S+\s/, ""), "العملية: " + e.title + " — " + msg);
    res.json({ ok: true, msg });
}));
app.post("/api/events/:id/resolve", auth, full, wrap(async (req, res) => {
    const e = await Event.findById(req.params.id);
    if (!e) return res.status(404).json({ error: "غير موجودة" });
    e.resolved = true; e.resolvedBy = req.session.user.tag; e.resolvedAt = new Date(); e.updatedAt = new Date(); await e.save();
    await panelLog(req, "حل عملية مشبوهة", "العملية: " + e.title);
    res.json({ ok: true });
}));

// ── استفسار الرتب: زر في اللوق يرسل للعضو بالخاص يسأله ليش عطى الرتبة ──
app.post("/api/events/:id/inquire", auth, full, wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "عملية غير صحيحة" });
    const e = await Event.findById(req.params.id).lean();
    if (!e) return res.status(404).json({ error: "العملية غير موجودة" });
    if (e.cat !== "role" || !e.actorId || !e.data || e.data.act !== "member_roles" || !String(e.details || "").includes("أُعطي")) return res.status(400).json({ error: "الزر فقط لعمليات إعطاء رتبة لعضو" });
    if (await Inquiry.findOne({ eventId: e._id })) return res.status(409).json({ error: "انرسل استفسار على هذي العملية من قبل" });
    if (await Inquiry.findOne({ dmId: e.actorId, status: "sent" })) return res.status(409).json({ error: "فيه استفسار مفتوح لهذا الشخص وينتظر رده" });
    const u = req.session.user;
    const inq = await Inquiry.create({
        eventId: e._id, dmId: e.actorId, dmTag: e.actorTag, subjectTag: e.targetTag || null,
        about: [e.title, e.details].filter(Boolean).join(" — ").slice(0, 500),
        senderId: u.id, senderTag: u.tag, senderAvatar: u.avatar,
    });
    try { await callBot("inq_send", { id: String(inq._id) }, 30000); }
    catch (err) { await Inquiry.deleteOne({ _id: inq._id }).catch(() => {}); throw err; }
    await panelLog(req, "إرسال استفسار عن رتبة", "المرسل له: " + (e.actorTag || e.actorId) + (e.targetTag ? "\nعن إعطاء: " + e.targetTag : ""), { targetId: e.actorId, targetTag: e.actorTag });
    res.json({ ok: true });
}));
app.post("/api/inquiries/:id/decide", auth, full, wrap(async (req, res) => {
    const d = req.body && req.body.decision;
    if (!["covenant", "investigation"].includes(d)) return res.status(400).json({ error: "قرار غير صحيح" });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "استفسار غير صحيح" });
    const u = req.session.user;
    // قفل ذري: ما ينفّذ القرار إلا مرة وحدة
    const inq = await Inquiry.findOneAndUpdate({ _id: req.params.id, status: "replied" },
        { $set: { status: d, decidedBy: u.tag, decidedById: u.id, decidedAvatar: u.avatar, decidedAt: new Date() } }, { new: true }).lean();
    if (!inq) return res.status(409).json({ error: "تم اتخاذ قرار على هذا الاستفسار من قبل (أو العضو ما رد بعد)" });
    try { await callBot("inq_notify", { id: String(inq._id) }, 30000); }
    catch (err) {
        await Inquiry.updateOne({ _id: inq._id }, { $set: { status: "replied" }, $unset: { decidedBy: 1, decidedById: 1, decidedAvatar: 1, decidedAt: 1 } }).catch(() => {});
        throw err;
    }
    await panelLog(req, d === "covenant" ? "تم التعاهد (استفسار رتبة)" : "تحويل للتحقيق (استفسار رتبة)", "العضو: " + (inq.dmTag || inq.dmId) + "\nالسبب اللي كتبه: " + String(inq.reason || "").slice(0, 300), { targetId: inq.dmId, targetTag: inq.dmTag });
    res.json({ ok: true });
}));

// ── API: البوتات ──
app.get("/api/bots", auth, wrap(async (req, res) => {
    const r = await callBot("bots");
    res.json({ bots: r.bots, presence: r.presence });
}));
app.post("/api/bots/:id/kick", auth, full, wrap(async (req, res) => {
    const r = await callBot("bot_kick", { id: req.params.id, who: req.session.user.tag });
    await panelLog(req, "طرد بوت", "البوت: " + r.name, { targetId: r.id, targetTag: r.name });
    res.json({ ok: true });
}));

// ── نشاط بوت معيّن آخر 7 أيام (من اللوق: أي عملية سواها البوت) ──
app.get("/api/bots/:id/activity", auth, wrap(async (req, res) => {
    const id = String(req.params.id || "");
    if (!/^\d{5,25}$/.test(id)) return res.status(400).json({ error: "آيدي البوت غير صحيح" });
    const today = dayKeyOf(Date.now()), from = addDays(today, -6);
    const evs = await Event.find({ actorId: id, createdAt: { $gte: dayStart(from) } }).sort({ createdAt: -1 }).limit(1000)
        .select("title details cat rule kind severity targetTag resolved resolvedBy createdAt actorTag").lean();
    const days = [];
    for (let k = from; k <= today; k = addDays(k, 1)) {
        const l = evs.filter(e => dayKeyOf(e.createdAt) === k);
        days.push({ d: k, total: l.length, sus: l.filter(e => e.kind === "suspicious").length });
    }
    const byCat = {}; evs.forEach(e => { const c = e.cat || "other"; byCat[c] = (byCat[c] || 0) + 1; });
    res.json({
        id, from, to: today, name: evs.length ? evs[0].actorTag : null,
        total: evs.length, sus: evs.filter(e => e.kind === "suspicious").length, unresolved: evs.filter(e => e.kind === "suspicious" && !e.resolved).length,
        days, byCat, truncated: evs.length >= 1000,
        ops: evs.slice(0, 500).map(e => ({ id: String(e._id), title: e.title, details: String(e.details || "").slice(0, 400), cat: e.cat, rule: e.rule, sus: e.kind === "suspicious",
            severity: e.severity, target: e.targetTag, resolved: !!e.resolved, resolvedBy: e.resolvedBy || null, createdAt: e.createdAt })),
    });
}));

// ── إحصائيات: أيام / أسابيع / عدد الأعضاء ──
const DAY = 864e5;
const dayKeyOf = t => new Date(new Date(t).getTime() + 3 * 3600e3).toISOString().slice(0, 10);   // تاريخ اليوم بتوقيت الرياض
const keyToMs = k => Date.parse(k + "T00:00:00Z");
const addDays = (k, n) => new Date(keyToMs(k) + n * DAY).toISOString().slice(0, 10);
const dayStart = k => new Date(keyToMs(k) - 3 * 3600e3);                                          // بداية اليوم بتوقيت الرياض
const isKey = k => /^\d{4}-\d{2}-\d{2}$/.test(k || "") && !isNaN(keyToMs(k));

async function getEpoch() {
    let m = await StatMeta.findById("epoch").lean();
    if (m) return m.value;
    const first = await Event.findOne().sort({ createdAt: 1 }).select("createdAt").lean();
    const v = dayKeyOf(first ? first.createdAt : Date.now());
    try { await StatMeta.create({ _id: "epoch", value: v }); } catch { m = await StatMeta.findById("epoch").lean(); return m ? m.value : v; }
    return v;
}
const loadStats = () => DailyStat.find().sort({ _id: 1 }).lean();
const membersOn = (docs, key) => { let r = null; for (const d of docs) { if (d._id <= key) r = d; else break; } return r ? { key: r._id, value: r.members } : null; };
function memberChange(docs, from, to, live) {
    const end = (live != null && to === dayKeyOf(Date.now())) ? { key: to, value: live } : membersOn(docs, to);
    const base = membersOn(docs, addDays(from, -1));
    return { end: end ? end.value : null, base: base ? base.value : null, baseKey: base ? base.key : null, delta: end && base ? end.value - base.value : null };
}
function dayRows(evs, docs, from, to) {
    const rows = [];
    for (let k = from; k <= to; k = addDays(k, 1)) {
        const list = evs.filter(e => dayKeyOf(e.createdAt) === k);
        const end = membersOn(docs, k), base = membersOn(docs, addDays(k, -1));
        rows.push({ d: k, total: list.length, resolved: list.filter(e => e.resolved).length, unresolved: list.filter(e => !e.resolved).length,
            members: end ? end.value : null, delta: end && base ? end.value - base.value : null });
    }
    return rows;
}
const countBy = evs => { const o = {}; evs.forEach(e => { const k = e.rule || "other"; o[k] = (o[k] || 0) + 1; }); return o; };

// يبني قائمة الأسابيع (كل أسبوع 7 أيام من أول يوم تسجيل) ويحفظ الأسابيع المكتملة بالأرشيف
async function buildWeeks() {
    const epoch = await getEpoch(), today = dayKeyOf(Date.now());
    const cur = Math.floor((keyToMs(today) - keyToMs(epoch)) / DAY / 7) + 1;
    const docs = await loadStats();
    const retentionStart = dayKeyOf(Date.now() - 59 * DAY);   // الأحداث تنحذف بعد 60 يوم
    const evs = await Event.find({ kind: "suspicious", createdAt: { $gte: dayStart(epoch) } }).select("rule resolved createdAt").lean();
    const arch = {}; (await WeekArchive.find().lean()).forEach(a => arch[a._id] = a);
    const weeks = [];
    for (let n = 1; n <= cur; n++) {
        const start = addDays(epoch, (n - 1) * 7), end = addDays(epoch, n * 7 - 1);
        const upto = end < today ? end : today, complete = end < today;
        const inWeek = evs.filter(e => { const k = dayKeyOf(e.createdAt); return k >= start && k <= end; });
        const mc = memberChange(docs, start, upto, null);
        let w = { no: n, start, end, complete, total: inWeek.length, resolved: inWeek.filter(e => e.resolved).length, unresolved: inWeek.filter(e => !e.resolved).length,
            byRule: countBy(inWeek), days: dayRows(inWeek, docs, start, upto), membersEnd: mc.end, membersBase: mc.base, delta: mc.delta };
        const a = arch[n];
        if (!inWeek.length && a && a.total) w = { ...w, total: a.total, resolved: a.resolved, unresolved: a.unresolved, byRule: a.byRule || {}, days: a.days || w.days, fromArchive: true };
        else if (complete && start >= retentionStart) {
            await WeekArchive.updateOne({ _id: n }, { $set: { start, end, total: w.total, resolved: w.resolved, unresolved: w.unresolved, byRule: w.byRule, days: w.days, savedAt: new Date() } }, { upsert: true }).catch(() => {});
        }
        weeks.push(w);
    }
    return { epoch, today, current: cur, weeks };
}
async function archiveWeeks() { try { await buildWeeks(); } catch (e) { console.error("archiveWeeks:", e.message); } }

app.get("/api/stats/weeks", auth, wrap(async (req, res) => {
    const w = await buildWeeks();
    res.json({ today: w.today, current: w.current, weeks: w.weeks.map(x => ({ no: x.no, start: x.start, end: x.end, complete: x.complete, total: x.total, resolved: x.resolved, unresolved: x.unresolved, membersEnd: x.membersEnd, delta: x.delta })) });
}));
app.get("/api/stats/range", auth, wrap(async (req, res) => {
    const from = String(req.query.from || ""), to = String(req.query.to || req.query.from || "");
    if (!isKey(from) || !isKey(to) || from > to || keyToMs(to) - keyToMs(from) > 62 * DAY) return res.status(400).json({ error: "تاريخ غير صحيح" });
    const docs = await loadStats(), liveM = await liveMembers();
    const rangeQ = { $gte: dayStart(from), $lt: dayStart(addDays(to, 1)) };
    const evs = await Event.find({ kind: "suspicious", createdAt: rangeQ }).sort({ createdAt: -1 }).limit(2000)
        .select("title details rule severity actorTag targetTag resolved resolvedBy createdAt").lean();
    const joins = await Event.countDocuments({ kind: "normal", cat: "join", createdAt: rangeQ });
    const leaves = await Event.countDocuments({ kind: "normal", cat: { $in: ["leave", "kick", "ban"] }, createdAt: rangeQ });
    let out = {
        from, to, total: evs.length, resolved: evs.filter(e => e.resolved).length, unresolved: evs.filter(e => !e.resolved).length, byRule: countBy(evs),
        days: dayRows(evs, docs, from, to), members: memberChange(docs, from, to, liveM), joins, leaves, archived: false, truncated: evs.length > 500,
        ops: evs.slice(0, 500).map(e => ({ id: String(e._id), title: e.title, details: String(e.details || "").slice(0, 500), rule: e.rule, severity: e.severity,
            actor: e.actorTag, target: e.targetTag, resolved: !!e.resolved, resolvedBy: e.resolvedBy || null, createdAt: e.createdAt })),
    };
    const wk = parseInt(req.query.week, 10);
    if (!evs.length && wk > 0) {
        const a = await WeekArchive.findById(wk).lean();
        if (a && a.total) out = { ...out, total: a.total, resolved: a.resolved, unresolved: a.unresolved, byRule: a.byRule || {}, days: a.days || out.days, archived: true };
    }
    res.json(out);
}));


// ── استرجاع الفائت من سجل ديسكورد (البوت هو اللي يقرأ السجل) ──
let catchRunning = false;
app.post("/api/catchup", auth, full, wrap(async (req, res) => {
    let hours = parseInt(req.body.hours, 10) || 0;
    if (!hours) {
        hours = 24;
        const gm = await StatMeta.findById("lastGap").lean(), gs = gm ? Number(gm.value) : 0;
        if (gs && Date.now() - gs <= 7 * 864e5) hours = Math.max(hours, Math.ceil((Date.now() - gs) / 3600e3) + 1);
    }
    hours = Math.min(Math.max(hours, 1), 24 * 44);
    if (catchRunning) return res.status(409).json({ error: "فيه استرجاع شغّال الحين، انتظر يخلص" });
    catchRunning = true;
    try {
        const out = await callBot("catchup", { hours }, 600000);
        await panelLog(req, "استرجاع الفائت من سجل ديسكورد", "المدة: آخر " + hours + " ساعة\nالمسترجع: " + out.n + " عملية");
        res.json({ ok: true, n: out.n, hours, probot: out.probot, events: out.events });
    } finally { catchRunning = false; }
}));

// ── API: الإحصائيات ──
app.get("/api/stats", auth, wrap(async (req, res) => {
    const since = new Date(Date.now() - 7 * 864e5);
    const sus = await Event.find({ kind: "suspicious", createdAt: { $gte: since } }).select("rule createdAt resolved").lean();
    const dayKey = t => new Date(new Date(t).getTime() + 3 * 3600e3).toISOString().slice(0, 10);
    const days = [];
    for (let i = 6; i >= 0; i--) days.push({ d: dayKey(Date.now() - i * 864e5), n: 0 });
    const byRule = {};
    sus.forEach(e => {
        const d = days.find(x => x.d === dayKey(e.createdAt)); if (d) d.n++;
        byRule[e.rule || "other"] = (byRule[e.rule || "other"] || 0) + 1;
    });
    let bl;
    try { bl = await callBot("bots"); }
    catch (e) { bl = { bots: [], presence: await getPresence(), members: await liveMembers() }; }   // البوت طافي — نكمل بالباقي من القاعدة
    const bots = bl.bots;
    const online = bots.filter(b => b.status !== "offline" && b.status !== "unknown");
    const offline = bots.filter(b => b.status === "offline");
    res.json({
        week: sus.length, unresolved: sus.filter(e => !e.resolved).length, resolved: sus.filter(e => e.resolved).length,
        today: (() => { const t = sus.filter(e => dayKey(e.createdAt) === dayKey(Date.now())); return { total: t.length, resolved: t.filter(e => e.resolved).length, unresolved: t.filter(e => !e.resolved).length }; })(),
        days, byRule, members: bl.members, presence: bl.presence,
        bots: { total: bots.length, online: online.map(b => ({ id: b.id, name: b.name, status: b.status })), offline: offline.map(b => ({ id: b.id, name: b.name })) },
    });
}));


// ── API: صلاحيات السيرفر (القراءة والتعديل عن طريق البوت) ──
app.get("/api/perms/meta", auth, (req, res) => res.json({ role: permMeta(ROLE_PERMS), channel: permMeta(CHANNEL_PERMS) }));
app.get("/api/perms/roles", auth, wrap(async (req, res) => res.json(await callBot("roles"))));
app.get("/api/perms/roles/:id/members", auth, wrap(async (req, res) => res.json(await callBot("role_members", { id: req.params.id }, 60000))));
app.put("/api/perms/roles/:id", auth, full, wrap(async (req, res) => {
    const r = await callBot("role_update", { id: req.params.id, perms: req.body.perms || [], who: req.session.user.tag });
    await panelLog(req, "تعديل صلاحيات رتبة", "الرتبة: " + r.name + (r.add.length ? "\n➕ " + r.add.map(n => PERM_AR[n] || n).join("، ") : "") + (r.rem.length ? "\n➖ " + r.rem.map(n => PERM_AR[n] || n).join("، ") : ""), { targetId: r.id, targetTag: r.name });
    res.json({ ok: true });
}));
app.get("/api/perms/members", auth, wrap(async (req, res) => res.json(await callBot("perm_members", {}, 60000))));
app.put("/api/perms/members/:id/roles", auth, full, wrap(async (req, res) => {
    const r = await callBot("member_roles", { id: req.params.id, add: req.body.add, remove: req.body.remove, who: req.session.user.tag });
    roleCheck.delete(r.id);
    await panelLog(req, "تعديل رتب عضو", "العضو: " + r.tag + (r.add.length ? "\n➕ " + r.add.join("، ") : "") + (r.rem.length ? "\n➖ " + r.rem.join("، ") : ""), { targetId: r.id, targetTag: r.tag });
    res.json({ ok: true });
}));
app.get("/api/perms/channels", auth, wrap(async (req, res) => res.json(await callBot("channels", {}, 60000))));
app.put("/api/perms/channels/:id/:tid", auth, full, wrap(async (req, res) => {
    const r = await callBot("channel_edit", { id: req.params.id, tid: req.params.tid, allow: req.body.allow || [], deny: req.body.deny || [], who: req.session.user.tag });
    await panelLog(req, "تعديل صلاحيات قناة", "القناة: #" + r.name + "\nالهدف: " + (req.body.name || req.params.tid), { targetId: r.id, targetTag: r.name });
    res.json({ ok: true });
}));
app.delete("/api/perms/channels/:id/:tid", auth, full, wrap(async (req, res) => {
    const r = await callBot("channel_ow_delete", { id: req.params.id, tid: req.params.tid, who: req.session.user.tag });
    await panelLog(req, "حذف صلاحيات من قناة", "القناة: #" + r.name + "\nالمحذوف: " + r.target + (r.isRole ? " (رتبة)" : " (عضو)"), { targetId: r.id, targetTag: r.name });
    res.json({ ok: true });
}));

// ── API: أعضاء الأمن السيبراني (للقائد والنائب فقط) ──
app.get("/api/members", auth, full, wrap(async (req, res) => {
    const r = await callBot("members", { meId: req.session.user.id }, 60000);
    const panelDocs = await PanelMember.find({ _id: { $in: r.members.map(m => m.id) } }).lean();
    const panelMap = {}; panelDocs.forEach(d => panelMap[d._id] = d);
    const out = r.members.map(m => {
        const p = panelMap[m.id];
        const durationMin = (p && p.lastLoginAt && p.lastSeenAt) ? Math.max(1, Math.round((new Date(p.lastSeenAt) - new Date(p.lastLoginAt)) / 60000)) : null;
        return { id: m.id, tag: m.tag, avatar: m.avatar, rank: m.rank, lastLoginAt: p?.lastLoginAt || null, lastSeenAt: p?.lastSeenAt || null, durationMin };
    }).sort((a, b) => {
        const w = x => x === "leader" ? 0 : x === "deputy" ? 1 : 2;
        return w(a.rank) - w(b.rank) || (b.lastLoginAt ? new Date(b.lastLoginAt).getTime() : 0) - (a.lastLoginAt ? new Date(a.lastLoginAt).getTime() : 0);
    });
    res.json({ members: out, meRank: r.meRank });
}));
app.get("/api/members/:id/activity", auth, full, wrap(async (req, res) => {
    if (!/^\d{5,25}$/.test(req.params.id)) return res.status(400).json({ error: "آيدي غير صالح" });
    res.json(await callBot("member_activity", { id: req.params.id }, 30000));
}));
app.post("/api/members/:id/dismiss", auth, full, wrap(async (req, res) => {
    if (req.params.id === req.session.user.id) return res.status(400).json({ error: "ما تقدر تفصل نفسك" });
    const r = await callBot("dismiss", { id: req.params.id, actorId: req.session.user.id, who: req.session.user.tag });
    applyAccess(r.id, null); // يظهر له فوراً إنه مفصول إذا كان فاتح الموقع
    await panelLog(req, "فصل من الأمن السيبراني", "العضو: " + r.tag, { targetId: r.id, targetTag: r.tag });
    res.json({ ok: true });
}));

// ══════════════════════════════════════════════════════════════════════════
// مراقبة إشارات البوت من القاعدة: تحديث اللوق لحظياً + تغيّر صلاحيات الأعضاء
// ══════════════════════════════════════════════════════════════════════════
let sigInit = false, lastChanged = null, lastAccessPulse = null, sigBusy = false;
const accessSeen = new Map();
async function syncAccessFromDb() {
    const docs = await Access.find().lean();
    const now = new Map(docs.map(d => [d._id, d.level || null]));
    if (sigInit) for (const [uid, lv] of now) { if ((accessSeen.has(uid) ? accessSeen.get(uid) : null) !== lv) applyAccess(uid, lv); }
    accessSeen.clear(); now.forEach((v, k) => accessSeen.set(k, v));
}
async function pollBotSignals() {
    if (sigBusy) return;
    sigBusy = true;
    try {
        const ms = await StatMeta.find({ _id: { $in: ["changed", "accessChanged"] } }).lean();
        const val = id => { const m = ms.find(x => x._id === id); return m ? m.value : null; };
        const ch = val("changed"), ac = val("accessChanged");
        if (sigInit && ch !== lastChanged) broadcastChanged();
        lastChanged = ch;
        if (!sigInit || ac !== lastAccessPulse) { lastAccessPulse = ac; await syncAccessFromDb(); }
        sigInit = true;
    } catch (e) { console.error("pollBotSignals:", e.message); }
    finally { sigBusy = false; }
}
function startSiteJobs() {
    setInterval(pollBotSignals, 1500);
    pollBotSignals();
    // أرشفة الأسابيع المكتملة (كانت تتم من البوت — الحين من الموقع)
    setTimeout(archiveWeeks, 8000);
    setInterval(archiveWeeks, 15 * 60 * 1000);
}

// ══════════════════════════════════════════════════════════════════════════
// 6) الواجهة (نفس تصميم موقع فلاش: نفس الألوان والأزرار والخط)
// ══════════════════════════════════════════════════════════════════════════
const CSS = String.raw`
:root { --bg1:#0a1628; --bg2:#0d1f3c; --panel:rgba(255,255,255,0.04); --border:rgba(59,130,246,0.25); --gold:#3b82f6; --gold-soft:#60a5fa; --green:#1d4ed8; --green2:#3b82f6; --red:#ef4444; --amber:#eab308; --text:#e2e8f0; --muted:#64748b; }
* { box-sizing:border-box; margin:0; padding:0; font-family:'Tajawal','Tahoma','Segoe UI',sans-serif; }
body { background:linear-gradient(135deg,#0a1628 0%,#0d1f3c 40%,#0a2744 70%,#0d3060 100%); color:var(--text); min-height:100vh; background-attachment:fixed; }
nav { background:rgba(5,15,30,0.95); backdrop-filter:blur(15px); border-bottom:1px solid rgba(59,130,246,0.3); padding:0 1.2rem; display:flex; align-items:center; justify-content:space-between; height:62px; position:sticky; top:0; z-index:900; gap:10px; }
.nav-start { display:flex; align-items:center; gap:12px; }
.logo { font-size:1.2rem; font-weight:900; background:linear-gradient(90deg,#3b82f6,#60a5fa,#93c5fd); -webkit-background-clip:text; -webkit-text-fill-color:transparent; letter-spacing:1px; white-space:nowrap; }
.nav-links { display:flex; gap:0.3rem; list-style:none; }
.nav-links button { background:transparent; border:1px solid transparent; color:#94a3b8; padding:0.4rem 0.9rem; border-radius:8px; cursor:pointer; font-family:inherit; font-size:0.88rem; transition:all .2s; }
.nav-links button:hover, .nav-links button.on { background:rgba(59,130,246,0.2); border-color:#3b82f6; color:#60a5fa; }
.hamburger-btn { display:none; background:rgba(59,130,246,0.15); border:1px solid #3b82f6; color:#60a5fa; padding:0.35rem 0.7rem; border-radius:8px; cursor:pointer; font-size:1.3rem; line-height:1; }
.userchip { display:flex; align-items:center; gap:8px; font-size:13px; color:#94a3b8; }
.userchip img { width:30px; height:30px; border-radius:50%; border:2px solid var(--gold); }
@media (max-width:1024px) { .nav-links { display:none !important; } .hamburger-btn { display:inline-block; } .userchip span { display:none; } }
.dov { display:none; position:fixed; inset:0; background:rgba(5,10,20,0.65); backdrop-filter:blur(2px); z-index:1400; }
.dov.open { display:block; }
.drawer { position:fixed; top:0; right:0; height:100%; width:270px; max-width:82vw; background:rgba(5,15,30,0.98); border-left:1px solid rgba(59,130,246,0.35); z-index:1500; transform:translateX(100%); transition:transform .25s ease; padding:14px 0; box-shadow:-8px 0 30px rgba(0,0,0,0.6); display:flex; flex-direction:column; }
.drawer.open { transform:none; }
.drawer .dh { padding:6px 20px 16px; border-bottom:1px solid rgba(59,130,246,0.2); margin-bottom:6px; }
.drawer button.item { display:block; width:100%; background:transparent; border:none; border-bottom:1px solid rgba(59,130,246,0.08); color:#94a3b8; padding:14px 22px; text-align:right; font-family:inherit; font-size:0.95rem; cursor:pointer; }
.drawer button.item:hover, .drawer button.item.on { background:rgba(59,130,246,0.18); color:#60a5fa; }
.wrap { max-width:1000px; margin:0 auto; padding:20px 14px 60px; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:18px; margin-bottom:16px; box-shadow:0 4px 20px rgba(0,0,0,0.4); }
h1,h2,h3 { color:var(--gold-soft); margin-bottom:12px; }
h2 { font-size:1.25rem; }
.btn { display:inline-block; background:linear-gradient(135deg,var(--green),var(--green2)); color:#fff; border:none; border-radius:8px; padding:0.6rem 1.3rem; font-size:0.9rem; font-weight:700; cursor:pointer; transition:.2s; font-family:inherit; text-decoration:none; }
.btn:hover { opacity:.85; transform:translateY(-1px); }
.btn:disabled { opacity:.5; cursor:wait; }
.btn.danger { background:#ef4444; }
.btn.ok { background:linear-gradient(135deg,#15803d,#22c55e); }
.btn.gray { background:rgba(255,255,255,0.08); border:1px solid rgba(59,130,246,0.25); color:#94a3b8; }
.btn.sm { padding:0.38rem 0.85rem; font-size:0.8rem; }
input, select { width:100%; padding:10px 12px; border-radius:8px; border:1px solid var(--border); background:rgba(255,255,255,0.06); color:#fff; font-size:14px; font-family:inherit; }
select option { background:#0d1f3c; }
input:focus, select:focus { outline:none; border-color:var(--gold-soft); }
.row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; justify-content:space-between; }
.badge { display:inline-block; padding:3px 10px; border-radius:20px; font-size:12px; font-weight:bold; white-space:nowrap; }
.badge.high { background:rgba(239,68,68,0.15); color:#fca5a5; border:1px solid #ef4444; }
.badge.medium { background:rgba(234,179,8,0.15); color:#fbbf24; border:1px solid #eab308; }
.badge.low { background:rgba(59,130,246,0.15); color:#93c5fd; border:1px solid #3b82f6; }
.badge.done { background:rgba(34,197,94,0.15); color:#4ade80; border:1px solid #22c55e; }
.filters { display:grid; grid-template-columns:1fr 1fr auto; gap:10px; align-items:center; }
@media (max-width:640px) { .filters { grid-template-columns:1fr; } }
.chk { display:flex; align-items:center; gap:8px; font-size:13px; color:#94a3b8; cursor:pointer; white-space:nowrap; }
.chk input { width:auto; }
.log-item { background:rgba(255,255,255,0.02); border:1px solid rgba(59,130,246,0.2); border-radius:10px; padding:12px 15px; margin-bottom:9px; display:flex; justify-content:space-between; align-items:flex-start; gap:12px; font-size:0.88rem; flex-wrap:wrap; }
.log-item.sus { border-color:rgba(239,68,68,0.55); background:rgba(239,68,68,0.06); }
.log-item.sus.medium { border-color:rgba(234,179,8,0.55); background:rgba(234,179,8,0.05); }
.log-item.fin { opacity:.6; }
.log-body { flex:1; min-width:210px; }
.log-title { font-weight:800; margin-bottom:4px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.log-det { color:#cbd5e1; white-space:pre-line; line-height:1.8; font-size:13px; word-break:break-word; }
.log-meta { color:var(--muted); font-size:12px; margin-top:6px; }
.log-act { display:flex; gap:6px; flex-wrap:wrap; }
.grid3 { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-bottom:16px; }
.grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:16px; }
@media (max-width:640px) { .grid3, .grid4 { grid-template-columns:repeat(2,1fr); } }
.stat { text-align:center; padding:14px; background:rgba(255,255,255,0.03); border-radius:10px; border:1px solid var(--border); }
.stat .num { font-size:26px; font-weight:900; color:var(--gold-soft); }
.stat .lbl { font-size:12px; color:var(--muted); }
.stat.red .num { color:#f87171; } .stat.green .num { color:#4ade80; } .stat.amber .num { color:#fbbf24; }
.bars { display:flex; align-items:flex-end; gap:8px; height:150px; padding-top:10px; }
.bar { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:flex-end; height:100%; font-size:11px; color:var(--muted); gap:4px; }
.bar i { display:block; width:100%; border-radius:6px 6px 0 0; background:linear-gradient(180deg,#60a5fa,#1d4ed8); min-height:3px; }
.bar b { color:var(--gold-soft); font-size:12px; }
.bar { cursor:pointer; } .bar:hover i { filter:brightness(1.3); } .stat.click { cursor:pointer; transition:.15s; } .stat.click:hover { border-color:var(--gold); transform:translateY(-2px); }
.tabs { display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap; }
.tab { background:rgba(255,255,255,0.04); border:1px solid rgba(59,130,246,0.3); padding:9px 18px; border-radius:8px; cursor:pointer; font-size:13px; color:#94a3b8; font-family:inherit; }
.tab.active { background:var(--green2); color:#fff; border-color:var(--green2); }
.chip { display:inline-block; padding:2px 9px; border-radius:20px; font-size:11px; font-weight:bold; margin:2px 0 2px 4px; }
.chip.critical { background:rgba(239,68,68,0.18); color:#fca5a5; border:1px solid #ef4444; }
.chip.high { background:rgba(234,179,8,0.15); color:#fbbf24; border:1px solid #eab308; }
.en { color:#94a3b8; font-weight:400; font-size:0.85em; margin-inline-start:4px; direction:ltr; unicode-bidi:isolate; display:inline-block; }
.mlist { display:flex; align-items:center; gap:10px; padding:8px 4px; border-bottom:1px dashed rgba(255,255,255,0.07); }
.mlist img { width:36px; height:36px; border-radius:50%; flex:none; }
.chip.safe { background:rgba(59,130,246,0.12); color:#93c5fd; border:1px solid rgba(59,130,246,0.4); }
.dot { display:inline-block; width:11px; height:11px; border-radius:50%; margin-inline-end:6px; vertical-align:middle; }
.st { display:inline-block; width:10px; height:10px; border-radius:50%; margin-inline-end:6px; }
.st.online { background:#22c55e; } .st.idle { background:#eab308; } .st.dnd { background:#ef4444; } .st.offline, .st.unknown { background:#64748b; }
.bot { display:flex; gap:12px; align-items:flex-start; flex-wrap:wrap; }
.bot img { width:52px; height:52px; border-radius:50%; border:2px solid var(--gold); }
.ov { position:fixed; inset:0; background:rgba(0,0,0,0.72); z-index:4000; display:flex; align-items:flex-start; justify-content:center; overflow-y:auto; padding:20px 12px; }
.modal { background:#0d1f3c; border:1px solid var(--gold); border-radius:14px; padding:20px; max-width:560px; width:100%; margin:auto; }
.modal h3 { text-align:center; }
.prow { display:flex; align-items:center; justify-content:space-between; gap:10px; padding:8px 4px; border-bottom:1px dashed rgba(255,255,255,0.07); font-size:13px; }
.prow.crit { background:rgba(239,68,68,0.07); } .prow.hi { background:rgba(234,179,8,0.05); }
.sw { position:relative; width:44px; height:24px; flex-shrink:0; }
.sw input { opacity:0; width:0; height:0; }
.sw span { position:absolute; inset:0; background:#334155; border-radius:24px; transition:.2s; cursor:pointer; }
.sw span:before { content:''; position:absolute; height:18px; width:18px; right:3px; top:3px; background:#fff; border-radius:50%; transition:.2s; }
.sw input:checked + span { background:var(--green2); }
.sw input:checked + span:before { transform:translateX(-20px); }
.tri { display:flex; gap:4px; }
.tri button { border:1px solid var(--border); background:rgba(255,255,255,0.05); color:#94a3b8; border-radius:6px; width:34px; height:28px; cursor:pointer; font-size:14px; font-family:inherit; }
.tri button.a.on { background:#16a34a; color:#fff; border-color:#22c55e; }
.tri button.n.on { background:#475569; color:#fff; }
.tri button.d.on { background:#dc2626; color:#fff; border-color:#ef4444; }
.msg { border-bottom:1px solid var(--border); padding:8px 2px; font-size:13px; line-height:1.7; }
.msg b { color:var(--gold-soft); }
.imgrow { display:flex; flex-wrap:wrap; gap:8px; margin-top:8px; }
.imgrow img { width:110px; height:110px; object-fit:cover; border-radius:8px; border:1px solid var(--border); cursor:pointer; }
.log-item[data-id] { cursor:pointer; transition:border-color .15s; }
.log-item[data-id]:hover { border-color:rgba(96,165,250,0.75); }
#toast { position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:#0d1f3c; padding:10px 20px; border-radius:10px; border:1px solid var(--gold); z-index:6000; display:none; max-width:90vw; text-align:center; }
.center { text-align:center; } .muted { color:var(--muted); }
.warn { background:rgba(234,179,8,0.1); border:1px solid #eab308; color:#fde68a; border-radius:10px; padding:10px 14px; font-size:13px; margin-bottom:14px; }
.auth-page { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px 14px; }
.auth-card { width:100%; max-width:480px; background:linear-gradient(180deg,#0d1f3c,#0a1628); border:1px solid var(--border); border-radius:24px; padding:36px 32px; box-shadow:0 25px 60px rgba(0,0,0,0.55); text-align:center; }
.auth-card .ico { font-size:64px; margin-bottom:8px; }
.auth-card h1 { font-size:1.9rem; color:#3b82f6; text-shadow:0 0 20px rgba(59,130,246,0.5); margin-bottom:6px; }
.auth-card p { color:#94a3b8; line-height:1.9; margin-bottom:22px; }
.auth-card .btn { width:100%; padding:15px; font-size:1.05rem; border-radius:999px; }
.auth-card.deny { border-color:rgba(239,68,68,0.5); } .auth-card.deny h1 { color:#f87171; text-shadow:none; }

/* ══ إصلاحات الجوال والايباد ══ */
html { -webkit-text-size-adjust:100%; overflow-x:hidden; max-width:100%; }
body { overflow-x:hidden; max-width:100vw; min-height:100dvh; }
nav { height:auto; min-height:62px; padding-top:env(safe-area-inset-top,0px); }
.nav-start { min-width:0; flex:1; }
.logo { overflow:hidden; text-overflow:ellipsis; min-width:0; }
.userchip { flex-shrink:0; }
.wrap, .card, .log-body, .log-det, .log-meta, .prow span, .log-title { min-width:0; }
.wrap { width:100%; }
.log-det, .log-meta, .log-title, .msg, .prow span { overflow-wrap:anywhere; word-break:break-word; }
.filters > * { min-width:0; }
.drawer { visibility:hidden; pointer-events:none; padding-top:calc(14px + env(safe-area-inset-top,0px)); }
.drawer.open { visibility:visible; pointer-events:auto; }
.ov { padding:calc(14px + env(safe-area-inset-top,0px)) 10px 20px; }
@media (max-width:640px) {
  .hide-sm { display:none; }
  .logo { font-size:1.05rem; }
  nav { padding-left:.7rem; padding-right:.7rem; }
  .wrap { padding:14px 10px 50px; }
  .card { padding:14px; border-radius:12px; }
  h2 { font-size:1.1rem; }
  .log-item { padding:11px 12px; }
  .log-body { min-width:0; flex:1 1 100%; }
  .log-act { width:100%; }
  .log-act .btn { flex:1 1 auto; text-align:center; }
  .modal { padding:16px; }
  .tabs .tab { flex:1 1 auto; text-align:center; padding:9px 10px; }
  .bot { flex-direction:row; }
  .bot > div { min-width:0; flex:1 1 60%; }
  .bot > .btn { width:100%; }
  .stat .num { font-size:22px; }
  .auth-card { padding:28px 20px; border-radius:20px; }
}
/* ══ نوافذ ما تتحرك ══ */
.ov { overscroll-behavior:contain; -webkit-overflow-scrolling:touch; }
.modal { margin:0 auto; }
`;

const HEAD = (title) => `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${title}</title>
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>${CSS}</style></head>`;

function loginPage(mode) {
    let body;
    if (mode === "denied") body = `<div class="auth-card deny"><div class="ico">⛔</div><h1>غير مصرّح</h1>
        <p>هذا الموقع فقط لمنسوبي الأمن السيبراني.<br>حسابك لا يملك الرتبة المطلوبة.</p>
        <a class="btn gray" href="/auth/discord">تسجيل الدخول بحساب آخر</a></div>`;
    else body = `<div class="auth-card"><div class="ico">🛡️</div><h1>${CONFIG.SITE_NAME}</h1>
        <p>${CONFIG.SITE_SUB}<br>الدخول مخصّص لمنسوبي الأمن السيبراني فقط، سجّل دخولك بحساب ديسكورد ليتم التحقق من رتبتك.</p>
        ${mode === "err" ? '<div class="warn">صار خطأ أثناء تسجيل الدخول، حاول مرة ثانية.</div>' : ""}
        <a class="btn" href="/auth/discord">🔐 تسجيل الدخول عبر ديسكورد</a></div>`;
    return HEAD(CONFIG.SITE_NAME) + `<body><div class="auth-page">${body}</div></body></html>`;
}

const CLIENT = String.raw`
var PAGES=[['logs','📜 اللوق'],['stats','📊 الإحصائيات'],['bots','🤖 البوتات'],['perms','🔐 صلاحيات السيرفر']];
var S={page:'logs',q:'',cat:'',unres:false,cu:false,events:[],sig:'',timer:null,permsTab:'roles',permsView:'danger',permsQ:'',meta:null,presence:true,level:'view',meId:null};
var CATS=[['','الكل'],['sus','⚠️ العمليات المشبوهة'],['newacc','🆕 حسابات جديدة'],['join','دخول'],['leave','خروج'],['kick','طرد'],['ban','حظر'],['role','الرتب'],['inquiry','📩 استفسارات الرتب'],['channel','القنوات'],['voice','🎙️ الرومات الصوتية'],['message','الرسائل المحذوفة'],['probot','🧹 حذف عبر ProBot'],['bot','البوتات'],['webhook','ويبهوكس'],['everyone','منشن everyone'],['server','إعدادات السيرفر'],['panel','عمليات اللوحة']];
var RULE_AR={new_account:'حساب جديد',mass_roles_created:'رتب جماعية',mass_role_delete:'حذف رتب',mass_channel_create:'إنشاء قنوات',mass_channel_delete:'حذف قنوات',mass_ban:'حظر جماعي',mass_kick:'طرد جماعي',dangerous_perm_grant:'صلاحيات خطيرة',dangerous_role_assigned:'رتبة خطيرة',bot_added:'بوت جديد',webhook_created:'ويبهوك',everyone_spam:'منشن everyone',mass_join:'غارة دخول',mass_msg_delete:'مسح ضخم',server_changed:'إعدادات السيرفر'};
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function toast(m){var t=$('toast');t.textContent=m;t.style.display='block';clearTimeout(t._t);t._t=setTimeout(function(){t.style.display='none';},3200);}
function fmt(d){try{return new Date(d).toLocaleString('ar-SA',{timeZone:'Asia/Riyadh',hour12:true,dateStyle:'medium',timeStyle:'short'});}catch(e){return new Date(d).toLocaleString();}}
function ago(d){var s=Math.floor((Date.now()-new Date(d).getTime())/1000);if(s<60)return 'الحين';if(s<3600)return 'قبل '+Math.floor(s/60)+' دقيقة';if(s<86400)return 'قبل '+Math.floor(s/3600)+' ساعة';return 'قبل '+Math.floor(s/86400)+' يوم';}
async function api(url,opt){
  var r=await fetch(url,Object.assign({headers:{'Content-Type':'application/json'}},opt||{}));
  var j=await r.json().catch(function(){return {};});
  if(r.status===401){
    if(j.error==='تم سحب صلاحيتك'){showDismissed();throw new Error(j.error);}
    location.href='/';throw new Error('غير مصرح');
  }
  if(!r.ok)throw new Error(j.error||'صار خطأ');
  return j;
}
function showDismissed(){
  try{if(S.es)S.es.close();}catch(e){}
  clearInterval(S.timer);closeModal();
  if($('dismissed'))return;
  var o=document.createElement('div');o.id='dismissed';
  o.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;z-index:99999;background:#050d1a;display:flex;align-items:center;justify-content:center;padding:20px;overflow:auto';
  o.innerHTML='<div class="auth-card deny"><div class="ico">🚫</div><h1>تم فصلك</h1><p>تم فصلك من الأمن السيبراني وسُحبت رتبتك.<br>ما تقدر تستخدم اللوحة بعد الحين.</p><a class="btn gray" href="/auth/logout">خروج</a></div>';
  document.body.appendChild(o);
}
function lockScroll(){
  if(S.locked)return;
  S.locked=true;S.lockY=window.pageYOffset||document.documentElement.scrollTop||0;
  var b=document.body;b.style.position='fixed';b.style.top='-'+S.lockY+'px';b.style.left='0';b.style.right='0';b.style.width='100%';
}
function unlockScroll(){
  if(!S.locked)return;
  if($('ov'))return;
  S.locked=false;
  var b=document.body;b.style.position='';b.style.top='';b.style.left='';b.style.right='';b.style.width='';
  window.scrollTo(0,S.lockY||0);
}
function modal(html){var old=$('ov');if(old)old.remove();var o=document.createElement('div');o.className='ov';o.id='ov';o.innerHTML='<div class="modal">'+html+'</div>';o.addEventListener('mousedown',function(e){if(e.target===o)closeModal();});document.body.appendChild(o);lockScroll();}
function closeModal(){var o=$('ov');if(o)o.remove();unlockScroll();}
function ask(msg){return new Promise(function(res){modal('<h3>تأكيد</h3><p style="line-height:1.8;margin-bottom:16px;white-space:pre-line">'+esc(msg)+'</p><div class="row" style="justify-content:flex-start"><button class="btn danger" id="ask-y">تأكيد</button><button class="btn gray" id="ask-n">إلغاء</button></div>');$('ask-y').onclick=function(){closeModal();res(true);};$('ask-n').onclick=function(){closeModal();res(false);};});}

/* ── التنقل ── */
function pagesList(){var p=PAGES.slice();if(S.level==='full')p.push(['members','👥 الأعضاء']);return p;}
function buildNav(){
  var list=pagesList();
  $('navlinks').innerHTML=list.map(function(p){return '<button class="'+(S.page===p[0]?'on':'')+'" onclick="go(\''+p[0]+'\')">'+p[1]+'</button>';}).join('');
  $('drawer-items').innerHTML=list.map(function(p){return '<button class="item '+(S.page===p[0]?'on':'')+'" onclick="go(\''+p[0]+'\')">'+p[1]+'</button>';}).join('');
}
function openDrawer(){$('drawer').classList.add('open');$('dov').classList.add('open');}
function closeDrawer(){$('drawer').classList.remove('open');$('dov').classList.remove('open');}
function go(p){S.page=p;closeDrawer();clearInterval(S.timer);buildNav();render();}
function render(){var f={logs:pgLogs,stats:pgStats,bots:pgBots,perms:pgPerms,members:pgMembers}[S.page];f();}

/* ══ اللوق ══ */
function openBackfill(){
  modal('<h3>🔄 استرجاع الفائت من سجل ديسكورد</h3><p class="muted" style="line-height:1.9;font-size:13px">يقرأ سجل ديسكورد الرسمي ويضيف للوق اللي ما انسجّل وقت ما كان البوت طافي. اللي موجود أصلاً ما يتكرر.<br>⚠️ نص الرسائل المحذوفة ما يرجع (ديسكورد ما يحتفظ به)، لكن يتسجّل من حذف وفي أي روم وكم رسالة.</p>'
   +'<p style="margin:10px 0 6px;font-weight:bold">اختر المدة:</p><div class="row" style="justify-content:flex-start;flex-wrap:wrap">'
   +[[6,'آخر 6 ساعات'],[12,'آخر 12 ساعة'],[24,'آخر 24 ساعة'],[72,'آخر 3 أيام'],[168,'آخر أسبوع'],[720,'آخر 30 يوم']].map(function(x){return '<button class="btn sm" onclick="runBackfill('+x[0]+')">'+x[1]+'</button>';}).join('')
   +'</div><div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
}
async function runBackfill(h){
  modal('<h3>🔄 جاري استرجاع الفائت...</h3><div class="card center muted">يقرأ سجل ديسكورد، ممكن ياخذ دقيقة — لا تسكّر الصفحة</div>');
  try{
    var j=await api('/api/catchup',{method:'POST',body:JSON.stringify({hours:h})});
    var sevAr={high:'خطير',medium:'متوسط',low:'منخفض'};
    var pb=j.probot;
    var pbCard=(pb&&pb.ops)?'<div class="card" style="border-color:#f59e0b;background:rgba(245,158,11,0.08);margin:8px 0"><h3 style="margin-bottom:6px">🧹 مسح رسائل ProBot</h3><div><b>'+pb.ops+'</b> عملية مسح • <b>'+pb.messages+'</b> رسالة انمسحت</div>'
      +((pb.byUser&&pb.byUser.length)?'<div class="muted" style="font-size:12px;margin:8px 0 2px">👤 من مسح:</div>'+pb.byUser.map(function(u){return '<div class="prow"><span>'+esc(u.user)+'</span><b>'+u.messages+' رسالة ('+u.ops+' مسح)</b></div>';}).join(''):'')+'<div class="muted" style="font-size:12px;margin:8px 0 2px">💬 في أي روم:</div>'+pb.byChannel.map(function(c){return '<div class="prow"><span>#'+esc(c.channel)+'</span><b>'+c.messages+' رسالة ('+c.ops+' مسح)</b></div>';}).join('')+'</div>':'';
    var evs=j.events.slice().sort(function(a,b){return (b.probot?1:0)-(a.probot?1:0);});
    var list=evs.map(function(e){
      return '<div class="card" onclick="openEv(\''+e.id+'\')" style="cursor:pointer;margin:8px 0;padding:12px'+(e.probot?';border-color:#f59e0b':'')+'"><div class="log-title"><span>'+esc(e.title)+'</span>'
       +(e.probot?'<span class="badge medium">🧹 ProBot</span>':'')
       +(e.kind==='suspicious'?'<span class="badge '+esc(e.severity)+'">⚠️ مشبوهة — '+(sevAr[e.severity]||esc(e.severity))+'</span>':'')+'</div>'
       +(e.details?'<div class="log-det">'+esc(e.details)+'</div>':'')
       +'<div class="log-meta">🕒 '+fmt(e.createdAt)+(e.actor?' &nbsp;•&nbsp; 👤 '+esc(e.actor):'')+(e.target?' &nbsp;•&nbsp; 🎯 '+esc(e.target):'')+'</div>'
       +(e.hasMsgs?'<div style="margin-top:8px"><button class="btn sm gray" onclick="event.stopPropagation();showMsgs(\''+e.id+'\')">📄 عرض الرسائل</button></div>':'')+'</div>';
    }).join('')||'<div class="card center muted">ما فيه شي ناقص — كل اللي في سجل ديسكورد مسجّل أصلاً.<br>اللي استرجعته قبل تقدر تشوفه من اللوق (فلتر 🔄 المسترجعة فقط).</div>';
    modal('<h3>🔄 العمليات المسترجعة ('+j.n+')</h3><p class="muted" style="font-size:12px;margin-bottom:6px">المدة: آخر '+j.hours+' ساعة'+(j.n>=300?' — معروض أحدث 300':'')+'</p>'
     +'<div style="max-height:58vh;overflow-y:auto">'+pbCard+list+'</div>'
     +'<div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn" onclick="showRecovered()">📜 إظهار في اللوق</button><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  }catch(e){closeModal();toast(e.message);}
}
function showRecovered(){
  closeModal();
  S.cu=true;S.unres=false;S.q='';S.cat='';
  if(S.page!=='logs'){go('logs');return;}
  var c=$('f-cu');if(c)c.checked=true;var u=$('f-un');if(u)u.checked=false;var fq=$('f-q');if(fq)fq.value='';var fc=$('f-cat');if(fc)fc.value='';
  loadEvents();
}
function pgLogs(){
  var opts=CATS.map(function(c){return '<option value="'+c[0]+'"'+(S.cat===c[0]?' selected':'')+'>'+c[1]+'</option>';}).join('');
  $('main').innerHTML='<h2>📜 اللوق الشامل</h2><div class="card"><div class="filters">'
   +'<input id="f-q" placeholder="🔎 شخص (اسم/آيدي) أو وقت وتاريخ" value="'+esc(S.q)+'">'
   +'<select id="f-cat">'+opts+'</select>'
   +'<label class="chk"><input type="checkbox" id="f-un"'+(S.unres?' checked':'')+'> غير المحلولة فقط</label>'
   +'<label class="chk"><input type="checkbox" id="f-cu"'+(S.cu?' checked':'')+'> 🔄 المسترجعة فقط</label>'
   +(S.level==='full'?'<button class="btn sm gray" onclick="openBackfill()">🔄 استرجاع الفائت</button>':'')+'</div><div class="muted" style="font-size:11px;margin-top:8px;line-height:1.8">💡 تقدر تبحث بالوقت والتاريخ بالعربي أو الإنجليزي، وتدمجه مع الاسم: <b>اليوم</b> • <b>أمس</b> • <b>10:30 م</b> • <b>3 مساء</b> • <b>5 أكتوبر</b> • <b>2026-10-01</b> • <b>الخميس</b> • <b>today</b> • <b>yesterday</b> • <b>9pm</b> • <b>ahmed أمس</b></div></div>'
   +'<div id="evlist"><div class="card center muted">جاري التحميل...</div></div><div class="center"><button class="btn gray" id="more" style="display:none" onclick="moreEvents()">تحميل المزيد</button></div>';
  var t;$('f-q').oninput=function(){S.q=this.value;clearTimeout(t);t=setTimeout(loadEvents,350);};
  $('f-cat').onchange=function(){S.cat=this.value;loadEvents();};
  $('f-un').onchange=function(){S.unres=this.checked;loadEvents();};
  $('f-cu').onchange=function(){S.cu=this.checked;loadEvents();};
  $('evlist').onclick=function(ev){
    if(ev.target.closest('button,a,img,input,select,.log-act'))return;
    if(window.getSelection&&String(window.getSelection()))return;
    var it=ev.target.closest('.log-item');if(it&&it.getAttribute('data-id'))openEv(it.getAttribute('data-id'));
  };
  loadEvents();
  S.timer=setInterval(function(){loadEvents(true);},6000);
}
function qs(before){return '/api/events?q='+encodeURIComponent(S.q)+'&cat='+encodeURIComponent(S.cat)+'&unres='+(S.unres?1:0)+'&cu='+(S.cu?1:0)+(before?'&before='+before:'');}
async function loadEvents(silent){
  try{
    var j=await api(qs());
    var sig=j.events.map(function(e){return e._id+e.updatedAt+e.resolved+(e.inq?e.inq.status:'');}).join('|');
    if(silent&&sig===S.sig)return;
    S.sig=sig;S.events=j.events;drawEvents(j.events.length>=50);
  }catch(e){if(!silent)toast(e.message);}
}
async function moreEvents(){
  var last=S.events[S.events.length-1];if(!last)return;
  try{var j=await api(qs(new Date(last.createdAt).getTime()));S.events=S.events.concat(j.events);drawEvents(j.events.length>=50);}catch(e){toast(e.message);}
}
function drawEvents(more){
  var box=$('evlist');if(!box)return;
  box.innerHTML=S.events.length?S.events.map(evRow).join(''):'<div class="card center muted">ما فيه عمليات مطابقة</div>';
  $('more').style.display=more?'inline-block':'none';
}
function evRow(e){
  var sus=e.kind==='suspicious';
  var cls='log-item'+(sus?' sus '+e.severity:'')+(e.resolved?' fin':'');
  var badge=sus?(e.resolved?'<span class="badge done">✅ محلولة</span>':'<span class="badge '+(e.severity==='high'?'high':'medium')+'">⚠️ '+esc(RULE_AR[e.rule]||'مشبوهة')+'</span>'):'';
  var meta='🕒 '+ago(e.createdAt)+' — '+fmt(e.createdAt);
  if(e.actorTag)meta='👤 '+esc(e.actorTag)+' &nbsp;•&nbsp; '+meta;
  if(e.targetTag&&e.cat!=='role'&&e.cat!=='channel')meta+=' &nbsp;•&nbsp; 🎯 '+esc(e.targetTag);
  if(e.resolved&&e.resolvedBy)meta+=' &nbsp;•&nbsp; حلّها: '+esc(e.resolvedBy);
  var acts='';
  if(e.hasMsgs)acts+='<button class="btn sm gray" onclick="showMsgs(\''+e._id+'\')">📄 عرض الرسائل</button>';
  if(sus&&S.level==='full'){
    if(e.remedy)acts+='<button class="btn sm danger" onclick="doRemedy(\''+e._id+'\',this)">'+esc(e.remedy.label)+'</button>';
    if(!e.resolved)acts+='<button class="btn sm ok" onclick="doResolve(\''+e._id+'\',this)">✅ حل العملية</button>';
  }
  var isReply=!!(e.data&&e.data.act==='inq_reply');
  if(e.cat==='role'&&e.actorId&&e.data&&e.data.act==='member_roles'&&String(e.details||'').indexOf('أُعطي')>-1){
    if(!e.inq){if(S.level==='full')acts+='<button class="btn sm" data-id="'+e._id+'" onclick="sendInq(this)">📩 إرسال رسالة للعضو</button>';}
    else acts+='<span class="badge '+(e.inq.status==='sent'?'medium':'done')+'">📩 '+(INQ_AR[e.inq.status]||'')+'</span>';
  }
  if(isReply&&e.inq){
    if(e.inq.status==='replied'){
      if(S.level==='full')acts+='<button class="btn sm ok" data-id="'+e.inq.id+'" onclick="decideInq(this,\'covenant\')">🤝 تم التعاهد</button><button class="btn sm danger" data-id="'+e.inq.id+'" onclick="decideInq(this,\'investigation\')">🔍 تحقيق</button>';
      else acts+='<span class="badge medium">⏳ بانتظار القرار</span>';
    }else acts+='<span class="badge '+(e.inq.status==='investigation'?'high':'done')+'">'+(INQ_AR[e.inq.status]||'')+'</span>';
  }
  var imgs=(e.data&&e.data.images&&e.data.images.length)?'<div class="imgrow">'+e.data.images.map(function(im){return '<img src="/api/images/'+im.id+'" alt="" loading="lazy" onclick="showImg(\''+im.id+'\')">';}).join('')+'</div>':'';
  return '<div class="'+cls+'" data-id="'+e._id+'"><div class="log-body"><div class="log-title">'+badge+'<span>'+esc(e.title)+'</span>'+(e.count>1&&sus?'<span class="badge low">×'+e.count+'</span>':'')+'</div>'
    +(e.details?'<div class="log-det">'+esc(e.details)+'</div>':'')+imgs+'<div class="log-meta">'+meta+'</div></div><div class="log-act">'+acts+'</div></div>';
}
function showImg(id){modal('<div class="center"><img src="/api/images/'+id+'" alt="" style="max-width:100%;max-height:75vh;border-radius:10px"></div><div style="margin-top:14px" class="center"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');}
var INQ_AR={sent:'أُرسل — بانتظار الرد',replied:'رد العضو',covenant:'تم التعاهد',investigation:'تحويل للتحقيق'};
async function sendInq(b){
  var ev=S.events.find(function(x){return x._id===b.dataset.id;});if(!ev)return;
  if(!(await ask('راح يوصل '+(ev.actorTag||'العضو')+' رسالة خاصة من البوت يسأله ليش أعطى الرتبة، ولازم يكتب السبب.\n\nنرسل؟')))return;
  b.disabled=true;
  try{await api('/api/events/'+ev._id+'/inquire',{method:'POST'});toast('انرسلت الرسالة للعضو');loadEvents();}catch(e){toast(e.message);b.disabled=false;}
}
async function decideInq(b,d){
  var all=b.parentNode.querySelectorAll('button');
  if(!(await ask(d==='covenant'?'راح توصل العضو رسالة: تم تعاهد الأمن السيبراني. تأكيد؟':'راح توصل العضو رسالة: سيتم استدعاؤك للتحقيق. تأكيد؟')))return;
  all.forEach(function(x){x.disabled=true;});
  try{await api('/api/inquiries/'+b.dataset.id+'/decide',{method:'POST',body:JSON.stringify({decision:d})});toast('انرسل القرار للعضو');loadEvents();}catch(e){toast(e.message);all.forEach(function(x){x.disabled=false;});}
}
async function doRemedy(id,b){
  var ev=S.events.find(function(x){return x._id===id;});
  if(!(await ask('تنفيذ الإجراء: '+ev.remedy.label+'\n\n'+ev.title)))return;
  b.disabled=true;
  try{var j=await api('/api/events/'+id+'/remedy',{method:'POST'});toast(j.msg||'تم');loadEvents();}catch(e){toast(e.message);b.disabled=false;}
}
async function doResolve(id,b){
  b.disabled=true;
  try{await api('/api/events/'+id+'/resolve',{method:'POST'});toast('تم حل العملية');loadEvents();}catch(e){toast(e.message);b.disabled=false;}
}
async function showMsgs(id){
  try{
    var j=await api('/api/events/'+id+'/messages');
    var html='<h3>🗑️ '+esc(j.title||'الرسائل المحذوفة')+'</h3>'+(j.channel?'<p class="muted center" style="margin-bottom:10px">الروم: #'+esc(j.channel)+(j.probot?' — عبر ProBot':'')+'</p>':'');
    html+=j.messages.length?j.messages.map(function(m){
      var mi=(m.images&&m.images.length)?'<div class="imgrow">'+m.images.map(function(im){return '<img src="/api/images/'+im.id+'" alt="" loading="lazy" onclick="showImg(\''+im.id+'\')">';}).join('')+'</div>':'';
      return '<div class="msg"><b>'+esc(m.authorTag)+'</b> <span class="muted" style="font-size:11px">'+(m.at?fmt(m.at):'')+'</span><br>'+(m.content?esc(m.content):'<span class="muted">(بدون نص)</span>')+(m.att?' <span class="chip safe">📎 '+m.att+' مرفق</span>':'')+mi+'</div>';
    }).join(''):'<p class="center muted">الرسائل ما انحفظت (كانت قبل تشغيل البوت)</p>';
    html+='<div style="margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>';
    modal(html);
  }catch(e){toast(e.message);}
}

/* ══ نسخ ══ */
function copyText(t,msg){
  function ok(){toast(msg||'تم النسخ');}
  function fb(){try{var a=document.createElement('textarea');a.value=t;a.style.cssText='position:fixed;opacity:0;top:0;left:0';document.body.appendChild(a);a.focus();a.select();document.execCommand('copy');a.remove();ok();}catch(e){toast('ما قدرت أنسخ');}}
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok,fb);}else fb();
}
function copyBtn(b){copyText(b.getAttribute('data-copy'),b.getAttribute('data-msg'));}
function cpb(val,msg,lbl){return val?' <button class="btn sm gray" style="padding:2px 9px;font-size:11px;margin-inline-start:4px" data-copy="'+esc(val)+'" data-msg="'+esc(msg)+'" onclick="copyBtn(this)">📋 '+lbl+'</button>':'';}

/* ══ فورم تفاصيل العملية (يطلع لما تضغط على أي عملية بأي مكان بالموقع) ══ */
function evBackBtn(){return S.evBack?'<button class="btn" onclick="evBack()">⬅️ رجوع</button>':'';}
function evBack(){
  var b=S.evBack;S.evBack=null;S.evId=null;
  if(!b){closeModal();return;}
  modal(b.html);
  var mm=$('ov')&&$('ov').querySelector('.modal'),sc=mm&&mm.querySelector('div[style*="overflow-y:auto"]');
  if(sc)sc.scrollTop=b.st;
}
async function openEv(id){
  var ov=$('ov'),mm=ov?ov.querySelector('.modal'):null;
  if(mm&&!$('evinfo')){var sc=mm.querySelector('div[style*="overflow-y:auto"]');S.evBack={html:mm.innerHTML,st:sc?sc.scrollTop:0};}
  else if(!mm)S.evBack=null;
  S.evId=id;S.evj=null;S.evp=null;
  modal('<div id="evinfo" style="max-height:70vh;overflow-y:auto"><h3>📋 تفاصيل العملية</h3><div class="card center muted">جاري التحميل...</div></div><div class="row" style="justify-content:flex-start;margin-top:14px">'+evBackBtn()+'<button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  try{
    var j=await api('/api/events/'+id+'/info');
    if(S.evId!==id||!$('evinfo'))return;
    S.evj=j.event;drawEv();
    var ids=[];if(j.event.actorId)ids.push(j.event.actorId);if(j.event.targetId&&ids.indexOf(j.event.targetId)<0)ids.push(j.event.targetId);
    if(ids.length){
      try{var r=await api('/api/people/lookup?ids='+ids.join(','));S.evp={ok:r.ok,people:r.people||{}};}
      catch(x){S.evp={ok:false,people:{}};}
      if(S.evId!==id||!$('evinfo'))return;
      drawEv();
    }
  }catch(e){if(S.evId===id&&$('evinfo'))$('evinfo').innerHTML='<h3>📋 تفاصيل العملية</h3><div class="card center muted">'+esc(e.message)+'</div>';}
}
function personHtml(label,id,tag,p,state){
  if(!id&&!tag)return '<div class="card" style="margin:8px 0;padding:12px"><div class="muted" style="font-size:12px;margin-bottom:4px">'+label+'</div><span class="muted">غير معروف (ما انسجّل مين سوّاها)</span></div>';
  var h='<div class="card" style="margin:8px 0;padding:12px"><div class="muted" style="font-size:12px;margin-bottom:6px">'+label+'</div><div class="mlist" style="border:none;padding:0;align-items:flex-start">';
  if(p&&p.avatar)h+='<img src="'+esc(p.avatar)+'" alt="">';
  h+='<div style="flex:1;min-width:0">';
  if(p){
    h+='<b>'+esc(p.server||p.global||p.username||tag||id)+'</b>'+(p.bot?' <span class="badge low">بوت</span>':'');
    h+='<div class="log-meta">🏷️ اسمه في السيرفر: '+esc(p.server||'-')+'</div>';
    h+='<div class="log-meta">👤 اسم البروفايل: '+esc(p.global||'-')+'</div>';
    h+='<div class="log-meta">🔖 اليوزر: @'+esc(p.username||'-')+cpb(p.username,'تم نسخ اليوزر','نسخ اليوزر')+'</div>';
  }else{
    h+='<b>'+esc(tag||id)+'</b>';
    var m=state==='wait'?'⏳ جاري جلب اسمه في السيرفر ويوزره...':state==='off'?'⚠️ تعذّر جلب اسمه ويوزره من السيرفر (البوت غير متصل) — المعروض هو المسجّل بالعملية':state==='gone'?'⚠️ ما لقيته بقائمة السيرفر الحالية (ممكن خرج أو مو عضو) — المعروض هو المسجّل بالعملية':'';
    if(m)h+='<div class="log-meta">'+m+'</div>';
  }
  if(id)h+='<div class="log-meta">🆔 '+esc(id)+cpb(id,'تم نسخ الآيدي','نسخ الآيدي')+'</div>';
  return h+'</div></div></div>';
}
function drawEv(){
  var e=S.evj,box=$('evinfo');if(!e||!box)return;
  var sus=e.kind==='suspicious',sevAr={high:'خطير',medium:'متوسط',low:'منخفض'};
  var st=S.evp;
  function stOf(id){return !st?'wait':!st.ok?'off':(st.people[id]?'ok':'gone');}
  function pOf(id){return (id&&st&&st.ok)?(st.people[id]||null):null;}
  var tm=new Date(e.createdAt);
  var timeStr='';try{timeStr=tm.toLocaleTimeString('ar-SA-u-nu-latn',{timeZone:'Asia/Riyadh',hour12:true,hour:'numeric',minute:'2-digit',second:'2-digit'});}catch(x){timeStr=tm.toLocaleTimeString();}
  var head='<div class="card" style="margin:8px 0;padding:12px"><div class="log-title"><span>'+esc(e.title)+'</span>'
    +(sus?'<span class="badge '+(e.severity==='high'?'high':'medium')+'">⚠️ '+esc(RULE_AR[e.rule]||'مشبوهة')+' — '+(sevAr[e.severity]||esc(e.severity))+'</span>':'')
    +(sus?(e.resolved?'<span class="badge done">✅ محلولة</span>':'<span class="badge medium">⏳ غير محلولة</span>'):'')
    +(e.count>1&&sus?'<span class="badge low">×'+e.count+'</span>':'')+'</div>'
    +'<div class="log-meta">🗂️ '+esc(CAT_AR[e.cat]||e.cat||'أخرى')+(e.probot?' • 🧹 ProBot':'')+(e.catchup?' • 🔄 مسترجعة':'')+(e.channel?' • 💬 #'+esc(e.channel):'')+'</div>'
    +(sus&&e.resolved?'<div class="log-meta">✔️ حلّها: '+esc(e.resolvedBy||'-')+(e.resolvedAt?' — '+fmt(e.resolvedAt):'')+'</div>':'')+'</div>';
  var actor=personHtml('👤 من الي سوّاها',e.actorId,e.actorTag,pOf(e.actorId),stOf(e.actorId));
  var target=(e.targetId||e.targetTag)?personHtml('🎯 على مين',e.targetId,e.targetTag,pOf(e.targetId),e.targetId?stOf(e.targetId):'none'):'';
  var when='<div class="card" style="margin:8px 0;padding:6px 12px">'
    +'<div class="prow"><span class="muted">📅 التاريخ</span><b>'+esc(dayFull(dayKeyClient(e.createdAt)))+'</b></div>'
    +'<div class="prow" style="border:none"><span class="muted">🕒 الوقت</span><span><b>'+esc(timeStr)+'</b> <span class="muted" style="font-size:11px">('+ago(e.createdAt)+')</span></span></div></div>';
  var det=e.details?'<div class="card" style="margin:8px 0;padding:12px"><div class="muted" style="font-size:12px;margin-bottom:4px">📝 التفاصيل</div><div class="log-det">'+esc(e.details)+'</div></div>':'';
  var imgs=(e.images&&e.images.length)?'<div class="imgrow">'+e.images.map(function(im){return '<img src="/api/images/'+im.id+'" alt="" loading="lazy" onclick="showImg(\''+im.id+'\')">';}).join('')+'</div>':'';
  var msgs=e.hasMsgs?'<div style="margin-top:8px"><button class="btn sm gray" onclick="showMsgs(\''+e._id+'\')">📄 عرض الرسائل</button></div>':'';
  box.innerHTML='<h3>📋 تفاصيل العملية</h3>'+head+actor+target+when+det+imgs+msgs;
}

/* ══ تفاصيل العمليات المشبوهة (يوم / أسبوع) ══ */
var WD_AR=['الأحد','الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'];
var WK_AR=['الأول','الثاني','الثالث','الرابع','الخامس','السادس','السابع','الثامن','التاسع','العاشر'];
function weekName(n){return 'الأسبوع '+(WK_AR[n-1]||n);}
function dayLabel(k){try{return new Date(k+'T12:00:00Z').toLocaleDateString('ar-SA-u-ca-gregory-nu-latn',{timeZone:'UTC',day:'numeric',month:'long',year:'numeric'});}catch(e){return k;}}
function dayFull(k){return WD_AR[new Date(k+'T12:00:00Z').getUTCDay()]+' — '+dayLabel(k);}
function prevDay(k){return new Date(new Date(k+'T12:00:00Z').getTime()-864e5).toISOString().slice(0,10);}
function ppl(n){return n===1?'شخص واحد':n===2?'شخصين':n<=10?n+' أشخاص':n+' شخص';}
function memberBadge(mc,from,single){
  if(mc.end==null)return '<span class="muted">👥 عدد الأعضاء: غير مسجّل لهذي الفترة</span>';
  var h='👥 الأعضاء: <b>'+mc.end+'</b> &nbsp;';
  if(mc.delta==null)return h+'<span class="muted">(ما فيه سجل سابق للمقارنة)</span>';
  var ref='';
  if(mc.baseKey)ref=' <span class="muted">عن '+((single&&mc.baseKey===prevDay(from))?WD_AR[new Date(mc.baseKey+'T12:00:00Z').getUTCDay()]:dayLabel(mc.baseKey))+'</span>';
  if(mc.delta>0)return h+'<span style="color:#4ade80;font-weight:bold">▲ زاد '+ppl(mc.delta)+'</span>'+ref;
  if(mc.delta<0)return h+'<span style="color:#f87171;font-weight:bold">▼ نقص '+ppl(-mc.delta)+'</span>'+ref;
  return h+'<span class="muted">＝ بدون تغيير</span>'+ref;
}
async function openRange(o){
  modal('<h3>'+esc(o.title)+'</h3><div class="card center muted">جاري التحميل...</div><div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  try{
    var j=await api('/api/stats/range?from='+o.from+'&to='+o.to+(o.week?'&week='+o.week:''));
    S.rng={o:o,j:j,f:o.filter||'all'};drawRange();
  }catch(e){closeModal();toast(e.message);}
}
function setRngFilter(f){S.rng.f=f;drawRange();}
function openDay(k,fromWeek){openRange({from:k,to:k,title:dayFull(k),back:(fromWeek&&S.rng)?S.rng.o:null});}
function openToday(f){openRange({from:S.todayKey,to:S.todayKey,title:'اليوم — '+dayFull(S.todayKey),filter:f});}
function openWeek(n){
  var x=S.wk.weeks.find(function(w){return w.no===n;});
  openRange({from:x.start,to:x.complete?x.end:S.wk.today,title:weekName(n)+(x.complete?'':' (جاري)'),sub:'من '+dayLabel(x.start)+' إلى '+dayLabel(x.end),week:n});
}
function drawRange(){
  var r=S.rng,o=r.o,j=r.j,single=o.from===o.to;
  var tabs=[['all','🚨 المشبوهة',j.total],['unresolved','⏳ غير محلولة',j.unresolved],['resolved','✅ محلولة',j.resolved]].map(function(t){
    return '<button class="tab '+(r.f===t[0]?'active':'')+'" onclick="setRngFilter(\''+t[0]+'\')">'+t[1]+' ('+t[2]+')</button>';}).join('');
  var days='';
  if(!single&&j.days&&j.days.length){
    days='<div class="card" style="margin:10px 0"><h3 style="font-size:14px;margin-bottom:6px">📅 الأيام <span class="muted" style="font-size:11px;font-weight:400">(اضغط على يوم لتفاصيله)</span></h3>'+j.days.map(function(d){
      var dl=(d.delta==null||d.delta===0)?'':' <span style="color:'+(d.delta>0?'#4ade80':'#f87171')+'">('+(d.delta>0?'+':'')+d.delta+')</span>';
      return '<div class="prow" style="cursor:pointer" onclick="openDay(\''+d.d+'\',true)"><span><b>'+WD_AR[new Date(d.d+'T12:00:00Z').getUTCDay()]+'</b> <span class="muted" style="font-size:11px">'+dayLabel(d.d)+'</span></span>'
       +'<span style="text-align:left;white-space:nowrap">🚨 '+d.total+' • ⏳ '+d.unresolved+' • ✅ '+d.resolved+(d.members!=null?' • 👥 '+d.members+dl:'')+'</span></div>';
    }).join('')+'</div>';
  }
  var sevAr={high:'خطير',medium:'متوسط',low:'منخفض'};
  var list=j.ops.filter(function(e){return r.f==='all'||(r.f==='resolved'?e.resolved:!e.resolved);});
  var ops=list.map(function(e){
    return '<div class="card" onclick="openEv(\''+e.id+'\')" style="cursor:pointer;margin:8px 0;padding:12px"><div class="log-title"><span>'+esc(e.title)+'</span><span class="badge '+esc(e.severity)+'">'+(sevAr[e.severity]||esc(e.severity))+'</span>'
     +(e.resolved?'<span class="badge done">✅ محلولة</span>':'<span class="badge medium">⏳ غير محلولة</span>')+'</div>'
     +(e.details?'<div class="log-det">'+esc(e.details)+'</div>':'')
     +'<div class="log-meta">🕒 '+fmt(e.createdAt)+(RULE_AR[e.rule]?' &nbsp;•&nbsp; '+esc(RULE_AR[e.rule]):'')+(e.actor?' &nbsp;•&nbsp; 👤 '+esc(e.actor):'')+(e.target?' &nbsp;•&nbsp; 🎯 '+esc(e.target):'')+(e.resolved&&e.resolvedBy?' &nbsp;•&nbsp; ✔️ '+esc(e.resolvedBy):'')+'</div></div>';
  }).join('')||'<div class="card center muted">'+(j.archived?'تفاصيل العمليات انحذفت (الأحداث تنحفظ 60 يوم) — الأرقام فوق محفوظة':'ما فيه عمليات')+'</div>';
  modal('<h3>'+esc(o.title)+'</h3>'+(o.sub?'<p class="muted center" style="font-size:12px;margin-bottom:8px">'+esc(o.sub)+'</p>':'')
   +'<div style="max-height:68vh;overflow-y:auto">'
   +'<div class="card" style="margin:8px 0"><div>'+memberBadge(j.members,o.from,single)+'</div><div class="log-meta">🚪 دخول: '+j.joins+' &nbsp;•&nbsp; خروج/طرد/حظر: '+j.leaves+'</div></div>'
   +'<div class="tabs" style="margin-top:10px">'+tabs+'</div>'+days+ops
   +(j.truncated?'<p class="muted center" style="font-size:12px">معروض أحدث 500 عملية فقط</p>':'')+'</div>'
   +'<div class="row" style="justify-content:flex-start;margin-top:14px">'+(o.back?'<button class="btn" onclick="openRange(S.rng.o.back)">⬅️ رجوع</button>':'')+'<button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
}
function weeksHtml(w){
  var rows=w.weeks.slice().reverse().map(function(x){
    var tag=x.complete?'<span class="badge done">مكتمل</span>':'<span class="badge medium">جاري</span>';
    var mem=x.membersEnd!=null?(' • 👥 '+x.membersEnd+((x.delta!=null&&x.delta!==0)?' <span style="color:'+(x.delta>0?'#4ade80':'#f87171')+'">('+(x.delta>0?'+':'')+x.delta+')</span>':'')):'';
    return '<div class="prow" style="cursor:pointer" onclick="openWeek('+x.no+')"><span><b>'+weekName(x.no)+'</b> '+tag+'<div class="log-meta">من '+dayLabel(x.start)+' إلى '+dayLabel(x.end)+'</div></span>'
     +'<span style="text-align:left;white-space:nowrap">🚨 '+x.total+' • ⏳ '+x.unresolved+' • ✅ '+x.resolved+mem+'</span></div>';
  }).join('');
  return '<div class="card"><h3>🗓️ الأسابيع</h3><p class="muted" style="font-size:12px;margin-bottom:8px">كل أسبوع 7 أيام، وإذا خلص يتسجّل. اضغط على أسبوع لعرض عملياته.</p>'+rows+'</div>';
}

/* ══ نشاط بوت آخر 7 أيام ══ */
var CAT_AR={join:'دخول',leave:'خروج',kick:'طرد',ban:'حظر',role:'الرتب',inquiry:'استفسارات الرتب',channel:'القنوات',voice:'الرومات الصوتية',message:'الرسائل',bot:'البوتات',webhook:'ويبهوكس',everyone:'منشن everyone',server:'إعدادات السيرفر',panel:'اللوحة',other:'أخرى'};
S.botNames={};
async function openBotAct(id){
  var nm=S.botNames[id]||'بوت';
  modal('<h3>🤖 نشاط '+esc(nm)+' — آخر 7 أيام</h3><div class="card center muted">جاري التحميل...</div><div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  try{
    var j=await api('/api/bots/'+id+'/activity');
    S.ba={id:id,name:j.name||nm,j:j,f:'all',day:''};drawBotAct();
  }catch(e){closeModal();toast(e.message);}
}
function setBaFilter(f){S.ba.f=f;drawBotAct();}
function setBaDay(d){S.ba.day=(S.ba.day===d?'':d);drawBotAct();}
function drawBotAct(){
  var b=S.ba,j=b.j;
  var max=Math.max.apply(null,j.days.map(function(d){return d.total;}).concat([1]));
  var bars=j.days.map(function(d){
    var dt=new Date(d.d+'T12:00:00Z');
    return '<div class="bar" style="'+(b.day===d.d?'outline:2px solid #d4af37;border-radius:8px':'')+'" onclick="setBaDay(\''+d.d+'\')"><b>'+d.total+'</b><i style="height:'+Math.round(d.total/max*100)+'%'+(d.sus?';background:#ef4444':'')+'"></i>'+WD_AR[dt.getUTCDay()]+'</div>';
  }).join('');
  var tabs=[['all','📋 كل العمليات',j.total],['sus','⚠️ المشبوهة',j.sus]].map(function(t){
    return '<button class="tab '+(b.f===t[0]?'active':'')+'" onclick="setBaFilter(\''+t[0]+'\')">'+t[1]+' ('+t[2]+')</button>';}).join('');
  var cats=Object.keys(j.byCat).sort(function(a,c){return j.byCat[c]-j.byCat[a];}).map(function(k){
    return '<div class="prow"><span>'+esc(CAT_AR[k]||k)+'</span><b>'+j.byCat[k]+'</b></div>';}).join('');
  var sevAr={high:'خطير',medium:'متوسط',low:'منخفض'};
  var list=j.ops.filter(function(e){
    if(b.f==='sus'&&!e.sus)return false;
    if(b.day&&dayKeyClient(e.createdAt)!==b.day)return false;
    return true;
  });
  var ops=list.map(function(e){
    return '<div class="card" onclick="openEv(\''+e.id+'\')" style="cursor:pointer;margin:8px 0;padding:12px"><div class="log-title"><span>'+esc(e.title)+'</span>'
     +(e.sus?'<span class="badge '+esc(e.severity)+'">⚠️ '+(sevAr[e.severity]||esc(e.severity))+'</span>':'')
     +(e.sus?(e.resolved?'<span class="badge done">✅ محلولة</span>':'<span class="badge medium">⏳ غير محلولة</span>'):'')+'</div>'
     +(e.details?'<div class="log-det">'+esc(e.details)+'</div>':'')
     +'<div class="log-meta">🕒 '+fmt(e.createdAt)+' &nbsp;•&nbsp; '+esc(CAT_AR[e.cat]||e.cat||'')+(RULE_AR[e.rule]?' &nbsp;•&nbsp; '+esc(RULE_AR[e.rule]):'')+(e.target?' &nbsp;•&nbsp; 🎯 '+esc(e.target):'')+'</div></div>';
  }).join('')||'<div class="card center muted">ما فيه عمليات'+(b.day||b.f!=='all'?' بهذا الفلتر':' للبوت آخر 7 أيام')+'</div>';
  modal('<h3>🤖 نشاط '+esc(b.name)+' — آخر 7 أيام</h3>'
   +'<p class="muted center" style="font-size:12px;margin-bottom:8px">من '+dayLabel(j.from)+' إلى '+dayLabel(j.to)+'</p>'
   +'<div style="max-height:68vh;overflow-y:auto">'
   +'<div class="card" style="margin:8px 0"><h3 style="font-size:14px;margin-bottom:6px">📅 العمليات حسب اليوم <span class="muted" style="font-size:11px;font-weight:400">(اضغط على يوم للتصفية)</span></h3><div class="bars">'+bars+'</div></div>'
   +(cats?'<div class="card" style="margin:8px 0"><h3 style="font-size:14px;margin-bottom:6px">حسب النوع</h3>'+cats+'</div>':'')
   +'<div class="tabs" style="margin-top:10px">'+tabs+'</div>'+ops
   +(j.truncated?'<p class="muted center" style="font-size:12px">معروض أحدث العمليات فقط</p>':'')+'</div>'
   +'<div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
}
function dayKeyClient(t){return new Date(new Date(t).getTime()+3*3600e3).toISOString().slice(0,10);}

/* ══ الإحصائيات ══ */
async function pgStats(){
  $('main').innerHTML='<h2>📊 الإحصائيات</h2><div class="card center muted">جاري التحميل...</div>';
  try{
    var s=await api('/api/stats');if(S.page!=='stats')return;
    S.todayKey=s.days[s.days.length-1].d;
    var wkHtml='';try{var wj=await api('/api/stats/weeks');S.wk=wj;wkHtml=weeksHtml(wj);}catch(e){}
    var max=Math.max.apply(null,s.days.map(function(d){return d.n;}).concat([1]));
    var wd=['الأحد','الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'];
    var bars=s.days.map(function(d){var dt=new Date(d.d+'T12:00:00Z');return '<div class="bar" onclick="openDay(\''+d.d+'\')"><b>'+d.n+'</b><i style="height:'+Math.round(d.n/max*100)+'%"></i>'+wd[dt.getUTCDay()]+'</div>';}).join('');
    var rules=Object.keys(s.byRule).sort(function(a,b){return s.byRule[b]-s.byRule[a];}).map(function(k){return '<div class="prow"><span>'+esc(RULE_AR[k]||k)+'</span><b>'+s.byRule[k]+'</b></div>';}).join('')||'<p class="muted center">ما فيه عمليات مشبوهة هذا الأسبوع 👌</p>';
    var on=s.bots.online.map(function(b){S.botNames[b.id]=b.name;return '<div class="prow" style="cursor:pointer" onclick="openBotAct(\''+b.id+'\')"><span><i class="st '+b.status+'"></i>'+esc(b.name)+'</span><span class="muted" style="font-size:12px">📊 نشاطه</span></div>';}).join('')||'<p class="muted center">لا أحد</p>';
    var off=s.bots.offline.map(function(b){S.botNames[b.id]=b.name;return '<div class="prow" style="cursor:pointer" onclick="openBotAct(\''+b.id+'\')"><span><i class="st offline"></i>'+esc(b.name)+'</span><span class="muted" style="font-size:12px">📊 نشاطه</span></div>';}).join('')||'<p class="muted center">لا أحد</p>';
    $('main').innerHTML='<h2>📊 الإحصائيات</h2>'
     +'<div class="grid4"><div class="stat red click" onclick="openToday(\'all\')"><div class="num">'+s.today.total+'</div><div class="lbl">عمليات مشبوهة اليوم</div><div class="lbl" style="font-size:11px">آخر 7 أيام: '+s.week+'</div></div>'
     +'<div class="stat amber click" onclick="openToday(\'unresolved\')"><div class="num">'+s.today.unresolved+'</div><div class="lbl">غير محلولة اليوم</div><div class="lbl" style="font-size:11px">آخر 7 أيام: '+s.unresolved+'</div></div>'
     +'<div class="stat green click" onclick="openToday(\'resolved\')"><div class="num">'+s.today.resolved+'</div><div class="lbl">محلولة اليوم</div><div class="lbl" style="font-size:11px">آخر 7 أيام: '+s.resolved+'</div></div>'
     +'<div class="stat"><div class="num">'+s.members+'</div><div class="lbl">أعضاء السيرفر</div></div></div>'
     +'<div class="card"><h3>العمليات المشبوهة خلال الأسبوع</h3><p class="muted" style="font-size:12px">اضغط على أي يوم لعرض عملياته وعدد الأعضاء فيه</p><div class="bars">'+bars+'</div></div>'+wkHtml
     +'<div class="card"><h3>حسب النوع</h3>'+rules+'</div>'
     +'<div class="grid3"><div class="stat"><div class="num">'+s.bots.total+'</div><div class="lbl">البوتات داخل السيرفر</div></div>'
     +'<div class="stat green"><div class="num">'+s.bots.online.length+'</div><div class="lbl">أونلاين الآن</div></div>'
     +'<div class="stat"><div class="num" style="color:#94a3b8">'+s.bots.offline.length+'</div><div class="lbl">أوفلاين الآن</div></div></div>'
     +(s.presence?'':'<div class="warn">⚠️ حالة البوتات غير دقيقة: فعّل <b>Presence Intent</b> من Discord Developer Portal → Bot ثم أعد تشغيل الخدمة.</div>')
     +'<div class="card"><h3>🟢 البوتات الأونلاين</h3>'+on+'</div><div class="card"><h3>⚫ البوتات الأوفلاين</h3>'+off+'</div>';
  }catch(e){toast(e.message);}
}

/* ══ البوتات ══ */
async function pgBots(){
  $('main').innerHTML='<h2>🤖 البوتات داخل السيرفر</h2><div class="card center muted">جاري التحميل...</div>';
  try{
    var j=await api('/api/bots');if(S.page!=='bots')return;
    var stAr={online:'أونلاين',idle:'خامل',dnd:'مشغول',offline:'أوفلاين',unknown:'غير معروف'};
    var html='<h2>🤖 البوتات داخل السيرفر ('+j.bots.length+')</h2>'+(j.presence?'':'<div class="warn">⚠️ فعّل Presence Intent لتظهر الحالة الحقيقية للبوتات.</div>');
    html+=j.bots.map(function(b){
      S.botNames[b.id]=b.name;
      return '<div class="card"><div class="bot"><img src="'+esc(b.avatar)+'" alt="" style="cursor:pointer" onclick="openBotAct(\''+b.id+'\')"><div style="flex:1;min-width:200px;cursor:pointer" onclick="openBotAct(\''+b.id+'\')">'
       +'<div class="log-title">'+esc(b.name)+' <span class="badge low"><i class="st '+b.status+'"></i>'+stAr[b.status]+'</span></div>'
       +'<div class="log-det">🧩 '+esc(b.desc)+'</div>'
       +(b.dang.length?'<div style="margin-top:6px">'+b.dang.map(function(d){return '<span class="chip '+d.level+'">'+esc(d.ar)+'</span>';}).join('')+'</div>':'')
       +(b.activity.length?'<div class="log-meta">⚙️ نشاطه آخر 24 ساعة: '+esc(b.activity.slice(0,4).join(' • '))+'</div>':'<div class="log-meta">⚙️ لا يوجد نشاط مسجّل آخر 24 ساعة</div>')
       +'<div class="log-meta">📥 دخل: '+(b.joinedAt?fmt(b.joinedAt):'-')+(b.addedBy?' • أضافه: '+esc(b.addedBy):'')+'</div></div>'
       +'<div style="display:flex;flex-direction:column;gap:6px"><button class="btn sm" onclick="openBotAct(\''+b.id+'\')">📊 نشاطه 7 أيام</button>'
       +(S.level==='full'?'<button class="btn sm danger" onclick="kickBot(\''+b.id+'\',\''+esc(b.name).replace(/'/g,'')+'\')">👢 طرد</button>':'')+'</div></div></div>';
    }).join('')||'<div class="card center muted">ما فيه بوتات</div>';
    $('main').innerHTML=html;
  }catch(e){toast(e.message);}
}
async function kickBot(id,name){
  if(!(await ask('متأكد تبي تطرد البوت '+name+'؟')))return;
  try{await api('/api/bots/'+id+'/kick',{method:'POST'});toast('تم طرد البوت');pgBots();}catch(e){toast(e.message);}
}

/* ══ صلاحيات السيرفر ══ */
async function pgPerms(){
  if(!S.meta)S.meta=await api('/api/perms/meta');
  var t=S.permsTab;
  $('main').innerHTML='<h2>🔐 صلاحيات السيرفر</h2>'
   +'<div class="tabs"><button class="tab '+(t==='roles'?'active':'')+'" onclick="S.permsTab=\'roles\';S.permsQ=\'\';pgPerms()">👥 قسم الرتب</button>'
   +'<button class="tab '+(t==='channels'?'active':'')+'" onclick="S.permsTab=\'channels\';S.permsQ=\'\';pgPerms()">💬 قسم الشاتات</button>'
   +'<button class="tab '+(t==='members'?'active':'')+'" onclick="S.permsTab=\'members\';S.permsQ=\'\';pgPerms()">👤 قسم الأعضاء</button></div>'
   +(t==='members'?'':'<div class="tabs"><button class="tab '+(S.permsView==='danger'?'active':'')+'" onclick="S.permsView=\'danger\';pgPerms()">⚠️ الخطرة فقط</button>'
   +'<button class="tab '+(S.permsView==='all'?'active':'')+'" onclick="S.permsView=\'all\';pgPerms()">📋 الكل</button>'
   +((t==='channels'&&S.level==='full')?'<button id="chEditBtn" class="tab'+(S.chEdit?' active':'')+'" style="margin-inline-start:auto" onclick="toggleChEdit()">'+(S.chEdit?'✅ إنهاء التعديل':'✏️ تعديل')+'</button>':'')+'</div>')
   +'<input id="pq" placeholder="'+(t==='roles'?'🔎 ابحث عن رتبة':t==='channels'?'🔎 ابحث عن شات':'🔎 ابحث بيوزر، اسم البروفايل، اسم السيرفر، أو الآيدي')+'" value="'+esc(S.permsQ)+'" style="margin-bottom:14px"><div id="pbox"><div class="card center muted">جاري التحميل...</div></div>';
  $('pq').oninput=function(){S.permsQ=this.value;if(S.permsTab==='roles')drawRoles(true);else if(S.permsTab==='channels')drawChannels(true);else drawMembers(true);};
  try{ if(t==='roles')await drawRoles();else if(t==='channels')await drawChannels();else await drawMembers(); }catch(e){toast(e.message);}
}
function pn(m){return esc(m.ar)+(m.en?' <span class="en">('+esc(m.en)+')</span>':'');}
function permChips(list,metaList){
  return list.map(function(k){var m=metaList.find(function(x){return x.k===k;})||{ar:k};return '<span class="chip '+(m.danger||'safe')+'">'+pn(m)+'</span>';}).join('');
}
async function drawRoles(nf){
  if(!nf){var j=await api('/api/perms/roles');S.roles=j.roles;}
  var q=(S.permsQ||'').trim().toLowerCase();
  var view=q?'all':S.permsView;
  var list=view==='danger'?S.roles.filter(function(r){return r.dang.length;}):S.roles;
  if(q)list=list.filter(function(r){return r.name.toLowerCase().indexOf(q)>-1;});
  var html=list.map(function(r){
    var shown=view==='danger'?r.dang:r.perms;
    return '<div class="card"><div class="row"><div><div class="log-title"><span><i class="dot" style="background:'+(r.color&&r.color!=='#000000'?r.color:'#64748b')+'"></i>'+esc(r.name)+'</span>'
     +(r.dang.length?'<span class="badge high">'+r.dang.length+' خطيرة</span>':'<span class="badge done">آمنة</span>')+'</div><div class="log-meta">👥 '+r.members+' عضو</div></div>'
     +'<div style="display:flex;gap:6px;flex-wrap:wrap"><button class="btn sm gray" onclick="roleMembers(\''+r.id+'\')">👥 عرض الأشخاص</button>'
     +'<button class="btn sm '+((r.editable&&S.level==='full')?'':'gray')+'" onclick="editRole(\''+r.id+'\')">'+((r.editable&&S.level==='full')?'✏️ عرض وتعديل':'👁️ عرض فقط')+'</button></div></div>'
     +'<div style="margin-top:8px">'+(shown.length?permChips(shown,S.meta.role):'<span class="muted" style="font-size:12px">لا صلاحيات</span>')+'</div></div>';
  }).join('')||(q?'<div class="card center muted">ما لقيت رتبة بهذا الاسم</div>':'<div class="card center muted">ما فيه رتب بصلاحيات خطيرة 👌</div>');
  if($('pbox'))$('pbox').innerHTML=html;
}
async function roleMembers(id){
  var r=S.roles.find(function(x){return x.id===id;});
  modal('<h3>👥 الأشخاص اللي معهم رتبة: '+esc(r.name)+'</h3><div class="card center muted">جاري التحميل...</div><div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  try{
    var j=await api('/api/perms/roles/'+id+'/members');
    var all=j.members,SHOW=300;
    modal('<h3>👥 الأشخاص اللي معهم رتبة: '+esc(j.role.name)+' ('+j.total+')</h3>'
      +'<input id="rmq" placeholder="🔎 ابحث بيوزر، اسم البروفايل، اسم السيرفر، أو الآيدي" style="margin-bottom:10px">'
      +'<div id="rmcount" class="muted" style="font-size:12px;margin-bottom:6px"></div>'
      +'<div id="rmlist" style="max-height:55vh;overflow-y:auto"></div>'
      +'<div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
    function draw(){
      var q=($('rmq').value||'').trim().toLowerCase();
      var f=q?all.filter(function(m){return [m.username,m.global,m.nick,m.server,m.name,m.tag,m.id].some(function(v){return (v||'').toLowerCase().indexOf(q)>-1;});}):all;
      $('rmcount').textContent=q?('النتائج: '+f.length+' من '+all.length):(all.length>SHOW?'معروض أول '+SHOW+' من '+all.length+' — استخدم البحث للباقي':'');
      $('rmlist').innerHTML=f.slice(0,SHOW).map(function(m){
        return '<div class="mlist"><img src="'+esc(m.avatar)+'" alt=""><div style="flex:1;min-width:0"><b>'+esc(m.server)+'</b>'+(m.bot?' <span class="badge low">بوت</span>':'')
          +'<div class="log-meta">🏷️ اسمه في السيرفر: '+esc(m.server)+'</div>'
          +'<div class="log-meta">👤 اسم البروفايل: '+esc(m.global)+'</div>'
          +'<div class="log-meta">🔖 اليوزر: @'+esc(m.username)+cpb(m.username,'تم نسخ اليوزر','نسخ اليوزر')+'</div></div></div>';
      }).join('')||'<div class="card center muted">'+(q?'ما لقيت أحد بهذا الاسم':'ما فيه أحد معه هذي الرتبة')+'</div>';
    }
    $('rmq').oninput=draw;draw();$('rmq').focus();
  }catch(e){closeModal();toast(e.message);}
}
function editRole(id){
  var r=S.roles.find(function(x){return x.id===id;});
  var canEdit=r.editable&&S.level==='full';
  var rows=S.meta.role.map(function(p){
    return '<div class="prow '+(p.danger==='critical'?'crit':p.danger==='high'?'hi':'')+'"><span>'+(p.danger?'<span class="chip '+p.danger+'">'+(p.danger==='critical'?'خطيرة جداً':'خطيرة')+'</span>':'')+pn(p)+'</span>'
     +'<label class="sw"><input type="checkbox" data-k="'+p.k+'"'+(r.perms.indexOf(p.k)>-1?' checked':'')+(canEdit?'':' disabled')+'><span></span></label></div>';
  }).join('');
  modal('<h3>صلاحيات الرتبة: '+esc(r.name)+'</h3>'+(canEdit?'':(r.editable?'<div class="warn">ماعندك صلاحية التعديل — عرض فقط.</div>':'<div class="warn">هذي الرتبة أعلى من رتبة البوت (أو رتبة بوت) — للعرض فقط.</div>'))
   +'<div style="max-height:60vh;overflow-y:auto">'+rows+'</div><div class="row" style="justify-content:flex-start;margin-top:14px">'
   +(canEdit?'<button class="btn" id="rs">💾 حفظ</button>':'')+'<button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  if(canEdit)$('rs').onclick=async function(){
    var perms=[].slice.call(document.querySelectorAll('.modal input[data-k]')).filter(function(i){return i.checked;}).map(function(i){return i.getAttribute('data-k');});
    if(perms.indexOf('Administrator')>-1&&r.perms.indexOf('Administrator')<0&&!(await ask('تفعيل صلاحية المدير (Administrator) يعطي الرتبة كل الصلاحيات. متأكد؟')))return;
    this.disabled=true;
    try{await api('/api/perms/roles/'+id,{method:'PUT',body:JSON.stringify({perms:perms})});toast('تم حفظ الصلاحيات');closeModal();drawRoles();}catch(e){toast(e.message);this.disabled=false;}
  };
}
async function drawMembers(nf){
  if(!nf){
    var j=await api('/api/perms/members');S.mem2=j.members;S.memTotal=j.total;
    var rj=await api('/api/perms/roles');S.roles=rj.roles;
  }
  var q=(S.permsQ||'').trim().toLowerCase(),SHOW=100;
  var f=q?S.mem2.filter(function(m){return [m.username,m.global,m.nick,m.server,m.tag,m.id].some(function(v){return (v||'').toLowerCase().indexOf(q)>-1;});}):S.mem2;
  var info='<div class="muted" style="font-size:12px;margin-bottom:8px">'+(q?('النتائج: '+f.length+' من '+S.mem2.length):('👤 '+S.memTotal+' عضو'+(f.length>SHOW?' — معروض أول '+SHOW+'، استخدم البحث للباقي':'')))+'</div>';
  var html=info+f.slice(0,SHOW).map(function(m){
    var set={};m.roles.forEach(function(x){set[x]=1;});
    var chips=S.roles.filter(function(r){return set[r.id];}).map(function(r){
      return '<span class="chip '+(r.dang.length?'high':'safe')+'"><i class="dot" style="background:'+(r.color&&r.color!=='#000000'?r.color:'#64748b')+'"></i>'+esc(r.name)+'</span>';
    }).join('')||'<span class="muted" style="font-size:12px">بدون رتب</span>';
    var canEdit=S.level==='full'&&m.editable;
    return '<div class="card"><div class="bot"><img src="'+esc(m.avatar)+'" alt=""><div style="flex:1;min-width:200px">'
     +'<div class="log-title"><b>'+esc(m.server)+'</b>'+(m.bot?' <span class="badge low">بوت</span>':'')+'</div>'
     +'<div class="log-meta">🏷️ اسمه في السيرفر: '+esc(m.server)+' &nbsp;•&nbsp; 👤 البروفايل: '+esc(m.global)+' &nbsp;•&nbsp; 🔖 @'+esc(m.username)+cpb(m.username,'تم نسخ اليوزر','نسخ اليوزر')+'</div>'
     +'<div style="margin-top:8px">'+chips+'</div></div>'
     +'<button class="btn sm '+(canEdit?'':'gray')+'" onclick="editMember(\''+m.id+'\')">'+(canEdit?'✏️ عرض وتعديل':'👁️ عرض فقط')+'</button></div></div>';
  }).join('')||'<div class="card center muted">'+(q?'ما لقيت أحد بهذا الاسم':'ما فيه أعضاء')+'</div>';
  if($('pbox'))$('pbox').innerHTML=html;
}
function editMember(id){
  var m=S.mem2.find(function(x){return x.id===id;});
  var canEdit=S.level==='full'&&m.editable;
  var has={};m.roles.forEach(function(x){has[x]=1;});
  var rows=S.roles.filter(function(r){return !r.everyone;}).map(function(r){
    var dis=!(canEdit&&r.editable);
    var why=r.managed?'🤖 رتبة بوت':(!r.editable?'🔒 أعلى من رتبة البوت':'');
    return '<div class="prow '+(r.dang.length?'hi':'')+'" style="'+(dis?'opacity:.45':'')+'" data-n="'+esc(r.name.toLowerCase())+'"><span><i class="dot" style="background:'+(r.color&&r.color!=='#000000'?r.color:'#64748b')+'"></i>'+esc(r.name)
     +(r.dang.length?' <span class="chip high">'+r.dang.length+' خطيرة</span>':'')+(why?' <span class="muted" style="font-size:11px">('+why+')</span>':'')+'</span>'
     +'<label class="sw"><input type="checkbox" data-r="'+r.id+'"'+(has[r.id]?' checked':'')+(dis?' disabled':'')+'><span></span></label></div>';
  }).join('');
  modal('<h3>رتب: '+esc(m.server)+' <span class="muted" style="font-size:12px">@'+esc(m.username)+'</span></h3>'
   +(canEdit?(S.roles.some(function(r){return r.editable&&!r.everyone;})?'':'<div class="warn">كل رتب السيرفر أعلى من رتبة البوت، فما يقدر يعدّلها. ارفع رتبة البوت فوقها من إعدادات السيرفر ← الرتب.</div>'):'<div class="warn">'+(S.level!=='full'?'ماعندك صلاحية التعديل — عرض فقط.':'رتبة هذا الشخص أعلى من رتبة البوت (أو مالك السيرفر) — للعرض فقط. ارفع رتبة البوت فوق رتبه من إعدادات السيرفر ← الرتب.')+'</div>')
   +'<input id="mrq" placeholder="🔎 ابحث عن رتبة" style="margin-bottom:8px">'
   +'<div style="max-height:55vh;overflow-y:auto">'+rows+'</div><div class="row" style="justify-content:flex-start;margin-top:14px">'
   +(canEdit?'<button class="btn" id="ms">💾 حفظ</button>':'')+'<button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  $('mrq').oninput=function(){var q=this.value.trim().toLowerCase();document.querySelectorAll('.modal .prow[data-n]').forEach(function(r){r.style.display=(!q||r.getAttribute('data-n').indexOf(q)>-1)?'':'none';});};
  if(canEdit)$('ms').onclick=async function(){
    var add=[],remove=[];
    document.querySelectorAll('.modal input[data-r]').forEach(function(i){
      if(i.disabled)return;var rid=i.getAttribute('data-r');
      if(i.checked&&!has[rid])add.push(rid);
      if(!i.checked&&has[rid])remove.push(rid);
    });
    if(!add.length&&!remove.length){toast('ما غيّرت شي');return;}
    var danger=add.filter(function(rid){var r=S.roles.find(function(x){return x.id===rid;});return r&&r.dang.length;});
    if(danger.length&&!(await ask('راح تعطيه رتبة بصلاحيات خطيرة. متأكد؟')))return;
    if(m.id===S.meId&&remove.length&&!(await ask('راح تسحب رتب من نفسك، وممكن تفقد صلاحياتك في اللوحة. متأكد؟')))return;
    this.disabled=true;
    try{await api('/api/perms/members/'+id+'/roles',{method:'PUT',body:JSON.stringify({add:add,remove:remove})});toast('تم حفظ الرتب');closeModal();drawMembers();}catch(e){toast(e.message);this.disabled=false;}
  };
}
async function drawChannels(nf){
  if(!nf){var j=await api('/api/perms/channels');S.chans=j.channels;}
  var q=(S.permsQ||'').trim().toLowerCase();
  var view=q?'all':S.permsView;
  var list=view==='danger'?S.chans.filter(function(c){return c.hasDanger;}):S.chans.filter(function(c){return c.overwrites.length;});
  if(q)list=S.chans.filter(function(c){return c.name.toLowerCase().indexOf(q)>-1||(c.parent||'').toLowerCase().indexOf(q)>-1||c.overwrites.some(function(o){return o.name.toLowerCase().indexOf(q)>-1;});});
  var editing=S.level==='full'&&!!S.chEdit;
  var html=(editing?'<div class="warn">✏️ وضع التعديل شغّال لكل الشاتات: اضغط 🗑️ حذف جنب أي رتبة (أو عضو) لحذف كل صلاحياتها الخاصة من ذاك الشات.</div>':'')+list.map(function(c){
    var ovs=(view==='danger'?c.overwrites.filter(function(o){return o.dang.length;}):c.overwrites).map(function(o){
      return '<div class="prow"><span><b>'+(o.type==='role'?'👥 ':'👤 ')+esc(o.name)+'</b> '+(o.dang.length?permChips(o.dang,S.meta.channel):'<span class="chip safe">بدون صلاحيات خطيرة</span>')+'</span>'
       +'<span style="display:flex;gap:6px;flex-wrap:wrap"><button class="btn sm '+(S.level==='full'?'':'gray')+'" onclick="editOv(\''+c.id+'\',\''+o.id+'\')">'+(S.level==='full'?'✏️ تعديل':'👁️ عرض')+'</button>'
       +(editing?'<button class="btn sm danger" onclick="delOv(\''+c.id+'\',\''+o.id+'\')">🗑️ حذف</button>':'')+'</span></div>';
    }).join('');
    return '<div class="card"><div class="log-title"><span>'+c.icon+' '+esc(c.name)+'</span>'+(c.parent?'<span class="muted" style="font-size:12px">'+esc(c.parent)+'</span>':'')+(c.hasDanger?'<span class="badge high">صلاحيات خطيرة</span>':'')
     +'</div>'+ovs+'</div>';
  }).join('')||(q?'<div class="card center muted">ما لقيت شات بهذا الاسم</div>':'<div class="card center muted">ما فيه قنوات بصلاحيات خطيرة 👌</div>');
  if($('pbox'))$('pbox').innerHTML=html;
}
function toggleChEdit(){
  S.chEdit=!S.chEdit;
  var b=$('chEditBtn');if(b){b.className='tab'+(S.chEdit?' active':'');b.textContent=S.chEdit?'✅ إنهاء التعديل':'✏️ تعديل';}
  drawChannels(true);
}
async function delOv(cid,tid){
  var c=S.chans.find(function(x){return x.id===cid;});var o=c.overwrites.find(function(x){return x.id===tid;});
  var msg='تحذف كل الصلاحيات الخاصة بـ «'+o.name+'» ('+(o.type==='role'?'رتبة':'عضو')+') من شات #'+c.name+'؟\nترجع للإعدادات الافتراضية للشات، وما تقدر تتراجع بسهولة.';
  if(o.name==='@everyone')msg+='\n\n⚠️ هذي رتبة @everyone — حذفها ممكن يغيّر مين يشوف الشات ويكتب فيه!';
  if(!(await ask(msg)))return;
  try{await api('/api/perms/channels/'+cid+'/'+tid,{method:'DELETE'});toast('تم حذف الصلاحيات من الشات');drawChannels();}catch(e){toast(e.message);}
}
function editOv(cid,tid){
  var c=S.chans.find(function(x){return x.id===cid;});var o=c.overwrites.find(function(x){return x.id===tid;});
  var canEdit=S.level==='full';
  var rows=S.meta.channel.map(function(p){
    var st=o.allow.indexOf(p.k)>-1?'a':o.deny.indexOf(p.k)>-1?'d':'n';
    return '<div class="prow '+(p.danger==='critical'?'crit':p.danger==='high'?'hi':'')+'" data-k="'+p.k+'" data-s="'+st+'"><span>'+(p.danger?'<span class="chip '+p.danger+'">'+(p.danger==='critical'?'خطيرة جداً':'خطيرة')+'</span>':'')+pn(p)+'</span>'
     +'<div class="tri"><button class="a '+(st==='a'?'on':'')+'"'+(canEdit?' onclick="setTri(this,\'a\')"':' disabled')+'>✓</button><button class="n '+(st==='n'?'on':'')+'"'+(canEdit?' onclick="setTri(this,\'n\')"':' disabled')+'>—</button><button class="d '+(st==='d'?'on':'')+'"'+(canEdit?' onclick="setTri(this,\'d\')"':' disabled')+'>✗</button></div></div>';
  }).join('');
  modal('<h3>'+esc(c.name)+' — '+esc(o.name)+'</h3>'+(canEdit?'<p class="muted center" style="font-size:12px;margin-bottom:8px">✓ سماح &nbsp; — افتراضي &nbsp; ✗ منع</p>':'<div class="warn">ماعندك صلاحية التعديل — عرض فقط.</div>')+'<div style="max-height:60vh;overflow-y:auto">'+rows+'</div>'
   +'<div class="row" style="justify-content:flex-start;margin-top:14px">'+(canEdit?'<button class="btn" id="os">💾 حفظ</button><button class="btn danger" onclick="delOv(\''+cid+'\',\''+tid+'\')">🗑️ حذف من الشات</button>':'')+'<button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  if(canEdit)$('os').onclick=async function(){
    var allow=[],deny=[];
    document.querySelectorAll('.modal .prow[data-k]').forEach(function(r){var s=r.getAttribute('data-s');if(s==='a')allow.push(r.getAttribute('data-k'));if(s==='d')deny.push(r.getAttribute('data-k'));});
    this.disabled=true;
    try{await api('/api/perms/channels/'+cid+'/'+tid,{method:'PUT',body:JSON.stringify({allow:allow,deny:deny,name:o.name})});toast('تم الحفظ');closeModal();drawChannels();}catch(e){toast(e.message);this.disabled=false;}
  };
}
function setTri(b,s){var row=b.closest('.prow');row.setAttribute('data-s',s);row.querySelectorAll('.tri button').forEach(function(x){x.classList.remove('on');});b.classList.add('on');}

/* ══ أعضاء الأمن السيبراني (للقائد والنائب) ══ */
var RANK_AR={leader:'👑 قائد',deputy:'🥈 نائب',member:'عضو'};
async function pgMembers(){
  $('main').innerHTML='<h2>👥 أعضاء الأمن السيبراني</h2><div class="card center muted">جاري التحميل...</div>';
  try{
    var j=await api('/api/members');if(S.page!=='members')return;
    S.meRank=j.meRank;S.memMap={};
    var html='<h2>👥 أعضاء الأمن السيبراني ('+j.members.length+')</h2><div class="muted" style="font-size:12px;margin:-4px 0 8px">👆 اضغط على بطاقة العضو لعرض آخر نشاط له في السيرفر</div>';
    html+=j.members.map(function(m){
      S.memMap[m.id]=m;
      var last=m.lastLoginAt?fmt(m.lastLoginAt):'لم يسجّل الدخول للوحة بعد';
      var dur=(m.durationMin!=null)?'⏱️ قعد آخر مرة: '+m.durationMin+' دقيقة':'';
      var canDismiss=m.id!==S.meId&&!(m.rank==='leader'&&S.meRank!=='leader');
      return '<div class="card" data-mid="'+esc(m.id)+'" style="cursor:pointer"><div class="bot"><img src="'+esc(m.avatar)+'" alt=""><div style="flex:1;min-width:200px">'
        +'<div class="log-title">'+esc(m.tag)+' <span class="badge '+(m.rank==='leader'?'high':m.rank==='deputy'?'medium':'low')+'">'+RANK_AR[m.rank]+'</span></div>'
        +'<div class="log-meta">🕒 آخر دخول للوحة: '+last+'</div>'
        +(dur?'<div class="log-meta">'+dur+'</div>':'')
        +'<div class="log-meta" style="color:#60a5fa">🕵️ اضغط لعرض نشاطه في السيرفر</div></div>'
        +(canDismiss?'<button class="btn sm danger" onclick="dismissMember(\''+m.id+'\',\''+esc(m.tag).replace(/'/g,'')+'\')">🚫 فصل</button>':'<span class="muted" style="font-size:12px">'+(m.id===S.meId?'أنت':'🔒 القائد')+'</span>')+'</div></div>';
    }).join('')||'<div class="card center muted">ما فيه أعضاء بعد</div>';
    $('main').innerHTML=html;
    $('main').onclick=function(ev){
      if(ev.target.closest('button,a'))return;
      if(window.getSelection&&String(window.getSelection()))return;
      var c=ev.target.closest('[data-mid]');if(c)openAct(c.getAttribute('data-mid'));
    };
  }catch(e){toast(e.message);}
}
var ST_AR={online:'🟢 أونلاين',idle:'🌙 خامل',dnd:'⛔ مشغول',offline:'⚫ أوفلاين',invisible:'⚫ أوفلاين',unknown:'❔ غير معروف'};
function actHead(b,id){
  return '<div class="card" style="margin:8px 0;padding:12px"><div class="mlist" style="border:none;padding:0;align-items:flex-start">'+(b.avatar?'<img src="'+esc(b.avatar)+'" alt="">':'')
    +'<div style="flex:1;min-width:0"><b>'+esc(b.tag||id)+'</b>'+(b.rank&&RANK_AR[b.rank]?' <span class="badge '+(b.rank==='leader'?'high':b.rank==='deputy'?'medium':'low')+'">'+RANK_AR[b.rank]+'</span>':'')
    +(b.name?'<div class="log-meta">🏷️ اسمه في السيرفر: '+esc(b.name)+'</div>':'')
    +'<div class="log-meta">🆔 '+esc(id)+cpb(id,'تم نسخ الآيدي','نسخ الآيدي')+'</div></div></div></div>';
}
async function openAct(id){
  S.actId=id;var b=(S.memMap||{})[id]||{};
  modal('<div id="actinfo" style="max-height:70vh;overflow-y:auto"><h3>🕵️ نشاط العضو</h3>'+actHead(b,id)+'<div class="card center muted">جاري التحميل...</div></div><div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  try{
    var j=await api('/api/members/'+id+'/activity');
    if(S.actId!==id||!$('actinfo'))return;
    drawAct(j,b);
  }catch(e){if(S.actId===id&&$('actinfo'))$('actinfo').innerHTML='<h3>🕵️ نشاط العضو</h3>'+actHead(b,id)+'<div class="card center muted">'+esc(e.message)+'</div>';}
}
function drawAct(a,b){
  var box=$('actinfo');if(!box)return;
  var hb={tag:a.tag||b.tag,avatar:a.avatar||b.avatar,rank:b.rank,name:a.name};
  var on=a.presenceOk&&a.status&&a.status!=='offline'&&a.status!=='unknown';
  var stTxt=a.presenceOk?(ST_AR[a.status]||ST_AR.unknown):'⚠️ تتبّع الحالة غير مفعّل (Presence Intent)';
  var since=a.trackedSince?fmt(Number(a.trackedSince)):'';
  var lastOn;
  if(on)lastOn='<b>الحين</b> <span class="muted" style="font-size:11px">(متصل)</span>';
  else if(a.lastOnlineAt)lastOn='<b>'+esc(fmt(a.lastOnlineAt))+'</b> <span class="muted" style="font-size:11px">('+ago(a.lastOnlineAt)+')</span>';
  else lastOn='<span class="muted">ما سجّلنا له أونلاين'+(since?' من بدأ التتبّع ('+esc(since)+')':'')+'</span>';
  var joined=a.joinedAt?'<b>'+esc(fmt(a.joinedAt))+'</b> <span class="muted" style="font-size:11px">('+ago(a.joinedAt)+')</span>':'<span class="muted">'+(a.inServer?'غير معروف':'⚠️ مو موجود بالسيرفر')+'</span>';
  var rows='<div class="card" style="margin:8px 0;padding:6px 12px">'
    +'<div class="prow"><span class="muted">📶 الحالة الحين</span><b>'+stTxt+'</b></div>'
    +'<div class="prow"><span class="muted">🕒 آخر مرة أونلاين</span><span style="text-align:left">'+lastOn+'</span></div>'
    +'<div class="prow" style="border:none"><span class="muted">📥 دخل السيرفر</span><span style="text-align:left">'+joined+'</span></div></div>';
  var lm=a.lastMsg,msg;
  if(lm){
    msg='<div class="card" style="margin:8px 0;padding:12px"><div class="muted" style="font-size:12px;margin-bottom:4px">💬 آخر رسالة له في السيرفر</div>'
      +'<div class="log-meta">🕒 '+esc(fmt(lm.at))+' <span class="muted">('+ago(lm.at)+')</span>'+(lm.channel?' &nbsp;•&nbsp; #'+esc(lm.channel):'')+'</div>'
      +'<div class="log-det" style="margin-top:6px;white-space:pre-wrap">'+(lm.content?esc(lm.content):'<span class="muted">(بدون نص)</span>')+'</div>'
      +(lm.att?'<div class="log-meta">📎 '+lm.att+' مرفق</div>':'')
      +(lm.url&&/^https:\/\/discord\.com\//.test(lm.url)?'<div style="margin-top:8px"><a class="btn sm gray" href="'+esc(lm.url)+'" target="_blank" rel="noopener">🔗 فتح الرسالة في ديسكورد</a></div>':'')+'</div>';
  }else msg='<div class="card" style="margin:8px 0;padding:12px"><div class="muted" style="font-size:12px;margin-bottom:4px">💬 آخر رسالة له في السيرفر</div><span class="muted">ما لقينا له رسالة'+(since?' من بدأ التتبّع ('+esc(since)+')':'')+'</span></div>';
  box.innerHTML='<h3>🕵️ نشاط العضو</h3>'+actHead(hb,a.id)+rows+msg;
}
async function dismissMember(id,name){
  if(!(await ask('متأكد تبي تفصل '+name+' من الأمن السيبراني؟\nراح تنسحب رتبته من ديسكورد وما يقدر يدخل اللوحة إلا إذا ترجعت له الرتبة.')))return;
  try{await api('/api/members/'+id+'/dismiss',{method:'POST'});toast('تم الفصل');pgMembers();}catch(e){toast(e.message);}
}

/* ── تشغيل ── */
(async function(){
  try{
    var me=await api('/api/me');S.presence=me.presence;S.level=me.user.level||'view';S.meId=me.user.id;
    $('uchip').innerHTML='<img src="'+esc(me.user.avatar)+'" alt=""><span>'+esc(me.user.tag)+'</span><a class="btn sm gray" href="/auth/logout">خروج</a>';
    buildNav();render();
    try{
      var es=S.es=new EventSource('/api/events/stream');
      es.addEventListener('changed',function(){ if(S.page==='logs')loadEvents(true); });
      es.addEventListener('dismissed',function(){showDismissed();});
      es.addEventListener('access',function(e){
        try{var d=JSON.parse(e.data);
          if(d.level&&d.level!==S.level){S.level=d.level;if(S.page==='members'&&d.level!=='full')S.page='logs';closeModal();buildNav();render();toast(d.level==='full'?'تمت ترقيتك — صارت عندك صلاحية التعديل':'تغيّرت صلاحيتك إلى عرض فقط');}
        }catch(x){}
      });
    }catch(e){}
  }catch(e){}
})();
`;

function appPage() {
    return HEAD(CONFIG.SITE_NAME + " — " + CONFIG.SITE_SUB) + `<body>
<nav>
  <div class="nav-start"><button class="hamburger-btn" onclick="openDrawer()" aria-label="القائمة">☰</button><div class="logo">🛡️ ${CONFIG.SITE_NAME}<span class="hide-sm"> — ${CONFIG.SITE_SUB}</span></div></div>
  <ul class="nav-links" id="navlinks"></ul>
  <div class="userchip" id="uchip"></div>
</nav>
<div class="dov" id="dov" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer"><div class="dh"><div class="logo">🛡️ ${CONFIG.SITE_NAME}</div><div class="muted" style="font-size:12px;margin-top:2px">${CONFIG.SITE_SUB}</div></div><div id="drawer-items"></div></div>
<div class="wrap" id="main"></div>
<div id="toast"></div>
<script>${CLIENT}</script>
</body></html>`;
}

app.get("/", (req, res) => {
    if (req.session.user) return res.send(appPage());
    const mode = req.query.denied ? "denied" : req.query.err ? "err" : "login";
    res.send(loginPage(mode));
});
app.get("/healthz", (req, res) => res.send("ok"));

app.use((err, req, res, next) => {
    console.error("❌ خطأ غير متوقع:", err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: err.message || "صار خطأ غير متوقع" });
});
process.on("unhandledRejection", e => console.error("❌ Unhandled Rejection:", e));
process.on("uncaughtException", e => console.error("❌ Uncaught Exception:", e));

startSiteJobs();
app.listen(CONFIG.PORT, "0.0.0.0", () => console.log("🚀 " + CONFIG.SITE_NAME + " running on port " + CONFIG.PORT));
