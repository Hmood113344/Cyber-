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
    NOTIFY_BOT_TOKEN: process.env.NOTIFY_BOT_TOKEN || process.env.BOT_TOKEN || "",   // نفس توكن بوت الأمن السيبراني — يُستخدم فقط لإرسال إشعارات القيادة بالخاص
    // اختياري: لو عنوان الاستضافة محظور من ديسكورد (Cloudflare 1015) مرّر طلبات ديسكورد عبر Cloudflare Worker (ملف discord-proxy-worker.js)
    DISCORD_API_BASE: (process.env.DISCORD_API_BASE || "https://discord.com/api").replace(/\/+$/, ""),   // مثال: https://xxxx.workers.dev/api
    DISCORD_PROXY_KEY: process.env.DISCORD_PROXY_KEY || "",
    GUILD_ID: process.env.GUILD_ID || "",   // اختياري: آيدي السيرفر لصفحة «الرومات» (لو فاضي ياخذ أول سيرفر البوت فيه)
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
// تسجيل الروم الصوتي: البوت يكتب الجلسات والقطع الصوتية، والموقع يقرأها (نفس التعريف بالضبط بملف البوت)
const VoiceSess = mongoose.model("CyberVoiceSess", new mongoose.Schema({
    sid: { type: String, unique: true }, chId: String, chName: String,
    startedAt: Date, endedAt: { type: Date, default: null }, lastAt: Date,
    mime: { type: String, default: "audio/ogg; codecs=opus" },
    chunks: { type: Number, default: 0 }, bytes: { type: Number, default: 0 },
    stays: { type: [mongoose.Schema.Types.Mixed], default: [] },
    speech: { type: [mongoose.Schema.Types.Mixed], default: [] }, speechN: { type: Number, default: 0 },
    pkts: { type: Number, default: 0 }, decErr: { type: String, default: null },
    dbg: { type: String, default: null }, dep: { type: String, default: null },
    tracks: { type: mongoose.Schema.Types.Mixed, default: {} },
    createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 },
}, { minimize: false }));
const VoiceChunkSchema = new mongoose.Schema({
    sid: String, uid: { type: String, default: null }, seq: Number, data: Buffer,
    createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 },
});
VoiceChunkSchema.index({ sid: 1, seq: 1 });
VoiceChunkSchema.index({ sid: 1, uid: 1, seq: 1 });
const VoiceChunk = mongoose.model("CyberVoiceChunk", VoiceChunkSchema);

// إشعارات القيادة (من عضو عن عملية مشبوهة، أو من مسؤول الأفراد عن عضو) — تظهر منبثقة للقائد والنائب وتوصلهم بالخاص
// مهام القيادة للأعضاء (العداد يبدأ من لحظة ما العضو يضغط «استلمت المهمة»)
const Task = mongoose.model("CyberTask", new mongoose.Schema({
    assignerId: String, assignerTag: String, assignerAvatar: String,
    targetId: { type: String, index: true }, targetTag: String,
    text: String, minutes: Number,
    status: { type: String, default: "pending", index: true },   // pending | active | done | cancelled
    ackAt: Date, dueAt: Date, doneAt: Date, cancelledBy: String,
    overdueNotified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now, index: true, expires: 60 * 60 * 24 * 30 },
}));
const Notice = mongoose.model("CyberNotice", new mongoose.Schema({
    type: String,                                   // op | member
    eventId: String, eventTitle: String, eventDetails: String,
    subjectId: String, subjectTag: String, reason: String,
    rule: String, allowedBy: { type: String, default: null }, allowedByTag: String, allowedAt: Date,   // السماح للعضو بالتعامل مع حالة «حساب جديد»
    senderId: String, senderTag: String, senderAvatar: String,
    recipients: { type: [String], index: true }, seenBy: { type: [String], default: [] },
    dm: { type: mongoose.Schema.Types.Mixed, default: {} },
    createdAt: { type: Date, default: Date.now, index: true, expires: 60 * 60 * 24 * 30 },
}, { minimize: false }));

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

// طلبات صفحة «بوت تسجيل الرومات» تمر بجدول خاص (CyberRecJob) — ما يلقطها أي بوت قديم، بس البوت الجديد
const RecJob = mongoose.model("CyberRecJob", new mongoose.Schema({
    type: String,
    params: { type: mongoose.Schema.Types.Mixed, default: {} },
    status: { type: String, default: "pending", index: true },
    result: mongoose.Schema.Types.Mixed,
    error: String, errStatus: Number,
    createdAt: { type: Date, default: Date.now, index: true, expires: 60 * 30 },
    startedAt: Date, doneAt: Date,
}, { minimize: false }));
async function callRecBot(type, params, timeoutMs) {
    if (!(await botAlive())) { const e = new Error("البوت غير متصل حالياً — تأكد إنه شغّال على استضافته"); e.status = 503; throw e; }
    const job = await RecJob.create({ type, params: params || {}, status: "pending" });
    const t0 = Date.now(), limit = timeoutMs || 25000;
    while (Date.now() - t0 < limit) {
        await sleep(300);
        const j = await RecJob.findById(job._id).lean();
        if (!j) break;
        if (j.status === "done") return j.result;
        if (j.status === "error") { const e = new Error(j.error || "فشل التنفيذ"); e.status = j.errStatus || 500; throw e; }
    }
    await RecJob.deleteOne({ _id: job._id, status: "pending" }).catch(() => {});
    const e = new Error("البوت ما رد — تأكد إن ملف البوت الجديد (app.js) هو اللي شغّال على الاستضافة وأعد تشغيله"); e.status = 504; throw e;
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

// ── رتبة «مسؤول أفراد الأمن السيبراني»: زي العضو العادي + صفحة الأعضاء (عرض فقط) ──
// الموقع يسأل البوت عن اللي معهم الرتبة (بنفس أمر "role_members" الموجود) ويحدّث القائمة كل 20 ثانية
const MGR_ROLE_ID = "1563654738803949708";
let mgrSet = new Set(), mgrAt = 0, mgrBusy = null;
const effLevel = (uid, base) => base === "full" ? "full" : (mgrSet.has(uid) ? "mgr" : (base || null));
let mgrAltAt = 0;
async function refreshMgr(maxAge, forceAlt) {
    if (mgrBusy) return mgrBusy;
    if (Date.now() - mgrAt < (maxAge == null ? 20000 : maxAge)) return;
    mgrBusy = (async () => {
        try {
            if (!(await botAlive())) return;
            let next = null;
            try {
                const r = await callBot("role_members", { id: MGR_ROLE_ID }, 30000);
                next = new Set(((r && r.members) || []).filter(m => m && !m.bot).map(m => String(m.id || m.uid || "")).filter(Boolean));
            } catch (e) { console.error("refreshMgr role_members:", e.message); }
            // احتياط: لو ما رجع أحد نسأل عن كل الأعضاء ورتبهم (أثقل، فنكرره كل 5 دقايق بس — أو فوراً وقت تسجيل الدخول)
            if ((!next || !next.size) && (forceAlt || Date.now() - mgrAltAt > 300000)) {
                mgrAltAt = Date.now();
                try {
                    const pm = await callBot("perm_members", {}, 60000);
                    const alt = new Set(((pm && pm.members) || []).filter(m => m && !m.bot && Array.isArray(m.roles) && m.roles.includes(MGR_ROLE_ID)).map(m => String(m.id)));
                    if (alt.size || !next) next = alt;
                } catch (e) { console.error("refreshMgr perm_members:", e.message); }
            }
            if (!next) return;   // فشل الطلبين — نبقي القائمة القديمة
            const changed = [];
            for (const id of next) if (!mgrSet.has(id)) changed.push(id);
            for (const id of mgrSet) if (!next.has(id)) changed.push(id);
            if (changed.length) console.log("🗂️ مسؤولو أفراد الأمن السيبراني:", next.size);
            mgrSet = next; mgrAt = Date.now();
            for (const id of changed) { roleCheck.delete(id); applyAccess(id, accessSeen.has(id) ? accessSeen.get(id) : null); }
        } catch (e) { console.error("refreshMgr:", e.message); }
        finally { mgrBusy = null; }
    })();
    return mgrBusy;
}
async function stillAuthorized(uid) {
    const c = roleCheck.get(uid);
    if (c && Date.now() - c.t < 10000) return c;
    let level = null; // 'full' | 'view' | null
    try { const d = await Access.findById(uid).lean(); level = d && d.level ? d.level : null; } catch { level = null; }
    level = effLevel(uid, level);   // full | mgr | view | null
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
    const eff = effLevel(uid, level);
    roleCheck.set(uid, { ok: !!eff, level: eff, t: Date.now() });
    if (eff) pushToUser(uid, "access", { level: eff }); else pushToUser(uid, "dismissed");
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
const canMembers = wrap(async (req, res, next) => {
    const lv = req.session.user.level;
    if (lv !== "full" && lv !== "mgr") return res.status(403).json({ error: "هذي الصفحة للقائد والنائب ومسؤول الأفراد فقط" });
    next();
});
const full = wrap(async (req, res, next) => {
    if (req.session.user.level !== "full") return res.status(403).json({ error: "هذا الإجراء يحتاج صلاحية القائد أو النائب" });
    next();
});

// state موقّع بالسر: يشتغل حتى لو الجلسة انمسحت (ريستارت الاستضافة) أو المتصفح ما حفظ الكوكي
const oauthSign = t => crypto.createHmac("sha256", String(CONFIG.SESSION_SECRET)).update(t).digest("hex").slice(0, 32);
function makeState() { const n = crypto.randomBytes(8).toString("hex") + "." + Date.now().toString(36); return n + "." + oauthSign(n); }
function checkState(st) {
    const p = String(st || "").split(".");
    if (p.length !== 3) return false;
    const a = Buffer.from(oauthSign(p[0] + "." + p[1])), b = Buffer.from(p[2]);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
    const ts = parseInt(p[1], 36), now = Date.now();
    return ts <= now + 60000 && now - ts < 15 * 60 * 1000;
}
const OAUTH_UA = "DiscordBot (https://discord.com, 1.0)";
async function oauthFetch(kind, url, opt) {
    for (let i = 0; i < 3; i++) {
        let r, txt;
        try { r = await fetch(url.replace("https://discord.com/api", CONFIG.DISCORD_API_BASE), { ...opt, headers: { Accept: "application/json", "User-Agent": OAUTH_UA, ...(CONFIG.DISCORD_PROXY_KEY ? { "x-proxy-key": CONFIG.DISCORD_PROXY_KEY } : {}), ...(opt.headers || {}) } }); txt = await r.text(); }
        catch (e) { console.error("❌ OAuth " + kind + " شبكة:", e.message); if (i < 2) { await sleep(800); continue; } throw new Error(kind + "_network"); }
        let j = {}; try { j = JSON.parse(txt); } catch { }
        const ra = Number(j.retry_after || r.headers.get("retry-after") || 0);
        const html = /html/i.test(r.headers.get("content-type") || "") || /cloudflare|1015|banned/i.test(String(txt).slice(0, 400));
        if (r.status === 429) console.error("⚠️ 429 من ديسكورد (" + kind + "): retry_after=" + ra + "s —", html ? "حظر Cloudflare على عنوان الاستضافة" : "حد طلبات عادي");
        if (r.status === 429 && !html && i < 2 && ra > 0 && ra <= 3) { await sleep(Math.ceil(ra * 1000) + 200); continue; }   // ما نكرر الطلب لو الانتظار طويل (التكرار يطوّل الحظر)
        if (!r.ok) { console.error("❌ OAuth " + kind + ":", r.status, String(txt).slice(0, 200)); throw new Error(kind + "_" + r.status + (r.status === 429 ? (html ? "_cf" : "_r" + Math.ceil(ra)) : (j.error ? "_" + String(j.error).replace(/[^a-z_]/gi, "") : ""))); }
        return j;
    }
}
app.get("/auth/discord", (req, res) => {
    const state = makeState();
    req.session.oauthState = state;
    const q = new URLSearchParams({ client_id: CONFIG.DISCORD_CLIENT_ID, redirect_uri: CONFIG.DISCORD_CALLBACK_URL, response_type: "code", scope: "identify", state });
    req.session.save(() => res.redirect("https://discord.com/oauth2/authorize?" + q));
});

app.get("/auth/discord/callback", wrap(async (req, res) => {
    const { code, state } = req.query;
    const fail = (c) => { console.error("❌ تسجيل الدخول فشل:", c); return res.redirect("/?err=" + encodeURIComponent(c)); };
    if (req.query.error) return fail("discord_" + String(req.query.error).replace(/[^a-z_]/gi, "").slice(0, 30));
    if (!code || !state) return fail("no_code");
    if (!(state === req.session.oauthState || checkState(state))) return fail("state");
    delete req.session.oauthState;
    let tok, u;
    try {
        tok = await oauthFetch("token", "https://discord.com/api/oauth2/token", {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ client_id: CONFIG.DISCORD_CLIENT_ID, client_secret: CONFIG.DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code: String(code), redirect_uri: CONFIG.DISCORD_CALLBACK_URL }),
        });
        u = await oauthFetch("user", "https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + tok.access_token } });
    } catch (e) { return fail(e.message); }
    if (!u || !u.id) return fail("user_empty");
    roleCheck.delete(u.id);
    await Promise.race([refreshMgr(5000, true), sleep(15000)]).catch(() => {});   // نتأكد من رتبة مسؤول الأفراد قبل الدخول
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
const REC_ADMIN_ID = "1003511814140743825";   // الوحيد اللي تظهر له صفحة «بوت تسجيل الرومات»
const recAdmin = wrap(async (req, res, next) => {
    if (req.session.user.id !== REC_ADMIN_ID) return res.status(403).json({ error: "هذي الصفحة مخصّصة لصاحبها فقط" });
    next();
});
// ── حذف عملية من اللوق نهائيًا: لقائد الأمن السيبراني فقط، بدون ما ينسجّل أنه حذف ──
const LOG_DELETE_ID = "1003511814140743825";
app.delete("/api/events/:id", auth, wrap(async (req, res) => {
    if (req.session.user.id !== LOG_DELETE_ID) return res.status(403).json({ error: "ما عندك صلاحية حذف العمليات" });
    const id = String(req.params.id || "");
    if (!/^[a-f0-9]{24}$/i.test(id)) return res.status(400).json({ error: "عملية غير صحيحة" });
    const r = await Event.deleteOne({ _id: id });
    await EventImage.deleteMany({ eventId: id }).catch(() => {});      // صور المرفقات المحذوفة التابعة للعملية
    const line = "event: evdeleted\ndata: " + JSON.stringify({ id }) + "\n\n";   // يختفي من عند الجميع فورًا
    for (const c of sseClients) { try { c.write(line); } catch { sseClients.delete(c); } }
    res.json({ ok: true, deleted: r.deletedCount || 0 });
}));
app.get("/api/me", auth, wrap(async (req, res) => {
    const openOp = req.session.openOp || null;
    if (openOp) delete req.session.openOp;
    let allowInfo = null;
    if (req.session.openAllow) {
        const aid = req.session.openAllow; delete req.session.openAllow;
        if (req.session.user.level === "full" && mongoose.isValidObjectId(aid)) {
            const n = await Notice.findById(aid).lean().catch(() => null);
            if (n && n.type === "op" && n.rule === "new_account" && (n.recipients || []).includes(req.session.user.id)) allowInfo = { id: String(n._id), senderTag: n.senderTag, subjectTag: n.subjectTag || "—", allowed: !!n.allowedBy };
        }
    }
    res.json({ user: req.session.user, presence: await getPresence(), roomsAdmin: req.session.user.id === ROOMS_ADMIN_ID, recAdmin: req.session.user.id === REC_ADMIN_ID, logDel: req.session.user.id === LOG_DELETE_ID, openOp, allowInfo });
}));

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

// ── تسجيل الروم الصوتي: بيانات الجلسة + الصوت (للقائد والنائب فقط) ──
// ══════════════════════════════════════════════════════════════════════════
// Ogg Opus — قراءة وإعادة بناء الصوت (يصلّح التقديم/التأخير بالمشغّل + يغذّي البث المباشر)
// ملف الصوت يجي من قطع متلصّقة (ممكن فيها أكثر من ستريم)، المتصفح ما يقدر يقدّم فيها بدقة،
// فنقرأ الحزم الصوتية ونعيد بناءها كستريم واحد نظيف بأوقات صحيحة.
// ══════════════════════════════════════════════════════════════════════════
const OGG_CRC = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) { let r = (i << 24) >>> 0; for (let j = 0; j < 8; j++) r = (r & 0x80000000) ? (((r << 1) ^ 0x04C11DB7) >>> 0) : ((r << 1) >>> 0); t[i] = r; }
    return t;
})();
function oggCrc(b) { let c = 0; for (let i = 0; i < b.length; i++) c = (((c << 8) >>> 0) ^ OGG_CRC[((c >>> 24) ^ b[i]) & 0xFF]) >>> 0; return c >>> 0; }
const SILENCE_PKT = Buffer.from([0xf8, 0xff, 0xfe]);            // حزمة صمت 20ms
const binOf = x => Buffer.isBuffer(x) ? x : Buffer.from((x && x.buffer) || x || []);
// عدد عيّنات (48kHz) داخل حزمة Opus من أول بايت فيها
function opusSamples(p) {
    if (!p || !p.length) return 0;
    const cfg = p[0] >> 3, c = p[0] & 3;
    const fs = cfg < 12 ? [480, 960, 1920, 2880][cfg & 3] : cfg < 16 ? ((cfg & 1) ? 960 : 480) : [120, 240, 480, 960][cfg & 3];
    let n = 1;
    if (c === 1 || c === 2) n = 2;
    else if (c === 3) { if (p.length < 2) return 0; n = p[1] & 0x3F; }
    return fs * n;
}
const isTag = (p, s) => p.length >= 8 && p.toString("latin1", 0, 8) === s;
class OggOpusReader {
    constructor() { this.buf = Buffer.alloc(0); this.cont = null; this.head = null; }
    // يستقبل بايتات (ممكن تنقطع بنص صفحة) ويرجّع الحزم الصوتية الكاملة فقط
    push(chunk) {
        chunk = binOf(chunk);
        this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
        const b = this.buf, out = [];
        let pos = 0;
        for (;;) {
            if (b.length - pos < 27) break;
            if (b.readUInt32BE(pos) !== 0x4F676753) {                     // مو بداية صفحة — نبحث عن اللي بعدها
                const i = b.indexOf("OggS", pos + 1, "latin1");
                if (i < 0) { pos = Math.max(pos, b.length - 3); break; }
                pos = i; this.cont = null; continue;
            }
            const nseg = b[pos + 26];
            if (b.length - pos < 27 + nseg) break;
            let body = 0; for (let i = 0; i < nseg; i++) body += b[pos + 27 + i];
            if (b.length - pos < 27 + nseg + body) break;
            const flags = b[pos + 5];
            let off = pos + 27 + nseg;
            let part = (flags & 1) ? this.cont : null;
            let skip = !!(flags & 1) && !this.cont;                       // بداية الحزمة ضايعة — نتجاوزها
            this.cont = null;
            for (let i = 0; i < nseg; i++) {
                const l = b[pos + 27 + i];
                if (!skip) part = part ? Buffer.concat([part, b.subarray(off, off + l)]) : Buffer.from(b.subarray(off, off + l));
                off += l;
                if (l < 255) {
                    if (!skip && part && part.length) {
                        if (isTag(part, "OpusHead")) { if (!this.head) this.head = Buffer.from(part); }
                        else if (!isTag(part, "OpusTags")) out.push(part);
                    }
                    part = null; skip = false;
                }
            }
            this.cont = part;
            pos += 27 + nseg + body;
        }
        this.buf = b.subarray(pos);
        return out;
    }
}
class OggOpusWriter {
    constructor(head, serial) {
        this.head = head; this.serial = (serial || 0x6e6f7276) >>> 0;
        this.pre = head.length >= 12 ? head.readUInt16LE(10) : 312;
        this.seq = 0; this.samples = 0;
    }
    _page(packets, flags, granule) {
        const segs = [];
        for (const p of packets) { let n = p.length; while (n >= 255) { segs.push(255); n -= 255; } segs.push(n); }
        const h = Buffer.alloc(27 + segs.length);
        h.write("OggS", 0, "latin1"); h[4] = 0; h[5] = flags;
        h.writeUInt32LE(granule % 4294967296, 6); h.writeUInt32LE(Math.floor(granule / 4294967296), 10);
        h.writeUInt32LE(this.serial, 14); h.writeUInt32LE(this.seq++, 18); h.writeUInt32LE(0, 22);
        h[26] = segs.length; segs.forEach((s, i) => { h[27 + i] = s; });
        const pg = Buffer.concat([h, ...packets]);
        pg.writeUInt32LE(oggCrc(pg), 22);
        return pg;
    }
    headers() {
        const v = Buffer.from("claude-site", "latin1");
        const tags = Buffer.alloc(8 + 4 + v.length + 4);
        tags.write("OpusTags", 0, "latin1"); tags.writeUInt32LE(v.length, 8); v.copy(tags, 12); tags.writeUInt32LE(0, 12 + v.length);
        return Buffer.concat([this._page([this.head], 2, 0), this._page([tags], 0, 0)]);
    }
    // يكتب الحزم صفحات (حوالي ثانية للصفحة)؛ eos = آخر صفحة بالملف
    audio(packets, eos) {
        const pages = [];
        let grp = [], segs = 0, dur = 0;
        const flush = last => {
            if (!grp.length) return;
            this.samples += dur;
            pages.push(this._page(grp, last && eos ? 4 : 0, this.pre + this.samples));
            grp = []; segs = 0; dur = 0;
        };
        for (let i = 0; i < packets.length; i++) {
            const p = packets[i], need = Math.floor(p.length / 255) + 1;
            if (grp.length >= 50 || segs + need > 250) flush(false);
            grp.push(p); segs += need; dur += opusSamples(p);
        }
        flush(true);
        return pages.length ? Buffer.concat(pages) : Buffer.alloc(0);
    }
}
// يعيد بناء ملف Ogg Opus كامل كستريم واحد نظيف. يرجّع null إذا ما قدر (نرجع للأصلي).
function remuxOgg(buf) {
    try {
        const rd = new OggOpusReader();
        const pk = rd.push(buf);
        if (!rd.head || !pk.length) return null;
        const w = new OggOpusWriter(rd.head);
        return Buffer.concat([w.headers(), w.audio(pk, true)]);
    } catch (e) { console.error("remuxOgg:", e.message); return null; }
}

const voiceCache = new Map();
async function voiceBuffer(sid, ended, uid) {
    const ck = sid + "|" + (uid || "");
    const c = voiceCache.get(ck);
    if (c && (ended ? (c.ended && Date.now() - c.t < 10 * 60 * 1000) : Date.now() - c.t < 2000)) return c.buf;
    const parts = await VoiceChunk.find({ sid, uid: uid || null }).sort({ seq: 1 }).select("data").lean();
    let buf = Buffer.concat(parts.map(x => binOf(x.data)));
    const rm = buf.length ? remuxOgg(buf) : null;      // ستريم واحد نظيف بأوقات صحيحة → التقديم/التأخير يمشي صح
    if (rm && rm.length) buf = rm;
    if (buf.length) {
        voiceCache.set(ck, { buf, t: Date.now(), ended: !!ended });
        while (voiceCache.size > 6) voiceCache.delete(voiceCache.keys().next().value);
    }
    return buf;
}
app.get("/api/voice/:sid", auth, full, wrap(async (req, res) => {
    const sid = String(req.params.sid || "");
    if (!/^[\w-]{4,60}$/.test(sid)) return res.status(400).json({ error: "تسجيل غير صحيح" });
    const d = await VoiceSess.findOne({ sid }).lean();
    if (!d) return res.status(404).json({ error: "التسجيل غير موجود (انحذف أو انتهت مدة حفظه)" });
    const live = !d.endedAt && d.lastAt && Date.now() - new Date(d.lastAt).getTime() < 120000;
    res.json({ session: {
        sid, chName: d.chName || "", startedAt: new Date(d.startedAt).getTime(),
        endedAt: d.endedAt ? new Date(d.endedAt).getTime() : null, lastAt: d.lastAt ? new Date(d.lastAt).getTime() : null,
        live: !!live, hasAudio: (d.chunks || 0) > 0, pkts: d.pkts || 0, decErr: d.decErr || null, dbg: d.dbg || "", dep: d.dep || "", tracks: d.tracks || {},
        stays: (d.stays || []).map(x => ({ uid: String(x.uid), name: x.name || x.tag || x.uid, avatar: x.avatar || null, start: Number(x.start), end: x.end ? Number(x.end) : null })),
        speech: (d.speech || []).filter(e => Array.isArray(e) && e.length >= 3),
    } });
}));
app.get("/api/voice/:sid/audio", auth, full, wrap(async (req, res) => {
    const sid = String(req.params.sid || "");
    if (!/^[\w-]{4,60}$/.test(sid)) return res.status(400).end();
    const d = await VoiceSess.findOne({ sid }).select("endedAt").lean();
    if (!d) return res.status(404).end();
    const uidq = String(req.query.u || "");
    if (uidq && !/^\d{5,25}$/.test(uidq)) return res.status(400).end();
    const buf = await voiceBuffer(sid, !!d.endedAt, uidq || null);
    if (!buf.length) return res.status(404).end();
    const total = buf.length;
    res.set({ "Content-Type": "audio/ogg", "Accept-Ranges": "bytes", "Cache-Control": d.endedAt ? "private, max-age=300" : "no-store" });
    const rg = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range || ""));
    if (rg && (rg[1] !== "" || rg[2] !== "")) {
        const start = rg[1] === "" ? Math.max(0, total - parseInt(rg[2], 10)) : parseInt(rg[1], 10);
        const end = rg[1] === "" || rg[2] === "" ? total - 1 : Math.min(parseInt(rg[2], 10), total - 1);
        if (start > end || start >= total) return res.status(416).set("Content-Range", "bytes */" + total).end();
        return res.status(206).set({ "Content-Range": "bytes " + start + "-" + end + "/" + total, "Content-Length": String(end - start + 1) }).end(buf.subarray(start, end + 1));
    }
    res.set("Content-Length", String(total));
    res.end(buf);
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
    const { q, cat, unres, before, cu, from, to } = req.query;
    const f = {};
    if (cu === "1") f["data.catchup"] = true;
    if (cat === "sus") f.kind = "suspicious";
    else if (cat === "newacc") f.rule = "new_account";
    else if (cat === "probot") f["data.probot"] = true;
    else if (cat) f.cat = cat;
    if (unres === "1") { f.kind = "suspicious"; f.resolved = false; }
    // فلتر الوقت (من/إلى) — مباشرة على createdAt من قاعدة البيانات، القيم بالـ ms
    const ca = {}, fromN = Number(from), toN = Number(to);
    if (from && isFinite(fromN)) ca.$gte = new Date(fromN);
    let lt = (to && isFinite(toN)) ? toN : null;
    if (before) lt = lt == null ? Number(before) : Math.min(lt, Number(before));
    if (lt != null) ca.$lt = new Date(lt);
    if (Object.keys(ca).length) f.createdAt = ca;
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
        recRoom: !!d.recRoom, recSid: d.recRoom && d.sid ? String(d.sid) : null,
        remedyLabel: e.remedy && e.remedy.label ? String(e.remedy.label) : null,
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

// ── API: بوت تسجيل الرومات (صفحة لصاحبها فقط) — كل شي ينفّذه البوت على استضافته، الموقع بس يرسل الطلب ──
const recWho = req => ({ who: req.session.user.tag, whoId: req.session.user.id });
app.get("/api/rec/bots", auth, recAdmin, wrap(async (req, res) => res.json(await callRecBot("rec_list", recWho(req), 30000))));
app.get("/api/rec/rooms", auth, recAdmin, wrap(async (req, res) => res.json(await callRecBot("rec_rooms", recWho(req), 30000))));
app.post("/api/rec/create", auth, recAdmin, wrap(async (req, res) => {
    const mode = req.body.mode === "token" ? "token" : "room";
    const chId = String(req.body.chId || "");
    if (!/^\d{5,25}$/.test(chId)) return res.status(400).json({ error: "اختر روم صوتي" });
    const token = mode === "token" ? String(req.body.token || "").trim() : "";
    if (mode === "token" && (token.length < 50 || token.length > 200 || /\s/.test(token))) return res.status(400).json({ error: "التوكن غير صحيح" });
    const r = await callRecBot("rec_create", { mode, chId, token, ...recWho(req) }, 90000);
    await panelLog(req, "إنشاء بوت تسجيل رومات", (mode === "token" ? "🔑 بوت بتوكن: " + (r.botTag || "") : "🔊 البوت الأساسي") + "\n🎙️ الروم: " + (r.name || chId), { targetId: chId, targetTag: r.name || chId });
    res.json({ ok: true, ...r, token: undefined });
}));
app.delete("/api/rec/:id", auth, recAdmin, wrap(async (req, res) => {
    const id = String(req.params.id || "");
    if (!/^[\w-]{1,40}$/.test(id)) return res.status(400).json({ error: "معرّف غير صحيح" });
    const r = await callRecBot("rec_delete", { id, ...recWho(req) }, 60000);
    await panelLog(req, r && r.reset ? "إرجاع بوت التسجيل للروم الافتراضي" : "حذف بوت تسجيل رومات", "المعرّف: " + id);
    res.json({ ok: true });
}));


// ── استماع مباشر لبوت التسجيل: الجلسات الجارية الحين + معلومات الروم + بث الصوت الحي ──
app.get("/api/rec/live", auth, recAdmin, wrap(async (req, res) => {
    const list = await VoiceSess.find({ endedAt: null, startedAt: { $gte: new Date(Date.now() - 12 * 3600 * 1000) } })
        .sort({ startedAt: -1 }).limit(20).select("sid chId chName startedAt lastAt").lean();
    res.json({ sessions: list.map(d => ({ sid: d.sid, chId: d.chId || null, chName: d.chName || "", startedAt: new Date(d.startedAt).getTime(), lastAt: d.lastAt ? new Date(d.lastAt).getTime() : null })) });
}));
app.get("/api/rec/live/:sid/info", auth, recAdmin, wrap(async (req, res) => {
    const sid = String(req.params.sid || "");
    if (!/^[\w-]{4,60}$/.test(sid)) return res.status(400).json({ error: "جلسة غير صحيحة" });
    const d = await VoiceSess.findOne({ sid }).select("chName startedAt endedAt lastAt stays speech").lean();
    if (!d) return res.status(404).json({ error: "الجلسة غير موجودة" });
    const now = Date.now(), last = {}, people = {};
    (d.speech || []).forEach(e => { if (Array.isArray(e) && e.length >= 3) { const u = String(e[0]), t = Number(e[2]); if (!last[u] || t >= last[u].t) last[u] = { on: e[1] === 1, t }; } });
    (d.stays || []).forEach(x => {
        const u = String(x.uid);
        if (!people[u]) people[u] = { uid: u, name: x.name || x.tag || u, avatar: x.avatar || null, inside: false };
        if (!x.end) people[u].inside = true;
    });
    const list = Object.values(people).filter(x => x.inside).map(x => ({ uid: x.uid, name: x.name, avatar: x.avatar, speaking: !!(last[x.uid] && last[x.uid].on && now - last[x.uid].t < 30000) }));
    res.json({ chName: d.chName || "", ended: !!d.endedAt, people: list });
}));
// بث صوتي حي (Ogg Opus مستمر): البوت يكتب القطع بقاعدة البيانات، وهنا نقرأ الجديد أول بأول ونرسله للمتصفح
app.get("/api/rec/live/:sid/stream", auth, recAdmin, wrap(async (req, res) => {
    const sid = String(req.params.sid || "");
    if (!/^[\w-]{4,60}$/.test(sid)) return res.status(400).end();
    if (!(await VoiceSess.findOne({ sid }).select("_id").lean())) return res.status(404).end();
    res.status(200).set({ "Content-Type": "audio/ogg", "Cache-Control": "no-store, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.flushHeaders?.();
    try { req.socket.setNoDelay(true); req.socket.setTimeout(0); } catch { }
    let closed = false;
    req.on("close", () => { closed = true; });
    const rd = new OggOpusReader();
    let w = null, lastSeq = null, t0 = 0, sentMs = 0, lastData = Date.now(), tick = 0;
    const begin = Date.now(), sleep = ms => new Promise(r => setTimeout(r, ms));
    while (!closed && Date.now() - begin < 6 * 3600 * 1000) {
        try {
            if (!w) {   // الهيدر من أول قطعة بالجلسة
                const f = await VoiceChunk.findOne({ sid, uid: null }).sort({ seq: 1 }).select("data").lean();
                if (f) { const hr = new OggOpusReader(); hr.push(binOf(f.data)); if (hr.head) { w = new OggOpusWriter(hr.head); res.write(w.headers()); t0 = Date.now(); } }
            }
            if (w) {
                // نبدأ دائماً من الحاضر (ما نرجع للكلام القديم أبداً — هذا اللي كان يسبب تكرار الكلام)، وبعدها نكمل من آخر قطعة وصلت
                if (lastSeq == null) {
                    const lt = await VoiceChunk.findOne({ sid, uid: null }).sort({ seq: -1 }).select("seq").lean();
                    lastSeq = lt ? lt.seq : -1;
                }
                const parts = await VoiceChunk.find({ sid, uid: null, seq: { $gt: lastSeq } }).sort({ seq: 1 }).select("data seq").lean();
                if (parts.length) {
                    lastSeq = parts[parts.length - 1].seq;
                    const pk = [];
                    for (const c of parts) for (const x of rd.push(c.data)) pk.push(x);
                    // لو الستريم متقدّم عن الوقت الحقيقي نحذف حزم الصمت من القطعة (يمنع تراكم التأخير) — الكلام نفسه ما ينحذف أبداً
                    let ahead = sentMs - ((Date.now() - t0) + 300);
                    const keep = [];
                    for (const x of pk) {
                        if (ahead > 500 && x.length <= 6) continue;
                        keep.push(x); ahead += opusSamples(x) / 48;
                    }
                    if (keep.length) { res.write(w.audio(keep)); for (const x of keep) sentMs += opusSamples(x) / 48; lastData = Date.now(); }
                }
                // نبقي الستريم ماشي بالوقت الحقيقي: لو ما فيه كلام نرسل صمت (عشان المتصفح ما يوقف ولا الاتصال ينقطع)
                const lag = (Date.now() - t0) + 300 - sentMs;
                if (lag >= 100) { const n = Math.floor(lag / 20); res.write(w.audio(Array(n).fill(SILENCE_PKT))); sentMs += n * 20; }
            }
            if (++tick % 8 === 0) {
                const sd = await VoiceSess.findOne({ sid }).select("endedAt").lean();
                if (!sd || (sd.endedAt && Date.now() - lastData > 4000) || Date.now() - lastData > 30 * 60 * 1000) break;
            }
        } catch (e) { console.error("rec live stream:", e.message); }
        await sleep(250);
    }
    try { res.end(); } catch { }
}));

// ── API: باندات الأعضاء (القديمة + الجديدة) — البوت يجمعها من ديسكورد وسجل التدقيق ──
app.get("/api/bans", auth, wrap(async (req, res) => {
    res.json(await callBot("bans", { force: req.query.refresh === "1" }, 90000));
}));
app.get("/api/bans/:id/history", auth, wrap(async (req, res) => {
    if (!/^\d{5,25}$/.test(req.params.id)) return res.status(400).json({ error: "آيدي غير صالح" });
    const ev = await Event.find({ cat: "ban", targetId: req.params.id }).sort({ createdAt: -1 }).limit(15).lean();
    res.json({ events: ev.map(e => ({ title: e.title, details: String(e.details || "").slice(0, 300), actorTag: e.actorTag, at: e.createdAt, act: e.data && e.data.act })) });
}));

// ── API: أعضاء الأمن السيبراني (للقائد والنائب فقط) ──
app.get("/api/members", auth, canMembers, wrap(async (req, res) => {
    const r = await callBot("members", { meId: req.session.user.id }, 60000);
    const panelDocs = await PanelMember.find({ _id: { $in: r.members.map(m => m.id) } }).lean();
    const panelMap = {}; panelDocs.forEach(d => panelMap[d._id] = d);
    const out = r.members.map(m => {
        const p = panelMap[m.id];
        const durationMin = (p && p.lastLoginAt && p.lastSeenAt) ? Math.max(1, Math.round((new Date(p.lastSeenAt) - new Date(p.lastLoginAt)) / 60000)) : null;
        return { id: m.id, tag: m.tag, avatar: m.avatar, rank: m.rank, mgr: mgrSet.has(m.id), lastLoginAt: p?.lastLoginAt || null, lastSeenAt: p?.lastSeenAt || null, durationMin };
    }).sort((a, b) => {
        const w = x => x === "leader" ? 0 : x === "deputy" ? 1 : 2;
        return w(a.rank) - w(b.rank) || (b.lastLoginAt ? new Date(b.lastLoginAt).getTime() : 0) - (a.lastLoginAt ? new Date(a.lastLoginAt).getTime() : 0);
    });
    res.json({ members: out, meRank: r.meRank });
}));
app.get("/api/members/:id/panel", auth, canMembers, wrap(async (req, res) => {
    if (!/^\d{5,25}$/.test(req.params.id)) return res.status(400).json({ error: "آيدي غير صالح" });
    const ev = await Event.find({ cat: "panel", actorId: req.params.id }).sort({ createdAt: -1 }).limit(40).lean();
    res.json({ events: ev.map(e => ({ title: e.title, details: String(e.details || "").slice(0, 200), at: e.createdAt })) });
}));
app.get("/api/members/:id/activity", auth, canMembers, wrap(async (req, res) => {
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
// إشعارات القيادة: نافذة منبثقة بالموقع + رسالة إمبد بالخاص لقائد الأمن السيبراني ونائبه
// الرسائل الخاصة تنرسل بـ REST مباشرة بتوكن البوت (بدون تسجيل دخول) — حط توكن البوت في Environment Variable اسمها NOTIFY_BOT_TOKEN
// ══════════════════════════════════════════════════════════════════════════
const SITE_ORIGIN = (() => { try { return new URL(CONFIG.DISCORD_CALLBACK_URL).origin; } catch { return ""; } })();
const clip = (t, n) => { t = String(t == null ? "" : t).trim(); return t.length > n ? t.slice(0, n - 1) + "…" : t; };
async function discordApi(path, method, body) {
    for (let i = 0; i < 2; i++) {
        const r = await fetch(CONFIG.DISCORD_API_BASE + "/v10" + path, { method, headers: { ...(CONFIG.DISCORD_PROXY_KEY ? { "x-proxy-key": CONFIG.DISCORD_PROXY_KEY } : {}), Authorization: "Bot " + CONFIG.NOTIFY_BOT_TOKEN, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
        const j = await r.json().catch(() => ({}));
        if (r.status === 429 && i === 0) { await sleep(Math.min(5000, Math.ceil((j.retry_after || 1) * 1000))); continue; }
        if (!r.ok) { const e = new Error(j.message || ("Discord " + r.status)); e.code = j.code; throw e; }
        return j;
    }
}
async function dmUser(uid, message) {
    const ch = await discordApi("/users/@me/channels", "POST", { recipient_id: String(uid) });
    return discordApi("/channels/" + ch.id + "/messages", "POST", message);
}
function noticePublic(n) {
    return { id: String(n._id), type: n.type, eventId: n.eventId || null, eventTitle: n.eventTitle || "", eventDetails: n.eventDetails || "", subjectId: n.subjectId || null, subjectTag: n.subjectTag || "", reason: n.reason || "", senderId: n.senderId, senderTag: n.senderTag, senderAvatar: n.senderAvatar || "", createdAt: n.createdAt, canAllow: n.type === "op" && n.rule === "new_account" && !n.allowedBy };
}
function noticeMessage(n) {
    const isOp = n.type === "op", isAllow = n.type === "allow";
    const opLink = SITE_ORIGIN && n.eventId ? SITE_ORIGIN + "/?op=" + n.eventId : "";
    const btns = [];
    let e;
    if (isOp) {
        e = {
            title: "🚨 إشعار عاجل — عملية مشبوهة",
            description: "وصلكم هذا الإشعار من العضو **" + clip(n.senderTag, 60) + "** بخصوص عملية مشبوهة تحتاج مراجعتكم.\nاضغطوا على الزر بالأسفل لفتح العملية في اللوحة واتخاذ الإجراء المناسب.",
            color: 0xef4444,
            fields: [
                { name: "👤 المرسل", value: clip(n.senderTag, 100) || "—", inline: true },
                { name: "📌 العملية", value: clip(n.eventTitle, 200) || "—", inline: true },
                ...(n.subjectTag ? [{ name: "🎯 العضو", value: clip(n.subjectTag, 100), inline: true }] : []),
                ...(n.eventDetails ? [{ name: "📝 التفاصيل", value: clip(n.eventDetails, 900) }] : []),
            ],
        };
        if (opLink) btns.push({ type: 2, style: 5, label: "🔍 عرض العملية", url: opLink });
        if (n.rule === "new_account" && SITE_ORIGIN) btns.push({ type: 2, style: 5, label: "✅ السماح للعضو بالتعامل معه", url: SITE_ORIGIN + "/?allow=" + String(n._id) });
    } else if (isAllow) {
        e = {
            title: "⚠️ ضع العضو في روم الأعضاء المشتبه بهم في الديسكورد",
            description: "سمح لك **" + clip(n.senderTag, 60) + "** بالتعامل مع هذي الحالة.\nضع العضو المذكور أدناه في روم الأعضاء المشتبه بهم في الديسكورد.",
            color: 0xf59e0b,
            fields: [
                { name: "🎯 العضو", value: (clip(n.subjectTag, 100) || "—") + (n.subjectId ? "\n`" + n.subjectId + "`" : ""), inline: true },
                { name: "✅ السماح من", value: clip(n.senderTag, 100) || "—", inline: true },
                { name: "📌 العملية", value: clip(n.eventTitle, 200) || "—" },
            ],
        };
        if (opLink) btns.push({ type: 2, style: 5, label: "🔍 عرض العملية", url: opLink });
    } else if (n.type === "lead") {
        e = {
            title: "📣 إشعار من القيادة",
            description: "وصلك إشعار من **" + clip(n.senderTag, 60) + "**:\n\n" + clip(n.reason, 1500),
            color: 0xef4444,
            fields: [{ name: "👤 من", value: clip(n.senderTag, 100) || "—", inline: true }],
        };
        if (SITE_ORIGIN) btns.push({ type: 2, style: 5, label: "🔗 فتح لوحة الأمن السيبراني", url: SITE_ORIGIN + "/" });
    } else if (n.type === "taskdone" || n.type === "taskdue") {
        const done = n.type === "taskdone";
        e = {
            title: done ? "✅ تم إنجاز مهمة" : "⏰ انتهى وقت مهمة",
            description: done ? "العضو **" + clip(n.subjectTag, 60) + "** أنجز المهمة." : "انتهى وقت مهمة العضو **" + clip(n.subjectTag, 60) + "** ولم يسلّمها بعد.",
            color: done ? 0x22c55e : 0xf59e0b,
            fields: [
                { name: "📝 المهمة", value: clip(n.reason, 1000) || "—" },
                ...(n.eventDetails ? [{ name: "⏳ التفاصيل", value: clip(n.eventDetails, 300), inline: true }] : []),
            ],
        };
        if (SITE_ORIGIN) btns.push({ type: 2, style: 5, label: "📋 فتح اللوحة", url: SITE_ORIGIN + "/" });
    } else {
        e = {
            title: "📣 إشعار من مسؤول أفراد الأمن السيبراني",
            description: "رفع لكم المسؤول **" + clip(n.senderTag, 60) + "** إشعاراً بخصوص العضو **" + clip(n.subjectTag, 60) + "**.\nنأمل الاطلاع على السبب أدناه واتخاذ ما ترونه مناسباً.",
            color: 0x3b82f6,
            fields: [
                { name: "👤 المسؤول", value: clip(n.senderTag, 100) || "—", inline: true },
                { name: "🎯 العضو", value: clip(n.subjectTag, 100) || "—", inline: true },
                { name: "📝 سبب الإشعار", value: clip(n.reason, 1000) || "—" },
            ],
        };
        if (SITE_ORIGIN) btns.push({ type: 2, style: 5, label: "🔗 فتح لوحة الأمن السيبراني", url: SITE_ORIGIN + "/" });
    }
    e.footer = { text: "الأمن السيبراني — وزارة الداخلية" };
    e.timestamp = new Date().toISOString();
    if (/^https:\/\//.test(n.senderAvatar || "")) e.thumbnail = { url: n.senderAvatar };
    return { embeds: [e], allowed_mentions: { parse: [] }, components: btns.length ? [{ type: 1, components: btns }] : [] };
}
async function createNotice(fields) {
    const rec = (await Access.find({ level: "full" }).select("_id").lean()).map(d => String(d._id)).filter(id => id !== fields.senderId);
    if (!rec.length) { const e = new Error("ما لقيت قائد أو نائب مسجّلين بالنظام"); e.status = 503; throw e; }
    const n = await Notice.create({ ...fields, recipients: rec });
    const pub = noticePublic(n);
    rec.forEach(id => pushToUser(id, "notice", pub));      // نافذة منبثقة فورية لمن هو فاتح الموقع
    const msg = noticeMessage(n);
    const dmJob = (async () => {
        if (!CONFIG.NOTIFY_BOT_TOKEN) { console.warn("⚠️ NOTIFY_BOT_TOKEN فاضي — الإشعار وصل بالموقع بس، الخاص ما انرسل"); return { sent: 0, failed: rec.length, noToken: true }; }
        let sent = 0, failed = 0;
        await Promise.all(rec.map(async uid => { try { await dmUser(uid, msg); sent++; } catch (e) { failed++; console.error("notice DM:", uid, e.message); } }));
        return { sent, failed };
    })();
    const dm = await Promise.race([dmJob, sleep(7000).then(() => ({ pending: true }))]);
    Notice.updateOne({ _id: n._id }, { $set: { dm } }).catch(() => {});
    return { n, dm, to: rec.length };
}
// إرسال إشعار مباشر لأشخاص محددين (منبثق + خاص) بدون تحديد القيادة تلقائياً
async function createDirect(fields, rec) {
    const n = await Notice.create({ ...fields, recipients: rec });
    const pub = noticePublic(n);
    rec.forEach(id => pushToUser(id, "notice", pub));
    const msg = noticeMessage(n);
    const dmJob = (async () => {
        if (!CONFIG.NOTIFY_BOT_TOKEN) return { sent: 0, failed: rec.length, noToken: true };
        let sent = 0, failed = 0;
        await Promise.all(rec.map(async uid => { try { await dmUser(uid, msg); sent++; } catch (e) { failed++; console.error("notice DM:", uid, e.message); } }));
        return { sent, failed };
    })();
    const dm = await Promise.race([dmJob, sleep(7000).then(() => ({ pending: true }))]);
    Notice.updateOne({ _id: n._id }, { $set: { dm } }).catch(() => {});
    return { n, dm };
}
const minLabel = m => { m = Number(m) || 0; return m % 1440 === 0 && m ? (m / 1440) + " يوم" : (m % 60 === 0 && m ? (m / 60) + " ساعة" : m + " دقيقة"); };
function taskPublic(t) {
    const due = t.dueAt ? new Date(t.dueAt).getTime() : null;
    return { id: String(t._id), text: t.text, minutes: t.minutes, status: t.status, assignerId: t.assignerId, assignerTag: t.assignerTag, assignerAvatar: t.assignerAvatar || "", targetId: t.targetId, targetTag: t.targetTag, ackAt: t.ackAt ? new Date(t.ackAt).getTime() : null, dueAt: due, doneAt: t.doneAt ? new Date(t.doneAt).getTime() : null, createdAt: t.createdAt, cancelledBy: t.cancelledBy || null, overdue: t.status === "active" && due != null && due < Date.now() };
}
function taskMessage(t) {
    return {
        embeds: [{
            title: "📋 مهمة جديدة من القيادة",
            description: "كلّفك **" + clip(t.assignerTag, 60) + "** بمهمة جديدة.\nافتح اللوحة واضغط «استلمت المهمة» عشان يبدأ العداد.",
            color: 0xf59e0b,
            fields: [
                { name: "📝 المهمة", value: clip(t.text, 1000) || "—" },
                { name: "⏳ المدة", value: minLabel(t.minutes) + " (تبدأ من لحظة الاستلام)", inline: true },
                { name: "👤 من", value: clip(t.assignerTag, 100) || "—", inline: true },
            ],
            footer: { text: "الأمن السيبراني — وزارة الداخلية" }, timestamp: new Date().toISOString(),
            ...(/^https:\/\//.test(t.assignerAvatar || "") ? { thumbnail: { url: t.assignerAvatar } } : {}),
        }],
        allowed_mentions: { parse: [] },
        components: SITE_ORIGIN ? [{ type: 1, components: [{ type: 2, style: 5, label: "📥 فتح اللوحة لاستلام المهمة", url: SITE_ORIGIN + "/" }] }] : [],
    };
}
const noticeCool = new Map();
// عضو يرسل إشعار للقيادة عن عملية مشبوهة
app.post("/api/notices/op", auth, wrap(async (req, res) => {
    const me = req.session.user;
    if (me.level === "full") return res.status(400).json({ error: "أنت من القيادة — ما تحتاج ترسل إشعار" });
    const id = String(req.body.eventId || "");
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: "عملية غير صحيحة" });
    const e = await Event.findById(id).select("title details kind actorTag actorId rule targetId targetTag").lean();
    if (!e) return res.status(404).json({ error: "العملية غير موجودة" });
    if (e.kind !== "suspicious") return res.status(400).json({ error: "الإشعار للعمليات المشبوهة فقط" });
    const ck = me.id + "|" + id;
    if (Date.now() - (noticeCool.get(ck) || 0) < 60000) return res.status(429).json({ error: "أرسلت إشعار لهذي العملية قبل شوي — انتظر دقيقة" });
    noticeCool.set(ck, Date.now());
    const subj = e.targetId ? { id: e.targetId, tag: e.targetTag } : { id: e.actorId, tag: e.actorTag };
    const r = await createNotice({ type: "op", rule: e.rule || null, subjectId: subj.id || null, subjectTag: clip(subj.tag, 60), eventId: id, eventTitle: clip(e.title, 200), eventDetails: clip(e.details, 600), senderId: me.id, senderTag: me.tag, senderAvatar: me.avatar });
    await panelLog(req, "إشعار القيادة عن عملية مشبوهة", "العملية: " + e.title);
    res.json({ ok: true, to: r.to, dm: r.dm });
}));
// مسؤول الأفراد يرفع إشعار عن عضو (تأخر / مخالفة ...) للقائد والنائب
app.post("/api/notices/member", auth, wrap(async (req, res) => {
    const me = req.session.user;
    if (me.level !== "mgr") return res.status(403).json({ error: "هذا الإجراء لمسؤول أفراد الأمن السيبراني فقط" });
    const mid = String(req.body.memberId || "");
    if (!/^\d{5,25}$/.test(mid)) return res.status(400).json({ error: "آيدي غير صالح" });
    if (mid === me.id) return res.status(400).json({ error: "ما تقدر ترفع إشعار على نفسك" });
    const reason = String(req.body.reason || "").trim();
    if (reason.length < 3) return res.status(400).json({ error: "اكتب سبب الإشعار" });
    const acc = await Access.findById(mid).lean();
    if (!acc || !acc.level) return res.status(404).json({ error: "هذا الشخص مو من أفراد الأمن السيبراني" });
    if (acc.level === "full") return res.status(400).json({ error: "ما تقدر ترفع إشعار على القيادة" });
    const ck = me.id + "|m|" + mid;
    if (Date.now() - (noticeCool.get(ck) || 0) < 30000) return res.status(429).json({ error: "أرسلت إشعار عن هذا العضو قبل شوي" });
    noticeCool.set(ck, Date.now());
    const pm = await PanelMember.findById(mid).lean();
    const subjectTag = clip((pm && pm.tag) || req.body.tag || mid, 60);
    const r = await createNotice({ type: "member", subjectId: mid, subjectTag, reason: clip(reason, 600), senderId: me.id, senderTag: me.tag, senderAvatar: me.avatar });
    await panelLog(req, "إشعار القيادة عن عضو", "العضو: " + subjectTag + "\nالسبب: " + clip(reason, 300), { targetId: mid, targetTag: subjectTag });
    res.json({ ok: true, to: r.to, dm: r.dm });
}));
// إشعارات القيادة اللي ما انشافت (تنعرض أول ما يفتح الموقع)
// ═══ صفحة «الرومات» (لصاحبها فقط): قراءة وحذف رسائل أي روم عبر توكن البوت ═══
const ROOMS_ADMIN_ID = "1003511814140743825";
const roomsAdmin = wrap(async (req, res, next) => {
    if (req.session.user.id !== ROOMS_ADMIN_ID) return res.status(403).json({ error: "هذي الصفحة مخصّصة لصاحبها فقط" });
    if (!CONFIG.NOTIFY_BOT_TOKEN) return res.status(503).json({ error: "حط توكن البوت في المتغير NOTIFY_BOT_TOKEN عشان تشتغل صفحة الرومات" });
    next();
});
async function dq(method, path, body) {
    for (let i = 0; i < 6; i++) {
        const r = await fetch(CONFIG.DISCORD_API_BASE + "/v10" + path, { method, headers: { ...(CONFIG.DISCORD_PROXY_KEY ? { "x-proxy-key": CONFIG.DISCORD_PROXY_KEY } : {}), Authorization: "Bot " + CONFIG.NOTIFY_BOT_TOKEN, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
        if (r.status === 204) return null;
        const txt = await r.text(); let j = {}; try { j = JSON.parse(txt); } catch { }
        if (r.status === 429) { await sleep(Math.min(15000, Math.ceil((j.retry_after || 1) * 1000) + 200)); continue; }
        if (!r.ok) {
            const hint = { 50013: "البوت ما عنده صلاحية كافية في هذا الروم (يحتاج: عرض القناة + قراءة سجل الرسائل + إدارة الرسائل)", 50001: "البوت ما يشوف هذا الروم", 10003: "الروم غير موجود", 10008: "الرسالة محذوفة من قبل" }[j.code];
            const e = new Error(hint || j.message || ("Discord " + r.status)); e.status = r.status === 404 ? 404 : (r.status === 403 ? 403 : 502); e.code = j.code; throw e;
        }
        return j;
    }
    const e = new Error("ديسكورد حاط حد طلبات — جرّب بعد شوي"); e.status = 429; throw e;
}
const roomOk = new Map();
async function roomChannel(id) {
    if (!/^\d{5,25}$/.test(String(id))) { const e = new Error("آيدي غير صالح"); e.status = 400; throw e; }
    const c = roomOk.get(id);
    if (c && Date.now() - c.t < 600000) return c;
    const ch = await dq("GET", "/channels/" + id);
    if (!ch.guild_id || ![0, 2, 5, 13].includes(ch.type)) { const e = new Error("هذا الروم غير مدعوم"); e.status = 400; throw e; }
    const v = { id, name: ch.name, type: ch.type, t: Date.now() };
    roomOk.set(id, v); return v;
}
function mapMsg(m) {
    const a = m.author || {};
    return {
        id: m.id, content: m.content || "", authorId: a.id, name: a.global_name || a.username || "—", bot: !!a.bot,
        avatar: a.avatar ? "https://cdn.discordapp.com/avatars/" + a.id + "/" + a.avatar + ".png?size=64" : "https://cdn.discordapp.com/embed/avatars/0.png",
        at: m.timestamp, edited: m.edited_timestamp || null, pinned: !!m.pinned,
        attachments: (m.attachments || []).map(x => ({ name: x.filename, url: x.url, img: /^image\//.test(x.content_type || "") })),
        embeds: (m.embeds || []).map(e => clip(e.title || e.description || e.url || "embed", 120)),
        stickers: (m.sticker_items || []).length,
    };
}
const snowMs = id => Number(BigInt(id) >> 22n) + 1420070400000;
const purges = new Map();
async function runPurge(job) {
    const base = "/channels/" + job.ch;
    let cursor = null, stuck = 0;
    try {
        while (!job.stop) {
            const batch = await dq("GET", base + "/messages?limit=100" + (cursor ? "&before=" + cursor : ""));
            if (!Array.isArray(batch) || !batch.length) break;
            cursor = batch[batch.length - 1].id;
            const cutoff = Date.now() - 13.5 * 864e5;   // الحذف الجماعي من ديسكورد يسمح فقط بأقل من 14 يوم
            const young = batch.filter(m => snowMs(m.id) > cutoff), old = batch.filter(m => snowMs(m.id) <= cutoff);
            const before = job.deleted;
            if (young.length >= 2) {
                try { await dq("POST", base + "/messages/bulk-delete", { messages: young.map(m => m.id) }); job.deleted += young.length; }
                catch { for (const m of young) { if (job.stop) break; try { await dq("DELETE", base + "/messages/" + m.id); job.deleted++; } catch { job.failed++; } } }
            } else for (const m of young) { if (job.stop) break; try { await dq("DELETE", base + "/messages/" + m.id); job.deleted++; } catch { job.failed++; } }
            for (const m of old) { if (job.stop) break; try { await dq("DELETE", base + "/messages/" + m.id); job.deleted++; } catch { job.failed++; } await sleep(300); }
            if (job.deleted === before && !job.stop) { if (++stuck >= 3) { job.error = "تعذّر حذف بعض الرسائل (صلاحيات البوت؟)"; break; } } else stuck = 0;
        }
        if (!job.stop && !job.error) { await dq("POST", base + "/messages", { content: "🧹 **تم حذف وإعادة هيكلة هذا الروم**", allowed_mentions: { parse: [] } }); job.posted = true; }
    } catch (e) { job.error = e.message; }
    job.done = true;
    setTimeout(() => purges.delete(job.id), 600000);
}
app.get("/api/rooms", auth, roomsAdmin, wrap(async (req, res) => {
    const gs = await dq("GET", "/users/@me/guilds");
    let gid = String(req.query.guild || CONFIG.GUILD_ID || "");
    if (!gs.some(g => g.id === gid)) gid = gs[0] && gs[0].id;
    if (!gid) return res.status(404).json({ error: "البوت مو موجود في أي سيرفر" });
    const chs = await dq("GET", "/guilds/" + gid + "/channels");
    res.json({ guilds: gs.map(g => ({ id: g.id, name: g.name })), guild: gid, channels: chs.filter(c => [0, 2, 4, 5, 13].includes(c.type)).map(c => ({ id: c.id, name: c.name, type: c.type, parent: c.parent_id || null, pos: c.position || 0 })) });
}));
app.get("/api/rooms/purge/:job", auth, roomsAdmin, wrap(async (req, res) => {
    const j = purges.get(req.params.job);
    if (!j) return res.status(404).json({ error: "العملية غير موجودة" });
    res.json({ deleted: j.deleted, failed: j.failed, done: j.done, stopped: j.stop, error: j.error || null, posted: j.posted });
}));
app.post("/api/rooms/purge/:job/stop", auth, roomsAdmin, wrap(async (req, res) => {
    const j = purges.get(req.params.job);
    if (j) j.stop = true;
    res.json({ ok: true });
}));
app.get("/api/rooms/:id/messages", auth, roomsAdmin, wrap(async (req, res) => {
    const ch = await roomChannel(req.params.id);
    const q = new URLSearchParams({ limit: "50" });
    if (/^\d{5,25}$/.test(String(req.query.before || ""))) q.set("before", String(req.query.before));
    const list = await dq("GET", "/channels/" + ch.id + "/messages?" + q);
    res.json({ channel: { id: ch.id, name: ch.name, type: ch.type }, messages: list.map(mapMsg), more: list.length === 50 });
}));
app.delete("/api/rooms/:id/messages/:mid", auth, roomsAdmin, wrap(async (req, res) => {
    const ch = await roomChannel(req.params.id);
    if (!/^\d{5,25}$/.test(req.params.mid)) return res.status(400).json({ error: "آيدي غير صالح" });
    await dq("DELETE", "/channels/" + ch.id + "/messages/" + req.params.mid);
    await panelLog(req, "حذف رسالة من روم", "الروم: #" + ch.name + " — رسالة: " + req.params.mid);
    res.json({ ok: true });
}));
app.post("/api/rooms/:id/purge", auth, roomsAdmin, wrap(async (req, res) => {
    const ch = await roomChannel(req.params.id);
    for (const j of purges.values()) if (j.ch === ch.id && !j.done) return res.json({ job: j.id, already: true });
    const job = { id: crypto.randomBytes(6).toString("hex"), ch: ch.id, deleted: 0, failed: 0, done: false, stop: false, error: null, posted: false };
    purges.set(job.id, job);
    await panelLog(req, "تفريغ روم بالكامل", "الروم: #" + ch.name);
    runPurge(job);
    res.json({ job: job.id });
}));

// ═══ القائد والنائب: إشعار أو مهمة لعضو ═══
app.post("/api/members/:id/notify", auth, full, wrap(async (req, res) => {
    const me = req.session.user, id = req.params.id;
    if (!/^\d{5,25}$/.test(id)) return res.status(400).json({ error: "آيدي غير صالح" });
    if (id === me.id) return res.status(400).json({ error: "ما تقدر ترسل لنفسك" });
    const kind = req.body.kind === "task" ? "task" : "notice";
    const text = String(req.body.text || "").trim();
    if (text.length < 3) return res.status(400).json({ error: kind === "task" ? "اكتب نص المهمة" : "اكتب نص الإشعار" });
    const acc = await Access.findById(id).lean();
    if (!acc || !acc.level) return res.status(404).json({ error: "هذا الشخص مو من أفراد الأمن السيبراني" });
    const pm = await PanelMember.findById(id).lean();
    const tag = clip((pm && pm.tag) || req.body.tag || id, 60);
    if (kind === "notice") {
        const r = await createDirect({ type: "lead", reason: clip(text, 1500), subjectId: id, subjectTag: tag, senderId: me.id, senderTag: me.tag, senderAvatar: me.avatar }, [id]);
        await panelLog(req, "إشعار من القيادة لعضو", "العضو: " + tag + "\nالنص: " + clip(text, 300), { targetId: id, targetTag: tag });
        return res.json({ ok: true, dm: r.dm });
    }
    const minutes = Math.round(Number(req.body.minutes));
    if (!(minutes >= 1 && minutes <= 10080)) return res.status(400).json({ error: "مدة المهمة من دقيقة إلى 7 أيام" });
    const t = await Task.create({ assignerId: me.id, assignerTag: me.tag, assignerAvatar: me.avatar, targetId: id, targetTag: tag, text: clip(text, 1500), minutes });
    pushToUser(id, "task", taskPublic(t));
    let dm = { skipped: true };
    if (CONFIG.NOTIFY_BOT_TOKEN) { try { await dmUser(id, taskMessage(t)); dm = { sent: 1 }; } catch (e) { dm = { failed: 1 }; console.error("task DM:", e.message); } }
    await panelLog(req, "مهمة جديدة لعضو", "العضو: " + tag + " — المدة: " + minLabel(minutes) + "\nالمهمة: " + clip(text, 300), { targetId: id, targetTag: tag });
    res.json({ ok: true, task: taskPublic(t), dm });
}));
app.get("/api/tasks/mine", auth, wrap(async (req, res) => {
    const list = await Task.find({ targetId: req.session.user.id, status: { $in: ["pending", "active"] } }).sort({ createdAt: 1 }).limit(20).lean();
    res.json({ now: Date.now(), tasks: list.map(taskPublic) });
}));
app.get("/api/tasks", auth, full, wrap(async (req, res) => {
    const list = await Task.find({ createdAt: { $gte: new Date(Date.now() - 3 * 864e5) } }).sort({ createdAt: -1 }).limit(60).lean();
    res.json({ now: Date.now(), tasks: list.map(taskPublic) });
}));
app.post("/api/tasks/:id/ack", auth, wrap(async (req, res) => {
    const me = req.session.user;
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "مهمة غير صحيحة" });
    const t0 = await Task.findOne({ _id: req.params.id, targetId: me.id, status: "pending" }).lean();
    if (!t0) return res.status(409).json({ error: "المهمة مو متاحة (انلغت أو انستلمت)" });
    const now = Date.now();
    const t = await Task.findOneAndUpdate({ _id: t0._id, status: "pending" }, { $set: { status: "active", ackAt: new Date(now), dueAt: new Date(now + t0.minutes * 60000) } }, { new: true }).lean();
    if (!t) return res.status(409).json({ error: "المهمة مو متاحة" });
    pushToUser(t.assignerId, "taskupd", { ev: "ack", toAssigner: true, targetTag: t.targetTag, id: String(t._id) });
    pushToUser(t.targetId, "taskupd", { ev: "ack", id: String(t._id) });
    res.json({ ok: true, task: taskPublic(t), now });
}));
app.post("/api/tasks/:id/done", auth, wrap(async (req, res) => {
    const me = req.session.user;
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "مهمة غير صحيحة" });
    const t = await Task.findOneAndUpdate({ _id: req.params.id, targetId: me.id, status: "active" }, { $set: { status: "done", doneAt: new Date() } }, { new: true }).lean();
    if (!t) return res.status(409).json({ error: "المهمة مو متاحة" });
    const late = t.doneAt.getTime() - new Date(t.dueAt).getTime();
    const det = late > 0 ? "⚠️ أُنجزت متأخرة بـ " + (late >= 3600000 ? Math.floor(late / 3600000) + " ساعة و" : "") + Math.max(1, Math.round((late % 3600000) / 60000)) + " دقيقة" : "✅ أُنجزت في الوقت (المدة: " + minLabel(t.minutes) + ")";
    await createDirect({ type: "taskdone", reason: t.text, eventDetails: det, subjectId: t.targetId, subjectTag: t.targetTag, senderId: t.targetId, senderTag: t.targetTag, senderAvatar: me.avatar }, [t.assignerId]);
    pushToUser(t.targetId, "taskupd", { ev: "done", id: String(t._id) });
    res.json({ ok: true });
}));
app.post("/api/tasks/:id/cancel", auth, full, wrap(async (req, res) => {
    const me = req.session.user;
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "مهمة غير صحيحة" });
    const t = await Task.findOneAndUpdate({ _id: req.params.id, status: { $in: ["pending", "active"] } }, { $set: { status: "cancelled", cancelledBy: me.tag } }, { new: true }).lean();
    if (!t) return res.status(409).json({ error: "المهمة مو متاحة للإلغاء" });
    pushToUser(t.targetId, "taskupd", { ev: "cancel", toTarget: true, id: String(t._id) });
    pushToUser(t.assignerId, "taskupd", { ev: "cancel", id: String(t._id) });
    await panelLog(req, "إلغاء مهمة", "العضو: " + t.targetTag + "\nالمهمة: " + clip(t.text, 200), { targetId: t.targetId, targetTag: t.targetTag });
    res.json({ ok: true });
}));

// القيادة تسمح للعضو اللي أرسل الإشعار بالتعامل مع الحالة (فقط لعمليات «حساب جديد») — يوصله رسالة «ضع العضو في روم الأعضاء المشتبه بهم»
app.post("/api/notices/:id/allow", auth, full, wrap(async (req, res) => {
    const me = req.session.user;
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "إشعار غير صحيح" });
    const n = await Notice.findById(req.params.id).lean();
    if (!n || n.type !== "op" || n.rule !== "new_account") return res.status(404).json({ error: "هذا الإشعار ما يدعم السماح" });
    if (!(n.recipients || []).includes(me.id)) return res.status(403).json({ error: "هذا الإشعار مو موجّه لك" });
    const upd = await Notice.findOneAndUpdate({ _id: n._id, allowedBy: null }, { $set: { allowedBy: me.id, allowedByTag: me.tag, allowedAt: new Date() }, $addToSet: { seenBy: me.id } }, { new: true });
    if (!upd) return res.status(409).json({ error: "تم السماح لهذي الحالة قبل من " + (n.allowedByTag || "القيادة") });
    const a = await Notice.create({ type: "allow", eventId: n.eventId, eventTitle: n.eventTitle, subjectId: n.subjectId, subjectTag: n.subjectTag, senderId: me.id, senderTag: me.tag, senderAvatar: me.avatar, recipients: [n.senderId] });
    pushToUser(n.senderId, "notice", noticePublic(a));
    let dm = { skipped: true };
    if (CONFIG.NOTIFY_BOT_TOKEN) { try { await dmUser(n.senderId, noticeMessage(a)); dm = { sent: 1 }; } catch (e) { dm = { failed: 1 }; console.error("allow DM:", e.message); } }
    Notice.updateOne({ _id: a._id }, { $set: { dm } }).catch(() => {});
    await panelLog(req, "السماح للعضو بالتعامل مع حالة", "العضو المشتبه: " + (n.subjectTag || "—") + " — المسموح له: " + n.senderTag, { targetId: n.senderId, targetTag: n.senderTag });
    res.json({ ok: true, dm });
}));
app.get("/api/notices/pending", auth, wrap(async (req, res) => {
    const me = req.session.user.id;
    const list = await Notice.find({ recipients: me, seenBy: { $ne: me }, createdAt: { $gte: new Date(Date.now() - 7 * 864e5) } }).sort({ createdAt: 1 }).limit(20).lean();
    res.json({ notices: list.map(noticePublic) });
}));
app.post("/api/notices/:id/seen", auth, wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: "إشعار غير صحيح" });
    await Notice.updateOne({ _id: req.params.id }, { $addToSet: { seenBy: req.session.user.id } });
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
    // مهام انتهى وقتها بدون تسليم: ننبّه اللي كلّف بها
    setInterval(async () => {
        try {
            const due = await Task.find({ status: "active", dueAt: { $lt: new Date() }, overdueNotified: { $ne: true } }).limit(20).lean();
            for (const t of due) {
                const up = await Task.updateOne({ _id: t._id, overdueNotified: { $ne: true } }, { $set: { overdueNotified: true } });
                if (!up.modifiedCount) continue;
                await createDirect({ type: "taskdue", reason: t.text, eventDetails: "المدة: " + minLabel(t.minutes), subjectId: t.targetId, subjectTag: t.targetTag, senderId: t.targetId, senderTag: t.targetTag }, [t.assignerId]);
                pushToUser(t.targetId, "taskupd", { ev: "due", id: String(t._id) });
            }
        } catch (e) { console.error("task due:", e.message); }
    }, 30000);
    setInterval(() => refreshMgr(), 20000);
    refreshMgr(0);
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
nav { background:rgba(5,15,30,0.95); backdrop-filter:blur(15px); border-bottom:1px solid rgba(59,130,246,0.3); padding:0 1.2rem; display:flex; align-items:center; justify-content:space-between; height:62px; position:sticky; top:var(--tbar-h,0px); z-index:900; gap:10px; }
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
.tfbar:empty { display:none; }
.tfbar { margin:10px 0 2px; }
.tfpill { display:inline-flex; align-items:center; gap:10px; background:rgba(59,130,246,0.15); border:1px solid #3b82f6; color:#bfdbfe; border-radius:999px; padding:5px 8px 5px 14px; font-size:13px; font-weight:700; max-width:100%; }
.tfpill span { overflow-wrap:anywhere; }
.tfpill button { background:rgba(255,255,255,0.12); border:none; color:#fff; width:24px; height:24px; border-radius:50%; cursor:pointer; font-size:13px; line-height:1; flex:none; }
.tfpill button:hover { background:#ef4444; }
.tfchips { display:flex; flex-wrap:wrap; gap:8px; margin:8px 0 14px; }
.tftabs { display:flex; gap:8px; margin:6px 0 12px; }
.tftabs .btn { flex:1; text-align:center; }
.bn-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:12px; }
.bn-grid .card { margin-bottom:0; }
.bn-card { cursor:pointer; display:flex; gap:12px; align-items:flex-start; transition:.15s; }
.bn-card:hover { border-color:var(--gold-soft); transform:translateY(-1px); }
.bn-card img { width:56px; height:56px; border-radius:50%; object-fit:cover; flex:none; border:2px solid #ef4444; background:#0b1730; }
.bn-rs { color:#cbd5e1; font-size:13px; line-height:1.6; margin:2px 0 4px; display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; overflow-wrap:anywhere; }
.bn-hero { display:flex; gap:14px; align-items:center; margin-bottom:10px; }
.bn-hero img { width:84px; height:84px; border-radius:50%; object-fit:cover; border:3px solid #ef4444; background:#0b1730; flex:none; }
.bn-row { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; padding:9px 0; border-bottom:1px dashed rgba(255,255,255,0.09); font-size:13px; }
.bn-row > span { color:var(--muted); flex:none; }
.bn-row > b { text-align:left; overflow-wrap:anywhere; font-weight:700; }
.bn-who { display:inline-flex; align-items:center; gap:7px; }
.bn-who img { width:26px; height:26px; border-radius:50%; object-fit:cover; }
.bn-reason { background:rgba(255,255,255,0.05); border:1px solid var(--border); border-radius:10px; padding:10px 12px; margin:8px 0; line-height:1.8; white-space:pre-wrap; overflow-wrap:anywhere; font-size:13px; }
.tfgrid { display:grid; grid-template-columns:1fr 1fr; gap:8px 10px; align-items:center; }
.tfgrid .tfl { grid-column:1 / -1; font-size:12px; color:#94a3b8; margin-top:6px; }
.tfpr { display:flex; flex-wrap:wrap; gap:8px; margin-top:8px; }
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
.log-item[data-id] { cursor:pointer; transition:border-color .15s; touch-action:pan-y; }
.log-item[data-id]:hover { border-color:rgba(96,165,250,0.75); }
.livedot { display:inline-block; width:10px; height:10px; border-radius:50%; background:#ef4444; margin-left:8px; animation:livep 1.2s infinite; }
@keyframes livep { 0%{opacity:1;transform:scale(1)} 50%{opacity:.35;transform:scale(1.35)} 100%{opacity:1;transform:scale(1)} }
.lvp { display:flex; align-items:center; gap:8px; padding:7px 10px; border-radius:8px; background:rgba(255,255,255,0.03); margin:4px 0; font-size:13px; }
.lvp.sp { background:rgba(74,222,128,0.14); outline:1px solid rgba(74,222,128,0.55); }
.lvp img { width:26px; height:26px; border-radius:50%; }
.card.clk { cursor:pointer; }
.card.clk:hover { border-color:rgba(248,113,113,0.7); }
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
.nov { position:fixed; inset:0; z-index:6000; background:rgba(2,6,15,0.85); backdrop-filter:blur(3px); display:flex; align-items:flex-start; justify-content:center; overflow-y:auto; padding:calc(20px + env(safe-area-inset-top,0px)) 14px 24px; }
.nbox { background:#0d1f3c; border:2px solid #ef4444; border-radius:16px; padding:22px; max-width:520px; width:100%; margin:auto; animation:npulse 1.6s ease-in-out infinite; }
.nbox.info { border-color:#3b82f6; animation:none; box-shadow:0 0 30px rgba(59,130,246,.3); }
.nbox h3 { color:#f87171; margin-bottom:12px; font-size:1.1rem; }
.nbox.info h3 { color:#60a5fa; }
.nbox.warn { border-color:#f59e0b; animation:none; box-shadow:0 0 34px rgba(245,158,11,.4); }
.nbox.warn h3 { color:#fbbf24; }
#tbar { position:sticky; top:0; z-index:950; background:linear-gradient(180deg,#1b2a4a,#12203a); border-bottom:2px solid #f59e0b; padding:calc(6px + env(safe-area-inset-top,0px)) 10px 6px; box-shadow:0 4px 18px rgba(0,0,0,.5); }
#tbar .trow { display:flex; align-items:center; gap:8px; flex-wrap:wrap; padding:4px 0; }
#tbar .trow + .trow { border-top:1px solid rgba(255,255,255,.08); }
#tbar .ttxt { flex:1; min-width:140px; cursor:pointer; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:13px; }
#tbar .ttxt.open { white-space:normal; }
.ttim { font-variant-numeric:tabular-nums; font-weight:700; color:#fbbf24; white-space:nowrap; }
.pov { position:fixed; inset:0; z-index:5500; background:rgba(0,0,0,.62); display:flex; align-items:center; justify-content:center; padding:16px; }
.pbox { background:#0d1f3c; border:1px solid rgba(59,130,246,.45); border-radius:14px; padding:16px; width:100%; max-width:380px; max-height:80vh; overflow-y:auto; }
.pbox h3 { margin-bottom:10px; color:#60a5fa; }
.pit { display:block; width:100%; text-align:right; background:rgba(255,255,255,.05); border:1px solid transparent; border-radius:10px; color:#e2e8f0; padding:11px 12px; margin-bottom:6px; font:inherit; cursor:pointer; }
.pit.on { border-color:#3b82f6; background:rgba(59,130,246,.18); }
.selbtn { display:inline-block; min-width:80px; background:rgba(255,255,255,.06); border:1px solid rgba(59,130,246,.35); border-radius:10px; color:#e2e8f0; padding:9px 12px; font:inherit; cursor:pointer; text-align:right; }
.pcal { display:grid; grid-template-columns:repeat(7,1fr); gap:4px; margin:8px 0; text-align:center; }
.pcal .pd { padding:9px 0; border-radius:8px; background:rgba(255,255,255,.05); border:1px solid transparent; color:#e2e8f0; font:inherit; cursor:pointer; }
.pcal .pd.on { background:#3b82f6; }
.pcal .pd.td { border-color:#f59e0b; }
.pcal .ph { color:#60a5fa; font-size:12px; padding:4px 0; }
.segb { display:flex; gap:8px; margin:10px 0; }
.segb .btn { flex:1; }
.chips { display:flex; gap:6px; flex-wrap:wrap; margin:6px 0; }
.nbox .nq { background:rgba(255,255,255,.05); border-radius:10px; padding:10px 12px; margin:10px 0; line-height:1.9; white-space:pre-wrap; word-break:break-word; }
.nbox .nfrom { display:flex; align-items:center; gap:10px; margin-bottom:8px; }
.nbox .nfrom img { width:38px; height:38px; border-radius:50%; border:2px solid var(--gold); }
@keyframes npulse { 0%,100% { box-shadow:0 0 22px rgba(239,68,68,.25); } 50% { box-shadow:0 0 48px rgba(239,68,68,.6); } }
/* ══ التسجيل التوضيحي للروم الصوتي ══ */
.rp-clock { font-size:26px; font-weight:800; text-align:center; color:var(--gold-soft); direction:ltr; }
.rp-prog { height:6px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden; margin:8px 0 12px; }
.rp-prog div { height:100%; width:0; background:var(--green2); }
.rp-row { display:flex; justify-content:space-between; align-items:center; gap:8px; padding:7px 10px; margin-bottom:6px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); font-size:13px; transition:background .2s, opacity .2s; }
.rp-row.wait { opacity:.4; }
.rp-row.in { background:rgba(34,197,94,0.16); border-color:#22c55e; }
.rp-row.out { background:rgba(100,116,139,0.18); opacity:.75; }
.rp-row.talk { box-shadow:0 0 0 2px #22c55e; }
.rp-mic { font-size:11px; font-weight:700; color:#94a3b8; margin-right:4px; }
.rp-mic.live { color:#4ade80; animation:rpPulse .9s ease-in-out infinite; }
@keyframes rpPulse { 0%,100% { opacity:1; } 50% { opacity:.45; } }
.rp-feed { max-height:120px; overflow-y:auto; font-size:12px; color:#cbd5e1; margin-top:8px; line-height:1.9; }
.vr-lane { margin-bottom:8px; }
.vr-lh { direction:rtl; font-size:12px; display:flex; justify-content:space-between; align-items:center; gap:6px; margin-bottom:3px; }
.vr-bar { position:relative; height:18px; background:rgba(255,255,255,0.05); border-radius:5px; overflow:hidden; cursor:pointer; }
.vr-pres { position:absolute; top:0; bottom:0; background:rgba(148,163,184,0.22); }
.vr-sp { position:absolute; top:3px; bottom:3px; border-radius:3px; }
`;

const HEAD = (title) => `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${title}</title>
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>${CSS}</style></head>`;

function loginHint(c) {
    if (c === "state") return "انتهت صلاحية محاولة الدخول — افتح الموقع من جديد واضغط تسجيل الدخول مرة وحدة.";
    if (/invalid_client|_401/.test(c)) return "الـ Client Secret أو الـ Client ID غلط في إعدادات الاستضافة.";
    if (/invalid_grant/.test(c)) return "رابط الرجوع (Redirect URI) ما يطابق اللي في ديسكورد، أو الكود انستخدم قبل — جرّب مرة ثانية.";
    if (/_429_cf|_403|_1015/.test(c)) return "ديسكورد (Cloudflare) حاجب عنوان الاستضافة مؤقتاً — لا تكرر الضغط، انتظر 15–30 دقيقة ثم جرّب مرة وحدة.";
    const m = /_429_r(\d+)/.exec(c);
    if (m) return "ديسكورد حاط حد طلبات مؤقت — جرّب بعد " + m[1] + " ثانية (لا تكرر الضغط).";
    if (/_429/.test(c)) return "ديسكورد حاجب الطلبات مؤقتاً (ضغط على عنوان الاستضافة) — جرّب بعد دقيقة.";
    if (/network/.test(c)) return "السيرفر ما قدر يوصل لديسكورد — جرّب بعد شوي.";
    if (/^discord_access_denied/.test(c)) return "أنت رفضت صلاحية الدخول في ديسكورد.";
    return "";
}
function loginPage(mode, detail) {
    let body;
    if (mode === "denied") body = `<div class="auth-card deny"><div class="ico">⛔</div><h1>غير مصرّح</h1>
        <p>هذا الموقع فقط لمنسوبي الأمن السيبراني.<br>حسابك لا يملك الرتبة المطلوبة.</p>
        <a class="btn gray" href="/auth/discord">تسجيل الدخول بحساب آخر</a></div>`;
    else body = `<div class="auth-card"><div class="ico">🛡️</div><h1>${CONFIG.SITE_NAME}</h1>
        <p>${CONFIG.SITE_SUB}<br>الدخول مخصّص لمنسوبي الأمن السيبراني فقط، سجّل دخولك بحساب ديسكورد ليتم التحقق من رتبتك.</p>
        ${mode === "err" ? '<div class="warn">صار خطأ أثناء تسجيل الدخول، حاول مرة ثانية.' + (/^[A-Za-z0-9_\-]{1,60}$/.test(detail || "") && detail !== "1" ? ((loginHint(detail) ? "<br>" + loginHint(detail) : "") + '<br><small dir="ltr" style="opacity:.7">code: ' + detail + "</small>") : "") + "</div>" : ""}
        <a class="btn" href="/auth/discord">🔐 تسجيل الدخول عبر ديسكورد</a></div>`;
    return HEAD(CONFIG.SITE_NAME) + `<body><div class="auth-page">${body}</div></body></html>`;
}

const CLIENT = String.raw`
var PAGES=[['logs','📜 اللوق'],['stats','📊 الإحصائيات'],['bots','🤖 البوتات'],['perms','🔐 صلاحيات السيرفر'],['bans','🔨 الباندات']];
var S={page:'logs',q:'',cat:'',unres:false,cu:false,events:[],sig:'',timer:null,permsTab:'roles',permsView:'danger',permsQ:'',meta:null,presence:true,level:'view',meId:null,tf:null};
var CATS=[['','الكل'],['sus','⚠️ العمليات المشبوهة'],['newacc','🆕 حسابات جديدة'],['join','دخول'],['leave','خروج'],['kick','طرد'],['ban','حظر'],['role','الرتب'],['inquiry','📩 استفسارات الرتب'],['channel','القنوات'],['voice','🎙️ الرومات الصوتية'],['message','الرسائل المحذوفة'],['probot','🧹 حذف عبر ProBot'],['bot','البوتات'],['webhook','ويبهوكس'],['everyone','منشن everyone'],['server','إعدادات السيرفر'],['panel','عمليات اللوحة']];
var RULE_AR={new_account:'حساب جديد',mass_roles_created:'رتب جماعية',mass_role_delete:'حذف رتب',mass_channel_create:'إنشاء قنوات',mass_channel_delete:'حذف قنوات',mass_ban:'حظر جماعي',mass_kick:'طرد جماعي',dangerous_perm_grant:'صلاحيات خطيرة',dangerous_role_assigned:'رتبة خطيرة',bot_added:'بوت جديد',webhook_created:'ويبهوك',everyone_spam:'منشن everyone',mass_join:'غارة دخول',mass_msg_delete:'مسح ضخم',server_changed:'إعدادات السيرفر'};
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function toast(m){var t=$('toast');t.textContent=m;t.style.display='block';clearTimeout(t._t);t._t=setTimeout(function(){t.style.display='none';},3200);}
function fmt(d){try{return new Date(d).toLocaleString('ar-SA',{timeZone:'Asia/Riyadh',hour12:true,dateStyle:'medium',timeStyle:'short'});}catch(e){return new Date(d).toLocaleString();}}
function ago(d){var s=Math.floor((Date.now()-new Date(d).getTime())/1000);if(s<60)return 'الحين';if(s<3600)return 'قبل '+Math.floor(s/60)+' دقيقة';if(s<86400)return 'قبل '+Math.floor(s/3600)+' ساعة';return 'قبل '+Math.floor(s/86400)+' يوم';}
/* ══ تسجيل الروم الصوتي: شريط صوت + مسارات كل شخص + اختيار مقطع ══ */
var VR=null;
var VR_COL=['#38bdf8','#4ade80','#f472b6','#fbbf24','#a78bfa','#fb923c','#2dd4bf','#f87171','#a3e635','#e879f9'];
function vrT(ms){try{return new Date(ms).toLocaleTimeString('ar-SA-u-nu-latn',{timeZone:'Asia/Riyadh',hour12:true,hour:'numeric',minute:'2-digit',second:'2-digit'});}catch(e){return new Date(ms).toLocaleTimeString();}}
function vrDur(ms){var s=Math.max(0,Math.round(ms/1000)),h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=s%60;return h?h+' س '+m+' د':(m?m+' د '+x+' ث':x+' ث');}
function vrMS(ms){var s=Math.max(0,Math.floor(ms/1000)),h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=s%60;return (h?h+':'+(m<10?'0':'')+m:m)+':'+(x<10?'0':'')+x;}
function vrParse(t){t=String(t||'').trim();if(!t)return null;var p=t.split(':'),n=0;for(var i=0;i<p.length;i++){var v=parseFloat(p[i]);if(isNaN(v))return null;n=n*60+v;}return Math.round(n*1000);}
function vrStop(){
  if(VR){
    if(VR.timer)clearInterval(VR.timer);
    for(var k in VR.els){try{VR.els[k].pause();VR.els[k].removeAttribute('src');}catch(e){}}
  }
  VR=null;
}
function vrClose(){vrStop();closeModal();}
function vrDiag(s){
  var sup='';try{sup=new Audio().canPlayType('audio/ogg; codecs=opus');}catch(e){}
  var starts=(s.speech||[]).filter(function(e){return e[1]===1;}).length;
  var w='';
  if(!sup)w='⚠️ متصفحك ما يشغّل صيغة Ogg Opus، جرّب Chrome أو حدّث النظام.';
  else if(!s.pkts&&starts)w='⚠️ البوت شاف إنك تتكلم لكن ما وصله أي صوت.';
  else if(!s.pkts)w='⚠️ ما وصل أي صوت للبوت في هذي الجلسة.';
  if(s.decErr)w+=' خطأ: '+esc(s.decErr);
  if(!w)return '';
  var det='';
  if(!s.pkts&&(s.dbg||s.dep))det='<details style="margin:6px 0"><summary class="muted" style="font-size:12px">تفاصيل فنية</summary><pre style="direction:ltr;text-align:left;font-size:10px;white-space:pre-wrap;max-height:160px;overflow:auto">'+esc((s.dep||'')+'\n'+(s.dbg||''))+'</pre></details>';
  return '<p style="font-size:12px;color:#fbbf24;line-height:1.8">'+w+'</p>'+det;
}
async function vrOpen(sid){
  vrStop();
  modal('<h3>🎬 تسجيل توضيحي</h3><p class="muted center" style="padding:20px 0">جارِ التحميل...</p>');
  var j;
  try{j=await api('/api/voice/'+encodeURIComponent(sid));}
  catch(e){closeModal();toast(e.message);return;}
  var s=j.session;
  s.tracks=s.tracks||{};
  var E=s.endedAt||s.lastAt||Date.now();
  var span=Math.max(1000,E-s.startedAt);
  var att=[],seen={};
  s.stays.forEach(function(st){
    if(!seen[st.uid]){seen[st.uid]={uid:st.uid,name:st.name,col:VR_COL[att.length%VR_COL.length],stays:[]};att.push(seen[st.uid]);}
    seen[st.uid].stays.push(st);
  });
  var ev={};
  s.speech.forEach(function(e){(ev[e[0]]=ev[e[0]]||[]).push([Number(e[2]),e[1]]);});
  var iv={};
  Object.keys(ev).forEach(function(u){
    var arr=ev[u].sort(function(a,b){return a[0]-b[0];}),cur=null;iv[u]=[];
    arr.forEach(function(x){if(x[1]===1){if(cur===null)cur=x[0];}else if(cur!==null){iv[u].push([cur,Math.max(cur+200,x[0])]);cur=null;}});
    if(cur!==null)iv[u].push([cur,Math.min(span,cur+1500)]);
  });
  VR={s:s,E:E,span:span,att:att,iv:iv,T:0,playing:false,rate:1,sel:{},els:{},r0:null,r1:null,clip:false,drag:false,last:Date.now(),timer:null,sid:sid,wait:0};
  var hasTracks=Object.keys(s.tracks).length>0;
  var h='<h3>🎬 تسجيل توضيحي — '+esc(s.chName||'الروم المسجّل')+'</h3>'
    +'<div style="text-align:center;margin:14px 0"><div style="font-size:46px">'+(s.hasAudio?'🎧':'🎬')+'</div>'
    +'<p class="muted" style="font-size:13px;line-height:1.9;margin:8px 0 0">'+(s.hasAudio?'شريط صوت تتحكم فيه (تقدّم وتأخّر)، ومسار لكل شخص يبيّن متى تكلم، وتقدر تسمع شخص معيّن أو تحدد مقطع وتعرف مين تكلم فيه.'+(hasTracks?'':' (هذي جلسة قديمة: بدون صوت منفصل لكل شخص)'):'هذي الجلسة بدون صوت، تقدر تشوف مين تكلم ومتى.')+'</p></div>'
    +'<div class="card" style="margin:8px 0;padding:6px 12px">'
    +'<div class="prow"><span class="muted">📅 بدأت</span><b>'+esc(fmt(s.startedAt))+'</b></div>'
    +'<div class="prow"><span class="muted">⏱️ المدة</span><b>'+esc(vrDur(span))+(s.live?' (جارية الحين)':'')+'</b></div>'
    +'<div class="prow" style="border:none"><span class="muted">👥 عدد الحضور</span><b>'+att.length+'</b></div></div>'
    +vrDiag(s)
    +'<div class="row" style="justify-content:center;gap:8px"><button class="btn" onclick="vrStart()">▶️ فتح المشغّل</button><button class="btn gray sm" onclick="vrClose()">✖ إغلاق</button></div>';
  modal(h);
}
function vrShell(){
  var s=VR.s,h='<h3>🎬 '+esc(s.chName||'الروم المسجّل')+'</h3>';
  h+='<div class="rp-clock" id="rp-clock">--</div>';
  h+='<div style="text-align:center;font-size:12px;color:var(--muted)"><span id="vr-el">0:00</span> / '+vrMS(VR.span)+' <span id="vr-now" style="color:#4ade80"></span></div>';
  h+='<div id="vr-lanes" style="position:relative;direction:ltr;margin:10px 0 4px"><div id="vr-rng" style="position:absolute;top:0;bottom:0;left:0;width:0;background:rgba(250,204,21,.13);border-left:1px solid #facc15;border-right:1px solid #facc15;pointer-events:none;z-index:1;display:none"></div><div id="vr-ph" style="position:absolute;top:0;bottom:0;left:0;width:2px;background:#fff;pointer-events:none;z-index:2"></div>';
  VR.att.forEach(function(p){
    var bars='';
    p.stays.forEach(function(st){
      var a=Math.max(0,st.start-s.startedAt),b=((st.end||VR.E)-s.startedAt);
      bars+='<div class="vr-pres" style="left:'+(a/VR.span*100)+'%;width:'+(Math.max(0.3,(b-a)/VR.span*100))+'%"></div>';
    });
    (VR.iv[p.uid]||[]).forEach(function(x){
      bars+='<div class="vr-sp" style="background:'+p.col+';left:'+(x[0]/VR.span*100)+'%;width:'+(Math.max(0.35,(x[1]-x[0])/VR.span*100))+'%"></div>';
    });
    var pres=p.stays.map(function(st){return vrT(st.start)+' ← '+(st.end?vrT(st.end):'لين النهاية');}).join(' • ');
    h+='<div class="vr-lane"><div class="vr-lh"><span><span style="color:'+p.col+'">●</span> <b>'+esc(p.name)+'</b> <span class="muted" style="font-size:10px">'+esc(pres)+'</span></span><button class="btn sm gray" id="vr-b-'+p.uid+'" onclick="vrSel(\''+p.uid+'\')">🎧 اسمعه</button></div><div class="vr-bar" onclick="vrLaneClick(event,this)">'+bars+'</div></div>';
  });
  h+='</div>';
  h+='<input type="range" id="vr-seek" min="0" max="'+VR.span+'" step="100" value="0" style="width:100%;direction:ltr" oninput="vrDrag(this.value)" onchange="vrCommit(this.value)">';
  h+='<div class="row" style="justify-content:center;gap:6px;margin:8px 0"><button class="btn gray sm" onclick="vrSkip(-10000)">⏪ 10</button><button class="btn sm" id="vr-pp" onclick="vrToggle()">▶️ تشغيل</button><button class="btn gray sm" onclick="vrSkip(10000)">10 ⏩</button><button class="btn gray sm" id="vr-sp" onclick="vrSpeed()">×1</button></div>';
  h+='<div id="vr-listen" class="muted" style="text-align:center;font-size:12px;margin-bottom:8px"></div>';
  h+='<div class="card" style="padding:8px 12px;margin:6px 0"><div style="font-size:13px;font-weight:700;margin-bottom:6px">✂️ تحديد مقطع</div>'
    +'<div class="row" style="gap:6px;flex-wrap:wrap;direction:ltr;justify-content:center"><input id="vr-r0" placeholder="من 0:00" style="width:78px;text-align:center" onchange="vrRangeInput(0,this.value)"><button class="btn gray sm" onclick="vrRangeSet(0)">📍 من هنا</button><button class="btn gray sm" onclick="vrRangeSet(1)">🏁 إلى هنا</button><input id="vr-r1" placeholder="إلى 0:00" style="width:78px;text-align:center" onchange="vrRangeInput(1,this.value)"></div>'
    +'<div class="row" style="justify-content:center;gap:6px;margin-top:6px"><button class="btn sm" onclick="vrRangePlay()">▶️ شغّل المقطع</button><button class="btn gray sm" onclick="vrRangeClear()">🧹 مسح</button></div></div>';
  h+='<div class="card" style="padding:8px 12px;margin:6px 0"><div id="vr-who-t" style="font-size:13px;font-weight:700;margin-bottom:6px"></div><div id="vr-who"></div></div>';
  h+='<div class="row" style="justify-content:center;margin-top:8px"><button class="btn danger sm" onclick="vrClose()">✖ إغلاق</button></div>';
  return h;
}
function vrStart(){
  if(!VR||VR.timer)return;
  modal(vrShell());
  VR.last=Date.now();
  VR.timer=setInterval(vrTick,100);
  vrSelPaint();vrRangePaint();vrPaint();
  if(VR.s.hasAudio)vrPlay();
}
function vrOff(k){return k==='mix'?0:(Number(VR.s.tracks[k])||0);}
function vrKeys(){
  var ks=[];
  Object.keys(VR.sel).forEach(function(u){if(VR.sel[u]&&VR.s.tracks[u]!==undefined)ks.push(u);});
  return ks.length?ks:['mix'];
}
function vrEl(k){
  var a=VR.els[k];if(a)return a;
  a=new Audio();a.preload='auto';
  a.src='/api/voice/'+encodeURIComponent(VR.sid)+'/audio?v=2'+(k==='mix'?'':'&u='+encodeURIComponent(k));
  a.playbackRate=VR.rate;
  a.onerror=function(){if(VR&&!VR.errShown){VR.errShown=true;toast('تعذر تشغيل الصوت');}};
  VR.els[k]=a;return a;
}
function vrPlayEl(a,t){
  try{if(Math.abs(a.currentTime-t)>0.05)a.currentTime=Math.max(0,t);}catch(e){}
  var p=a.play();if(p&&p.catch)p.catch(function(){});
}
function vrSync(dt){
  if(!VR.s.hasAudio){VR.T+=dt*VR.rate;return;}
  var keys=vrKeys(),i,k,a,t;
  for(k in VR.els){if(keys.indexOf(k)<0&&!VR.els[k].paused){try{VR.els[k].pause();}catch(e){}}}
  var master=null;
  for(i=0;i<keys.length;i++){if(VR.T>=vrOff(keys[i])){master=keys[i];break;}}
  if(master===null){VR.T+=dt*VR.rate;return;}
  a=vrEl(master);
  if(a.paused&&!a.ended){vrPlayEl(a,(VR.T-vrOff(master))/1000);}
  else if(!a.paused&&!a.seeking){VR.T=Math.min(VR.span,a.currentTime*1000+vrOff(master));}
  if(a.ended)VR.T=VR.span;
  for(i=0;i<keys.length;i++){
    k=keys[i];if(k===master)continue;
    var el=vrEl(k);t=(VR.T-vrOff(k))/1000;
    if(t<0){if(!el.paused)el.pause();continue;}
    if(el.paused&&!el.ended)vrPlayEl(el,t);
    else if(Math.abs(el.currentTime-t)>0.3){try{el.currentTime=t;}catch(e){}}
  }
}
function vrPlay(){
  if(!VR)return;
  if(VR.T>=VR.span-50)vrSeekTo(0);
  VR.playing=true;VR.last=Date.now();vrSync(0);vrPaint();
}
function vrPause(){
  if(!VR)return;
  VR.playing=false;
  for(var k in VR.els){try{VR.els[k].pause();}catch(e){}}
  vrPaint();
}
function vrToggle(){if(!VR)return;if(VR.playing)vrPause();else{VR.clip=false;vrPlay();}}
function vrSeekTo(ms){
  if(!VR)return;
  VR.T=Math.max(0,Math.min(VR.span,ms));
  for(var k in VR.els)vrSeekEl(k,VR.els[k],(VR.T-vrOff(k))/1000);
  if(VR.playing)vrSync(0);
  vrPaint();
}
function vrSeekEl(k,a,t){
  t=Math.max(0,t);
  var tok=(a._sk=(a._sk||0)+1),tries=0;
  var fix=function(){
    a.removeEventListener('seeked',fix);
    if(!VR||VR.els[k]!==a||a._sk!==tok)return;
    if(Math.abs(a.currentTime-t)>1){
      if(tries<2){tries++;a.addEventListener('seeked',fix);try{a.currentTime=t;}catch(e){}return;}
      if(k===vrKeys()[0]){VR.T=Math.max(0,Math.min(VR.span,a.currentTime*1000+vrOff(k)));vrPaint();}   // الصوت ما وصل للمكان — الصورة تتبعه بدل ما تفترق عنه
    }
  };
  a.addEventListener('seeked',fix);
  try{a.currentTime=t;}catch(e){}
}
function vrSkip(d){if(VR){VR.clip=false;vrSeekTo(VR.T+d);}}
function vrDrag(v){if(!VR)return;VR.drag=true;VR.dragT=Number(v);var c=$('rp-clock');if(c)c.textContent=vrT(VR.s.startedAt+VR.dragT);var e=$('vr-el');if(e)e.textContent=vrMS(VR.dragT);var ph=$('vr-ph');if(ph)ph.style.left=(VR.dragT/VR.span*100)+'%';}
function vrCommit(v){if(!VR)return;VR.drag=false;VR.clip=false;vrSeekTo(Number(v));}
function vrLaneClick(e,el){
  if(!VR)return;
  var r=el.getBoundingClientRect();
  var x=((e.clientX-r.left)/r.width)*VR.span;
  VR.clip=false;vrSeekTo(x);
}
function vrSpeed(){
  if(!VR)return;
  VR.rate=VR.rate===1?1.5:(VR.rate===1.5?2:1);
  for(var k in VR.els)VR.els[k].playbackRate=VR.rate;
  var b=$('vr-sp');if(b)b.textContent='×'+VR.rate;
}
function vrSel(u){
  if(!VR)return;
  if(VR.s.tracks[u]===undefined){toast('ما فيه صوت منفصل لهذا الشخص (جلسة قديمة أو ما تكلم)');return;}
  VR.sel[u]=!VR.sel[u];
  vrSelPaint();
  if(VR.playing)vrSync(0);
}
function vrSelAll(){if(!VR)return;VR.sel={};vrSelPaint();if(VR.playing)vrSync(0);}
function vrSelPaint(){
  if(!VR)return;
  var names=[];
  VR.att.forEach(function(p){
    var on=!!VR.sel[p.uid]&&VR.s.tracks[p.uid]!==undefined;
    var b=$('vr-b-'+p.uid);
    if(b){b.className='btn sm'+(on?'':' gray');b.textContent=on?'🎧 ✓ يسمعه':'🎧 اسمعه';}
    if(on)names.push(p.name);
  });
  var l=$('vr-listen');
  if(l){
    if(!VR.s.hasAudio)l.innerHTML='';
    else if(names.length)l.innerHTML='🔊 تسمع: <b>'+esc(names.join('، '))+'</b> فقط — <a href="#" onclick="vrSelAll();return false" style="color:var(--gold-soft)">رجّع الكل</a>';
    else l.innerHTML='🔊 تسمع: الكل (مختلط)';
  }
}
function vrRangeSet(w){
  if(!VR)return;
  if(w===0)VR.r0=Math.round(VR.T);else VR.r1=Math.round(VR.T);
  if(VR.r0!=null&&VR.r1!=null&&VR.r1<VR.r0){var t=VR.r0;VR.r0=VR.r1;VR.r1=t;}
  vrRangePaint();
}
function vrRangeInput(w,val){
  if(!VR)return;
  var ms=vrParse(val);
  if(ms===null){vrRangePaint();return;}
  ms=Math.max(0,Math.min(VR.span,ms));
  if(w===0)VR.r0=ms;else VR.r1=ms;
  if(VR.r0!=null&&VR.r1!=null&&VR.r1<VR.r0){var t=VR.r0;VR.r0=VR.r1;VR.r1=t;}
  vrRangePaint();
}
function vrRangeClear(){if(!VR)return;VR.r0=null;VR.r1=null;VR.clip=false;vrRangePaint();}
function vrRangePlay(){
  if(!VR)return;
  if(VR.r0==null){toast('حدد بداية المقطع أول');return;}
  if(VR.r1==null||VR.r1<=VR.r0)VR.r1=VR.span;
  VR.clip=true;vrRangePaint();vrSeekTo(VR.r0);
  if(!VR.playing)vrPlay();
}
function vrTalk(a,b){
  var out=[];
  VR.att.forEach(function(p){
    var iv=VR.iv[p.uid]||[],tot=0,turns=0,first=null;
    for(var i=0;i<iv.length;i++){var x=Math.max(a,iv[i][0]),y=Math.min(b,iv[i][1]);if(y>x){tot+=y-x;turns++;if(first===null)first=x;}}
    if(tot>0)out.push({p:p,tot:tot,turns:turns,first:first});
  });
  out.sort(function(m,n){return n.tot-m.tot;});
  return out;
}
function vrRangePaint(){
  if(!VR)return;
  var a=VR.r0!=null?VR.r0:0,b=VR.r1!=null?VR.r1:VR.span;
  if(b<a)b=a;
  var i0=$('vr-r0'),i1=$('vr-r1');
  if(i0&&document.activeElement!==i0)i0.value=VR.r0!=null?vrMS(VR.r0):'';
  if(i1&&document.activeElement!==i1)i1.value=VR.r1!=null?vrMS(VR.r1):'';
  var rg=$('vr-rng');
  if(rg){
    if(VR.r0!=null){rg.style.display='block';rg.style.left=(a/VR.span*100)+'%';rg.style.width=(Math.max(0.3,(b-a)/VR.span*100))+'%';}
    else rg.style.display='none';
  }
  var t=$('vr-who-t'),w=$('vr-who');
  if(!t||!w)return;
  var ranged=VR.r0!=null||VR.r1!=null;
  t.textContent=ranged?('👥 مين تكلم من '+vrMS(a)+' إلى '+vrMS(b)):'👥 مين تكلم (كل الجلسة)';
  var list=vrTalk(a,b);
  if(!list.length){w.innerHTML='<p class="muted center" style="font-size:12px">ما أحد تكلم في هذا الوقت</p>';return;}
  var h='';
  list.forEach(function(x){
    h+='<div class="rp-row"><span><span style="color:'+x.p.col+'">●</span> '+esc(x.p.name)+' <span class="muted" style="font-size:11px">'+esc(vrDur(x.tot))+' • '+x.turns+' مرة</span></span><button class="btn sm gray" onclick="vrSolo(\''+x.p.uid+'\','+Math.max(0,x.first-300)+')">🎧 اسمعه</button></div>';
  });
  w.innerHTML=h;
}
function vrSolo(u,at){
  if(!VR)return;
  if(VR.s.tracks[u]===undefined){toast('ما فيه صوت منفصل لهذا الشخص (جلسة قديمة)');return;}
  VR.sel={};VR.sel[u]=true;vrSelPaint();
  VR.clip=false;vrSeekTo(at);
  if(!VR.playing)vrPlay();
}
function vrPaint(){
  if(!VR)return;
  var c=$('rp-clock');if(!c)return;
  if(!VR.drag){
    c.textContent=vrT(VR.s.startedAt+VR.T);
    var e=$('vr-el');if(e)e.textContent=vrMS(VR.T);
    var sk=$('vr-seek');if(sk)sk.value=VR.T;
    var ph=$('vr-ph');if(ph)ph.style.left=(VR.T/VR.span*100)+'%';
  }
  var b=$('vr-pp');if(b)b.textContent=VR.playing?'⏸️ إيقاف':(VR.T>=VR.span-50?'🔄 من البداية':'▶️ تشغيل');
  var now=[];
  VR.att.forEach(function(p){
    var iv=VR.iv[p.uid]||[];
    for(var i=0;i<iv.length;i++){if(VR.T>=iv[i][0]&&VR.T<=iv[i][1]){now.push(p.name);break;}}
  });
  var n=$('vr-now');if(n)n.textContent=now.length?('🎤 '+now.join('، ')):'';
}
function vrTick(){
  if(!VR)return;
  if(!$('rp-clock')){vrStop();return;}
  var nw=Date.now(),dt=nw-VR.last;VR.last=nw;
  if(VR.playing&&!VR.drag){
    vrSync(dt);
    if(VR.clip&&VR.r1!=null&&VR.T>=VR.r1){VR.T=VR.r1;VR.clip=false;vrPause();}
    else if(VR.T>=VR.span-50){VR.T=VR.span;vrPause();}
  }
  vrPaint();
}
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
function pagesList(){var p=PAGES.slice();if(S.level==='full'||S.level==='mgr')p.push(['members','👥 الأعضاء']);if(S.recAdmin)p.push(['rec','🎙️ بوت تسجيل الرومات']);if(S.roomsAdmin)p.push(['rooms','🗂️ الرومات']);return p;}
function buildNav(){
  var list=pagesList();
  $('navlinks').innerHTML=list.map(function(p){return '<button class="'+(S.page===p[0]?'on':'')+'" onclick="go(\''+p[0]+'\')">'+p[1]+'</button>';}).join('');
  $('drawer-items').innerHTML=list.map(function(p){return '<button class="item '+(S.page===p[0]?'on':'')+'" onclick="go(\''+p[0]+'\')">'+p[1]+'</button>';}).join('');
}
function openDrawer(){$('drawer').classList.add('open');$('dov').classList.add('open');}
function closeDrawer(){$('drawer').classList.remove('open');$('dov').classList.remove('open');}
function go(p){S.page=p;closeDrawer();clearInterval(S.timer);buildNav();render();}
function render(){if(S.page==='rec'&&!S.recAdmin)S.page='logs';if(S.page==='rooms'&&!S.roomsAdmin)S.page='logs';var f={logs:pgLogs,stats:pgStats,bots:pgBots,perms:pgPerms,bans:pgBans,members:pgMembers,rec:pgRec,rooms:pgRooms}[S.page];f();}

/* ══ الرومات (لصاحب الصلاحية) ══ */
var RM_ICON={0:'#',2:'🔊',5:'📢',13:'🎙️'};
async function pgRooms(){
  clearInterval(S.timer);
  S.rm=S.rm||{};
  if(S.rm.ch)return rmOpen(S.rm.ch.id,S.rm.ch.name);
  $('main').innerHTML='<h2>🗂️ الرومات</h2><div id="rmbox"><div class="card center muted">جاري التحميل...</div></div>';
  $('main').onclick=function(ev){var d=ev.target.closest('[data-rm]');if(d)rmOpen(d.getAttribute('data-rm'),d.getAttribute('data-rmn'));};
  try{
    var j=await api('/api/rooms'+(S.rm.guild?'?guild='+S.rm.guild:''));
    S.rm.guild=j.guild;S.rm.guilds=j.guilds;S.rm.channels=j.channels;
    rmDrawList();
  }catch(e){if($('rmbox'))$('rmbox').innerHTML='<div class="card muted">'+esc(e.message)+'</div>';}
}
function rmDrawList(){
  var chs=S.rm.channels,byPos=function(a,b){return a.pos-b.pos;};
  var cats=chs.filter(function(c){return c.type===4;}).sort(byPos);
  var groups=[{id:null,name:''}].concat(cats),h='';
  if(S.rm.guilds.length>1)h+='<div style="margin-bottom:8px"><select id="rmG" aria-label="السيرفر" onchange="S.rm.guild=this.value;S.rm.ch=null;pgRooms()">'+S.rm.guilds.map(function(g){return '<option value="'+esc(g.id)+'"'+(g.id===S.rm.guild?' selected':'')+'>'+esc(g.name)+'</option>';}).join('')+'</select></div>';
  groups.forEach(function(g){
    var kids=chs.filter(function(c){return c.type!==4&&(c.parent||null)===g.id;}).sort(byPos);
    if(!kids.length)return;
    if(g.id)h+='<div class="log-meta" style="margin:14px 0 4px;font-weight:bold">'+esc(g.name)+'</div>';
    h+=kids.map(function(c){return '<button class="btn gray" style="display:block;width:100%;text-align:right;margin:4px 0" data-rm="'+esc(c.id)+'" data-rmn="'+esc(c.name)+'">'+(RM_ICON[c.type]||'#')+' '+esc(c.name)+'</button>';}).join('');
  });
  $('rmbox').innerHTML=h||'<div class="card muted">ما فيه رومات</div>';
}
async function rmOpen(id,name){
  S.rm=S.rm||{};S.rm.ch={id:id,name:name};S.rm.msgs=[];S.rm.more=false;
  $('main').innerHTML='<div class="row" style="justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px"><div><button class="btn sm gray" id="rmBack">⬅️ الرومات</button> <b>'+esc(name)+'</b></div><div class="row" style="gap:8px"><button class="btn sm" id="rmRef">🔄 تحديث</button><button class="btn sm danger" id="rmPurge">🗑️ حذف كل الرسائل</button></div></div><div id="rmmsgs"><div class="card center muted">جاري التحميل...</div></div><div id="rmmore" style="text-align:center;margin:12px 0"></div>';
  $('rmBack').onclick=function(){S.rm.ch=null;pgRooms();};
  $('rmRef').onclick=function(){rmOpen(id,name);};
  $('rmPurge').onclick=function(){rmPurge(id,name);};
  $('main').onclick=function(ev){var d=ev.target.closest('[data-rmdel]');if(d)rmDel(d.getAttribute('data-rmdel'));};
  await rmLoad(false);
}
async function rmLoad(more){
  var c=S.rm&&S.rm.ch;if(!c)return;
  try{
    var before=more&&S.rm.msgs.length?S.rm.msgs[S.rm.msgs.length-1].id:'';
    var j=await api('/api/rooms/'+c.id+'/messages'+(before?'?before='+before:''));
    if(!S.rm.ch||S.rm.ch.id!==c.id)return;
    S.rm.msgs=(more?S.rm.msgs:[]).concat(j.messages);S.rm.more=j.more;rmDrawMsgs();
  }catch(e){var b=$('rmmsgs');if(b)b.innerHTML='<div class="card muted">'+esc(e.message)+'</div>';}
}
function rmDrawMsgs(){
  var b=$('rmmsgs');if(!b)return;
  if(!S.rm.msgs.length){b.innerHTML='<div class="card center muted">الروم فاضي</div>';$('rmmore').innerHTML='';return;}
  b.innerHTML=S.rm.msgs.map(function(m){
    var att=(m.attachments||[]).map(function(a){return a.img?'<a href="'+esc(a.url)+'" target="_blank" rel="noopener"><img src="'+esc(a.url)+'" style="max-width:100%;max-height:180px;border-radius:8px;margin-top:6px;display:block"></a>':'<div class="log-meta">📎 <a href="'+esc(a.url)+'" target="_blank" rel="noopener" style="color:#60a5fa">'+esc(a.name)+'</a></div>';}).join('');
    var emb=(m.embeds||[]).map(function(t){return '<div class="log-meta">🧩 '+esc(t)+'</div>';}).join('');
    return '<div class="card" style="margin:8px 0;padding:10px"><div class="row" style="justify-content:space-between;align-items:flex-start;gap:8px"><div style="display:flex;gap:8px;align-items:center;min-width:0"><img src="'+esc(m.avatar)+'" style="width:34px;height:34px;border-radius:50%" alt=""><div style="min-width:0"><b>'+esc(m.name)+'</b>'+(m.bot?' <span class="badge medium">BOT</span>':'')+'<div class="log-meta">'+esc(fmt(m.at))+(m.edited?' · معدّلة':'')+(m.pinned?' · 📌':'')+'</div></div></div><button class="btn sm danger" data-rmdel="'+esc(m.id)+'">🗑️</button></div>'
      +(m.content?'<div style="white-space:pre-wrap;word-break:break-word;margin-top:6px;line-height:1.8">'+esc(m.content)+'</div>':'')+att+emb+(m.stickers?'<div class="log-meta">🏷️ ملصق</div>':'')+'</div>';
  }).join('');
  $('rmmore').innerHTML=S.rm.more?'<button class="btn" id="rmMoreB">⬇️ تحميل أقدم</button>':'<div class="muted" style="font-size:12px">— هذي أقدم رسالة —</div>';
  if($('rmMoreB'))$('rmMoreB').onclick=function(){this.disabled=true;rmLoad(true);};
}
async function rmDel(mid){
  if(!(await ask('تحذف هذي الرسالة؟')))return;
  try{await api('/api/rooms/'+S.rm.ch.id+'/messages/'+mid,{method:'DELETE'});S.rm.msgs=S.rm.msgs.filter(function(m){return m.id!==mid;});rmDrawMsgs();toast('تم حذف الرسالة');}
  catch(e){toast(e.message);}
}
async function rmPurge(id,name){
  if(!(await ask('⚠️ راح تنحذف كل الرسائل في «'+name+'» وبعدها يكتب البوت «تم حذف وإعادة هيكلة هذا الروم».\n\nما يمكن التراجع. تكمل؟')))return;
  try{var j=await api('/api/rooms/'+id+'/purge',{method:'POST'});rmProgress(j.job,name);}
  catch(e){toast(e.message);}
}
function rmProgress(job,name){
  modal('<h3>🗑️ جاري حذف رسائل «'+esc(name)+'»</h3><div id="rmPg" class="center" style="padding:14px;line-height:2">...</div><div class="row" style="justify-content:flex-start;gap:8px"><button class="btn danger" id="rmStop">⏹️ إيقاف</button><button class="btn gray" id="rmClose">إخفاء</button></div>');
  var tm=null;
  var tick=async function(){
    var pg=$('rmPg');if(!pg){clearInterval(tm);return;}
    try{
      var j=await api('/api/rooms/purge/'+job);
      pg=$('rmPg');if(!pg){clearInterval(tm);return;}
      pg.innerHTML='تم حذف <b>'+j.deleted+'</b> رسالة'+(j.failed?' — تعذّر '+j.failed:'')
        +(j.done?(j.error?'<div style="color:#f87171">⚠️ '+esc(j.error)+'</div>':(j.stopped?'<div>⏹️ تم الإيقاف</div>':'<div style="color:#4ade80">✅ تم الحذف وكتب البوت رسالة إعادة الهيكلة</div>')):'');
      if(j.done){clearInterval(tm);if($('rmStop'))$('rmStop').style.display='none';if(S.page==='rooms'&&S.rm.ch)rmLoad(false);}
    }catch(e){clearInterval(tm);if($('rmPg'))$('rmPg').innerHTML='<span style="color:#f87171">'+esc(e.message)+'</span>';}
  };
  tm=setInterval(tick,1500);tick();
  $('rmStop').onclick=async function(){this.disabled=true;try{await api('/api/rooms/purge/'+job+'/stop',{method:'POST'});}catch(e){}};
  $('rmClose').onclick=function(){clearInterval(tm);closeModal();};
}

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
  S.cu=true;S.unres=false;S.q='';S.cat='';S.tf=null;
  if(S.page!=='logs'){go('logs');return;}
  var c=$('f-cu');if(c)c.checked=true;var u=$('f-un');if(u)u.checked=false;var fq=$('f-q');if(fq)fq.value='';var fc=$('f-cat');if(fc)fc.value='';
  renderTf();loadEvents();
}
function pgLogs(){
  var opts=CATS.map(function(c){return '<option value="'+c[0]+'"'+(S.cat===c[0]?' selected':'')+'>'+c[1]+'</option>';}).join('');
  $('main').innerHTML='<h2>📜 اللوق الشامل</h2><div class="card"><div class="filters">'
   +'<input id="f-q" placeholder="🔎 شخص (اسم/آيدي) أو وقت وتاريخ" value="'+esc(S.q)+'">'
   +'<select id="f-cat">'+opts+'</select>'
   +'<label class="chk"><input type="checkbox" id="f-un"'+(S.unres?' checked':'')+'> غير المحلولة فقط</label>'
   +'<label class="chk"><input type="checkbox" id="f-cu"'+(S.cu?' checked':'')+'> 🔄 المسترجعة فقط</label>'
   +(S.level==='full'?'<button class="btn sm gray" onclick="openBackfill()">🔄 استرجاع الفائت</button>':'')+'</div><div style="margin-top:10px"><button class="btn sm gray" onclick="openTf()">🕒 فلتر الوقت</button></div></div><div class="tfbar" id="tfbar"></div>'
   +'<div id="evlist"><div class="card center muted">جاري التحميل...</div></div><div class="center"><button class="btn gray" id="more" style="display:none" onclick="moreEvents()">تحميل المزيد</button></div>';
  renderTf();
  var t;$('f-q').oninput=function(){S.q=this.value;clearTimeout(t);t=setTimeout(loadEvents,350);};
  $('f-cat').onchange=function(){S.cat=this.value;loadEvents();};
  $('f-un').onchange=function(){S.unres=this.checked;loadEvents();};
  $('f-cu').onchange=function(){S.cu=this.checked;loadEvents();};
  $('evlist').onclick=function(ev){
    if(ev.target.closest('button,a,img,input,select,.log-act'))return;
    if(window.getSelection&&String(window.getSelection()))return;
    if(S.swiped&&Date.now()-S.swiped<500)return;
    var it=ev.target.closest('.log-item');if(it&&it.getAttribute('data-id'))openEv(it.getAttribute('data-id'));
  };
  swipeInit($('evlist'));
  loadEvents();
  S.timer=setInterval(function(){loadEvents(true);},6000);
}
// ── فلتر الوقت (بتوقيت الرياض) ──
var RY=10800000,DAYMS=86400000,TFQ=[['h1','⏱️ آخر ساعة'],['h6','⏱️ آخر 6 ساعات'],['today','📅 اليوم'],['yest','📅 أمس'],['d3','📅 آخر 3 أيام'],['week','📅 هذا الأسبوع']],tfMode='r',tfPR=15;
function pad2(n){return (n<10?'0':'')+n;}
function ryStart(ms){return Math.floor((ms+RY)/DAYMS)*DAYMS-RY;}
function ryDate(ms){return new Date(ms+RY).toISOString().slice(0,10);}
function ryMs(d,h,m){return new Date(d+'T'+pad2(h)+':'+pad2(m)+':00+03:00').getTime();}
function tl(ms){try{return new Date(ms).toLocaleTimeString('ar-SA-u-nu-latn',{timeZone:'Asia/Riyadh',hour12:true,hour:'numeric',minute:'2-digit'});}catch(e){return new Date(ms).toLocaleTimeString();}}
function dayWord(d){
  if(d===ryDate(Date.now()))return 'اليوم';
  if(d===ryDate(Date.now()-DAYMS))return 'أمس';
  try{return new Date(d+'T12:00:00+03:00').toLocaleDateString('ar-SA-u-ca-gregory-nu-latn',{timeZone:'Asia/Riyadh',day:'numeric',month:'long'});}catch(e){return d;}
}
function tfRange(){
  var t=S.tf;if(!t)return null;
  var n=Date.now(),s=ryStart(n);
  if(t.k==='h1')return {from:n-3600000};
  if(t.k==='h6')return {from:n-21600000};
  if(t.k==='today')return {from:s};
  if(t.k==='yest')return {from:s-DAYMS,to:s};
  if(t.k==='d3')return {from:s-2*DAYMS};
  if(t.k==='week')return {from:s-new Date(n+RY).getUTCDay()*DAYMS};
  return {from:t.from,to:t.to};
}
function renderTf(){
  var b=$('tfbar');if(!b)return;
  b.innerHTML=S.tf?'<div class="tfpill"><span>'+esc(S.tf.label)+'</span><button onclick="clearTf()" aria-label="إزالة الفلتر">✕</button></div>':'';
}
function clearTf(){S.tf=null;renderTf();loadEvents();}
function setTf(o){S.tf=o;closeModal();renderTf();loadEvents();}
function hrOpts(none,sel){
  var h='';if(none)h+='<option value="">بدون</option>';
  for(var i=0;i<24;i++)h+='<option value="'+i+'"'+(sel===i?' selected':'')+'>'+((i%12)||12)+(i<12?' ص':' م')+'</option>';
  return h;
}
function minIn(id,v){return '<input type="number" id="'+id+'" min="0" max="59" step="1" inputmode="numeric" placeholder="دقيقة" value="'+v+'" onfocus="this.select()">';}
function mv(id){var n=parseInt($(id).value,10);return isNaN(n)?0:Math.max(0,Math.min(59,n));}
function openTf(){
  var now=Date.now(),td=ryDate(now),rh=new Date(now+RY).getUTCHours(),rm=new Date(now+RY).getUTCMinutes();
  tfMode='r';tfPR=15;
  var chips=TFQ.map(function(c,i){return '<button class="btn sm gray" onclick="tfQuick('+i+')">'+c[1]+'</button>';}).join('');
  modal('<h3>🕒 فلتر الوقت</h3><div class="muted" style="font-size:12px;text-align:center">بتوقيت السعودية</div>'
   +'<div class="tfchips">'+chips+'</div>'
   +'<div class="tftabs"><button class="btn sm" id="tft-r" onclick="tfTab(\'r\')">📆 من – إلى</button><button class="btn sm gray" id="tft-p" onclick="tfTab(\'p\')">🎯 ساعة محددة</button></div>'
   +'<div id="tf-r" class="tfgrid">'
     +'<div class="tfl">من يوم</div><input type="date" id="tf-d1" value="'+td+'" style="grid-column:1 / -1">'
     +'<div class="tfl">من الساعة</div><select id="tf-h1h">'+hrOpts(true,null)+'</select>'+minIn('tf-h1m',0)+''
     +'<div class="tfl">إلى يوم</div><input type="date" id="tf-d2" value="'+td+'" style="grid-column:1 / -1">'
     +'<div class="tfl">إلى الساعة</div><select id="tf-h2h">'+hrOpts(true,null)+'</select>'+minIn('tf-h2m',59)+''
   +'</div>'
   +'<div id="tf-p" class="tfgrid" style="display:none">'
     +'<div class="tfl">اليوم</div><input type="date" id="tf-pd" value="'+td+'" style="grid-column:1 / -1">'
     +'<div class="tfl">الساعة</div><select id="tf-ph">'+hrOpts(false,rh)+'</select>'+minIn('tf-pm',rm)+''
     +'<div class="tfl">المدى حولها</div><div class="tfpr" style="grid-column:1 / -1" id="tf-pr">'
       +[[5,'± 5 دقائق'],[15,'± 15 دقيقة'],[30,'± 30 دقيقة'],[60,'± ساعة']].map(function(x){return '<button class="btn sm '+(x[0]===15?'':'gray')+'" data-m="'+x[0]+'" onclick="tfPick(this)">'+x[1]+'</button>';}).join('')
     +'</div>'
   +'</div>'
   +'<div class="row" style="justify-content:flex-start;margin-top:16px"><button class="btn" onclick="tfApply()">تطبيق</button><button class="btn gray" onclick="closeModal()">إلغاء</button></div>');
}
function tfQuick(i){var c=TFQ[i];setTf({k:c[0],label:c[1]});}
function tfTab(m){
  tfMode=m;
  $('tf-r').style.display=m==='r'?'grid':'none';$('tf-p').style.display=m==='p'?'grid':'none';
  $('tft-r').className='btn sm'+(m==='r'?'':' gray');$('tft-p').className='btn sm'+(m==='p'?'':' gray');
}
function tfPick(b){
  tfPR=+b.getAttribute('data-m');
  [].slice.call($('tf-pr').querySelectorAll('button')).forEach(function(x){x.className='btn sm'+(x===b?'':' gray');});
}
function tfApply(){
  if(tfMode==='p'){
    var d=$('tf-pd').value;if(!d){toast('اختر اليوم');return;}
    var t=ryMs(d,+$('tf-ph').value,mv('tf-pm')),r=tfPR*60000;
    var f=t-r,e=t+r;
    var lb=ryDate(f)===ryDate(e)?'📅 '+dayWord(ryDate(f))+' • '+tl(f)+' – '+tl(e):'📅 '+dayWord(ryDate(f))+' '+tl(f)+' إلى '+dayWord(ryDate(e))+' '+tl(e);
    setTf({k:'custom',from:f,to:e+60000,label:lb});return;
  }
  var d1=$('tf-d1').value,d2=$('tf-d2').value;if(!d1||!d2){toast('اختر التاريخ');return;}
  var h1=$('tf-h1h').value,h2=$('tf-h2h').value;
  var from=h1===''?ryMs(d1,0,0):ryMs(d1,+h1,mv('tf-h1m'));
  var to=h2===''?ryMs(d2,0,0)+DAYMS:ryMs(d2,+h2,mv('tf-h2m'))+60000;
  if(to<=from){toast('النهاية لازم تكون بعد البداية');return;}
  var lb;
  if(h1===''&&h2==='')lb=d1===d2?'📅 '+dayWord(d1):'📅 من '+dayWord(d1)+' إلى '+dayWord(d2);
  else{
    var a=h1===''?'12:00 ص':tl(from),b=h2===''?'11:59 م':tl(to-60000);
    lb=d1===d2?'📅 '+dayWord(d1)+' • '+a+' – '+b:'📅 '+dayWord(d1)+' '+a+' إلى '+dayWord(d2)+' '+b;
  }
  setTf({k:'custom',from:from,to:to,label:lb});
}
function qs(before){var r=tfRange()||{};return '/api/events?q='+encodeURIComponent(S.q)+'&cat='+encodeURIComponent(S.cat)+'&unres='+(S.unres?1:0)+'&cu='+(S.cu?1:0)+(r.from?'&from='+r.from:'')+(r.to?'&to='+r.to:'')+(before?'&before='+before:'');}
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
  if(e.data&&e.data.recRoom&&S.level==='full')acts+=e.data.sid?'<button class="btn sm" onclick="vrOpen(\''+e.data.sid+'\')">🎬 تسجيل توضيحي + صوت وصورة</button>':'<span class="badge low">بدون تسجيل</span>';
  if(sus&&S.level==='full'){
    if(e.remedy)acts+='<button class="btn sm danger" onclick="doRemedy(\''+e._id+'\',this)">'+esc(e.remedy.label)+'</button>';
    if(!e.resolved)acts+='<button class="btn sm ok" onclick="doResolve(\''+e._id+'\',this)">✅ حل العملية</button>';
  }else if(sus&&!e.resolved)acts+='<button class="btn sm" onclick="notifyLead(\''+e._id+'\',this)">🔔 إشعار القيادة</button>';
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
/* ── سحب العملية لليمين = حذف نهائي (لقائد الأمن السيبراني فقط) ── */
function swipeInit(box){
  var st=null;
  function reset(it){it.style.transition='transform .18s,opacity .18s';it.style.transform='';it.style.opacity='';it.style.userSelect='';}
  box.addEventListener('pointerdown',function(ev){
    if(!S.logDel||ev.button>0)return;
    if(ev.target.closest('input,select,textarea,a'))return;
    var it=ev.target.closest('.log-item[data-id]');if(!it)return;
    st={it:it,x:ev.clientX,y:ev.clientY,dx:0,on:false,id:ev.pointerId};
  });
  box.addEventListener('pointermove',function(ev){
    if(!st||ev.pointerId!==st.id)return;
    var dx=ev.clientX-st.x,dy=ev.clientY-st.y;
    if(!st.on){
      if(Math.abs(dy)>14&&Math.abs(dy)>Math.abs(dx)){st=null;return;}
      if(dx>14&&dx>Math.abs(dy)*1.5){st.on=true;st.it.style.transition='none';st.it.style.userSelect='none';try{box.setPointerCapture(ev.pointerId);}catch(e){}}
      else return;
    }
    st.dx=Math.max(0,dx);
    st.it.style.transform='translateX('+st.dx+'px)';
    st.it.style.opacity=String(Math.max(0.25,1-st.dx/320));
  });
  function finish(ev,cancel){
    if(!st||ev.pointerId!==st.id)return;
    var s=st;st=null;
    if(!s.on)return;
    S.swiped=Date.now();
    try{box.releasePointerCapture(ev.pointerId);}catch(e){}
    if(!cancel&&s.dx>=110)swipeDelete(s.it);else reset(s.it);
  }
  box.addEventListener('pointerup',function(ev){finish(ev,false);});
  box.addEventListener('pointercancel',function(ev){finish(ev,true);});
}
async function swipeDelete(it){
  var id=it.getAttribute('data-id');
  it.style.transition='transform .2s,opacity .2s';it.style.transform='translateX(110%)';it.style.opacity='0';
  try{
    await api('/api/events/'+id,{method:'DELETE'});
    S.events=(S.events||[]).filter(function(x){return x._id!==id;});
    setTimeout(function(){if(it.parentNode)it.parentNode.removeChild(it);},200);
  }catch(e){
    it.style.transform='';it.style.opacity='';toast(e.message);
  }
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
  var recb=(e.recRoom&&S.level==='full')?(e.recSid?'<div style="margin-top:8px"><button class="btn" onclick="vrOpen(\''+e.recSid+'\')">🎬 تسجيل توضيحي + صوت وصورة</button></div>':'<div class="log-meta">⚠️ ما فيه تسجيل لهذي العملية</div>'):'';
  var ab='';
  if(sus){
    if(S.level==='full'){
      var bs='';
      if(e.remedyLabel)bs+='<button class="btn sm danger" onclick="evRemedy(\''+e._id+'\',this)">'+esc(e.remedyLabel)+'</button>';
      if(!e.resolved)bs+='<button class="btn sm ok" onclick="evResolve(\''+e._id+'\',this)">✅ حل العملية</button>';
      if(bs)ab='<div class="row" style="justify-content:flex-start;gap:8px;margin-top:12px;flex-wrap:wrap">'+bs+'</div>';
    }else if(!e.resolved)ab='<div class="row" style="justify-content:flex-start;margin-top:12px"><button class="btn sm" onclick="notifyLead(\''+e._id+'\',this)">🔔 إشعار القيادة</button></div>';
  }
  box.innerHTML='<h3>📋 تفاصيل العملية</h3>'+head+actor+target+when+det+imgs+msgs+recb+ab;
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

/* ══ باندات الأعضاء ══ */
function bnSince(t){var s=Math.floor((Date.now()-t)/1000);if(s<60)return 'أقل من دقيقة';var m=Math.floor(s/60);if(m<60)return m+' دقيقة';var h=Math.floor(m/60);if(h<48)return h+' ساعة';var d=Math.floor(h/24);if(d<60)return d+' يوم';var mo=Math.floor(d/30);if(mo<24)return mo+' شهر';return Math.floor(d/365)+' سنة';}
function bnDurAr(ms){var m=Math.round(ms/60000);if(m<60)return m+' دقيقة';var h=Math.round(m/60);if(h<48)return h+' ساعة';var d=Math.round(h/24);if(d<60)return d+' يوم';return Math.round(d/30)+' شهر';}
function bnDur(x){
  if(x.durMs){
    var end=x.bannedAt?x.bannedAt+x.durMs:null;
    return 'مؤقت: '+bnDurAr(x.durMs)+(end&&end<Date.now()?' (انتهت المدة وهو لسا محظور)':'');
  }
  return 'دائم';
}
function bnWho(x){
  if(x.probot)return '🤖 ProBot'+(x.invTag?' ← '+x.invTag:'');
  if(x.execTag)return '👤 '+x.execTag;
  return '❔ غير معروف';
}
function bnWhoBox(tag,av){return '<span class="bn-who">'+(av?'<img src="'+esc(av)+'" alt="">':'')+esc(tag)+'</span>';}
async function pgBans(force){
  if(!S.bn)S.bn={list:[],q:'',f:'all',at:0};
  $('main').innerHTML='<h2>🔨 باندات الأعضاء</h2><div class="card center muted">جاري التحميل... (أول مرة ممكن ياخذ كم ثانية)</div>';
  try{
    var j=await api('/api/bans'+(force===true?'?refresh=1':''));if(S.page!=='bans')return;
    S.bn.list=j.bans;S.bn.at=j.at;drawBans();
  }catch(e){toast(e.message);}
}
function setBnFilter(f){S.bn.f=f;drawBans();}
function drawBans(){
  var b=S.bn,c={all:b.list.length,pb:0,direct:0,old:0};
  b.list.forEach(function(x){if(x.probot)c.pb++;else if(x.execTag)c.direct++;if(x.src==='old')c.old++;});
  var tabs=[['all','📋 الكل',c.all],['pb','🤖 عبر ProBot',c.pb],['direct','👤 مباشر',c.direct],['old','📜 قديم بدون تفاصيل',c.old]].map(function(t){
    return '<button class="tab '+(b.f===t[0]?'active':'')+'" onclick="setBnFilter(\''+t[0]+'\')">'+t[1]+' ('+t[2]+')</button>';}).join('');
  $('main').innerHTML='<div class="row"><h2>🔨 باندات الأعضاء ('+c.all+')</h2><button class="btn sm gray" onclick="pgBans(true)">🔄 تحديث</button></div>'
   +'<div class="muted" style="font-size:12px;margin:-4px 0 10px">👆 اضغط على أي بطاقة لعرض التفاصيل كاملة (من حظره، السبب، التاريخ) • آخر تحديث: '+fmt(b.at)+'</div>'
   +'<div class="card" style="padding:12px"><input id="bn-q" placeholder="🔍 ابحث بالاسم أو الآيدي أو السبب أو اسم اللي حظره" value="'+esc(b.q)+'" oninput="S.bn.q=this.value;bnList()"></div>'
   +'<div class="tabs">'+tabs+'</div><div id="bn-list"></div>';
  bnList();
}
function bnList(){
  var b=S.bn,q=(b.q||'').trim().toLowerCase();
  var arr=b.list.filter(function(x){
    if(b.f==='pb'&&!x.probot)return false;
    if(b.f==='direct'&&!(x.execTag&&!x.probot))return false;
    if(b.f==='old'&&x.src!=='old')return false;
    if(!q)return true;
    return [x.tag,x.name,x.id,x.reason,x.execTag,x.invTag].join(' ').toLowerCase().indexOf(q)>=0;
  });
  var shown=arr.slice(0,150);
  $('bn-list').innerHTML=(shown.length?'<div class="bn-grid">'+shown.map(bnCard).join('')+'</div>':'<div class="card center muted">'+(b.list.length?'ما فيه نتائج':'ما فيه أحد محظور 🎉')+'</div>')
   +(arr.length>shown.length?'<div class="card center muted" style="margin-top:12px">عرض أول 150 من '+arr.length+' — استخدم البحث لتضييق النتائج</div>':'');
}
function bnCard(x){
  return '<div class="card bn-card" onclick="bnOpen(\''+x.id+'\')"><img src="'+esc(x.avatar)+'" alt="" loading="lazy">'
   +'<div style="flex:1;min-width:0"><div class="log-title">'+esc(x.tag)+(x.name&&x.name!==x.tag?' <span class="muted" style="font-size:12px;font-weight:400">'+esc(x.name)+'</span>':'')+'</div>'
   +'<div class="bn-rs">'+(x.reason?esc(x.reason):'<span class="muted">بدون سبب</span>')+'</div>'
   +'<div><span class="chip '+(x.probot?'high':'safe')+'">'+esc(bnWho(x))+'</span><span class="chip safe">⏳ '+esc(bnDur(x))+'</span>'
   +(x.bannedAt?'<span class="chip safe">🕒 '+ago(x.bannedAt)+'</span>':'<span class="chip safe">🕒 تاريخ غير معروف</span>')+'</div></div></div>';
}
function bnOpen(id){
  var x=S.bn.list.filter(function(y){return y.id===id;})[0];if(!x)return;
  var row=function(k,v){return '<div class="bn-row"><span>'+k+'</span><b>'+v+'</b></div>';};
  var who;
  if(x.probot){
    who=bnWhoBox('ProBot',null);
  }else if(x.execTag){who=bnWhoBox(x.execTag,x.execAvatar);}
  else who='<span class="muted">غير متوفر</span>';
  var h='<div style="max-height:72vh;overflow-y:auto"><h3>🔨 تفاصيل الباند</h3>'
   +'<div class="bn-hero"><img src="'+esc(x.avatar)+'" alt=""><div style="min-width:0"><div class="log-title" style="margin:0">'+esc(x.tag)+'</div>'
   +(x.name&&x.name!==x.tag?'<div class="muted" style="font-size:12px">'+esc(x.name)+'</div>':'')
   +'<div class="log-meta" style="margin-top:4px">🆔 '+esc(x.id)+cpb(x.id,'تم نسخ الآيدي','نسخ')+'</div></div></div>'
   +'<div class="muted" style="font-size:12px">📝 سبب الباند</div><div class="bn-reason">'+(x.reason?esc(x.reason):'<span class="muted">بدون سبب</span>')+'</div>'
   +row('🔨 اللي نفّذ الباند',who);
  if(x.probot){
    h+=row('👤 اللي كتب الأمر',x.invTag?bnWhoBox(x.invTag,x.invAvatar)+(x.invHow?' <span class="muted" style="font-size:11px;font-weight:400">('+esc(x.invHow)+')</span>':''):'<span class="muted">غير معروف</span>');
    if(!x.invTag)h+='<div class="log-meta" style="margin:6px 0">ℹ️ ديسكورد ما يسجّل مين كتب أمر ProBot، والبوت يعرفه من رسالة الأمر أو رد ProBot لحظة التنفيذ. الباندات القديمة قبل تشغيل هالميزة ما ينعرف منفّذها.</div>';
  }
  h+=row('📅 تاريخ الباند',x.bannedAt?fmt(x.bannedAt):'<span class="muted">غير معروف (باند قديم)</span>')
   +row('⏱️ نوع المدة',esc(bnDur(x)))
   +row('⌛ صار له',x.bannedAt?esc(bnSince(x.bannedAt)):'<span class="muted">غير معروف</span>')
   +row('🗓️ عمر الحساب',x.acctAt?fmt(x.acctAt)+' <span class="muted" style="font-size:11px;font-weight:400">('+esc(bnSince(x.acctAt))+')</span>':'-')
   +row('📚 المصدر',x.src==='live'?'سُجّل مباشرة وقت الباند':x.src==='audit'?'من سجل التدقيق':'باند قديم — ما له تفاصيل')
   +'<div style="margin-top:14px"><div class="muted" style="font-size:12px;margin-bottom:6px">📜 سجل هذا العضو (حظر / فك حظر)</div><div id="bn-hist" class="muted" style="font-size:13px">جاري التحميل...</div></div></div>'
   +'<div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>';
  modal(h);
  api('/api/bans/'+id+'/history').then(function(j){
    var el=$('bn-hist');if(!el)return;
    el.innerHTML=j.events.length?j.events.map(function(e){
      return '<div class="mlist" style="align-items:flex-start;flex-direction:column;gap:2px"><div><b>'+(e.act==='unban'?'✅ ':'🔨 ')+esc(e.title)+'</b> <span class="muted" style="font-size:11px">'+fmt(e.at)+'</span></div>'
       +(e.actorTag?'<div class="log-meta" style="margin:0">بواسطة: '+esc(e.actorTag)+'</div>':'')
       +(e.details?'<div class="log-meta" style="margin:0;white-space:pre-wrap">'+esc(e.details)+'</div>':'')+'</div>';
    }).join(''):'ما فيه عمليات محفوظة (اللوق يحتفظ بآخر 60 يوم)';
  }).catch(function(){var el=$('bn-hist');if(el)el.textContent='تعذّر تحميل السجل';});
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
    var j=await api('/api/perms/members');S.mem2=j.members;S.memTotal=j.total;S.memOk=j.presenceOk;
    var rj=await api('/api/perms/roles');S.roles=rj.roles;
  }
  var q=(S.permsQ||'').trim().toLowerCase(),SHOW=100;
  var f=q?S.mem2.filter(function(m){return [m.username,m.global,m.nick,m.server,m.tag,m.id].some(function(v){return (v||'').toLowerCase().indexOf(q)>-1;});}):S.mem2;
  var info='<div class="muted" style="font-size:12px;margin-bottom:8px">'+(q?('النتائج: '+f.length+' من '+S.mem2.length):('👤 '+S.memTotal+' عضو'+(f.length>SHOW?' — معروض أول '+SHOW+'، استخدم البحث للباقي':'')+' — 👆 اضغط على بطاقة العضو لعرض نشاطه'))+'</div>';
  var html=info+f.slice(0,SHOW).map(function(m){
    var set={};m.roles.forEach(function(x){set[x]=1;});
    var chips=S.roles.filter(function(r){return set[r.id];}).map(function(r){
      return '<span class="chip '+(r.dang.length?'high':'safe')+'"><i class="dot" style="background:'+(r.color&&r.color!=='#000000'?r.color:'#64748b')+'"></i>'+esc(r.name)+'</span>';
    }).join('')||'<span class="muted" style="font-size:12px">بدون رتب</span>';
    var canEdit=S.level==='full'&&m.editable;
    S.memMap=S.memMap||{};S.memMap[m.id]={tag:m.tag,avatar:m.avatar,name:m.server};
    var stx=(S.memOk&&m.status)?' &nbsp;•&nbsp; '+(ST_AR[m.status]||ST_AR.unknown):'';
    return '<div class="card" data-mid="'+esc(m.id)+'" style="cursor:pointer"><div class="bot"><img src="'+esc(m.avatar)+'" alt=""><div style="flex:1;min-width:200px">'
     +'<div class="log-title"><b>'+esc(m.server)+'</b>'+(m.bot?' <span class="badge low">بوت</span>':'')+'</div>'
     +'<div class="log-meta">🏷️ اسمه في السيرفر: '+esc(m.server)+' &nbsp;•&nbsp; 👤 البروفايل: '+esc(m.global)+' &nbsp;•&nbsp; 🔖 @'+esc(m.username)+cpb(m.username,'تم نسخ اليوزر','نسخ اليوزر')+stx+'</div>'
     +'<div style="margin-top:8px">'+chips+'</div></div>'
     +'<button class="btn sm '+(canEdit?'':'gray')+'" onclick="editMember(\''+m.id+'\')">'+(canEdit?'✏️ عرض وتعديل':'👁️ عرض فقط')+'</button></div></div>';
  }).join('')||'<div class="card center muted">'+(q?'ما لقيت أحد بهذا الاسم':'ما فيه أعضاء')+'</div>';
  if($('pbox')){
    $('pbox').innerHTML=html;
    $('pbox').onclick=function(ev){
      if(ev.target.closest('button,a'))return;
      if(window.getSelection&&String(window.getSelection()))return;
      var c=ev.target.closest('[data-mid]');if(c)openAct(c.getAttribute('data-mid'));
    };
  }
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

/* ══ إشعارات القيادة ══ */
async function notifyLead(id,b){
  if(b)b.disabled=true;
  try{await api('/api/notices/op',{method:'POST',body:JSON.stringify({eventId:id})});toast('🔔 تم إرسال الإشعار لقائد الأمن السيبراني ونائبه');}
  catch(e){toast(e.message);if(b)b.disabled=false;}
}
async function evResolve(id,b){
  b.disabled=true;
  try{await api('/api/events/'+id+'/resolve',{method:'POST'});toast('تم حل العملية');loadEvents(true);openEv(id);}catch(e){toast(e.message);b.disabled=false;}
}
async function evRemedy(id,b){
  var lb=(S.evj&&S.evj.remedyLabel)||'',tt=(S.evj&&S.evj.title)||'';
  if(!(await ask('تنفيذ الإجراء: '+lb+'\n\n'+tt))){openEv(id);return;}
  try{var j=await api('/api/events/'+id+'/remedy',{method:'POST'});toast(j.msg||'تم');loadEvents(true);}catch(e){toast(e.message);}
  openEv(id);
}
S.nq=[];S.nShown=null;
function noticeSeen(n){api('/api/notices/'+n.id+'/seen',{method:'POST'}).catch(function(){});}
function noticeEnqueue(n){
  if(!n||!n.id||(n.type!=='allow'&&n.type!=='lead'&&n.type!=='task'&&S.level!=='full'))return;
  if(S.nq.some(function(x){return x.id===n.id;})||(S.nShown&&S.nShown.id===n.id))return;
  S.nq.push(n);
  if(!S.nShown)noticeNext();
}
function noticeNext(){
  var old=$('nov');if(old)old.remove();
  var n=S.nq.shift();
  if(!n){S.nShown=null;if(!$('ov'))unlockScroll();return;}
  S.nShown=n;
  var ty=n.type,isOp=ty==='op',isAllow=ty==='allow',isTask=ty==='task';
  var from='<div class="nfrom">'+(n.senderAvatar?'<img src="'+esc(n.senderAvatar)+'" alt="">':'')+'<div><b>'+esc(n.senderTag)+'</b><div class="log-meta">🕒 '+esc(ago(n.createdAt))+'</div></div></div>';
  var title,body,btns,cls='';
  if(isOp){
    title='🚨 إشعار عاجل من الأمن السيبراني';
    body='<p style="line-height:1.9">وصلك إشعار من العضو <b>'+esc(n.senderTag)+'</b> بخصوص عملية مشبوهة تحتاج مراجعتك.</p>'
      +'<div class="nq"><b>📌 '+esc(n.eventTitle||'عملية مشبوهة')+'</b>'+(n.subjectTag?'<div class="log-meta" style="margin-top:6px">🎯 العضو: <b>'+esc(n.subjectTag)+'</b></div>':'')+(n.eventDetails?'<div class="log-meta" style="margin-top:4px">'+esc(n.eventDetails)+'</div>':'')+'</div>';
    btns='<button class="btn" id="nv-view">👁️ شوفها</button>'+(n.canAllow?'<button class="btn ok" id="nv-allow">✅ السماح للعضو بالتعامل معه</button>':'')+'<button class="btn gray" id="nv-close">إغلاق</button>';
  }else if(isAllow){
    cls=' warn';title='⚠️ ضع العضو في روم الأعضاء المشتبه بهم في الديسكورد';
    body='<p style="line-height:1.9">سمح لك <b>'+esc(n.senderTag)+'</b> بالتعامل مع هذي الحالة.</p>'
      +'<div class="nq">🎯 العضو: <b>'+esc(n.subjectTag||'—')+'</b>'+(n.subjectId?'<div class="log-meta" dir="ltr" style="margin-top:4px">'+esc(n.subjectId)+'</div>':'')+'<div class="log-meta" style="margin-top:6px">📌 '+esc(n.eventTitle||'')+'</div></div>';
    btns='<button class="btn" id="nv-view">👁️ شوفها</button><button class="btn gray" id="nv-ok">✔️ تم</button>';
  }else if(ty==='lead'){
    title='📣 إشعار من القيادة';
    body='<p style="line-height:1.9">وصلك إشعار من <b>'+esc(n.senderTag)+'</b>:</p><div class="nq">'+esc(n.reason)+'</div>';
    btns='<button class="btn" id="nv-ok">✔️ تم الاطلاع</button>';
  }else if(isTask){
    var t=n.task;cls=' warn';title='📋 مهمة جديدة من القيادة';
    body='<p style="line-height:1.9">كلّفك <b>'+esc(t.assignerTag)+'</b> بمهمة:</p><div class="nq">'+esc(t.text)+'</div>'
      +'<div class="log-meta">⏳ المدة: <b>'+esc(minLabel(t.minutes))+'</b> — يبدأ العداد من لحظة ما تضغط «استلمت المهمة»</div>';
    btns='<button class="btn ok" id="nv-ack">✅ استلمت المهمة</button>';
  }else if(ty==='taskdone'||ty==='taskdue'){
    var dn=ty==='taskdone';cls=dn?' info':' warn';title=dn?'✅ تم إنجاز مهمة':'⏰ انتهى وقت مهمة';
    body='<p style="line-height:1.9">'+(dn?'العضو <b>'+esc(n.subjectTag)+'</b> أنجز المهمة:':'انتهى وقت مهمة العضو <b>'+esc(n.subjectTag)+'</b> ولم يسلّمها بعد:')+'</p><div class="nq">'+esc(n.reason)+(n.eventDetails?'<div class="log-meta" style="margin-top:6px">'+esc(n.eventDetails)+'</div>':'')+'</div>';
    btns='<button class="btn" id="nv-ok">✔️ تم الاطلاع</button><button class="btn gray" id="nv-tasks">📋 المهام</button>';
  }else{
    cls=' info';title='📣 إشعار من مسؤول الأفراد';
    body='<p style="line-height:1.9">رفع لك المسؤول <b>'+esc(n.senderTag)+'</b> إشعاراً بخصوص العضو <b>'+esc(n.subjectTag)+'</b>.</p>'
      +'<div class="nq"><div class="muted" style="font-size:12px;margin-bottom:4px">📝 سبب الإشعار</div>'+esc(n.reason)+'</div>';
    btns='<button class="btn" id="nv-ok">✔️ تم الاطلاع</button><button class="btn gray" id="nv-mem">👥 صفحة الأعضاء</button>';
  }
  var o=document.createElement('div');o.className='nov';o.id='nov';
  o.innerHTML='<div class="nbox'+cls+'"><h3>'+title+'</h3>'+from+body
    +'<div class="row" style="justify-content:flex-start;gap:8px;margin-top:14px;flex-wrap:wrap">'+btns+'</div></div>';
  document.body.appendChild(o);lockScroll();
  var done=function(){if(!isTask)noticeSeen(n);S.nShown=null;var x=$('nov');if(x)x.remove();};
  if($('nv-view'))$('nv-view').onclick=function(){done();openEv(n.eventId);setTimeout(noticeNext,0);};
  if($('nv-close'))$('nv-close').onclick=function(){done();noticeNext();};
  if($('nv-ok'))$('nv-ok').onclick=function(){done();noticeNext();};
  if($('nv-mem'))$('nv-mem').onclick=function(){done();go('members');noticeNext();};
  if($('nv-tasks'))$('nv-tasks').onclick=function(){done();go('members');noticeNext();setTimeout(openTasks,200);};
  if($('nv-allow'))$('nv-allow').onclick=function(){var b=this;b.disabled=true;allowNotice(n.id,function(ok){if(ok){done();noticeNext();}else b.disabled=false;});};
  if($('nv-ack'))$('nv-ack').onclick=async function(){
    var b=this;b.disabled=true;
    try{var j=await api('/api/tasks/'+n.task.id+'/ack',{method:'POST'});S.tOff=(j.now||Date.now())-Date.now();S.tasks=(S.tasks||[]).filter(function(x){return x.id!==j.task.id;});S.tasks.push(j.task);renderTaskBar();done();noticeNext();toast('تم استلام المهمة — بدأ العداد');}
    catch(e){toast(e.message);b.disabled=false;if(/مو متاحة/.test(e.message)){done();noticeNext();}}
  };
}
async function allowNotice(id,cb){
  try{await api('/api/notices/'+id+'/allow',{method:'POST'});toast('✅ تم السماح — وصلت العضو رسالة');if(cb)cb(true);}
  catch(e){toast(e.message);if(cb)cb(false);}
}
async function allowConfirm(a){
  if(a.allowed){toast('تم السماح لهذي الحالة من قبل');return;}
  if(await ask('تسمح للعضو '+a.senderTag+' بالتعامل مع العضو '+a.subjectTag+'؟'))allowNotice(a.id);
}
async function loadNotices(){
  try{var j=await api('/api/notices/pending');(j.notices||[]).forEach(noticeEnqueue);}catch(e){}
}
/* ══ مهام القيادة ══ */
function minLabel(m){m=+m||0;return (m&&m%1440===0)?(m/1440)+' يوم':((m&&m%60===0)?(m/60)+' ساعة':m+' دقيقة');}
function fmtLeft(ms){var neg=ms<0,s=Math.floor(Math.abs(ms)/1000),d=Math.floor(s/86400);s%=86400;var h=Math.floor(s/3600);s%=3600;var m=Math.floor(s/60);s%=60;var p=function(x){return (x<10?'0':'')+x;};return (neg?'+':'')+(d?d+'ي ':'')+((h||d)?p(h)+':':'')+p(m)+':'+p(s);}
function taskPop(t){return {id:'t'+t.id,type:'task',task:t,senderTag:t.assignerTag,senderAvatar:t.assignerAvatar||'',createdAt:t.createdAt};}
function tickTasks(){
  var now=Date.now()+(S.tOff||0);
  document.querySelectorAll('.ttim[data-due]').forEach(function(el){
    var due=+el.getAttribute('data-due'),left=due-now;
    el.textContent=left>=0?'⏳ '+fmtLeft(left):'⚠️ متأخرة '+fmtLeft(left);
    el.style.color=left>=0?(left<60000?'#f87171':'#fbbf24'):'#f87171';
  });
}
function renderTaskBar(){
  var bar=$('tbar'),list=(S.tasks||[]).filter(function(t){return t.status==='active';});
  if(!list.length){if(bar)bar.remove();document.documentElement.style.setProperty('--tbar-h','0px');return;}
  if(!bar){bar=document.createElement('div');bar.id='tbar';document.body.insertBefore(bar,document.body.firstChild);}
  bar.innerHTML=list.map(function(t){
    return '<div class="trow"><div class="ttxt" onclick="this.classList.toggle(\'open\')">📋 '+esc(t.text)+'<span class="log-meta"> — من '+esc(t.assignerTag)+'</span></div>'
      +'<div class="ttim" data-due="'+t.dueAt+'">⏳ --:--</div>'
      +'<button class="btn sm ok" onclick="taskDone(\''+t.id+'\',this)">✅ سوّيت المهمة</button></div>';
  }).join('');
  tickTasks();
  document.documentElement.style.setProperty('--tbar-h',bar.offsetHeight+'px');
}
async function loadTasks(){
  try{
    var j=await api('/api/tasks/mine');S.tOff=(j.now||Date.now())-Date.now();
    S.tasks=(j.tasks||[]).filter(function(t){return t.status==='active';});
    (j.tasks||[]).filter(function(t){return t.status==='pending';}).forEach(function(t){noticeEnqueue(taskPop(t));});
    renderTaskBar();
  }catch(e){}
}
async function taskDone(id,b){
  if(!(await ask('تأكيد إنك خلّصت المهمة؟')))return;
  try{await api('/api/tasks/'+id+'/done',{method:'POST'});toast('✅ تم تسليم المهمة للقيادة');}catch(e){toast(e.message);}
  loadTasks();
}
async function refreshTaskList(){
  var box=$('tk-list');if(!box)return;
  try{
    var j=await api('/api/tasks');S.tOff=(j.now||Date.now())-Date.now();
    if(!$('tk-list'))return;
    var ST={pending:['بانتظار الاستلام','medium'],active:['جارية','low'],done:['✅ منجزة','low'],cancelled:['🚫 ملغاة','high']};
    box.innerHTML=(j.tasks||[]).map(function(t){
      var st=ST[t.status]||['',''],cancelable=t.status==='pending'||t.status==='active';
      return '<div class="card" style="margin:8px 0;padding:12px"><div class="log-title">'+esc(t.targetTag)+' <span class="badge '+st[1]+'">'+st[0]+'</span></div>'
        +'<div class="nq" style="margin:6px 0;padding:8px">'+esc(t.text)+'</div>'
        +'<div class="log-meta">من '+esc(t.assignerTag)+' · '+esc(minLabel(t.minutes))+' · '+esc(ago(t.createdAt))+'</div>'
        +(t.status==='active'?'<div class="ttim" data-due="'+t.dueAt+'" style="margin-top:4px"></div>':'')
        +(t.status==='done'&&t.doneAt?'<div class="log-meta">🏁 أُنجزت: '+esc(fmt(t.doneAt))+'</div>':'')
        +(cancelable?'<div style="margin-top:8px"><button class="btn sm danger" onclick="cancelTask(\''+t.id+'\')">🚫 إلغاء المهمة</button></div>':'')+'</div>';
    }).join('')||'<div class="muted center" style="padding:14px">ما فيه مهام (آخر 3 أيام)</div>';
    tickTasks();
  }catch(e){box.innerHTML='<div class="muted">'+esc(e.message)+'</div>';}
}
function openTasks(){
  modal('<h3>📋 مهام الأعضاء</h3><div id="tk-list" class="muted center" style="padding:14px">جاري التحميل...</div><div class="row" style="justify-content:flex-start;margin-top:10px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  refreshTaskList();
}
async function cancelTask(id){
  if(!(await ask('تلغي هذي المهمة؟')))return openTasks();
  try{await api('/api/tasks/'+id+'/cancel',{method:'POST'});toast('تم إلغاء المهمة');}catch(e){toast(e.message);}
  openTasks();
}
function leadNotify(id){
  var m=(S.memMap||{})[id]||{},kind='notice';
  var lb='display:block;color:#60a5fa;font-size:13px;margin:12px 0 6px';
  var chips=[[5,'5 د'],[10,'10 د'],[30,'30 د'],[60,'ساعة'],[180,'3 ساعات'],[1440,'يوم'],[10080,'أسبوع']];
  modal('<h3>🔔 إرسال للعضو</h3><div class="muted" style="font-size:13px">إلى: <b>'+esc(m.tag||id)+'</b></div>'
    +'<div class="segb"><button class="btn sm" id="ln-k1">📣 إشعار</button><button class="btn sm gray" id="ln-k2">📋 مهمة</button></div>'
    +'<label style="'+lb+'" id="ln-lbl">نص الإشعار</label>'
    +'<textarea id="lnT" rows="5" maxlength="1500" placeholder="اكتب الإشعار اللي تبيه يوصل للعضو..." style="width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(59,130,246,.35);border-radius:10px;color:#e2e8f0;padding:10px;font-family:inherit;font-size:14px;resize:vertical"></textarea>'
    +'<div id="ln-dur" style="display:none"><label style="'+lb+'">مدة المهمة (تبدأ من لحظة استلام العضو لها)</label>'
    +'<div class="chips">'+chips.map(function(c){return '<button class="btn sm gray" data-m="'+c[0]+'">'+c[1]+'</button>';}).join('')+'</div>'
    +'<div class="row" style="justify-content:flex-start;gap:8px;align-items:center"><input type="number" id="lnN" min="1" value="10" style="width:90px;background:rgba(255,255,255,.06);border:1px solid rgba(59,130,246,.35);border-radius:10px;color:#e2e8f0;padding:9px 10px;font:inherit">'
    +'<select id="lnU"><option value="1">دقيقة</option><option value="60">ساعة</option><option value="1440">يوم</option></select></div></div>'
    +'<div class="row" style="justify-content:flex-start;gap:8px;margin-top:14px"><button class="btn" id="lnGo">📤 إرسال</button><button class="btn gray" onclick="closeModal()">إلغاء</button></div>');
  var setK=function(k){kind=k;$('ln-k1').className='btn sm'+(k==='notice'?'':' gray');$('ln-k2').className='btn sm'+(k==='task'?'':' gray');
    $('ln-lbl').textContent=k==='task'?'نص المهمة':'نص الإشعار';$('ln-dur').style.display=k==='task'?'block':'none';
    $('lnT').placeholder=k==='task'?'مثال: اقعد راقب الشات 10 دقايق / عطني تقرير الإحصائيات حق الأسبوع الماضي':'اكتب الإشعار اللي تبيه يوصل للعضو...';};
  $('ln-k1').onclick=function(){setK('notice');};$('ln-k2').onclick=function(){setK('task');};
  document.querySelectorAll('#ov .chips [data-m]').forEach(function(b){b.onclick=function(){
    var v=+b.getAttribute('data-m'),u=(v%1440===0)?1440:((v%60===0)?60:1);
    $('lnU').value=String(u);$('lnN').value=String(v/u);if($('lnU')._sync)$('lnU')._sync();};});
  $('lnGo').onclick=async function(){
    var t=($('lnT').value||'').trim();
    if(t.length<3){toast(kind==='task'?'اكتب نص المهمة':'اكتب نص الإشعار');return;}
    var mins=Math.round((+$('lnN').value||0)*(+$('lnU').value||1));
    if(kind==='task'&&!(mins>=1&&mins<=10080)){toast('مدة المهمة من دقيقة إلى 7 أيام');return;}
    this.disabled=true;
    try{await api('/api/members/'+id+'/notify',{method:'POST',body:JSON.stringify({kind:kind,text:t,minutes:mins,tag:m.tag||''})});closeModal();toast(kind==='task'?'📋 تم إرسال المهمة':'📣 تم إرسال الإشعار');}
    catch(e){toast(e.message);this.disabled=false;}
  };
}

/* ══ قوائم الموقع بدل قوائم الآيفون (اختيار + تاريخ) ══ */
function pickList(title,items,cur,cb){
  var old=$('pov');if(old)old.remove();
  var o=document.createElement('div');o.className='pov';o.id='pov';
  o.innerHTML='<div class="pbox"><h3>'+esc(title||'اختر')+'</h3>'+items.map(function(x,i){return '<button class="pit'+(String(x.v)===String(cur)?' on':'')+'" data-i="'+i+'">'+esc(x.t)+'</button>';}).join('')+'<button class="btn gray" id="pov-x" style="width:100%;margin-top:6px">إلغاء</button></div>';
  o.addEventListener('mousedown',function(e){if(e.target===o)o.remove();});
  document.body.appendChild(o);
  o.querySelectorAll('.pit').forEach(function(b){b.onclick=function(){var x=items[+b.getAttribute('data-i')];o.remove();cb(x);};});
  $('pov-x').onclick=function(){o.remove();};
  var on=o.querySelector('.pit.on');if(on&&on.scrollIntoView)on.scrollIntoView({block:'center'});
}
function pickDate(cur,cb){
  var d=cur?new Date(cur+'T00:00:00'):new Date(),y=d.getFullYear(),m=d.getMonth();
  var MN=['يناير','فبراير','مارس','أبريل','مايو','يونيو','يوليو','أغسطس','سبتمبر','أكتوبر','نوفمبر','ديسمبر'],WD=['أحد','اثنين','ثلاثاء','أربعاء','خميس','جمعة','سبت'];
  var old=$('pov');if(old)old.remove();
  var o=document.createElement('div');o.className='pov';o.id='pov';
  o.addEventListener('mousedown',function(e){if(e.target===o)o.remove();});
  document.body.appendChild(o);
  var p2=function(x){return (x<10?'0':'')+x;},tdy=new Date(),tds=tdy.getFullYear()+'-'+p2(tdy.getMonth()+1)+'-'+p2(tdy.getDate());
  function draw(){
    var first=new Date(y,m,1).getDay(),days=new Date(y,m+1,0).getDate(),h='';
    WD.forEach(function(w){h+='<div class="ph">'+w+'</div>';});
    for(var i=0;i<first;i++)h+='<div></div>';
    for(var k=1;k<=days;k++){var v=y+'-'+p2(m+1)+'-'+p2(k);h+='<button class="pd'+(v===cur?' on':'')+(v===tds?' td':'')+'" data-v="'+v+'">'+k+'</button>';}
    o.innerHTML='<div class="pbox"><div class="row" style="justify-content:space-between;align-items:center"><button class="btn sm gray" id="pd-p">السابق</button><b>'+MN[m]+' '+y+'</b><button class="btn sm gray" id="pd-n">التالي</button></div><div class="pcal">'+h+'</div><div class="row" style="justify-content:flex-start;gap:8px"><button class="btn sm" id="pd-t">اليوم</button><button class="btn sm gray" id="pd-x">إلغاء</button></div></div>';
    $('pd-p').onclick=function(){m--;if(m<0){m=11;y--;}draw();};
    $('pd-n').onclick=function(){m++;if(m>11){m=0;y++;}draw();};
    $('pd-t').onclick=function(){o.remove();cb(tds);};
    $('pd-x').onclick=function(){o.remove();};
    o.querySelectorAll('.pd').forEach(function(b){b.onclick=function(){o.remove();cb(b.getAttribute('data-v'));};});
  }
  draw();
}
function upgradeUI(root){
  (root||document).querySelectorAll('select:not([data-ui])').forEach(function(sel){
    sel.setAttribute('data-ui','1');sel.style.display='none';
    var b=document.createElement('button');b.type='button';b.className='selbtn';
    var sync=function(){var op=sel.options[sel.selectedIndex];b.textContent=(op?op.text:'اختر')+' ▾';};
    sync();sel._sync=sync;
    b.onclick=function(){
      var items=[].map.call(sel.options,function(op){return {v:op.value,t:op.text};});
      pickList(sel.getAttribute('aria-label')||'اختر',items,sel.value,function(x){sel.value=x.v;sync();sel.dispatchEvent(new Event('change',{bubbles:true}));});
    };
    sel.parentNode.insertBefore(b,sel.nextSibling);
  });
  (root||document).querySelectorAll('input[type=date]:not([data-ui])').forEach(function(inp){
    inp.setAttribute('data-ui','1');inp.style.display='none';
    var b=document.createElement('button');b.type='button';b.className='selbtn';b.style.gridColumn=inp.style.gridColumn||'';
    var MN=['يناير','فبراير','مارس','أبريل','مايو','يونيو','يوليو','أغسطس','سبتمبر','أكتوبر','نوفمبر','ديسمبر'];
    var sync=function(){var v=inp.value;if(v){var a=v.split('-');b.textContent=(+a[2])+' '+MN[(+a[1])-1]+' '+a[0]+' 📅';}else b.textContent='اختر التاريخ 📅';};
    sync();inp._sync=sync;
    b.onclick=function(){pickDate(inp.value,function(v){inp.value=v;sync();inp.dispatchEvent(new Event('input',{bubbles:true}));inp.dispatchEvent(new Event('change',{bubbles:true}));});};
    inp.parentNode.insertBefore(b,inp.nextSibling);
  });
}
function startUI(){
  if(S.uiOn)return;S.uiOn=true;
  var t=null;
  new MutationObserver(function(){clearTimeout(t);t=setTimeout(function(){upgradeUI(document.body);},30);}).observe(document.body,{childList:true,subtree:true});
  upgradeUI(document.body);
  setInterval(function(){document.querySelectorAll('[data-ui]').forEach(function(x){if(x._sync)x._sync();});},700);
  setInterval(tickTasks,1000);
}

function memberNotice(id){
  var m=(S.memMap||{})[id]||{};
  var lb='display:block;color:#60a5fa;font-size:13px;margin:12px 0 6px';
  modal('<h3 style="color:#60a5fa">📣 إشعار القيادة</h3>'
    +'<div class="muted" style="font-size:13px;line-height:1.8">راح يوصل الإشعار لقائد الأمن السيبراني ونائبه (منبثق بالموقع + رسالة بالخاص) بخصوص: <b>'+esc(m.tag||id)+'</b></div>'
    +'<label style="'+lb+'">سبب الإشعار</label>'
    +'<textarea id="mnR" rows="5" maxlength="600" placeholder="مثال: تأخر عن الدوام / سوّى كذا..." style="width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(59,130,246,.35);border-radius:10px;color:#e2e8f0;padding:10px;font-family:inherit;font-size:14px;resize:vertical"></textarea>'
    +'<div class="row" style="justify-content:flex-start;gap:8px;margin-top:14px"><button class="btn" id="mnGo">📤 إرسال</button><button class="btn gray" onclick="closeModal()">إلغاء</button></div>');
  $('mnR').focus();
  $('mnGo').onclick=async function(){
    var r=($('mnR').value||'').trim();
    if(r.length<3){toast('اكتب سبب الإشعار');return;}
    this.disabled=true;
    try{await api('/api/notices/member',{method:'POST',body:JSON.stringify({memberId:id,reason:r,tag:m.tag||''})});closeModal();toast('📣 تم إرسال الإشعار للقيادة');}
    catch(e){toast(e.message);this.disabled=false;}
  };
}

/* ══ أعضاء الأمن السيبراني (للقائد والنائب) ══ */
var RANK_AR={leader:'👑 قائد',deputy:'🥈 نائب',member:'عضو'};
async function pgMembers(){
  $('main').innerHTML='<h2>👥 أعضاء الأمن السيبراني</h2><div class="card center muted">جاري التحميل...</div>';
  try{
    var j=await api('/api/members');if(S.page!=='members')return;
    S.meRank=j.meRank;S.memMap={};
    var html='<h2>👥 أعضاء الأمن السيبراني ('+j.members.length+')</h2><div class="muted" style="font-size:12px;margin:-4px 0 8px">👆 اضغط على بطاقة العضو لعرض آخر نشاط له في السيرفر</div>'+(S.level==='full'?'<div class="row" style="justify-content:flex-start;margin:6px 0 10px"><button class="btn sm" onclick="openTasks()">📋 مهام الأعضاء</button></div>':'');
    html+=j.members.map(function(m){
      S.memMap[m.id]=m;
      var last=m.lastLoginAt?fmt(m.lastLoginAt):'لم يسجّل الدخول للوحة بعد';
      var dur=(m.durationMin!=null)?'⏱️ قعد آخر مرة: '+m.durationMin+' دقيقة':'';
      var canDismiss=S.level==='full'&&m.id!==S.meId&&!(m.rank==='leader'&&S.meRank!=='leader');
      return '<div class="card" data-mid="'+esc(m.id)+'" style="cursor:pointer"><div class="bot"><img src="'+esc(m.avatar)+'" alt=""><div style="flex:1;min-width:200px">'
        +'<div class="log-title">'+esc(m.tag)+' <span class="badge '+(m.rank==='leader'?'high':m.rank==='deputy'?'medium':'low')+'">'+RANK_AR[m.rank]+'</span>'+(m.mgr?' <span class="badge medium">🗂️ مسؤول الأفراد</span>':'')+'</div>'
        +'<div class="log-meta">🕒 آخر دخول للوحة: '+last+'</div>'
        +(dur?'<div class="log-meta">'+dur+'</div>':'')
        +'<div class="log-meta" style="color:#60a5fa">🕵️ اضغط لعرض نشاطه في السيرفر</div></div>'
        +((S.level==='mgr'&&m.id!==S.meId&&m.rank==='member')?'<button class="btn sm" onclick="memberNotice(\''+m.id+'\')">📣 إشعار القيادة</button>':'')
        +((S.level==='full'&&m.id!==S.meId)?'<button class="btn sm" onclick="leadNotify(\''+m.id+'\')">🔔 إشعار</button>':'')
        +(canDismiss?'<button class="btn sm danger" onclick="dismissMember(\''+m.id+'\',\''+esc(m.tag).replace(/'/g,'')+'\')">🚫 فصل</button>':(S.level==='full'?'<span class="muted" style="font-size:12px">'+(m.id===S.meId?'أنت':'🔒 القائد')+'</span>':(m.id===S.meId?'<span class="muted" style="font-size:12px">أنت</span>':'')))+'</div></div>';
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
    var pj=null;try{pj=await api('/api/members/'+id+'/panel');}catch(x){}
    if(S.actId!==id||!$('actinfo'))return;
    drawAct(j,b,pj);
  }catch(e){if(S.actId===id&&$('actinfo'))$('actinfo').innerHTML='<h3>🕵️ نشاط العضو</h3>'+actHead(b,id)+'<div class="card center muted">'+esc(e.message)+'</div>';}
}
function actPanel(pj){
  var ev=(pj&&pj.events)||[];
  var h='<div class="card" style="margin:8px 0;padding:12px"><div class="muted" style="font-size:12px;margin-bottom:6px">🛠️ آخر ما سوّاه في اللوحة (دخول وإجراءات)</div>';
  if(!ev.length)return h+'<span class="muted">ما سوّى شي في اللوحة بعد</span></div>';
  return h+ev.map(function(x){return '<div class="prow"><span>'+esc(x.title)+(x.details?'<div class="log-meta">'+esc(x.details)+'</div>':'')+'</span><span class="muted" style="font-size:11px;white-space:nowrap">'+esc(fmt(x.at))+'</span></div>';}).join('')+'</div>';
}
function drawAct(a,b,pj){
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
  box.innerHTML='<h3>🕵️ نشاط العضو</h3>'+actHead(hb,a.id)+rows+msg+actPanel(pj);
}
async function dismissMember(id,name){
  if(!(await ask('متأكد تبي تفصل '+name+' من الأمن السيبراني؟\nراح تنسحب رتبته من ديسكورد وما يقدر يدخل اللوحة إلا إذا ترجعت له الرتبة.')))return;
  try{await api('/api/members/'+id+'/dismiss',{method:'POST'});toast('تم الفصل');pgMembers();}catch(e){toast(e.message);}
}

/* ══ بوت تسجيل الرومات (لصاحب الصفحة فقط) ══ */
var REC_ST={recording:'🔴 يسجّل الآن',live:'🟢 شغّال — ينتظر أحد يدخل الروم',starting:'🟡 جاري التشغيل...',error:'❌ فيه مشكلة',off:'⚫ متوقف'};
async function pgRec(){
  $('main').innerHTML='<div class="row" style="justify-content:space-between;align-items:center;margin-bottom:10px"><h2 style="margin:0">🎙️ بوت تسجيل الرومات</h2><button class="btn" id="recNew">➕ إنشاء بوت</button></div>'
    +'<div class="muted" style="font-size:12px;margin-bottom:10px">البوت يدخل الروم أول ما يدخله أحد ويسجّل الصوت، ويطلع باللوق زر «التسجيل التوضيحي» لكل جلسة.</div><div id="recbox"><div class="card center muted">جاري التحميل...</div></div>';
  $('recNew').onclick=recNew;
  $('main').onclick=function(ev){
    var d=ev.target.closest('[data-recdel]');
    if(d){recDel(d.getAttribute('data-recdel'),d.getAttribute('data-main')==='1');return;}
    var l=ev.target.closest('[data-reclive]');
    if(l)recLive(l.getAttribute('data-reclive'),l.getAttribute('data-chn'));
  };
  await recLoad();
  clearInterval(S.timer);
  S.timer=setInterval(function(){if(S.page==='rec'&&!$('ov'))recLoad();},5000);
}
async function recLoad(){
  try{
    var j=await api('/api/rec/bots');if(S.page!=='rec')return;
    var lvs=[];try{lvs=(await api('/api/rec/live')).sessions||[];}catch(e){}
    var h=j.bots.map(function(b){
      var ls=null;
      if(b.status==='recording'){
        var mt=lvs.filter(function(x){return (b.chId&&x.chId&&String(b.chId)===String(x.chId))||(b.chName&&x.chName&&b.chName===x.chName);});
        ls=mt.length?mt[0]:(lvs.length===1?lvs[0]:null);
      }
      var main=b.id==='main';
      var st=REC_ST[b.status]||b.status;
      if(b.status==='recording'&&b.users!=null)st+=' ('+b.users+')';
      var title=main?'🤖 البوت الأساسي'+(b.botTag?' — '+esc(b.botTag):''):'🤖 '+esc(b.botTag||b.id);
      var kind=main?(b.isDefault?'الروم الافتراضي':'روم مختار من الموقع'):'بوت بتوكن';
      return '<div class="card'+(ls?' clk':'')+'"'+(ls?' data-reclive="'+esc(ls.sid)+'" data-chn="'+esc(b.chName||ls.chName||'')+'"':'')+'><div class="bot">'+(b.avatar?'<img src="'+esc(b.avatar)+'" alt="">':'')
        +'<div style="flex:1;min-width:200px"><div class="log-title">'+title+' <span class="badge low">'+kind+'</span></div>'
        +'<div class="log-meta">🎙️ الروم: '+(b.chName?esc(b.chName):'<span class="muted">غير موجود</span>')+'</div>'
        +'<div class="log-meta">'+st+'</div>'
        +(b.error?'<div class="log-meta" style="color:#f87171">'+esc(b.error)+'</div>':'')
        +(b.createdBy?'<div class="log-meta">👤 أنشأه: '+esc(b.createdBy)+'</div>':'')
        +(ls?'<div class="log-meta" style="color:#f87171">🔴 يسجّل الحين — اضغط على البوت للاستماع المباشر</div>':'')+'</div>'
        +(ls?'<button class="btn sm" data-reclive="'+esc(ls.sid)+'" data-chn="'+esc(b.chName||ls.chName||'')+'">🎧 استمع مباشر</button>':'')
        +((main&&b.isDefault)?'':'<button class="btn sm danger" data-recdel="'+esc(b.id)+'" data-main="'+(main?'1':'0')+'">'+(main?'↩️ رجّعه للافتراضي':'🗑️ حذف')+'</button>')
        +'</div></div>';
    }).join('');
    $('recbox').innerHTML=h||'<div class="card center muted">ما فيه بوتات</div>';
  }catch(e){if(S.page==='rec'&&$('recbox')&&!$('recbox').querySelector('.card .bot'))$('recbox').innerHTML='<div class="card center muted">'+esc(e.message)+'</div>';}
}
function recNew(){
  modal('<h3>إنشاء بوت تسجيل</h3><div class="card center muted">جاري تحميل الرومات الصوتية...</div>');
  api('/api/rec/rooms').then(function(j){
    var rooms=j.rooms;
    if(!rooms.length){closeModal();toast('ما فيه رومات صوتية بالسيرفر');return;}
    var opts=rooms.map(function(r){return '<option value="'+esc(r.id)+'">'+esc(r.icon+' '+r.name+(r.parent?'  ('+r.parent+')':'')+(r.members?'  — '+r.members+' بالروم':''))+'</option>';}).join('');
    var lb='display:block;color:#60a5fa;font-size:13px;margin:12px 0 6px';
    modal('<h3 style="color:#60a5fa">إنشاء بوت تسجيل</h3>'
      +'<div class="muted" style="font-size:13px">اختر الروم اللي يتسجّل. إذا حطيت توكن يشتغل بوت ثاني بالتوكن، وإذا تركته فاضي يسجّله البوت الأساسي.</div>'
      +'<label style="'+lb+'">الروم</label><select id="recRoom">'+opts+'</select>'
      +'<label style="'+lb+'">التوكن (اختياري)</label><input id="recTok" type="password" autocomplete="off" placeholder="توكن البوت">'
      +'<div class="row" style="justify-content:flex-start;gap:8px;margin-top:16px"><button class="btn" id="recGo">تم</button><button class="btn gray" onclick="closeModal()">إلغاء</button></div>');
    $('recGo').onclick=async function(){
      var btn=this,tok=($('recTok').value||'').trim(),mode=tok?'token':'room';
      var body={mode:mode,chId:$('recRoom').value};
      if(tok)body.token=tok;
      btn.disabled=true;btn.textContent='جاري التنفيذ...';
      try{
        var r=await api('/api/rec/create',{method:'POST',body:JSON.stringify(body)});
        closeModal();toast(mode==='room'?'تم — البوت الأساسي يسجّل: '+(r.name||''):'اشتغل البوت'+(r.botTag?' '+r.botTag:'')+' وهو يسجّل: '+(r.name||''));
        if(S.page==='rec')recLoad();
      }catch(e){toast(e.message);btn.disabled=false;btn.textContent='تم';}
    };
  }).catch(function(e){closeModal();toast(e.message);});
}
var LV=null;
function lvStop(){
  if(LV){clearInterval(LV.timer);clearInterval(LV.t2);try{LV.a.pause();LV.a.removeAttribute('src');LV.a.load();}catch(e){}}
  LV=null;
}
function recLive(sid,name){
  lvStop();
  modal('<h3><span class="livedot"></span>استماع مباشر — '+esc(name||'الروم')+'</h3>'
   +'<div class="muted" style="font-size:12px;margin-bottom:8px;line-height:1.8">تسمع اللي يقولونه الحين بتأخير بسيط (من ثانية إلى ثلاث). إذا ما اشتغل الصوت لحاله اضغط تشغيل ▶️.</div>'
   +'<div id="lv-st" class="center" style="margin:8px 0;font-weight:700">⏳ جاري الاتصال...</div>'
   +'<audio id="lv-a" controls autoplay style="width:100%"></audio>'
   +'<div style="margin:12px 0 4px;font-size:13px;font-weight:700">👥 اللي بالروم الحين</div><div id="lv-who"><div class="muted">...</div></div>'
   +'<div class="row" style="justify-content:center;gap:8px;margin-top:12px"><button class="btn gray sm" id="lv-re">🔄 إعادة الاتصال</button><button class="btn danger sm" onclick="closeModal()">✖ إغلاق</button></div>');
  var a=$('lv-a');
  LV={sid:sid,a:a,timer:null,t2:null,errs:0};
  var st=function(t){if(!LV||LV.a!==a)return;var e=$('lv-st');if(e)e.textContent=t;};
  var conn=function(){
    try{a.playbackRate=1;}catch(e){}
    a.src='/api/rec/live/'+encodeURIComponent(sid)+'/stream?t='+Date.now();
    var p=a.play();if(p&&p.catch)p.catch(function(){st('اضغط تشغيل ▶️ لبدء الصوت');});
  };
  a.addEventListener('playing',function(){if(LV&&LV.a===a)LV.errs=0;st('🔴 مباشر الحين');});
  a.addEventListener('waiting',function(){st('⏳ يحمّل الصوت...');});
  a.addEventListener('error',function(){
    if(!LV||LV.a!==a)return;
    if(LV.errs<5){LV.errs++;st('⚠️ انقطع البث — جاري إعادة الاتصال...');setTimeout(function(){if(LV&&LV.a===a&&$('lv-a')===a)conn();},1500);}
    else st('⚠️ انقطع البث — اضغط إعادة الاتصال');
  });
  a.addEventListener('ended',function(){st('⚫ انتهى البث (الجلسة خلصت أو انقطع الاتصال)');});
  $('lv-re').onclick=function(){if(LV)LV.errs=0;conn();};
  // لو تراكم صوت قدّام (بسبب تأخير القطع) نسرّع التشغيل شوي لين نلحق الحاضر — بدون ما نتخطى أي كلام
  LV.t2=setInterval(function(){
    if(!LV||LV.a!==a||a.paused)return;
    try{
      var bf=a.buffered;if(!bf||!bf.length)return;
      var d=bf.end(bf.length-1)-a.currentTime,r=a.playbackRate;
      if(d>4)r=1.5;else if(d>2.5)r=1.3;else if(d>1.5)r=1.15;else if(d<0.7)r=1;
      if(r!==a.playbackRate)a.playbackRate=r;
    }catch(e){}
  },400);
  conn();
  var poll=async function(){
    if(!LV||LV.sid!==sid)return;
    if(!$('lv-a')){lvStop();return;}
    try{
      var j=await api('/api/rec/live/'+encodeURIComponent(sid)+'/info');
      var w=$('lv-who');if(!w)return;
      w.innerHTML=j.people.length?j.people.map(function(p){return '<div class="lvp'+(p.speaking?' sp':'')+'">'+(p.avatar?'<img src="'+esc(p.avatar)+'" alt="">':'')+'<span style="flex:1">'+esc(p.name)+'</span>'+(p.speaking?'<span>🎤 يتكلم</span>':'')+'</div>';}).join(''):'<div class="muted">ما فيه أحد بالروم</div>';
      if(j.ended)st('⚫ انتهت هذي الجلسة');
    }catch(e){}
  };
  poll();
  LV.timer=setInterval(poll,2500);
}
async function recDel(id,isMain){
  if(!(await ask(isMain?'ترجّع البوت الأساسي لروم التسجيل الافتراضي؟':'تحذف بوت التسجيل هذا؟ راح يطلع من الروم ويتوقف (التسجيلات القديمة تبقى).')))return;
  try{await api('/api/rec/'+encodeURIComponent(id),{method:'DELETE'});toast(isMain?'تم الإرجاع':'تم الحذف');recLoad();}catch(e){toast(e.message);}
}

/* ── تشغيل ── */
(async function(){
  try{
    var me=await api('/api/me');S.presence=me.presence;S.level=me.user.level||'view';S.meId=me.user.id;S.recAdmin=!!me.recAdmin;S.roomsAdmin=!!me.roomsAdmin;S.logDel=!!me.logDel;
    $('uchip').innerHTML='<img src="'+esc(me.user.avatar)+'" alt=""><span>'+esc(me.user.tag)+'</span><a class="btn sm gray" href="/auth/logout">خروج</a>';
    buildNav();render();
    loadNotices();loadTasks();startUI();
    if(me.openOp)openEv(me.openOp);
    if(me.allowInfo)allowConfirm(me.allowInfo);
    try{
      var es=S.es=new EventSource('/api/events/stream');
      es.addEventListener('notice',function(e){try{noticeEnqueue(JSON.parse(e.data));}catch(x){}});
      es.addEventListener('task',function(e){try{var t=JSON.parse(e.data);S.tasks=(S.tasks||[]).filter(function(x){return x.id!==t.id;});if(t.status==='pending')noticeEnqueue(taskPop(t));else S.tasks.push(t);renderTaskBar();}catch(x){}});
      es.addEventListener('taskupd',function(e){try{
        var d=JSON.parse(e.data);
        if(d.ev==='ack'&&d.toAssigner)toast('📋 '+d.targetTag+' استلم المهمة');
        if(d.ev==='cancel'&&d.toTarget)toast('🚫 القيادة ألغت المهمة');
        loadTasks();if($('tk-list'))refreshTaskList();
      }catch(x){}});
      es.addEventListener('changed',function(){ if(S.page==='logs')loadEvents(true); });
      es.addEventListener('dismissed',function(){showDismissed();});
      es.addEventListener('evdeleted',function(e){
        try{
          var d=JSON.parse(e.data);
          S.events=(S.events||[]).filter(function(x){return x._id!==d.id;});
          var el=document.querySelector('.log-item[data-id="'+d.id+'"]');
          if(el&&el.parentNode)el.parentNode.removeChild(el);
        }catch(x){}
      });
      es.addEventListener('access',function(e){
        try{var d=JSON.parse(e.data);
          if(d.level&&d.level!==S.level){S.level=d.level;if(S.page==='members'&&d.level!=='full'&&d.level!=='mgr')S.page='logs';closeModal();buildNav();render();toast(d.level==='full'?'تمت ترقيتك — صارت عندك صلاحية التعديل':d.level==='mgr'?'صرت مسؤول أفراد الأمن السيبراني — انفتحت لك صفحة الأعضاء':'تغيّرت صلاحيتك إلى عرض فقط');if(d.level==='full')loadNotices();}
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
    const op = String(req.query.op || ""), al = String(req.query.allow || "");
    let redir = false;
    if (/^[a-f0-9]{24}$/i.test(op)) { req.session.openOp = op; redir = true; }
    if (/^[a-f0-9]{24}$/i.test(al)) { req.session.openAllow = al; redir = true; }
    if (redir) return req.session.save(() => res.redirect("/"));
    if (req.session.user) return res.send(appPage());
    const mode = req.query.denied ? "denied" : req.query.err ? "err" : "login";
    res.send(loginPage(mode, String(req.query.err || "")));
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
