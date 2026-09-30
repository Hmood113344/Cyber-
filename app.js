// ══════════════════════════════════════════════════════════════════════════
// الأمن السيبراني — وزارة الداخلية (ملف واحد شامل: موقع + بوت)
// ══════════════════════════════════════════════════════════════════════════
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const mongoose = require("mongoose");
const {
    Client, GatewayIntentBits, Partials, PermissionFlagsBits, PermissionsBitField, AuditLogEvent,
} = require("discord.js");

// ══════════════════════════════════════════════════════════════════════════
// 1) الإعدادات — من Environment Variables في Render
// ══════════════════════════════════════════════════════════════════════════
const CONFIG = {
    DISCORD_CLIENT_ID: process.env.DISCORD_CLIENT_ID || "",
    DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET || "",
    DISCORD_CALLBACK_URL: process.env.DISCORD_CALLBACK_URL || "",   // مثال: https://xxx.onrender.com/auth/discord/callback
    BOT_TOKEN: process.env.BOT_TOKEN || "",
    // ⬇️ حط آيدي سيرفر وزارة الداخلية هنا
    GUILD_ID: process.env.GUILD_ID || "1497233353030766662",
    MONGO_URI: process.env.MONGO_URI || "",
    // ⬇️ حط آيدي رتبة الأمن السيبراني هنا بين علامتي التنصيص (شرط الدخول للموقع)
    CYBER_ROLE_ID: "1554783236369031240",
    SESSION_SECRET: process.env.SESSION_SECRET || "غيّر_هذا_السر_2026",
    PORT: process.env.PORT || 7800,
    SITE_NAME: "الأمن السيبراني",
    SITE_SUB: "وزارة الداخلية",
    PROBOT_ID: process.env.PROBOT_ID || "282859044593598464",

    // حدود العمليات المشبوهة
    YOUNG_ACCOUNT_DAYS: 30,
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
const CRITICAL = ["Administrator", "ManageGuild", "ManageRoles", "ManageChannels", "ManageWebhooks", "BanMembers", "KickMembers"].filter(n => P[n]);
const HIGH = ["MentionEveryone", "ManageMessages", "ModerateMembers", "ViewAuditLog", "ManageNicknames", "MuteMembers", "DeafenMembers", "MoveMembers", "ManageGuildExpressions", "ManageThreads", "ManageEvents"].filter(n => P[n]);
const DANGER_LEVEL = {}; CRITICAL.forEach(n => DANGER_LEVEL[n] = "critical"); HIGH.forEach(n => DANGER_LEVEL[n] = "high");
const isDanger = n => !!DANGER_LEVEL[n];
const ROLE_PERMS = Object.keys(P);
const CHANNEL_PERMS = ["CreateInstantInvite", "ManageChannels", "ManageRoles", "ManageWebhooks", "ViewChannel", "SendMessages", "SendMessagesInThreads",
    "CreatePublicThreads", "CreatePrivateThreads", "EmbedLinks", "AttachFiles", "AddReactions", "UseExternalEmojis", "UseExternalStickers", "MentionEveryone",
    "ManageMessages", "ManageThreads", "ReadMessageHistory", "SendTTSMessages", "UseApplicationCommands", "SendPolls", "SendVoiceMessages", "Connect", "Speak",
    "Stream", "UseVAD", "PrioritySpeaker", "MuteMembers", "DeafenMembers", "MoveMembers", "UseEmbeddedActivities", "UseSoundboard", "RequestToSpeak", "ManageEvents"].filter(n => P[n]);
const permMeta = list => list.map(k => ({ k, ar: PERM_AR[k] || k, danger: DANGER_LEVEL[k] || null }))
    .sort((a, b) => (b.danger ? 1 : 0) - (a.danger ? 1 : 0));

// ══════════════════════════════════════════════════════════════════════════
// 4) البوت
// ══════════════════════════════════════════════════════════════════════════
let client = null;
let PRESENCE_OK = true;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const tagOf = u => u ? (u.tag && !u.tag.endsWith("#0") ? u.tag : u.username) : null;
const getGuild = async () => client.guilds.cache.get(CONFIG.GUILD_ID) || await client.guilds.fetch(CONFIG.GUILD_ID);

const inviteCache = new Map();  // code -> uses
const msgCache = new Map();     // آخر الرسائل (لعرض المحذوف)
const everyoneHits = new Map();

function cacheMsg(m) {
    msgCache.set(m.id, {
        id: m.id, authorId: m.author?.id, authorTag: tagOf(m.author), bot: !!m.author?.bot, channelId: m.channelId,
        content: String(m.content || "").slice(0, 500), att: m.attachments?.size || 0, at: m.createdTimestamp,
    });
    if (msgCache.size > 20000) msgCache.delete(msgCache.keys().next().value);
}

async function logEvent(o) {
    try { return await Event.create({ ...o, updatedAt: new Date() }); }
    catch (e) { console.error("logEvent:", e.message); }
}

// عملية مشبوهة (تُدمج مع المفتوحة المشابهة خلال 24 ساعة)
async function raise(o) {
    try {
        if (o.key) {
            const ev = await Event.findOne({ kind: "suspicious", key: o.key, resolved: false, createdAt: { $gte: new Date(Date.now() - 864e5) } });
            if (ev) {
                ev.details = o.details; ev.remedy = o.remedy || ev.remedy; ev.count = o.count || (ev.count + 1);
                ev.data = o.data || ev.data; ev.markModified("data"); ev.markModified("remedy"); ev.updatedAt = new Date();
                await ev.save(); return ev;
            }
        }
        return await Event.create({ severity: "high", ...o, kind: "suspicious", updatedAt: new Date() });
    } catch (e) { console.error("raise:", e.message); }
}

async function findAudit(guild, type, match) {
    await sleep(900);
    for (let i = 0; i < 2; i++) {
        try {
            const logs = await guild.fetchAuditLogs({ type, limit: 8 });
            const now = Date.now();
            const e = logs.entries.find(x => now - x.createdTimestamp < 20000 && (!match || match(x)));
            if (e) return e;
        } catch { return null; }
        await sleep(1200);
    }
    return null;
}
const isSelf = id => client && client.user && id === client.user.id;

// قواعد العمليات المشبوهة المبنية على التكرار
const RULES = {
    mass_roles_created: { title: "إنشاء 5 رتب أو أكثر خلال يوم واحد", action: "role_create", min: 1440, limit: 5, cat: "role", remedy: "delete_roles" },
    mass_role_delete:   { title: "حذف 3 رتب أو أكثر خلال 10 دقائق", action: "role_delete", min: 10, limit: 3, cat: "role", remedy: "strip" },
    mass_channel_create:{ title: "إنشاء 5 قنوات أو أكثر خلال 10 دقائق", action: "channel_create", min: 10, limit: 5, cat: "channel", remedy: "delete_channels" },
    mass_channel_delete:{ title: "حذف 3 قنوات أو أكثر خلال 10 دقائق", action: "channel_delete", min: 10, limit: 3, cat: "channel", remedy: "strip" },
    mass_ban:           { title: "حظر 3 أعضاء أو أكثر خلال 10 دقائق", action: "ban", min: 10, limit: 3, cat: "ban", remedy: "strip" },
    mass_kick:          { title: "طرد 3 أعضاء أو أكثر خلال 10 دقائق", action: "kick", min: 10, limit: 3, cat: "kick", remedy: "strip" },
};
async function burst(ruleKey, actorId, actorTag) {
    const R = RULES[ruleKey];
    if (!R || !actorId || isSelf(actorId)) return;
    const evs = await Event.find({ "data.act": R.action, actorId, createdAt: { $gte: new Date(Date.now() - R.min * 60000) } }).lean();
    if (evs.length < R.limit) return;
    let remedy;
    if (R.remedy === "delete_roles") remedy = { type: "delete_roles", label: "🗑️ حذف جميع الرتب (" + evs.length + ")", params: { roleIds: evs.map(e => e.targetId).filter(Boolean) } };
    else if (R.remedy === "delete_channels") remedy = { type: "delete_channels", label: "🗑️ حذف القنوات (" + evs.length + ")", params: { channelIds: evs.map(e => e.targetId).filter(Boolean) } };
    else remedy = { type: "strip_roles", label: "🚫 سحب جميع رتبه", params: { userId: actorId } };
    await raise({
        rule: ruleKey, key: ruleKey + ":" + actorId, cat: R.cat, title: R.title, severity: "high",
        details: "المنفذ نفّذ " + evs.length + " عملية متتالية", actorId, actorTag, count: evs.length, remedy,
    });
}

function dangerOf(permNames) { return permNames.filter(n => DANGER_LEVEL[n] === "critical"); }

const LOGCAT = (o) => logEvent({ kind: "normal", severity: "low", ...o });

function startBot() {
    const intents = [
        GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildModeration, GatewayIntentBits.GuildInvites, GatewayIntentBits.GuildWebhooks,
    ];
    if (PRESENCE_OK) intents.push(GatewayIntentBits.GuildPresences);
    client = new Client({ intents, partials: [Partials.Message, Partials.Channel, Partials.GuildMember] });
    attachHandlers();
    client.login(CONFIG.BOT_TOKEN).catch(e => {
        console.log("❌ فشل تسجيل دخول البوت:", e.message);
        if (PRESENCE_OK && /disallowed/i.test(e.message)) {
            console.log("⚠️ Presence Intent غير مفعّل — نكمل بدونه (حالة البوتات أونلاين/أوفلاين ما راح تظهر بدقة). فعّله من Developer Portal → Bot");
            PRESENCE_OK = false; try { client.destroy(); } catch {} startBot();
        }
    });
}

function attachHandlers() {
    const G = () => CONFIG.GUILD_ID;

    client.once("ready", async () => {
        console.log("🤖 Bot ready:", client.user.tag);
        try {
            const g = await getGuild();
            await g.members.fetch().catch(() => {});
            await g.channels.fetch().catch(() => {});
            await g.roles.fetch().catch(() => {});
            const invs = await g.invites.fetch().catch(() => null);
            if (invs) invs.forEach(i => inviteCache.set(i.code, i.uses || 0));
        } catch (e) { console.log("ready err:", e.message); }
    });

    client.on("inviteCreate", i => inviteCache.set(i.code, i.uses || 0));
    client.on("inviteDelete", i => inviteCache.delete(i.code));

    // ── دخول عضو ──
    client.on("guildMemberAdd", async m => {
        if (m.guild.id !== G()) return;
        const ageDays = Math.floor((Date.now() - m.user.createdTimestamp) / 864e5);
        let inviterId = null, inviterTag = null, code = null;
        try {
            const invs = await m.guild.invites.fetch();
            const used = invs.find(i => (i.uses || 0) > (inviteCache.get(i.code) || 0));
            invs.forEach(i => inviteCache.set(i.code, i.uses || 0));
            if (used) { code = used.code; inviterId = used.inviter?.id || null; inviterTag = tagOf(used.inviter); }
        } catch {}
        const base = {
            cat: "join", actorId: inviterId, actorTag: inviterTag, targetId: m.id, targetTag: tagOf(m.user),
            data: { act: "join", ageDays, created: m.user.createdTimestamp, inviterId, inviterTag, code, bot: m.user.bot },
        };
        const lines = [
            "📅 عمر الحساب: " + ageDays + " يوم (أُنشئ " + new Date(m.user.createdTimestamp).toLocaleDateString("ar-SA") + ")",
            "📨 الداعي: " + (inviterTag ? inviterTag + " (" + inviterId + ")" : "غير معروف") + (code ? " — الدعوة: " + code : ""),
        ].join("\n");

        if (m.user.bot) {
            const a = await findAudit(m.guild, AuditLogEvent.BotAdd, x => x.target?.id === m.id);
            const by = a?.executor;
            await raise({
                cat: "bot", rule: "bot_added", key: "bot_added:" + m.id, severity: "high", title: "إضافة بوت جديد للسيرفر",
                details: "البوت: " + tagOf(m.user) + "\nأضافه: " + (tagOf(by) || "غير معروف"), actorId: by?.id, actorTag: tagOf(by),
                targetId: m.id, targetTag: tagOf(m.user), data: { act: "bot_add" },
                remedy: { type: "kick_member", label: "👢 طرد البوت", params: { userId: m.id } },
            });
            return;
        }
        if (ageDays < CONFIG.YOUNG_ACCOUNT_DAYS) {
            await raise({
                ...base, rule: "new_account", key: "new_account:" + m.id, severity: "medium", title: "دخول حساب جديد (أقل من شهر)",
                details: lines, remedy: { type: "kick_member", label: "👢 طرد", params: { userId: m.id } },
            });
        } else {
            await LOGCAT({ ...base, title: "دخول عضو", details: lines });
        }
        // غارة: 10 دخول خلال دقيقة
        const recent = await Event.find({ "data.act": "join", createdAt: { $gte: new Date(Date.now() - 60000) } }).lean();
        if (recent.length >= 10) {
            await raise({
                cat: "join", rule: "mass_join", key: "mass_join", severity: "high", title: "دخول جماعي مفاجئ (احتمال غارة)",
                details: recent.length + " عضو دخلوا خلال آخر دقيقة", count: recent.length,
                remedy: { type: "kick_many", label: "👢 طرد الداخلين (" + recent.length + ")", params: { userIds: recent.map(e => e.targetId) } },
            });
        }
    });

    // ── خروج / طرد ──
    client.on("guildMemberRemove", async m => {
        if (m.guild.id !== G()) return;
        const a = await findAudit(m.guild, AuditLogEvent.MemberKick, x => x.target?.id === m.id);
        if (a) {
            if (isSelf(a.executor?.id)) return;
            await LOGCAT({ cat: "kick", title: "طرد عضو", details: "السبب: " + (a.reason || "بدون سبب"), actorId: a.executor?.id, actorTag: tagOf(a.executor), targetId: m.id, targetTag: tagOf(m.user), data: { act: "kick" } });
            return burst("mass_kick", a.executor?.id, tagOf(a.executor));
        }
        await LOGCAT({ cat: "leave", title: "خروج عضو", details: "", targetId: m.id, targetTag: tagOf(m.user), data: { act: "leave" } });
    });

    // ── باند ──
    client.on("guildBanAdd", async b => {
        if (b.guild.id !== G()) return;
        const a = await findAudit(b.guild, AuditLogEvent.MemberBanAdd, x => x.target?.id === b.user.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({ cat: "ban", title: "حظر عضو", details: "السبب: " + (b.reason || a?.reason || "بدون سبب"), actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: b.user.id, targetTag: tagOf(b.user), data: { act: "ban" } });
        if (a?.executor) await burst("mass_ban", a.executor.id, tagOf(a.executor));
    });
    client.on("guildBanRemove", async b => {
        if (b.guild.id !== G()) return;
        const a = await findAudit(b.guild, AuditLogEvent.MemberBanRemove, x => x.target?.id === b.user.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({ cat: "ban", title: "فك حظر عضو", details: "", actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: b.user.id, targetTag: tagOf(b.user), data: { act: "unban" } });
    });

    // ── الرتب ──
    client.on("roleCreate", async r => {
        if (r.guild.id !== G()) return;
        const a = await findAudit(r.guild, AuditLogEvent.RoleCreate, x => x.target?.id === r.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({ cat: "role", title: "إنشاء رتبة", details: "الرتبة: " + r.name, actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: r.id, targetTag: r.name, data: { act: "role_create" } });
        if (a?.executor && !r.managed) await burst("mass_roles_created", a.executor.id, tagOf(a.executor));
        const crit = dangerOf(r.permissions.toArray());
        if (crit.length) await raise({
            cat: "role", rule: "dangerous_perm_grant", key: "dpg:" + r.id, title: "إنشاء رتبة بصلاحيات خطيرة",
            details: "الرتبة: " + r.name + "\nالصلاحيات: " + crit.map(n => PERM_AR[n] || n).join("، "), actorId: a?.executor?.id, actorTag: tagOf(a?.executor),
            targetId: r.id, targetTag: r.name, remedy: { type: "revoke_perms", label: "🔒 سحب الصلاحيات الخطيرة", params: { roleId: r.id, perms: crit } },
        });
    });
    client.on("roleDelete", async r => {
        if (r.guild.id !== G()) return;
        const a = await findAudit(r.guild, AuditLogEvent.RoleDelete, x => x.target?.id === r.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({ cat: "role", title: "حذف رتبة", details: "الرتبة: " + r.name, actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: r.id, targetTag: r.name, data: { act: "role_delete" } });
        if (a?.executor) await burst("mass_role_delete", a.executor.id, tagOf(a.executor));
    });
    client.on("roleUpdate", async (o, n) => {
        if (n.guild.id !== G() || o.permissions.bitfield === n.permissions.bitfield) return;
        const before = o.permissions.toArray(), after = n.permissions.toArray();
        const added = after.filter(x => !before.includes(x)), removed = before.filter(x => !after.includes(x));
        const a = await findAudit(n.guild, AuditLogEvent.RoleUpdate, x => x.target?.id === n.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({
            cat: "role", title: "تعديل صلاحيات رتبة",
            details: "الرتبة: " + n.name + (added.length ? "\n➕ أضاف: " + added.map(x => PERM_AR[x] || x).join("، ") : "") + (removed.length ? "\n➖ سحب: " + removed.map(x => PERM_AR[x] || x).join("، ") : ""),
            actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: n.id, targetTag: n.name, data: { act: "role_perms" },
        });
        const crit = dangerOf(added);
        if (crit.length) await raise({
            cat: "role", rule: "dangerous_perm_grant", key: "dpg:" + n.id, title: "منح صلاحيات خطيرة لرتبة",
            details: "الرتبة: " + n.name + "\nالصلاحيات: " + crit.map(x => PERM_AR[x] || x).join("، "), actorId: a?.executor?.id, actorTag: tagOf(a?.executor),
            targetId: n.id, targetTag: n.name, remedy: { type: "revoke_perms", label: "🔒 سحب الصلاحيات الخطيرة", params: { roleId: n.id, perms: crit } },
        });
    });

    // ── تغيير رتب عضو ──
    client.on("guildMemberUpdate", async (o, n) => {
        if (n.guild.id !== G() || !o.roles) return;
        const added = n.roles.cache.filter(r => !o.roles.cache.has(r.id)), removed = o.roles.cache.filter(r => !n.roles.cache.has(r.id));
        if (!added.size && !removed.size) return;
        const a = await findAudit(n.guild, AuditLogEvent.MemberRoleUpdate, x => x.target?.id === n.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({
            cat: "role", title: "تغيير رتب عضو",
            details: (added.size ? "➕ أُعطي: " + added.map(r => r.name).join("، ") : "") + (removed.size ? (added.size ? "\n" : "") + "➖ سُحب منه: " + removed.map(r => r.name).join("، ") : ""),
            actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: n.id, targetTag: tagOf(n.user), data: { act: "member_roles" },
        });
        for (const r of added.values()) {
            const crit = dangerOf(r.permissions.toArray());
            if (crit.length) await raise({
                cat: "role", rule: "dangerous_role_assigned", key: "dra:" + n.id + ":" + r.id, title: "إعطاء رتبة خطيرة لعضو",
                details: "العضو: " + tagOf(n.user) + "\nالرتبة: " + r.name + "\nصلاحياتها الخطيرة: " + crit.map(x => PERM_AR[x] || x).join("، "),
                actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: n.id, targetTag: tagOf(n.user),
                remedy: { type: "remove_role", label: "➖ سحب الرتبة منه", params: { userId: n.id, roleId: r.id } },
            });
        }
    });

    // ── القنوات ──
    client.on("channelCreate", async c => {
        if (!c.guild || c.guild.id !== G()) return;
        const a = await findAudit(c.guild, AuditLogEvent.ChannelCreate, x => x.target?.id === c.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({ cat: "channel", title: "إنشاء قناة", details: "القناة: " + c.name, actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: c.id, targetTag: c.name, data: { act: "channel_create" } });
        if (a?.executor) await burst("mass_channel_create", a.executor.id, tagOf(a.executor));
    });
    client.on("channelDelete", async c => {
        if (!c.guild || c.guild.id !== G()) return;
        const a = await findAudit(c.guild, AuditLogEvent.ChannelDelete, x => x.target?.id === c.id);
        if (isSelf(a?.executor?.id)) return;
        await LOGCAT({ cat: "channel", title: "حذف قناة", details: "القناة: " + c.name, actorId: a?.executor?.id, actorTag: tagOf(a?.executor), targetId: c.id, targetTag: c.name, data: { act: "channel_delete" } });
        if (a?.executor) await burst("mass_channel_delete", a.executor.id, tagOf(a.executor));
    });

    // ── ويبهوك ──
    client.on("webhooksUpdate", async ch => {
        if (!ch.guild || ch.guild.id !== G()) return;
        const a = await findAudit(ch.guild, AuditLogEvent.WebhookCreate, null);
        if (!a || isSelf(a.executor?.id)) return;
        await raise({
            cat: "webhook", rule: "webhook_created", key: "wh:" + a.target?.id, title: "إنشاء ويبهوك جديد",
            details: "القناة: " + ch.name + "\nالاسم: " + (a.target?.name || "-"), actorId: a.executor?.id, actorTag: tagOf(a.executor), targetId: a.target?.id,
            remedy: { type: "delete_webhook", label: "🗑️ حذف الويبهوك", params: { webhookId: a.target?.id } },
        });
    });

    // ── إعدادات السيرفر ──
    client.on("guildUpdate", async (o, n) => {
        if (n.id !== G()) return;
        const ch = [];
        if (o.name !== n.name) ch.push("الاسم: " + o.name + " ← " + n.name);
        if (o.icon !== n.icon) ch.push("تغيير أيقونة السيرفر");
        if (o.vanityURLCode !== n.vanityURLCode) ch.push("تغيير الرابط المخصص");
        if (o.verificationLevel !== n.verificationLevel) ch.push("تغيير مستوى التحقق");
        if (!ch.length) return;
        const a = await findAudit(n, AuditLogEvent.GuildUpdate, null);
        if (isSelf(a?.executor?.id)) return;
        await raise({
            cat: "server", rule: "server_changed", key: "srv:" + (a?.executor?.id || "x"), severity: "medium", title: "تغيير إعدادات السيرفر",
            details: ch.join("\n"), actorId: a?.executor?.id, actorTag: tagOf(a?.executor),
        });
    });

    // ── الرسائل ──
    client.on("messageCreate", async m => {
        if (m.guildId !== G() || !m.author) return;
        cacheMsg(m);
        if (!m.author.bot && m.mentions.everyone) {
            const arr = (everyoneHits.get(m.author.id) || []).filter(t => Date.now() - t < 600000); arr.push(Date.now()); everyoneHits.set(m.author.id, arr);
            if (arr.length >= 3) await raise({
                cat: "everyone", rule: "everyone_spam", key: "ev:" + m.author.id, severity: "medium", title: "تكرار منشن @everyone / @here",
                details: arr.length + " منشن خلال 10 دقائق", actorId: m.author.id, actorTag: tagOf(m.author), count: arr.length,
                remedy: { type: "timeout", label: "⏳ تقييد ساعة", params: { userId: m.author.id, minutes: 60 } },
            });
        }
    });

    client.on("messageDelete", async msg => {
        if (msg.guildId !== G()) return;
        const c = msgCache.get(msg.id);
        const authorId = msg.author?.id || c?.authorId;
        if (isSelf(authorId)) return;
        const a = await findAudit(await getGuild(), AuditLogEvent.MessageDelete, x => x.extra?.channel?.id === msg.channelId && (!authorId || x.target?.id === authorId));
        const exId = a?.executor?.id;
        if (isSelf(exId)) return;
        const probot = exId === CONFIG.PROBOT_ID;
        const content = String(msg.content || c?.content || "").slice(0, 500);
        await LOGCAT({
            cat: "message", title: probot ? "حذف رسالة عبر ProBot" : "حذف رسالة",
            details: "الروم: #" + (msg.channel?.name || msg.channelId) + "\nصاحب الرسالة: " + (tagOf(msg.author) || c?.authorTag || "غير معروف") + "\nالمحتوى: " + (content || "(غير متوفر)"),
            actorId: exId || authorId, actorTag: a ? tagOf(a.executor) : (tagOf(msg.author) || c?.authorTag),
            targetId: authorId, targetTag: tagOf(msg.author) || c?.authorTag, data: { act: "msg_delete", probot },
        });
    });

    client.on("messageDeleteBulk", async (msgs, channel) => {
        if (!channel.guild || channel.guild.id !== G()) return;
        const list = [];
        msgs.forEach(m => {
            const c = msgCache.get(m.id) || {};
            list.push({
                id: m.id, authorId: m.author?.id || c.authorId, authorTag: tagOf(m.author) || c.authorTag || "غير معروف",
                content: String(m.content || c.content || "").slice(0, 300), att: m.attachments?.size || c.att || 0, at: m.createdTimestamp || c.at,
            });
        });
        list.sort((x, y) => (x.at || 0) - (y.at || 0));
        const a = await findAudit(channel.guild, AuditLogEvent.MessageBulkDelete, x => x.target?.id === channel.id);
        if (isSelf(a?.executor?.id)) return;
        const probot = a?.executor?.id === CONFIG.PROBOT_ID;
        // من هو اللي كتب أمر المسح (رسالة الأمر تنحذف مع المسح)
        const cmd = list.find(x => x.authorId && x.authorId !== CONFIG.PROBOT_ID && /^[-!.\/]?(clear|purge|prune|مسح|امسح)(\s|$)/i.test(x.content || ""));
        const invokerId = cmd?.authorId || a?.executor?.id || null;
        const invokerTag = cmd?.authorTag || tagOf(a?.executor);
        const count = msgs.size;
        const ev = await LOGCAT({
            cat: "message", title: (probot ? "مسح رسائل عبر ProBot" : "حذف جماعي للرسائل") + " (" + count + " رسالة)",
            details: "الروم: #" + channel.name + (probot && cmd ? "\nنفّذ أمر المسح: " + invokerTag : "") + (probot ? "\nالمنفّذ الفعلي: ProBot" : ""),
            actorId: invokerId, actorTag: invokerTag, count, data: { act: "bulk_delete", probot, channel: channel.name, messages: list.slice(0, 200) },
        });
        if (count >= 30) await raise({
            cat: "message", rule: "mass_msg_delete", key: "mmd:" + (invokerId || "x"), severity: "medium", title: "مسح رسائل ضخم (" + count + " رسالة)",
            details: "الروم: #" + channel.name + "\nالمنفّذ: " + (invokerTag || "غير معروف") + (probot ? " (عبر ProBot)" : ""), actorId: invokerId, actorTag: invokerTag,
            count, data: { act: "mass_msg_delete", probot, messages: list.slice(0, 200), channel: channel.name },
        });
        return ev;
    });

    client.on("error", e => console.log("client error:", e.message));
}

if (CONFIG.BOT_TOKEN) startBot();
else console.log("⚠️ BOT_TOKEN غير موجود");

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
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(e => { console.error("❌", req.method, req.path, e); if (!res.headersSent) res.status(500).json({ error: e.message || "صار خطأ بالسيرفر" }); });

const roleCheck = new Map();
const lastReason = new Map();
async function stillAuthorized(uid) {
    const c = roleCheck.get(uid);
    if (c && Date.now() - c.t < 30000) return c.ok;
    let ok = false, reason = "";
    try {
        if (!CONFIG.CYBER_ROLE_ID || /[^0-9]/.test(CONFIG.CYBER_ROLE_ID)) reason = "آيدي الرتبة CYBER_ROLE_ID ما انحط بالكود (لازم أرقام فقط). القيمة الحالية: " + CONFIG.CYBER_ROLE_ID;
        else if (!client || !client.isReady()) reason = "البوت مو شغال (تأكد من BOT_TOKEN وشوف Logs في Render).";
        else {
            let g = null;
            try { g = await getGuild(); } catch {}
            if (!g) reason = "البوت ما لقى السيرفر — GUILD_ID غلط أو البوت مو داخل السيرفر. القيمة الحالية: " + CONFIG.GUILD_ID;
            else {
                const m = await g.members.fetch({ user: uid }).catch(() => null);
                if (!m) reason = "ما لقيت حسابك داخل السيرفر «" + g.name + "» — تأكد إنك داخل نفس السيرفر اللي فيه البوت، ومن تفعيل Server Members Intent.";
                else if (!m.roles.cache.has(CONFIG.CYBER_ROLE_ID)) reason = "حسابك موجود بالسيرفر «" + g.name + "» لكن ما عنده الرتبة المطلوبة (" + CONFIG.CYBER_ROLE_ID + ").\nرتبك الحالية:\n" + m.roles.cache.filter(r => r.id !== g.id).map(r => r.name + " = " + r.id).join("\n");
                else ok = true;
            }
        }
    } catch (e) { reason = "خطأ: " + e.message; }
    roleCheck.set(uid, { ok, t: Date.now() });
    lastReason.set(uid, reason);
    return ok;
}
const auth = wrap(async (req, res, next) => {
    const u = req.session.user;
    if (!u) return res.status(401).json({ error: "سجّل دخولك" });
    if (!(await stillAuthorized(u.id))) { req.session.destroy(() => {}); return res.status(401).json({ error: "تم سحب صلاحيتك" }); }
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
    const allowed = await stillAuthorized(u.id);
    if (!allowed) {
        await LOGCAT({ cat: "panel", severity: "medium", title: "محاولة دخول مرفوضة للوحة", details: "ما معه رتبة الأمن السيبراني", actorId: u.id, actorTag: u.username, data: { act: "panel_denied" } });
        req.session.denied = true;
        return req.session.save(() => res.redirect("/?denied=1"));
    }
    req.session.user = {
        id: u.id, tag: u.global_name || u.username,
        avatar: u.avatar ? "https://cdn.discordapp.com/avatars/" + u.id + "/" + u.avatar + ".png?size=64" : "https://cdn.discordapp.com/embed/avatars/0.png",
    };
    delete req.session.denied;
    await LOGCAT({ cat: "panel", title: "تسجيل دخول للوحة", details: "", actorId: u.id, actorTag: u.username, data: { act: "panel_login" } });
    req.session.save(() => res.redirect("/"));
}));
app.get("/auth/logout", (req, res) => req.session.destroy(() => res.redirect("/")));

// ── API: من أنا ──
app.get("/api/me", auth, (req, res) => res.json({ user: req.session.user, presence: PRESENCE_OK }));

// ── API: اللوق ──
const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
app.get("/api/events", auth, wrap(async (req, res) => {
    const { q, cat, unres, before } = req.query;
    const f = {};
    if (cat === "sus") f.kind = "suspicious";
    else if (cat === "newacc") f.rule = "new_account";
    else if (cat === "probot") f["data.probot"] = true;
    else if (cat) f.cat = cat;
    if (unres === "1") { f.kind = "suspicious"; f.resolved = false; }
    if (before) f.createdAt = { $lt: new Date(Number(before)) };
    if (q && String(q).trim()) {
        const t = String(q).trim(), re = new RegExp(escRe(t), "i");
        f.$or = [{ actorId: t }, { targetId: t }, { actorTag: re }, { targetTag: re }];
    }
    const list = await Event.find(f).sort({ createdAt: -1 }).limit(50).select("-data.messages").lean();
    res.json({ events: list.map(e => ({ ...e, hasMsgs: !!(e.data && (e.data.act === "bulk_delete" || e.data.act === "mass_msg_delete")) })) });
}));
app.get("/api/events/:id/messages", auth, wrap(async (req, res) => {
    const e = await Event.findById(req.params.id).lean();
    res.json({ messages: (e && e.data && e.data.messages) || [], channel: e?.data?.channel, probot: !!e?.data?.probot, title: e?.title });
}));

async function panelLog(req, title, details, extra = {}) {
    await LOGCAT({ cat: "panel", title, details, actorId: req.session.user.id, actorTag: req.session.user.tag, data: { act: "panel_action" }, ...extra });
}

// ── تنفيذ العلاج (الأزرار) ──
async function runRemedy(g, r, who) {
    const reason = "لوحة الأمن السيبراني — " + who;
    const p = r.params || {};
    switch (r.type) {
        case "kick_member": {
            const m = await g.members.fetch(p.userId).catch(() => null);
            if (!m) throw new Error("العضو مو موجود بالسيرفر (طلع أو انطرد)");
            if (!m.kickable) throw new Error("ما أقدر أطرده — رتبته أعلى من البوت");
            await m.kick(reason); return "تم الطرد";
        }
        case "kick_many": {
            let ok = 0;
            for (const id of p.userIds || []) { const m = await g.members.fetch(id).catch(() => null); if (m && m.kickable) { await m.kick(reason).catch(() => {}); ok++; } }
            return "تم طرد " + ok + " عضو";
        }
        case "delete_roles": {
            let ok = 0;
            for (const id of p.roleIds || []) { const ro = g.roles.cache.get(id); if (ro && ro.editable) { await ro.delete(reason).catch(() => {}); ok++; } }
            return "تم حذف " + ok + " رتبة";
        }
        case "delete_channels": {
            let ok = 0;
            for (const id of p.channelIds || []) { const c = g.channels.cache.get(id); if (c && c.deletable) { await c.delete(reason).catch(() => {}); ok++; } }
            return "تم حذف " + ok + " قناة";
        }
        case "strip_roles": {
            const m = await g.members.fetch(p.userId).catch(() => null);
            if (!m) throw new Error("العضو مو موجود بالسيرفر");
            const keep = m.roles.cache.filter(x => x.id === g.id || x.managed || !x.editable);
            const removed = m.roles.cache.size - keep.size;
            await m.roles.set(keep.map(x => x.id), reason);
            return "تم سحب " + removed + " رتبة" + (keep.size > 1 ? " (بعض الرتب أعلى من البوت وما انسحبت)" : "");
        }
        case "remove_role": {
            const m = await g.members.fetch(p.userId).catch(() => null);
            if (!m) throw new Error("العضو مو موجود بالسيرفر");
            await m.roles.remove(p.roleId, reason); return "تم سحب الرتبة";
        }
        case "revoke_perms": {
            const ro = g.roles.cache.get(p.roleId);
            if (!ro) throw new Error("الرتبة انحذفت");
            if (!ro.editable) throw new Error("ما أقدر أعدّل الرتبة — أعلى من رتبة البوت");
            const keep = ro.permissions.toArray().filter(n => !(p.perms || []).includes(n));
            await ro.setPermissions(new PermissionsBitField(keep.map(n => P[n])), reason); return "تم سحب الصلاحيات الخطيرة";
        }
        case "delete_webhook": {
            const whs = await g.fetchWebhooks();
            const w = whs.get(p.webhookId);
            if (!w) throw new Error("الويبهوك انحذف");
            await w.delete(reason); return "تم حذف الويبهوك";
        }
        case "timeout": {
            const m = await g.members.fetch(p.userId).catch(() => null);
            if (!m) throw new Error("العضو مو موجود بالسيرفر");
            if (!m.moderatable) throw new Error("ما أقدر أقيّده — رتبته أعلى من البوت");
            await m.timeout((p.minutes || 60) * 60000, reason); return "تم التقييد";
        }
    }
    throw new Error("إجراء غير معروف");
}
app.post("/api/events/:id/remedy", auth, wrap(async (req, res) => {
    const e = await Event.findById(req.params.id);
    if (!e || !e.remedy) return res.status(404).json({ error: "ما فيه إجراء لهذي العملية" });
    if (e.resolved) return res.status(400).json({ error: "العملية محلولة من قبل" });
    const g = await getGuild();
    const msg = await runRemedy(g, e.remedy, req.session.user.tag);
    e.resolved = true; e.resolvedBy = req.session.user.tag; e.resolvedAt = new Date(); e.updatedAt = new Date(); await e.save();
    await panelLog(req, "تنفيذ إجراء: " + e.remedy.label.replace(/^\S+\s/, ""), "العملية: " + e.title + " — " + msg);
    res.json({ ok: true, msg });
}));
app.post("/api/events/:id/resolve", auth, wrap(async (req, res) => {
    const e = await Event.findById(req.params.id);
    if (!e) return res.status(404).json({ error: "غير موجودة" });
    e.resolved = true; e.resolvedBy = req.session.user.tag; e.resolvedAt = new Date(); e.updatedAt = new Date(); await e.save();
    await panelLog(req, "حل عملية مشبوهة", "العملية: " + e.title);
    res.json({ ok: true });
}));

// ── API: البوتات ──
const KNOWN_BOTS = [
    [/probot/i, "بوت إدارة عام: ترحيب، حماية، مسح الرسائل (clear)، لوق، مستويات ورتب تلقائية."],
    [/mee6/i, "بوت إدارة: مستويات، ترحيب، مودريشن، رتب تلقائية."],
    [/dyno/i, "بوت مودريشن: عقوبات، أوامر مخصصة، رتب تلقائية، لوق."],
    [/carl/i, "بوت رتب تفاعلية ولوق ومودريشن."],
    [/wick/i, "بوت حماية من الغارات والسبام والحسابات الجديدة."],
    [/ticket/i, "بوت نظام التذاكر (فتح وإغلاق تذاكر الدعم)."],
    [/sapphire/i, "بوت إدارة: لوق، مودريشن، ترحيب، رتب تفاعلية."],
    [/dank|owo|mudae|mimu/i, "بوت ترفيه/ألعاب واقتصاد."],
    [/fredboat|jockie|groovy|rythm|music|hydra/i, "بوت موسيقى بالرومات الصوتية."],
    [/discord ?servers|disboard/i, "بوت نشر وترويج السيرفر."],
    [/giveaway/i, "بوت مسابقات وهدايا."],
];
function botInfo(m) {
    const hit = KNOWN_BOTS.find(([re]) => re.test(m.user.username));
    const perms = m.permissions.toArray();
    const dang = perms.filter(isDanger);
    let desc = hit ? hit[1] : "بوت غير معروف — راجع صلاحياته أدناه وتأكد إنه موثوق.";
    if (perms.includes("Administrator")) desc += " ⚠️ عنده صلاحية مدير كاملة.";
    return { desc, dang: dang.map(n => ({ k: n, ar: PERM_AR[n] || n, level: DANGER_LEVEL[n] })) };
}
async function botList() {
    const g = await getGuild();
    const bots = g.members.cache.filter(m => m.user.bot && m.id !== client.user.id);
    const since = new Date(Date.now() - 864e5);
    const acts = await Event.aggregate([
        { $match: { actorId: { $in: [...bots.keys()] }, createdAt: { $gte: since } } },
        { $group: { _id: { a: "$actorId", t: "$title" }, n: { $sum: 1 } } },
    ]);
    const actMap = {};
    acts.forEach(x => { (actMap[x._id.a] = actMap[x._id.a] || []).push(x._id.t + " ×" + x.n); });
    const addedBy = {};
    (await Event.find({ rule: "bot_added", targetId: { $in: [...bots.keys()] } }).lean()).forEach(e => { addedBy[e.targetId] = e.actorTag; });
    return bots.map(m => {
        const st = PRESENCE_OK ? (m.presence?.status || "offline") : "unknown";
        const info = botInfo(m);
        return {
            id: m.id, name: m.user.username, avatar: m.user.displayAvatarURL({ size: 64 }), status: st,
            desc: info.desc, dang: info.dang, joinedAt: m.joinedTimestamp, addedBy: addedBy[m.id] || null,
            activity: actMap[m.id] || [],
        };
    }).sort((a, b) => (b.dang.length - a.dang.length));
}
app.get("/api/bots", auth, wrap(async (req, res) => res.json({ bots: await botList(), presence: PRESENCE_OK })));
app.post("/api/bots/:id/kick", auth, wrap(async (req, res) => {
    const g = await getGuild();
    const m = await g.members.fetch(req.params.id).catch(() => null);
    if (!m || !m.user.bot) return res.status(404).json({ error: "البوت مو موجود" });
    if (!m.kickable) return res.status(400).json({ error: "ما أقدر أطرده — رتبته أعلى من رتبة بوت الحماية" });
    await m.kick("لوحة الأمن السيبراني — " + req.session.user.tag);
    await panelLog(req, "طرد بوت", "البوت: " + m.user.username, { targetId: m.id, targetTag: m.user.username });
    res.json({ ok: true });
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
    const bots = await botList();
    const online = bots.filter(b => b.status !== "offline" && b.status !== "unknown");
    const offline = bots.filter(b => b.status === "offline");
    const g = await getGuild();
    res.json({
        week: sus.length, unresolved: sus.filter(e => !e.resolved).length, resolved: sus.filter(e => e.resolved).length,
        days, byRule, members: g.memberCount, presence: PRESENCE_OK,
        bots: { total: bots.length, online: online.map(b => ({ id: b.id, name: b.name, status: b.status })), offline: offline.map(b => ({ id: b.id, name: b.name })) },
    });
}));

// ── API: صلاحيات السيرفر ──
app.get("/api/perms/meta", auth, (req, res) => res.json({ role: permMeta(ROLE_PERMS), channel: permMeta(CHANNEL_PERMS) }));
app.get("/api/perms/roles", auth, wrap(async (req, res) => {
    const g = await getGuild();
    const roles = [...g.roles.cache.values()].sort((a, b) => b.position - a.position).map(r => {
        const perms = r.permissions.toArray();
        return { id: r.id, name: r.name, color: r.hexColor, members: r.members.size, perms, dang: perms.filter(isDanger), editable: r.editable && !r.managed, managed: r.managed, everyone: r.id === g.id };
    });
    res.json({ roles });
}));
app.put("/api/perms/roles/:id", auth, wrap(async (req, res) => {
    const g = await getGuild();
    const r = g.roles.cache.get(req.params.id);
    if (!r) return res.status(404).json({ error: "الرتبة مو موجودة" });
    if (!r.editable || r.managed) return res.status(400).json({ error: "ما أقدر أعدّل هذي الرتبة — أعلى من رتبة البوت أو رتبة بوت" });
    const perms = (req.body.perms || []).filter(n => ROLE_PERMS.includes(n));
    const before = r.permissions.toArray();
    await r.setPermissions(new PermissionsBitField(perms.map(n => P[n])), "لوحة الأمن السيبراني — " + req.session.user.tag);
    const add = perms.filter(n => !before.includes(n)), rem = before.filter(n => !perms.includes(n));
    await panelLog(req, "تعديل صلاحيات رتبة", "الرتبة: " + r.name + (add.length ? "\n➕ " + add.map(n => PERM_AR[n] || n).join("، ") : "") + (rem.length ? "\n➖ " + rem.map(n => PERM_AR[n] || n).join("، ") : ""), { targetId: r.id, targetTag: r.name });
    res.json({ ok: true });
}));
const chIcon = t => ({ 0: "💬", 2: "🔊", 4: "📁", 5: "📢", 13: "🎙️", 15: "🗂️" }[t] || "#");
app.get("/api/perms/channels", auth, wrap(async (req, res) => {
    const g = await getGuild();
    const chans = [...g.channels.cache.values()].filter(c => c.permissionOverwrites).sort((a, b) => a.rawPosition - b.rawPosition).map(c => {
        const ov = [...c.permissionOverwrites.cache.values()].map(o => {
            const allow = new PermissionsBitField(o.allow).toArray().filter(n => CHANNEL_PERMS.includes(n));
            const deny = new PermissionsBitField(o.deny).toArray().filter(n => CHANNEL_PERMS.includes(n));
            const name = o.type === 0 ? (g.roles.cache.get(o.id)?.name || o.id) : (g.members.cache.get(o.id)?.user.username || o.id);
            return { id: o.id, type: o.type === 0 ? "role" : "member", name, allow, deny, dang: allow.filter(isDanger) };
        }).sort((a, b) => b.dang.length - a.dang.length);
        return { id: c.id, name: c.name, icon: chIcon(c.type), parent: c.parent?.name || null, overwrites: ov, hasDanger: ov.some(o => o.dang.length) };
    });
    res.json({ channels: chans });
}));
app.put("/api/perms/channels/:id/:tid", auth, wrap(async (req, res) => {
    const g = await getGuild();
    const c = g.channels.cache.get(req.params.id);
    if (!c || !c.permissionOverwrites) return res.status(404).json({ error: "القناة مو موجودة" });
    const allow = req.body.allow || [], deny = req.body.deny || [];
    const obj = {};
    CHANNEL_PERMS.forEach(n => { obj[n] = allow.includes(n) ? true : deny.includes(n) ? false : null; });
    await c.permissionOverwrites.edit(req.params.tid, obj, { reason: "لوحة الأمن السيبراني — " + req.session.user.tag });
    await panelLog(req, "تعديل صلاحيات قناة", "القناة: #" + c.name + "\nالهدف: " + (req.body.name || req.params.tid), { targetId: c.id, targetTag: c.name });
    res.json({ ok: true });
}));

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
.tabs { display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap; }
.tab { background:rgba(255,255,255,0.04); border:1px solid rgba(59,130,246,0.3); padding:9px 18px; border-radius:8px; cursor:pointer; font-size:13px; color:#94a3b8; font-family:inherit; }
.tab.active { background:var(--green2); color:#fff; border-color:var(--green2); }
.chip { display:inline-block; padding:2px 9px; border-radius:20px; font-size:11px; font-weight:bold; margin:2px 0 2px 4px; }
.chip.critical { background:rgba(239,68,68,0.18); color:#fca5a5; border:1px solid #ef4444; }
.chip.high { background:rgba(234,179,8,0.15); color:#fbbf24; border:1px solid #eab308; }
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
`;

const HEAD = (title) => `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
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
var S={page:'logs',q:'',cat:'',unres:false,events:[],sig:'',timer:null,permsTab:'roles',permsView:'danger',meta:null,presence:true};
var CATS=[['','الكل'],['sus','⚠️ العمليات المشبوهة'],['newacc','🆕 حسابات جديدة'],['join','دخول'],['leave','خروج'],['kick','طرد'],['ban','حظر'],['role','الرتب'],['channel','القنوات'],['message','الرسائل المحذوفة'],['probot','🧹 حذف عبر ProBot'],['bot','البوتات'],['webhook','ويبهوكس'],['everyone','منشن everyone'],['server','إعدادات السيرفر'],['panel','عمليات اللوحة']];
var RULE_AR={new_account:'حساب جديد',mass_roles_created:'رتب جماعية',mass_role_delete:'حذف رتب',mass_channel_create:'إنشاء قنوات',mass_channel_delete:'حذف قنوات',mass_ban:'حظر جماعي',mass_kick:'طرد جماعي',dangerous_perm_grant:'صلاحيات خطيرة',dangerous_role_assigned:'رتبة خطيرة',bot_added:'بوت جديد',webhook_created:'ويبهوك',everyone_spam:'منشن everyone',mass_join:'غارة دخول',mass_msg_delete:'مسح ضخم',server_changed:'إعدادات السيرفر'};
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function toast(m){var t=$('toast');t.textContent=m;t.style.display='block';clearTimeout(t._t);t._t=setTimeout(function(){t.style.display='none';},3200);}
function fmt(d){try{return new Date(d).toLocaleString('ar-SA',{timeZone:'Asia/Riyadh',hour12:true,dateStyle:'medium',timeStyle:'short'});}catch(e){return new Date(d).toLocaleString();}}
function ago(d){var s=Math.floor((Date.now()-new Date(d).getTime())/1000);if(s<60)return 'الحين';if(s<3600)return 'قبل '+Math.floor(s/60)+' دقيقة';if(s<86400)return 'قبل '+Math.floor(s/3600)+' ساعة';return 'قبل '+Math.floor(s/86400)+' يوم';}
async function api(url,opt){
  var r=await fetch(url,Object.assign({headers:{'Content-Type':'application/json'}},opt||{}));
  if(r.status===401){location.href='/';throw new Error('غير مصرح');}
  var j=await r.json().catch(function(){return {};});
  if(!r.ok)throw new Error(j.error||'صار خطأ');
  return j;
}
function modal(html){closeModal();var o=document.createElement('div');o.className='ov';o.id='ov';o.innerHTML='<div class="modal">'+html+'</div>';o.addEventListener('mousedown',function(e){if(e.target===o)closeModal();});document.body.appendChild(o);}
function closeModal(){var o=$('ov');if(o)o.remove();}
function ask(msg){return new Promise(function(res){modal('<h3>تأكيد</h3><p style="line-height:1.8;margin-bottom:16px;white-space:pre-line">'+esc(msg)+'</p><div class="row" style="justify-content:flex-start"><button class="btn danger" id="ask-y">تأكيد</button><button class="btn gray" id="ask-n">إلغاء</button></div>');$('ask-y').onclick=function(){closeModal();res(true);};$('ask-n').onclick=function(){closeModal();res(false);};});}

/* ── التنقل ── */
function buildNav(){
  $('navlinks').innerHTML=PAGES.map(function(p){return '<button class="'+(S.page===p[0]?'on':'')+'" onclick="go(\''+p[0]+'\')">'+p[1]+'</button>';}).join('');
  $('drawer-items').innerHTML=PAGES.map(function(p){return '<button class="item '+(S.page===p[0]?'on':'')+'" onclick="go(\''+p[0]+'\')">'+p[1]+'</button>';}).join('');
}
function openDrawer(){$('drawer').classList.add('open');$('dov').classList.add('open');}
function closeDrawer(){$('drawer').classList.remove('open');$('dov').classList.remove('open');}
function go(p){S.page=p;closeDrawer();clearInterval(S.timer);buildNav();render();}
function render(){var f={logs:pgLogs,stats:pgStats,bots:pgBots,perms:pgPerms}[S.page];f();}

/* ══ اللوق ══ */
function pgLogs(){
  var opts=CATS.map(function(c){return '<option value="'+c[0]+'"'+(S.cat===c[0]?' selected':'')+'>'+c[1]+'</option>';}).join('');
  $('main').innerHTML='<h2>📜 اللوق الشامل</h2><div class="card"><div class="filters">'
   +'<input id="f-q" placeholder="🔎 فرز حسب الشخص (اسم أو آيدي)" value="'+esc(S.q)+'">'
   +'<select id="f-cat">'+opts+'</select>'
   +'<label class="chk"><input type="checkbox" id="f-un"'+(S.unres?' checked':'')+'> غير المحلولة فقط</label></div></div>'
   +'<div id="evlist"><div class="card center muted">جاري التحميل...</div></div><div class="center"><button class="btn gray" id="more" style="display:none" onclick="moreEvents()">تحميل المزيد</button></div>';
  var t;$('f-q').oninput=function(){S.q=this.value;clearTimeout(t);t=setTimeout(loadEvents,350);};
  $('f-cat').onchange=function(){S.cat=this.value;loadEvents();};
  $('f-un').onchange=function(){S.unres=this.checked;loadEvents();};
  loadEvents();
  S.timer=setInterval(function(){if(!$('ov'))loadEvents(true);},6000);
}
function qs(before){return '/api/events?q='+encodeURIComponent(S.q)+'&cat='+encodeURIComponent(S.cat)+'&unres='+(S.unres?1:0)+(before?'&before='+before:'');}
async function loadEvents(silent){
  try{
    var j=await api(qs());
    var sig=j.events.map(function(e){return e._id+e.updatedAt+e.resolved;}).join('|');
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
  if(sus&&!e.resolved){
    if(e.remedy)acts+='<button class="btn sm danger" onclick="doRemedy(\''+e._id+'\',this)">'+esc(e.remedy.label)+'</button>';
    acts+='<button class="btn sm ok" onclick="doResolve(\''+e._id+'\',this)">✅ حل العملية</button>';
  }
  return '<div class="'+cls+'"><div class="log-body"><div class="log-title">'+badge+'<span>'+esc(e.title)+'</span>'+(e.count>1&&sus?'<span class="badge low">×'+e.count+'</span>':'')+'</div>'
    +(e.details?'<div class="log-det">'+esc(e.details)+'</div>':'')+'<div class="log-meta">'+meta+'</div></div><div class="log-act">'+acts+'</div></div>';
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
    html+=j.messages.length?j.messages.map(function(m){return '<div class="msg"><b>'+esc(m.authorTag)+'</b> <span class="muted" style="font-size:11px">'+(m.at?fmt(m.at):'')+'</span><br>'+(m.content?esc(m.content):'<span class="muted">(بدون نص)</span>')+(m.att?' <span class="chip safe">📎 '+m.att+' مرفق</span>':'')+'</div>';}).join(''):'<p class="center muted">الرسائل ما انحفظت (كانت قبل تشغيل البوت)</p>';
    html+='<div style="margin-top:14px"><button class="btn gray" onclick="closeModal()">إغلاق</button></div>';
    modal(html);
  }catch(e){toast(e.message);}
}

/* ══ الإحصائيات ══ */
async function pgStats(){
  $('main').innerHTML='<h2>📊 الإحصائيات</h2><div class="card center muted">جاري التحميل...</div>';
  try{
    var s=await api('/api/stats');if(S.page!=='stats')return;
    var max=Math.max.apply(null,s.days.map(function(d){return d.n;}).concat([1]));
    var wd=['الأحد','الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'];
    var bars=s.days.map(function(d){var dt=new Date(d.d+'T12:00:00Z');return '<div class="bar"><b>'+d.n+'</b><i style="height:'+Math.round(d.n/max*100)+'%"></i>'+wd[dt.getUTCDay()]+'</div>';}).join('');
    var rules=Object.keys(s.byRule).sort(function(a,b){return s.byRule[b]-s.byRule[a];}).map(function(k){return '<div class="prow"><span>'+esc(RULE_AR[k]||k)+'</span><b>'+s.byRule[k]+'</b></div>';}).join('')||'<p class="muted center">ما فيه عمليات مشبوهة هذا الأسبوع 👌</p>';
    var on=s.bots.online.map(function(b){return '<div class="prow"><span><i class="st '+b.status+'"></i>'+esc(b.name)+'</span></div>';}).join('')||'<p class="muted center">لا أحد</p>';
    var off=s.bots.offline.map(function(b){return '<div class="prow"><span><i class="st offline"></i>'+esc(b.name)+'</span></div>';}).join('')||'<p class="muted center">لا أحد</p>';
    $('main').innerHTML='<h2>📊 الإحصائيات</h2>'
     +'<div class="grid4"><div class="stat red"><div class="num">'+s.week+'</div><div class="lbl">عمليات مشبوهة (آخر 7 أيام)</div></div>'
     +'<div class="stat amber"><div class="num">'+s.unresolved+'</div><div class="lbl">غير محلولة</div></div>'
     +'<div class="stat green"><div class="num">'+s.resolved+'</div><div class="lbl">محلولة</div></div>'
     +'<div class="stat"><div class="num">'+s.members+'</div><div class="lbl">أعضاء السيرفر</div></div></div>'
     +'<div class="card"><h3>العمليات المشبوهة خلال الأسبوع</h3><div class="bars">'+bars+'</div></div>'
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
      return '<div class="card"><div class="bot"><img src="'+esc(b.avatar)+'" alt=""><div style="flex:1;min-width:200px">'
       +'<div class="log-title">'+esc(b.name)+' <span class="badge low"><i class="st '+b.status+'"></i>'+stAr[b.status]+'</span></div>'
       +'<div class="log-det">🧩 '+esc(b.desc)+'</div>'
       +(b.dang.length?'<div style="margin-top:6px">'+b.dang.map(function(d){return '<span class="chip '+d.level+'">'+esc(d.ar)+'</span>';}).join('')+'</div>':'')
       +(b.activity.length?'<div class="log-meta">⚙️ نشاطه آخر 24 ساعة: '+esc(b.activity.slice(0,4).join(' • '))+'</div>':'<div class="log-meta">⚙️ لا يوجد نشاط مسجّل آخر 24 ساعة</div>')
       +'<div class="log-meta">📥 دخل: '+(b.joinedAt?fmt(b.joinedAt):'-')+(b.addedBy?' • أضافه: '+esc(b.addedBy):'')+'</div></div>'
       +'<button class="btn sm danger" onclick="kickBot(\''+b.id+'\',\''+esc(b.name).replace(/'/g,'')+'\')">👢 طرد</button></div></div>';
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
  $('main').innerHTML='<h2>🔐 صلاحيات السيرفر</h2>'
   +'<div class="tabs"><button class="tab '+(S.permsTab==='roles'?'active':'')+'" onclick="S.permsTab=\'roles\';pgPerms()">👥 قسم الرتب</button>'
   +'<button class="tab '+(S.permsTab==='channels'?'active':'')+'" onclick="S.permsTab=\'channels\';pgPerms()">💬 قسم الشاتات</button></div>'
   +'<div class="tabs"><button class="tab '+(S.permsView==='danger'?'active':'')+'" onclick="S.permsView=\'danger\';pgPerms()">⚠️ الخطرة فقط</button>'
   +'<button class="tab '+(S.permsView==='all'?'active':'')+'" onclick="S.permsView=\'all\';pgPerms()">📋 الكل</button></div><div id="pbox"><div class="card center muted">جاري التحميل...</div></div>';
  try{ if(S.permsTab==='roles')await drawRoles();else await drawChannels(); }catch(e){toast(e.message);}
}
function permChips(list,metaList){
  return list.map(function(k){var m=metaList.find(function(x){return x.k===k;})||{ar:k};return '<span class="chip '+(m.danger||'safe')+'">'+esc(m.ar)+'</span>';}).join('');
}
async function drawRoles(){
  var j=await api('/api/perms/roles');S.roles=j.roles;
  var list=S.permsView==='danger'?j.roles.filter(function(r){return r.dang.length;}):j.roles;
  var html=list.map(function(r){
    var shown=S.permsView==='danger'?r.dang:r.perms;
    return '<div class="card"><div class="row"><div><div class="log-title"><span><i class="dot" style="background:'+(r.color&&r.color!=='#000000'?r.color:'#64748b')+'"></i>'+esc(r.name)+'</span>'
     +(r.dang.length?'<span class="badge high">'+r.dang.length+' خطيرة</span>':'<span class="badge done">آمنة</span>')+'</div><div class="log-meta">👥 '+r.members+' عضو</div></div>'
     +'<button class="btn sm '+(r.editable?'':'gray')+'" onclick="editRole(\''+r.id+'\')">'+(r.editable?'✏️ عرض وتعديل':'👁️ عرض فقط')+'</button></div>'
     +'<div style="margin-top:8px">'+(shown.length?permChips(shown,S.meta.role):'<span class="muted" style="font-size:12px">لا صلاحيات</span>')+'</div></div>';
  }).join('')||'<div class="card center muted">ما فيه رتب بصلاحيات خطيرة 👌</div>';
  $('pbox').innerHTML=html;
}
function editRole(id){
  var r=S.roles.find(function(x){return x.id===id;});
  var rows=S.meta.role.map(function(p){
    return '<div class="prow '+(p.danger==='critical'?'crit':p.danger==='high'?'hi':'')+'"><span>'+(p.danger?'<span class="chip '+p.danger+'">'+(p.danger==='critical'?'خطيرة جداً':'خطيرة')+'</span>':'')+esc(p.ar)+'</span>'
     +'<label class="sw"><input type="checkbox" data-k="'+p.k+'"'+(r.perms.indexOf(p.k)>-1?' checked':'')+(r.editable?'':' disabled')+'><span></span></label></div>';
  }).join('');
  modal('<h3>صلاحيات الرتبة: '+esc(r.name)+'</h3>'+(r.editable?'':'<div class="warn">هذي الرتبة أعلى من رتبة البوت (أو رتبة بوت) — للعرض فقط.</div>')
   +'<div style="max-height:60vh;overflow-y:auto">'+rows+'</div><div class="row" style="justify-content:flex-start;margin-top:14px">'
   +(r.editable?'<button class="btn" id="rs">💾 حفظ</button>':'')+'<button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  if(r.editable)$('rs').onclick=async function(){
    var perms=[].slice.call(document.querySelectorAll('.modal input[data-k]')).filter(function(i){return i.checked;}).map(function(i){return i.getAttribute('data-k');});
    if(perms.indexOf('Administrator')>-1&&r.perms.indexOf('Administrator')<0&&!(await ask('تفعيل صلاحية المدير (Administrator) يعطي الرتبة كل الصلاحيات. متأكد؟')))return;
    this.disabled=true;
    try{await api('/api/perms/roles/'+id,{method:'PUT',body:JSON.stringify({perms:perms})});toast('تم حفظ الصلاحيات');closeModal();drawRoles();}catch(e){toast(e.message);this.disabled=false;}
  };
}
async function drawChannels(){
  var j=await api('/api/perms/channels');S.chans=j.channels;
  var list=S.permsView==='danger'?j.channels.filter(function(c){return c.hasDanger;}):j.channels.filter(function(c){return c.overwrites.length;});
  var html=list.map(function(c){
    var ovs=(S.permsView==='danger'?c.overwrites.filter(function(o){return o.dang.length;}):c.overwrites).map(function(o){
      return '<div class="prow"><span><b>'+(o.type==='role'?'👥 ':'👤 ')+esc(o.name)+'</b> '+(o.dang.length?permChips(o.dang,S.meta.channel):'<span class="chip safe">بدون صلاحيات خطيرة</span>')+'</span>'
       +'<button class="btn sm" onclick="editOv(\''+c.id+'\',\''+o.id+'\')">✏️ تعديل</button></div>';
    }).join('');
    return '<div class="card"><div class="log-title"><span>'+c.icon+' '+esc(c.name)+'</span>'+(c.parent?'<span class="muted" style="font-size:12px">'+esc(c.parent)+'</span>':'')+(c.hasDanger?'<span class="badge high">صلاحيات خطيرة</span>':'')+'</div>'+ovs+'</div>';
  }).join('')||'<div class="card center muted">ما فيه قنوات بصلاحيات خطيرة 👌</div>';
  $('pbox').innerHTML=html;
}
function editOv(cid,tid){
  var c=S.chans.find(function(x){return x.id===cid;});var o=c.overwrites.find(function(x){return x.id===tid;});
  var rows=S.meta.channel.map(function(p){
    var st=o.allow.indexOf(p.k)>-1?'a':o.deny.indexOf(p.k)>-1?'d':'n';
    return '<div class="prow '+(p.danger==='critical'?'crit':p.danger==='high'?'hi':'')+'" data-k="'+p.k+'" data-s="'+st+'"><span>'+(p.danger?'<span class="chip '+p.danger+'">'+(p.danger==='critical'?'خطيرة جداً':'خطيرة')+'</span>':'')+esc(p.ar)+'</span>'
     +'<div class="tri"><button class="a '+(st==='a'?'on':'')+'" onclick="setTri(this,\'a\')">✓</button><button class="n '+(st==='n'?'on':'')+'" onclick="setTri(this,\'n\')">—</button><button class="d '+(st==='d'?'on':'')+'" onclick="setTri(this,\'d\')">✗</button></div></div>';
  }).join('');
  modal('<h3>'+esc(c.name)+' — '+esc(o.name)+'</h3><p class="muted center" style="font-size:12px;margin-bottom:8px">✓ سماح &nbsp; — افتراضي &nbsp; ✗ منع</p><div style="max-height:60vh;overflow-y:auto">'+rows+'</div>'
   +'<div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn" id="os">💾 حفظ</button><button class="btn gray" onclick="closeModal()">إغلاق</button></div>');
  $('os').onclick=async function(){
    var allow=[],deny=[];
    document.querySelectorAll('.modal .prow[data-k]').forEach(function(r){var s=r.getAttribute('data-s');if(s==='a')allow.push(r.getAttribute('data-k'));if(s==='d')deny.push(r.getAttribute('data-k'));});
    this.disabled=true;
    try{await api('/api/perms/channels/'+cid+'/'+tid,{method:'PUT',body:JSON.stringify({allow:allow,deny:deny,name:o.name})});toast('تم الحفظ');closeModal();drawChannels();}catch(e){toast(e.message);this.disabled=false;}
  };
}
function setTri(b,s){var row=b.closest('.prow');row.setAttribute('data-s',s);row.querySelectorAll('.tri button').forEach(function(x){x.classList.remove('on');});b.classList.add('on');}

/* ── تشغيل ── */
(async function(){
  try{
    var me=await api('/api/me');S.presence=me.presence;
    $('uchip').innerHTML='<img src="'+esc(me.user.avatar)+'" alt=""><span>'+esc(me.user.tag)+'</span><a class="btn sm gray" href="/auth/logout">خروج</a>';
    buildNav();render();
  }catch(e){}
})();
`;

function appPage() {
    return HEAD(CONFIG.SITE_NAME + " — " + CONFIG.SITE_SUB) + `<body>
<nav>
  <div class="nav-start"><button class="hamburger-btn" onclick="openDrawer()" aria-label="القائمة">☰</button><div class="logo">🛡️ ${CONFIG.SITE_NAME} — ${CONFIG.SITE_SUB}</div></div>
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

app.listen(CONFIG.PORT, "0.0.0.0", () => console.log("🚀 " + CONFIG.SITE_NAME + " running on port " + CONFIG.PORT));
