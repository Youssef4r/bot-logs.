const { Client, GatewayIntentBits, EmbedBuilder, Partials, time, AuditLogEvent, Events } = require('discord.js');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-discord');
const { QuickDB } = require("quick.db");
const db = new QuickDB();
const config = require('./config.json');

// ================= [ نظام الإدارة ] =================
const SUPER_ADMIN_IDS = ['1404043575741911043']; // أضف أيدي الديسكورد الخاص بك هنا
const BANNED_ACCOUNTS = new Set(); // حساب محظور مؤقتاً
let adminAccounts = new Map(); // لحفظ حسابات الأدمن

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildVoiceStates,
        GatewayIntentBits.GuildModeration,
        GatewayIntentBits.GuildMessageReactions,
        GatewayIntentBits.GuildPresences,
        GatewayIntentBits.GuildBans,
        GatewayIntentBits.GuildInvites,
        GatewayIntentBits.GuildWebhooks,
        GatewayIntentBits.GuildEmojisAndStickers,
        GatewayIntentBits.GuildMessageTyping
    ],
    partials: [Partials.Message, Partials.Channel, Partials.GuildMember, Partials.User, Partials.Reaction]
});

const app = express();
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ 
    secret: 'alomda_secret_2026', 
    resave: false, 
    saveUninitialized: true,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 يوم
}));
app.use(passport.initialize());
app.use(passport.session());

// ================= [ Middleware للتحقق من الحظر ] =================
app.use(async (req, res, next) => {
    try {
        if (req.isAuthenticated() && req.session.isLogged) {
            // تحميل قائمة المحظورين من قاعدة البيانات
            const bannedList = await db.get('banned_accounts') || [];
            
            // التحقق إذا كان المستخدم مشرفاً محظوراً
            const adminBanList = await db.get('banned_admins') || [];
            
            if (bannedList.includes(req.user.id) || 
                BANNED_ACCOUNTS.has(req.user.id) ||
                adminBanList.includes(req.user.id)) {
                
                console.log(`🚫 Middleware: حساب محظور حاول الوصول: ${req.user.username}`);
                
                // حذف الجلسة
                req.session.destroy();
                
                if (req.originalUrl.includes('/api')) {
                    return res.status(403).json({ 
                        success: false, 
                        message: 'حسابك محظور من الوصول' 
                    });
                }
                
                return res.redirect('/login?error=حسابك محظور من الوصول إلى لوحة التحكم');
            }
        }
    } catch (error) {
        console.error('❌ خطأ في تحميل قائمة المحظورين:', error);
    }
    next();
});

// ================= [ نظام تسجيل الحسابات ] =================
async function registerAccount(discordId, accountData) {
    try {
        // تسجيل الحساب في قاعدة البيانات
        await db.set(`acc_${discordId}`, {
            ...accountData,
            id: discordId,
            discordId: discordId,
            createdAt: new Date().toISOString(),
            createdBy: 'system',
            isBlocked: false,
            lastLogin: null,
            role: 'user'
        });
        
        // تسجيل في سجل الحسابات
        const accountLogs = await db.get('account_logs') || [];
        accountLogs.push({
            action: 'create',
            discordId: discordId,
            username: accountData.user,
            timestamp: new Date().toISOString(),
            ip: accountData.ip || 'unknown'
        });
        await db.set('account_logs', accountLogs);
        
        console.log(`✅ تم تسجيل حساب جديد للمستخدم: ${discordId}`);
        return true;
    } catch (error) {
        console.error('❌ خطأ في تسجيل الحساب:', error);
        return false;
    }
}

// ================= [ نظام إدارة المشرفين ] =================
async function addAdmin(userId, username, addedBy) {
    try {
        const adminData = {
            id: userId,
            username: username,
            addedBy: addedBy,
            addedAt: new Date().toISOString(),
            permissions: {
                viewAccounts: true,
                manageLogs: true,
                blockUsers: false,
                deleteAccounts: false
            },
            status: 'active',
            lastActive: new Date().toISOString()
        };
        
        // حفظ في قاعدة البيانات
        const admins = await db.get('admin_accounts') || [];
        const existingIndex = admins.findIndex(admin => admin.id === userId);
        
        if (existingIndex > -1) {
            admins[existingIndex] = adminData;
        } else {
            admins.push(adminData);
        }
        
        await db.set('admin_accounts', admins);
        
        // تسجيل في سجل الإجراءات
        const adminLogs = await db.get('admin_logs') || [];
        adminLogs.push({
            action: 'add_admin',
            adminId: userId,
            adminName: username,
            by: addedBy,
            timestamp: new Date().toISOString()
        });
        await db.set('admin_logs', adminLogs);
        
        console.log(`✅ تم إضافة مشرف جديد: ${username} (${userId})`);
        return true;
    } catch (error) {
        console.error('❌ خطأ في إضافة مشرف:', error);
        return false;
    }
}

async function removeAdmin(userId, removedBy) {
    try {
        const admins = await db.get('admin_accounts') || [];
        const updatedAdmins = admins.filter(admin => admin.id !== userId);
        
        await db.set('admin_accounts', updatedAdmins);
        
        // تسجيل في سجل الإجراءات
        const adminLogs = await db.get('admin_logs') || [];
        adminLogs.push({
            action: 'remove_admin',
            adminId: userId,
            by: removedBy,
            timestamp: new Date().toISOString()
        });
        await db.set('admin_logs', adminLogs);
        
        console.log(`✅ تم إزالة مشرف: ${userId}`);
        return true;
    } catch (error) {
        console.error('❌ خطأ في إزالة مشرف:', error);
        return false;
    }
}

async function blockAdmin(userId, reason, blockedBy) {
    try {
        // إضافة إلى قائمة المشرفين المحظورين
        const bannedAdmins = await db.get('banned_admins') || [];
        if (!bannedAdmins.includes(userId)) {
            bannedAdmins.push(userId);
            await db.set('banned_admins', bannedAdmins);
        }
        
        // تحديث حالة المشرف
        const admins = await db.get('admin_accounts') || [];
        const adminIndex = admins.findIndex(admin => admin.id === userId);
        if (adminIndex > -1) {
            admins[adminIndex].status = 'blocked';
            admins[adminIndex].blockedAt = new Date().toISOString();
            admins[adminIndex].blockedBy = blockedBy;
            admins[adminIndex].blockReason = reason;
            await db.set('admin_accounts', admins);
        }
        
        // تسجيل في سجل الإجراءات
        const adminLogs = await db.get('admin_logs') || [];
        adminLogs.push({
            action: 'block_admin',
            adminId: userId,
            by: blockedBy,
            reason: reason,
            timestamp: new Date().toISOString()
        });
        await db.set('admin_logs', adminLogs);
        
        console.log(`✅ تم حظر مشرف: ${userId}`);
        return true;
    } catch (error) {
        console.error('❌ خطأ في حظر مشرف:', error);
        return false;
    }
}

async function unblockAdmin(userId, unblockedBy) {
    try {
        // إزالة من قائمة المشرفين المحظورين
        let bannedAdmins = await db.get('banned_admins') || [];
        bannedAdmins = bannedAdmins.filter(id => id !== userId);
        await db.set('banned_admins', bannedAdmins);
        
        // تحديث حالة المشرف
        const admins = await db.get('admin_accounts') || [];
        const adminIndex = admins.findIndex(admin => admin.id === userId);
        if (adminIndex > -1) {
            admins[adminIndex].status = 'active';
            admins[adminIndex].unblockedAt = new Date().toISOString();
            admins[adminIndex].unblockedBy = unblockedBy;
            await db.set('admin_accounts', admins);
        }
        
        // تسجيل في سجل الإجراءات
        const adminLogs = await db.get('admin_logs') || [];
        adminLogs.push({
            action: 'unblock_admin',
            adminId: userId,
            by: unblockedBy,
            timestamp: new Date().toISOString()
        });
        await db.set('admin_logs', adminLogs);
        
        console.log(`✅ تم فك حظر مشرف: ${userId}`);
        return true;
    } catch (error) {
        console.error('❌ خطأ في فك حظر مشرف:', error);
        return false;
    }
}

async function getAllAdmins() {
    const admins = await db.get('admin_accounts') || [];
    return admins;
}

async function getAllAccounts() {
    const allKeys = await db.all();
    const accounts = [];
    
    for (const item of allKeys) {
        if (item.id.startsWith('acc_')) {
            const discordId = item.id.replace('acc_', '');
            accounts.push({
                ...item.value,
                discordId: discordId
            });
        }
    }
    
    return accounts;
}

// ================= [ وظائف مساعدة ] =================
async function getDiscordUserData(userId) {
    try {
        const user = await client.users.fetch(userId);
        return {
            username: user.username,
            discriminator: user.discriminator,
            avatar: user.avatar,
            bot: user.bot,
            createdTimestamp: user.createdTimestamp,
            tag: user.tag,
            displayAvatarURL: user.displayAvatarURL({ dynamic: true })
        };
    } catch (error) {
        console.error(`❌ خطأ في جلب بيانات الديسكورد للمستخدم ${userId}:`, error.message);
        return null;
    }
}

async function saveDiscordUserData() {
    try {
        const allAccounts = await getAllAccounts();
        const discordData = {};
        
        for (const account of allAccounts) {
            const userData = await getDiscordUserData(account.discordId);
            if (userData) {
                discordData[account.discordId] = userData;
            }
        }
        
        await db.set('discord_users', discordData);
        console.log(`✅ تم حفظ بيانات ${Object.keys(discordData).length} مستخدم ديسكورد`);
        return discordData;
    } catch (error) {
        console.error('❌ خطأ في حفظ بيانات الديسكورد:', error);
        return {};
    }
}

// ================= [ Middleware للتحقق من المشرفين ] =================
async function checkAdminAccess(req, res, next) {
    try {
        if (!req.isAuthenticated() || !req.user) {
            return res.redirect('/');
        }
        
        // التحقق من الحظر
        const bannedAdmins = await db.get('banned_admins') || [];
        if (bannedAdmins.includes(req.user.id)) {
            req.session.destroy();
            return res.redirect('/login?error=حسابك محظور من الوصول إلى لوحة التحكم');
        }
        
        // التحقق إذا كان مستخدم عادي يحاول الوصول لقسم المشرفين
        const admins = await db.get('admin_accounts') || [];
        const isAdmin = admins.some(admin => admin.id === req.user.id);
        const isSuperAdmin = SUPER_ADMIN_IDS.includes(req.user.id);
        
        if (req.path.includes('/admin/') && !isAdmin && !isSuperAdmin) {
            return res.redirect('/dashboard');
        }
        
        req.isSuperAdmin = isSuperAdmin;
        req.isAdmin = isAdmin || isSuperAdmin;
        
        next();
    } catch (error) {
        console.error('❌ خطأ في التحقق من صلاحيات المشرف:', error);
        res.redirect('/dashboard');
    }
}

// ================= [ صفحات الموقع ] =================
// الصفحة الرئيسية
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/verify');
    }
    res.render('login', { user: null });
});

// تسجيل الدخول بالديسكورد
app.get('/auth/discord', passport.authenticate('discord'));

// رد الاتصال من الديسكورد
app.get('/auth/discord/callback', 
    passport.authenticate('discord', { 
        failureRedirect: '/',
        failureFlash: true
    }),
    async (req, res) => {
        try {
            if (!req.user) {
                console.log('❌ المستخدم غير موجود في الطلب');
                return res.redirect('/');
            }
            
            console.log(`✅ تسجيل دخول ناجح: ${req.user.username} (${req.user.id})`);
            
            // التحقق من الحظر
            const bannedAdmins = await db.get('banned_admins') || [];
            const bannedAccounts = await db.get('banned_accounts') || [];
            
            if (bannedAdmins.includes(req.user.id) || bannedAccounts.includes(req.user.id)) {
                console.log(`🚫 حساب محظور حاول الدخول: ${req.user.username}`);
                req.logout(() => {
                    res.redirect('/login?error=حسابك محظور من الوصول إلى لوحة التحكم');
                });
                return;
            }
            
            // التحقق مما إذا كان المستخدم لديه حساب مسبقًا
            const existingAccount = await db.get(`acc_${req.user.id}`);
            
            if (!existingAccount) {
                console.log('📝 المستخدم جديد، توجيه لإنشاء حساب');
                return res.redirect('/setup-account');
            }
            
            console.log('✅ المستخدم موجود، توجيه للتحقق');
            return res.redirect('/verify');
        } catch (error) {
            console.error('❌ خطأ في تسجيل الدخول:', error);
            res.redirect('/');
        }
    }
);

// صفحة إنشاء حساب جديد
app.get('/setup-account', (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        console.log('❌ محاولة الوصول لإنشاء حساب بدون مصادقة');
        return res.redirect('/');
    }
    
    console.log(`📄 صفحة إنشاء حساب للمستخدم: ${req.user.username}`);
    res.render('setup', { 
        user: req.user || { username: 'مستخدم', id: 'غير معروف' },
        error: null 
    });
});

// معالجة إنشاء الحساب
app.post('/setup-account', async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        console.log('❌ محاولة إنشاء حساب بدون مصادقة');
        return res.redirect('/');
    }
    
    const { user: username, pass } = req.body;
    
    console.log(`📝 محاولة إنشاء حساب: ${username} للمستخدم ${req.user.username}`);
    
    // التحقق من صحة البيانات
    if (!username || !pass || username.length < 3 || pass.length < 6) {
        console.log('❌ بيانات غير صالحة');
        return res.render('setup', { 
            user: req.user,
            error: 'يجب أن يكون اسم المستخدم 3 أحرف على الأقل وكلمة المرور 6 أحرف على الأقل'
        });
    }
    
    try {
        // تسجيل الحساب
        await registerAccount(req.user.id, {
            user: username,
            pass: pass,
            discordUsername: req.user.username,
            discordDiscriminator: req.user.discriminator,
            discordAvatar: req.user.avatar
        });
        
        console.log(`✅ حساب تم إنشاؤه للمستخدم: ${req.user.username}`);
        
        // تسجيل الدخول التلقائي بعد إنشاء الحساب
        req.session.isLogged = true;
        req.session.loginTime = new Date().toISOString();
        req.session.accountId = req.user.id;
        
        // توجيه لصفحة النجاح
        res.redirect('/success');
    } catch (error) {
        console.error('❌ خطأ في إنشاء الحساب:', error);
        res.render('setup', { 
            user: req.user,
            error: 'حدث خطأ أثناء إنشاء الحساب' 
        });
    }
});

// صفحة النجاح بعد إنشاء الحساب
app.get('/success', async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        console.log('❌ محاولة الوصول لصفحة النجاح بدون مصادقة');
        return res.redirect('/');
    }
    
    try {
        const acc = await db.get(`acc_${req.user.id}`);
        
        if (!acc) {
            console.log('❌ لا يوجد حساب للمستخدم');
            return res.redirect('/setup-account');
        }
        
        console.log(`🎉 صفحة النجاح للمستخدم: ${req.user.username}`);
        
        res.render('success', { 
            user: req.user,
            acc: acc
        });
    } catch (error) {
        console.error('❌ خطأ في تحميل صفحة النجاح:', error);
        res.redirect('/dashboard');
    }
});

// صفحة التحقق من الحساب
app.get('/verify', (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        console.log('❌ محاولة الوصول للتحقق بدون مصادقة');
        return res.redirect('/');
    }
    
    console.log(`🔐 صفحة التحقق للمستخدم: ${req.user.username}`);
    
    // إذا كان مسجل الدخول بالفعل، توجهه للداشبورد
    if (req.session.isLogged) {
        console.log('✅ المستخدم مسجل بالفعل، توجيه للداشبورد');
        return res.redirect('/dashboard');
    }
    
    res.render('verify', { 
        user: req.user,
        error: null,
        username: ''
    });
});

// معالجة التحقق من الحساب
app.post('/verify', async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        console.log('❌ محاولة تحقق بدون مصادقة');
        return res.redirect('/');
    }
    
    const { u, p } = req.body;
    
    console.log(`🔑 محاولة تحقق للمستخدم: ${req.user.username}`);
    
    try {
        // التحقق من الحظر
        const bannedAdmins = await db.get('banned_admins') || [];
        const bannedAccounts = await db.get('banned_accounts') || [];
        
        if (bannedAdmins.includes(req.user.id) || bannedAccounts.includes(req.user.id)) {
            console.log(`🚫 حساب محظور حاول الدخول: ${req.user.username}`);
            return res.render('verify', { 
                user: req.user,
                error: 'حسابك محظور من الوصول إلى لوحة التحكم! تواصل مع المسؤول.',
                username: u 
            });
        }
        
        const acc = await db.get(`acc_${req.user.id}`);
        
        if (!acc) {
            console.log('❌ حساب غير موجود');
            return res.render('verify', { 
                user: req.user,
                error: 'الحساب غير موجود، يرجى إنشاء حساب جديد',
                username: u 
            });
        }
        
        if (u === acc.user && p === acc.pass) {
            // تسجيل الدخول الناجح
            req.session.isLogged = true;
            req.session.loginTime = new Date().toISOString();
            req.session.accountId = acc.id || req.user.id;
            
            // تحديث وقت آخر دخول
            await db.set(`acc_${req.user.id}.lastLogin`, new Date().toISOString());
            
            console.log(`✅ تحقق ناجح للمستخدم: ${req.user.username}`);
            
            res.redirect('/dashboard');
        } else {
            // بيانات غير صحيحة
            console.log('❌ بيانات تحقق غير صحيحة');
            res.render('verify', { 
                user: req.user,
                error: 'بيانات الدخول غير صحيحة!',
                username: u 
            });
        }
    } catch (error) {
        console.error('❌ خطأ في التحقق:', error);
        res.render('verify', { 
            user: req.user,
            error: 'حدث خطأ أثناء التحقق',
            username: u 
        });
    }
});

// صفحة الداشبورد الرئيسية
app.get('/dashboard', checkAdminAccess, async (req, res) => {
    if (!req.isAuthenticated() || !req.user || !req.session.isLogged) {
        console.log('❌ محاولة الوصول للداشبورد بدون صلاحية');
        return res.redirect('/verify');
    }
    
    try {
        // جلب السيرفرات التي يديرها البوت
        const guilds = client.guilds.cache.map(guild => ({
            id: guild.id,
            name: guild.name,
            icon: guild.iconURL({ dynamic: true }),
            memberCount: guild.memberCount,
            channels: guild.channels.cache
                .filter(channel => channel.type === 0) // فقط قنوات النص
                .map(channel => ({ id: channel.id, name: channel.name }))
        }));
        
        // جلب بيانات حساب المستخدم
        const acc = await db.get(`acc_${req.user.id}`);
        
        if (!acc) {
            console.log('❌ حساب غير موجود في الداشبورد');
            return res.redirect('/setup-account');
        }
        
        // جلب إعدادات السيرفرات
        const guildSettings = {};
        for (const guild of guilds) {
            const settings = await db.get(`logs_${guild.id}`);
            guildSettings[guild.id] = settings || {};
        }
        
        res.render('dashboard', { 
            guilds, 
            user: req.user, 
            acc,
            guildSettings,
            loginTime: req.session.loginTime ? new Date(req.session.loginTime).toLocaleString('ar-SA') : null,
            isAdmin: req.isAdmin,
            isSuperAdmin: req.isSuperAdmin
        });
    } catch (error) {
        console.error('❌ خطأ في جلب بيانات الداشبورد:', error);
        res.redirect('/verify');
    }
});

/// صفحة إدارة المشرفين (للمسؤولين فقط)
app.get('/admin/manage', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isAdmin) {
            return res.redirect('/dashboard');
        }
        
        console.log(`🔐 مسؤول يدخل صفحة إدارة المشرفين: ${req.user.username}`);
        
        // جلب جميع المشرفين
        const admins = await getAllAdmins();
        
        // جلب جميع الحسابات
        const allAccounts = await getAllAccounts();
        
        // جلب سجل إجراءات المشرفين
        const adminLogs = await db.get('admin_logs') || [];
        
        // جلب بيانات الديسكورد
        const discordUsers = await db.get('discord_users') || {};
        
        // جلب قائمة المحظورين
        const bannedAccounts = await db.get('banned_accounts') || [];
        const bannedAdmins = await db.get('banned_admins') || [];
        
        res.render('admin-manage', {
            user: req.user,
            currentUser: await db.get(`acc_${req.user.id}`) || { user: req.user.username, id: req.user.id },
            admins: admins,
            allAccounts: allAccounts,
            adminLogs: adminLogs.reverse().slice(0, 50), // آخر 50 إجراء
            discordUsers: discordUsers,
            bannedAccounts: bannedAccounts,
            bannedAdmins: bannedAdmins,
            isSuperAdmin: req.isSuperAdmin,
            isAdmin: req.isAdmin,
            SUPER_ADMIN_IDS: SUPER_ADMIN_IDS // إضافة هذا السطر
        });
        
    } catch (error) {
        console.error('❌ خطأ في تحميل صفحة إدارة المشرفين:', error);
        res.redirect('/dashboard');
    }
});

// ================= [ API إدارة المشرفين ] =================

// جلب جميع المشرفين
app.get('/api/admin/get-admins', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بالوصول' 
            });
        }
        
        const admins = await getAllAdmins();
        
        // جلب بيانات الديسكورد لكل مشرف
        const adminsWithData = [];
        for (const admin of admins) {
            const discordData = await getDiscordUserData(admin.id);
            adminsWithData.push({
                ...admin,
                discordData: discordData
            });
        }
        
        res.json({
            success: true,
            admins: adminsWithData,
            total: adminsWithData.length
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب المشرفين:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في جلب البيانات' 
        });
    }
});

// إضافة مشرف جديد
app.post('/api/admin/add-admin', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isSuperAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بإضافة مشرفين' 
            });
        }
        
        const { discordId, permissions } = req.body;
        
        if (!discordId) {
            return res.status(400).json({
                success: false,
                message: 'معرف الديسكورد مطلوب'
            });
        }
        
        // جلب بيانات الديسكورد
        const discordData = await getDiscordUserData(discordId);
        if (!discordData) {
            return res.status(404).json({
                success: false,
                message: 'المستخدم غير موجود على الديسكورد'
            });
        }
        
        // التحقق من وجود حساب
        const account = await db.get(`acc_${discordId}`);
        if (!account) {
            return res.status(400).json({
                success: false,
                message: 'المستخدم ليس لديه حساب في النظام'
            });
        }
        
        // إضافة المشرف
        const success = await addAdmin(
            discordId,
            discordData.username,
            req.user.id,
            permissions || {
                viewAccounts: true,
                manageLogs: true,
                blockUsers: false,
                deleteAccounts: false
            }
        );
        
        if (success) {
            res.json({
                success: true,
                message: `تم إضافة ${discordData.username} كمشرف بنجاح`
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'حدث خطأ أثناء إضافة المشرف'
            });
        }
        
    } catch (error) {
        console.error('❌ خطأ في إضافة مشرف:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في معالجة الطلب' 
        });
    }
});

// حظر مشرف
app.post('/api/admin/block-admin', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isSuperAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بحظر مشرفين' 
            });
        }
        
        const { adminId, reason } = req.body;
        
        if (!adminId) {
            return res.status(400).json({
                success: false,
                message: 'معرف المشرف مطلوب'
            });
        }
        
        // منع المستخدم من حظر نفسه
        if (adminId === req.user.id) {
            return res.status(400).json({
                success: false,
                message: 'لا يمكنك حظر حسابك الخاص'
            });
        }
        
        const success = await blockAdmin(adminId, reason || 'لم يتم تقديم سبب', req.user.id);
        
        if (success) {
            res.json({
                success: true,
                message: 'تم حظر المشرف بنجاح'
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'حدث خطأ أثناء حظر المشرف'
            });
        }
        
    } catch (error) {
        console.error('❌ خطأ في حظر مشرف:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في معالجة الطلب' 
        });
    }
});

// فك حظر مشرف
app.post('/api/admin/unblock-admin', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isSuperAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بفك حظر مشرفين' 
            });
        }
        
        const { adminId } = req.body;
        
        if (!adminId) {
            return res.status(400).json({
                success: false,
                message: 'معرف المشرف مطلوب'
            });
        }
        
        const success = await unblockAdmin(adminId, req.user.id);
        
        if (success) {
            res.json({
                success: true,
                message: 'تم فك حظر المشرف بنجاح'
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'حدث خطأ أثناء فك حظر المشرف'
            });
        }
        
    } catch (error) {
        console.error('❌ خطأ في فك حظر مشرف:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في معالجة الطلب' 
        });
    }
});

// إزالة مشرف
app.delete('/api/admin/remove-admin/:adminId', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isSuperAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بإزالة مشرفين' 
            });
        }
        
        const { adminId } = req.params;
        
        // منع المستخدم من إزالة نفسه
        if (adminId === req.user.id) {
            return res.status(400).json({
                success: false,
                message: 'لا يمكنك إزالة نفسك'
            });
        }
        
        const success = await removeAdmin(adminId, req.user.id);
        
        if (success) {
            res.json({
                success: true,
                message: 'تم إزالة المشرف بنجاح'
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'حدث خطأ أثناء إزالة المشرف'
            });
        }
        
    } catch (error) {
        console.error('❌ خطأ في إزالة مشرف:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في معالجة الطلب' 
        });
    }
});

// جلب جميع الحسابات
app.get('/api/admin/get-accounts', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بالوصول' 
            });
        }
        
        const accounts = await getAllAccounts();
        
        // جلب بيانات الديسكورد
        const accountsWithData = [];
        for (const account of accounts) {
            const discordData = await getDiscordUserData(account.discordId);
            accountsWithData.push({
                ...account,
                discordData: discordData
            });
        }
        
        res.json({
            success: true,
            accounts: accountsWithData,
            total: accountsWithData.length
        });
        
    } catch (error) {
        console.error('❌ خطأ في جلب الحسابات:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في جلب البيانات' 
        });
    }
});

// حظر حساب
app.post('/api/admin/block-account', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بحظر حسابات' 
            });
        }
        
        const { accountId, reason } = req.body;
        
        if (!accountId) {
            return res.status(400).json({
                success: false,
                message: 'معرف الحساب مطلوب'
            });
        }
        
        // منع المستخدم من حظر نفسه
        if (accountId === req.user.id) {
            return res.status(400).json({
                success: false,
                message: 'لا يمكنك حظر حسابك الخاص'
            });
        }
        
        // التحقق من وجود الحساب
        const account = await db.get(`acc_${accountId}`);
        if (!account) {
            return res.status(404).json({ 
                success: false, 
                message: 'الحساب غير موجود' 
            });
        }
        
        // إضافة لقائمة المحظورين
        const bannedList = await db.get('banned_accounts') || [];
        if (!bannedList.includes(accountId)) {
            bannedList.push(accountId);
            await db.set('banned_accounts', bannedList);
        }
        
        // تحديث حالة الحساب
        await db.set(`acc_${accountId}.isBlocked`, true);
        await db.set(`acc_${accountId}.blockedAt`, new Date().toISOString());
        await db.set(`acc_${accountId}.blockedBy`, req.user.id);
        await db.set(`acc_${accountId}.blockReason`, reason || 'لم يتم تقديم سبب');
        
        // تسجيل في سجل الإجراءات
        const adminLogs = await db.get('admin_logs') || [];
        adminLogs.push({
            action: 'block_account',
            accountId: accountId,
            accountName: account.user,
            by: req.user.id,
            reason: reason,
            timestamp: new Date().toISOString()
        });
        await db.set('admin_logs', adminLogs);
        
        res.json({
            success: true,
            message: `تم حظر حساب ${account.user} بنجاح`
        });
        
    } catch (error) {
        console.error('❌ خطأ في حظر الحساب:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في معالجة الطلب' 
        });
    }
});

// فك حظر حساب
app.post('/api/admin/unblock-account', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بفك حظر حسابات' 
            });
        }
        
        const { accountId } = req.body;
        
        if (!accountId) {
            return res.status(400).json({
                success: false,
                message: 'معرف الحساب مطلوب'
            });
        }
        
        // التحقق من وجود الحساب
        const account = await db.get(`acc_${accountId}`);
        if (!account) {
            return res.status(404).json({ 
                success: false, 
                message: 'الحساب غير موجود' 
            });
        }
        
        // إزالة من قائمة المحظورين
        let bannedList = await db.get('banned_accounts') || [];
        bannedList = bannedList.filter(id => id !== accountId);
        await db.set('banned_accounts', bannedList);
        
        // تحديث حالة الحساب
        await db.set(`acc_${accountId}.isBlocked`, false);
        await db.set(`acc_${accountId}.unblockedAt`, new Date().toISOString());
        await db.set(`acc_${accountId}.unblockedBy`, req.user.id);
        
        // تسجيل في سجل الإجراءات
        const adminLogs = await db.get('admin_logs') || [];
        adminLogs.push({
            action: 'unblock_account',
            accountId: accountId,
            accountName: account.user,
            by: req.user.id,
            timestamp: new Date().toISOString()
        });
        await db.set('admin_logs', adminLogs);
        
        res.json({
            success: true,
            message: `تم فك حظر حساب ${account.user} بنجاح`
        });
        
    } catch (error) {
        console.error('❌ خطأ في فك حظر الحساب:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في معالجة الطلب' 
        });
    }
});

// حذف حساب
app.delete('/api/admin/delete-account/:accountId', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بحذف حسابات' 
            });
        }
        
        const { accountId } = req.params;
        const { reason } = req.body;
        
        // منع المستخدم من حذف نفسه
        if (accountId === req.user.id) {
            return res.status(400).json({
                success: false,
                message: 'لا يمكنك حذف حسابك الخاص'
            });
        }
        
        // التحقق من وجود الحساب
        const account = await db.get(`acc_${accountId}`);
        if (!account) {
            return res.status(404).json({ 
                success: false, 
                message: 'الحساب غير موجود' 
            });
        }
        
        // حذف الحساب
        await db.delete(`acc_${accountId}`);
        
        // إزالته من قائمة المحظورين
        let bannedList = await db.get('banned_accounts') || [];
        bannedList = bannedList.filter(id => id !== accountId);
        await db.set('banned_accounts', bannedList);
        
        // تسجيل في سجل الإجراءات
        const adminLogs = await db.get('admin_logs') || [];
        adminLogs.push({
            action: 'delete_account',
            accountId: accountId,
            accountName: account.user,
            by: req.user.id,
            reason: reason || 'لا يوجد سبب محدد',
            timestamp: new Date().toISOString()
        });
        await db.set('admin_logs', adminLogs);
        
        console.log(`🗑️ المشرف ${req.user.username} حذف حساب ${account.user} (${accountId})`);
        
        res.json({
            success: true,
            message: `تم حذف حساب ${account.user} بنجاح`
        });
        
    } catch (error) {
        console.error('❌ خطأ في حذف الحساب:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في حذف الحساب' 
        });
    }
});

// تصدير جميع البيانات
app.get('/api/admin/export-data', checkAdminAccess, async (req, res) => {
    try {
        if (!req.isSuperAdmin) {
            return res.status(403).json({ 
                success: false, 
                message: 'غير مصرح لك بتصدير البيانات' 
            });
        }
        
        const accounts = await getAllAccounts();
        const admins = await getAllAdmins();
        const adminLogs = await db.get('admin_logs') || [];
        const bannedAccounts = await db.get('banned_accounts') || [];
        const bannedAdmins = await db.get('banned_admins') || [];
        
        const exportData = {
            accounts: accounts,
            admins: admins,
            adminLogs: adminLogs,
            bannedAccounts: bannedAccounts,
            bannedAdmins: bannedAdmins,
            exportedAt: new Date().toISOString(),
            exportedBy: req.user.username
        };
        
        res.json({
            success: true,
            data: exportData
        });
        
    } catch (error) {
        console.error('❌ خطأ في تصدير البيانات:', error);
        res.status(500).json({ 
            success: false, 
            message: 'حدث خطأ في تصدير البيانات' 
        });
    }
});

// ================= [ باقي الكود (نظام اللوجات) ] =================
// ... [إبقى باقي الكود الخاص بنظام اللوجات كما هو] ...

// منتصف الخادم للرصد
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    if (req.isAuthenticated()) {
        console.log(`المستخدم: ${req.user?.username || 'غير معروف'} (${req.user?.id || 'غير معروف'})`);
    }
    next();
});

passport.use(new Strategy({
    clientID: config.clientId,
    clientSecret: config.clientSecret,
    callbackURL: config.callbackURL,
    scope: ['identify', 'guilds']
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ================= [ نظام التخزين ] =================
const memberWarns = new Map(); // { guildId_memberId: { count: number, lastWarn: timestamp } }
const memberTimeouts = new Map(); // { guildId_memberId: { end: timestamp, reason: string, moderator: string } }

// --- دالة جلب بيانات الإداري من الأوديت لوج ---
async function getAudit(guild, type) {
    try {
        // انتظار 1.5 ثانية لضمان ظهور الأوديت لوج
        await new Promise(resolve => setTimeout(resolve, 1500));
        const logs = await guild.fetchAuditLogs({ 
            limit: 1, 
            type: type 
        }).catch(err => {
            console.error(`❌ خطأ في جلب الأوديت لوج (${type}):`, err.message);
            return null;
        });
        
        if (!logs || logs.entries.size === 0) {
            return null;
        }
        
        return logs.entries.first();
    } catch (e) { 
        console.error('❌ خطأ في جلب الأوديت لوج:', e.message);
        return null; 
    }
}

// --- دالة إرسال اللوجات ---
async function sendLog(guild, type, embedData) {
    try {
        if (!guild) {
            console.log('❌ السيرفر غير موجود');
            return;
        }
        
        const settings = await db.get(`logs_${guild.id}`);
        if (!settings || !settings[type]?.enabled) {
            console.log(`ℹ️ اللوج ${type} غير مفعل لسيرفر ${guild.name}`);
            return;
        }
        
        const channelId = settings[type].channel;
        if (!channelId) {
            console.log(`❌ لم يتم تحديد قناة للوج ${type}`);
            return;
        }
        
        const channel = await guild.channels.fetch(channelId).catch(err => {
            console.error(`❌ خطأ في جلب القناة ${channelId}:`, err.message);
            return null;
        });
        
        if (!channel) {
            console.log(`❌ القناة ${channelId} غير موجودة`);
            return;
        }
        
        const embed = new EmbedBuilder()
            .setColor(settings[type].color || '#D4AF37')
            .setTitle(embedData.title)
            .setTimestamp();
        
        if (embedData.authorName) {
            embed.setAuthor({ 
                name: embedData.authorName, 
                iconURL: guild.iconURL({ dynamic: true }) || undefined 
            });
        }
        
        if (embedData.fields && embedData.fields.length > 0) {
            embed.addFields(embedData.fields);
        }
        
        if (embedData.thumbnail) {
            embed.setThumbnail(embedData.thumbnail);
        }
        
        if (embedData.description) {
            embed.setDescription(embedData.description);
        }
        
        if (embedData.footer) {
            embed.setFooter({ text: embedData.footer });
        }
        
        if (embedData.image) {
            embed.setImage(embedData.image);
        }
        
        await channel.send({ embeds: [embed] }).catch(err => {
            console.error(`❌ خطأ في إرسال اللوج ${type}:`, err.message);
        });
        
        console.log(`✅ تم إرسال لوج ${type} لسيرفر ${guild.name}`);
    } catch (error) {
        console.error(`❌ خطأ في دالة sendLog:`, error);
    }
}

// ================= [ نظام التحذيرات الشامل ] =================

// مراقبة الرسائل للتحذيرات
client.on(Events.MessageCreate, async (message) => {
    if (!message.guild || message.author.bot) return;
    
    try {
        const content = message.content.toLowerCase();
        
        // كلمات مفتاحية للتحذيرات
        const warnKeywords = [
            '!تحذير', '!warn', '!انذار', '!warning',
            'تحذير @', 'warn @', 'انذار @', 'warning @',
            'يتم تحذير', 'يتم انذار', 'تم التحذير', 'تم الانذار'
        ];
        
        for (const keyword of warnKeywords) {
            if (content.includes(keyword.toLowerCase())) {
                // البحث عن منشن في الرسالة
                const mention = message.mentions.members?.first();
                if (mention) {
                    // استخراج السبب
                    let reason = 'لم يتم تقديم سبب';
                    const parts = message.content.split(' ');
                    const reasonIndex = parts.findIndex(p => p.includes('@')) + 1;
                    if (reasonIndex < parts.length && parts[reasonIndex]) {
                        reason = parts.slice(reasonIndex).join(' ');
                    }
                    
                    // حساب عدد التحذيرات
                    const warnKey = `${message.guild.id}_${mention.id}`;
                    const currentData = memberWarns.get(warnKey) || { count: 0, lastWarn: 0 };
                    const newWarnCount = currentData.count + 1;
                    
                    memberWarns.set(warnKey, { 
                        count: newWarnCount, 
                        lastWarn: Date.now(),
                        warnedBy: message.author.id
                    });
                    
                    // إرسال اللوج
                    await sendLog(message.guild, 'warnLog', {
                        title: 'تحذير جديد ⚠️',
                        authorName: 'نظام التحذيرات',
                        thumbnail: mention.user.displayAvatarURL({ dynamic: true, size: 256 }),
                        fields: [
                            { name: '👤 العضو', value: `<@${mention.id}> (${mention.id})` },
                            { name: '🛡️ المسؤول', value: `<@${message.author.id}> (${message.author.username})` },
                            { name: '📝 السبب', value: reason },
                            { name: '🔢 عدد التحذيرات', value: `${newWarnCount}/4` },
                            { name: '📋 الحالة', value: `تحذير ${newWarnCount}` },
                            { name: '🏷️ رقم التحذير', value: `#${newWarnCount}` },
                            { name: '💬 الروم', value: `<#${message.channel.id}>` }
                        ]
                    });
                    
                    console.log(`✅ تم اكتشاف تحذير للعضو ${mention.user.username}`);
                    break;
                }
            }
        }
        
        // إزالة التحذيرات
        const unwarnKeywords = [
            '!إزالة-تحذير', '!unwarn', '!فك-تحذير', '!ازالة-تحذير',
            'إزالة تحذير @', 'unwarn @', 'فك تحذير @', 'ازالة تحذير @'
        ];
        
        for (const keyword of unwarnKeywords) {
            if (content.includes(keyword.toLowerCase())) {
                const mention = message.mentions.members?.first();
                if (mention) {
                    // استخراج السبب
                    let reason = 'لم يتم تقديم سبب';
                    const parts = message.content.split(' ');
                    const reasonIndex = parts.findIndex(p => p.includes('@')) + 1;
                    if (reasonIndex < parts.length && parts[reasonIndex]) {
                        reason = parts.slice(reasonIndex).join(' ');
                    }
                    
                    const warnKey = `${message.guild.id}_${mention.id}`;
                    const currentData = memberWarns.get(warnKey) || { count: 1, lastWarn: 0 };
                    const newWarnCount = Math.max(0, currentData.count - 1);
                    
                    memberWarns.set(warnKey, { 
                        count: newWarnCount, 
                        lastWarn: currentData.lastWarn 
                    });
                    
                    await sendLog(message.guild, 'warnLog', {
                        title: 'إزالة تحذير ✅',
                        authorName: 'نظام التحذيرات',
                        fields: [
                            { name: '👤 العضو', value: `<@${mention.id}> (${mention.id})` },
                            { name: '🛡️ المسؤول', value: `<@${message.author.id}> (${message.author.username})` },
                            { name: '📝 السبب', value: reason },
                            { name: '🔢 عدد التحذيرات الحالي', value: `${newWarnCount}/4` },
                            { name: '📋 العملية', value: `إزالة تحذير` },
                            { name: '💬 الروم', value: `<#${message.channel.id}>` }
                        ]
                    });
                    
                    console.log(`✅ تم اكتشاف إزالة تحذير للعضو ${mention.user.username}`);
                    break;
                }
            }
        }
    } catch (error) {
        console.error('❌ خطأ في نظام التحذيرات:', error);
    }
});

// ================= [ نظام التايم أوت الشامل ] =================

// مراقبة التايم أوت
client.on(Events.GuildMemberUpdate, async (oldMember, newMember) => {
    try {
        // تايم أوت جديد
        if (!oldMember.communicationDisabledUntilTimestamp && newMember.communicationDisabledUntilTimestamp) {
            const audit = await getAudit(newMember.guild, AuditLogEvent.MemberUpdate);
            
            const duration = newMember.communicationDisabledUntilTimestamp - Date.now();
            const minutes = Math.floor(duration / 60000);
            const endsAt = new Date(newMember.communicationDisabledUntilTimestamp);
            
            // حفظ التايم أوت
            const timeoutKey = `${newMember.guild.id}_${newMember.id}`;
            memberTimeouts.set(timeoutKey, {
                end: newMember.communicationDisabledUntilTimestamp,
                reason: audit?.reason || 'لم يتم تقديم سبب',
                moderator: audit?.executor?.id || 'غير معروف'
            });
            
            await sendLog(newMember.guild, 'timeoutLog', {
                title: 'تايم اوت عضو ⏳',
                authorName: 'نظام التايم اوت',
                thumbnail: newMember.user.displayAvatarURL({ dynamic: true, size: 256 }),
                fields: [
                    { name: '👤 العضو', value: `<@${newMember.id}> (${newMember.id})` },
                    { name: '🛡️ المسؤول', value: `<@${audit?.executor?.id || 'غير معروف'}>` },
                    { name: '⏰ المدة', value: `${minutes} دقيقة` },
                    { name: '📅 ينتهي في', value: time(endsAt, 'R') },
                    { name: '📝 السبب', value: audit?.reason || 'لم يتم تقديم سبب' }
                ]
            });
            
            console.log(`✅ تم اكتشاف تايم أوت للعضو ${newMember.user.username}`);
        }
        
        // فك تايم أوت
        else if (oldMember.communicationDisabledUntilTimestamp && !newMember.communicationDisabledUntilTimestamp) {
            const audit = await getAudit(newMember.guild, AuditLogEvent.MemberUpdate);
            
            // حذف التايم أوت
            const timeoutKey = `${newMember.guild.id}_${newMember.id}`;
            const timeoutData = memberTimeouts.get(timeoutKey);
            memberTimeouts.delete(timeoutKey);
            
            await sendLog(newMember.guild, 'timeoutLog', {
                title: 'فك تايم اوت عضو ✅',
                authorName: 'نظام التايم اوت',
                fields: [
                    { name: '👤 العضو', value: `<@${newMember.id}> (${newMember.id})` },
                    { name: '🛡️ المسؤول', value: `<@${audit?.executor?.id || 'غير معروف'}>` },
                    { name: '📝 السبب', value: audit?.reason || 'لم يتم تقديم سبب' }
                ]
            });
            
            console.log(`✅ تم اكتشاف فك تايم أوت للعضو ${newMember.user.username}`);
        }
        
        // ================= [ نظام رصد التحذيرات عبر الرتب ] =================
        // إضافة رتبة تحذير
        const addedRoles = newMember.roles.cache.filter(role => !oldMember.roles.cache.has(role.id));
        
        for (const role of addedRoles.values()) {
            const roleName = role.name.toLowerCase();
            if (roleName.includes('تحذير') || 
                roleName.includes('warning') ||
                roleName.includes('warn') ||
                roleName.includes('انذار')) {
                
                const audit = await getAudit(newMember.guild, AuditLogEvent.MemberRoleUpdate);
                
                const warnKey = `${newMember.guild.id}_${newMember.id}`;
                const currentData = memberWarns.get(warnKey) || { count: 0, lastWarn: 0 };
                const newWarnCount = currentData.count + 1;
                
                memberWarns.set(warnKey, { 
                    count: newWarnCount, 
                    lastWarn: Date.now(),
                    warnedBy: audit?.executor?.id || 'غير معروف'
                });
                
                await sendLog(newMember.guild, 'warnLog', {
                    title: 'تحذير (رتبة) ⚠️',
                    authorName: 'نظام التحذيرات',
                    thumbnail: newMember.user.displayAvatarURL({ dynamic: true, size: 256 }),
                    fields: [
                        { name: '👤 العضو', value: `<@${newMember.id}> (${newMember.id})` },
                        { name: '🛡️ المسؤول', value: `<@${audit?.executor?.id || 'غير معروف'}>` },
                        { name: '📝 السبب', value: audit?.reason || 'لم يتم تقديم سبب' },
                        { name: '🔢 عدد التحذيرات', value: `${newWarnCount}/4` },
                        { name: '📋 الحالة', value: `تحذير ${newWarnCount}` },
                        { name: '🎖️ الرتبة', value: `<@&${role.id}>` }
                    ]
                });
                
                console.log(`✅ تم اكتشاف رتبة تحذير للعضو ${newMember.user.username}`);
            }
        }
        
        // إزالة رتبة تحذير
        const removedRoles = oldMember.roles.cache.filter(role => !newMember.roles.cache.has(role.id));
        
        for (const role of removedRoles.values()) {
            const roleName = role.name.toLowerCase();
            if (roleName.includes('تحذير') || 
                roleName.includes('warning') ||
                roleName.includes('warn') ||
                roleName.includes('انذار')) {
                
                const audit = await getAudit(newMember.guild, AuditLogEvent.MemberRoleUpdate);
                
                const warnKey = `${newMember.guild.id}_${newMember.id}`;
                const currentData = memberWarns.get(warnKey) || { count: 1, lastWarn: 0 };
                const newWarnCount = Math.max(0, currentData.count - 1);
                
                memberWarns.set(warnKey, { 
                    count: newWarnCount, 
                    lastWarn: currentData.lastWarn 
                });
                
                await sendLog(newMember.guild, 'warnLog', {
                    title: 'إزالة تحذير (رتبة) ✅',
                    authorName: 'نظام التحذيرات',
                    fields: [
                        { name: '👤 العضو', value: `<@${newMember.id}> (${newMember.id})` },
                        { name: '🛡️ المسؤول', value: `<@${audit?.executor?.id || 'غير معروف'}>` },
                        { name: '🔢 عدد التحذيرات الحالي', value: `${newWarnCount}/4` },
                        { name: '📋 العملية', value: `إزالة رتبة تحذير` },
                        { name: '🎖️ الرتبة المزالة', value: role.name }
                    ]
                });
                
                console.log(`✅ تم اكتشاف إزالة رتبة تحذير للعضو ${newMember.user.username}`);
            }
        }
    } catch (error) {
        console.error('❌ خطأ في نظام التايم أوت/التحذيرات:', error);
    }
});

// ================= [ نظام اللوجات الأساسية ] =================

// 1. انضمام عضو
client.on(Events.GuildMemberAdd, async (member) => {
    try {
        const joinDate = new Date(member.joinedTimestamp);
        const creationDate = new Date(member.user.createdTimestamp);
        
        await sendLog(member.guild, 'memberJoin', {
            title: 'انضمام شخص 👤',
            authorName: 'انضم عضو جديد إلى السيرفر',
            thumbnail: member.user.displayAvatarURL({ dynamic: true, size: 256 }),
            fields: [
                { name: '📋 معلومات العضو', value: `**الاسم:** ${member.user.username}\n**اليوزر:** ${member.user.tag}\n**المنشن:** <@${member.id}>\n**الرقم:** ${member.id}\n**تاريخ الإنشاء:** ${time(creationDate, 'R')}` },
                { name: '📊 إحصائيات السيرفر', value: `**عدد الأعضاء:** ${member.guild.memberCount}\n**تاريخ الانضمام:** ${time(joinDate, 'F')}` }
            ]
        });
        
        console.log(`✅ تم تسجيل انضمام العضو ${member.user.username}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل انضمام عضو:', error);
    }
});

// 2. مغادرة عضو
client.on(Events.GuildMemberRemove, async (member) => {
    try {
        const audit = await getAudit(member.guild, AuditLogEvent.MemberKick);
        const banAudit = await getAudit(member.guild, AuditLogEvent.MemberBanAdd);
        
        // إذا كان بان
        if (banAudit && banAudit.target.id === member.id && (Date.now() - banAudit.createdTimestamp < 5000)) {
            return;
        }
        
        // إذا كان طرد
        if (audit && audit.target.id === member.id && (Date.now() - audit.createdTimestamp < 5000)) {
            await sendLog(member.guild, 'memberLeave', {
                title: 'طرد عضو ⚠️',
                authorName: 'تم طرد عضو من السيرفر',
                fields: [
                    { name: '👤 معلومات العضو', value: `**المستخدم:** <@${member.id}>\n**اسم المستخدم:** ${member.user.username}\n**معرف المستخدم:** ${member.id}` },
                    { name: '🛡️ الادمن', value: `**الادمن:** <@${audit.executor.id}>\n**السبب:** ${audit.reason || 'لم يقدم سبب'}` },
                    { name: '⏰ الوقت', value: time(new Date(), 'F') }
                ]
            });
            
            console.log(`✅ تم تسجيل طرد العضو ${member.user.username}`);
            return;
        }
        
        // إذا خرج من نفسه
        await sendLog(member.guild, 'memberLeave', {
            title: 'مغادرة شخص 🚪',
            authorName: `عضو ${member.user.username} قد غادر السيرفر`,
            fields: [
                { name: '👤 معلومات العضو', value: `**العضو:** <@${member.id}>\n**اسم المستخدم:** ${member.user.username}\n**معرف المستخدم:** ${member.id}` },
                { name: '⏰ الوقت', value: time(new Date(), 'F') }
            ]
        });
        
        console.log(`✅ تم تسجيل مغادرة العضو ${member.user.username}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل مغادرة عضو:', error);
    }
});

// 3. حذف رسالة
client.on(Events.MessageDelete, async (message) => {
    try {
        if (!message.guild || message.author?.bot) return;
        
        const audit = await getAudit(message.guild, AuditLogEvent.MessageDelete);
        const executor = (audit && audit.target && audit.target.id === message.author.id) ? audit.executor : message.author;
        
        await sendLog(message.guild, 'msgDelete', {
            title: 'حذف رسالة 🗑️',
            authorName: `تم حذف رسالة في #${message.channel.name}!`,
            fields: [
                { name: '👤 صاحب الرسالة', value: `**الشخص:** <@${message.author.id}>\n**اسم الشخص:** ${message.author.username}\n**معرّف الشخص:** ${message.author.id}` },
                { name: '📝 معلومات الرسالة', value: message.content?.substring(0, 1000) || 'محتوى غير نصي' },
                { name: '🆔 ايدي الرسالة', value: message.id },
                { name: '💬 الروم', value: `**الروم:** <#${message.channel.id}>\n**الاسم:** ${message.channel.name}` },
                { name: '🛡️ الادمن', value: `**الادمن:** <@${executor.id}>\n**اسم الادمن:** ${executor.username}\n**معرّف الادمن:** ${executor.id}` },
                { name: '⏰ التوقيت', value: time(new Date(), 'F') }
            ]
        });
        
        console.log(`✅ تم تسجيل حذف رسالة في ${message.channel.name}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل حذف رسالة:', error);
    }
});

// 4. تعديل رسالة
client.on(Events.MessageUpdate, async (oldMessage, newMessage) => {
    try {
        if (!oldMessage.guild || oldMessage.author?.bot || oldMessage.content === newMessage.content) return;
        
        await sendLog(oldMessage.guild, 'msgUpdate', {
            title: 'تعديل رسالة 📝',
            authorName: 'معلومات الرسالة',
            fields: [
                { name: '👤 صاحب الرسالة', value: `**الشخص:** <@${oldMessage.author.id}>\n**اسم الشخص:** ${oldMessage.author.username}` },
                { name: '📝 الرسالة القديمة', value: oldMessage.content?.substring(0, 1000) || 'لا توجد' },
                { name: '📝 الرسالة الجديدة', value: newMessage.content?.substring(0, 1000) || 'لا توجد' },
                { name: '⏰ التوقيت', value: time(new Date(), 'F') }
            ]
        });
        
        console.log(`✅ تم تسجيل تعديل رسالة من ${oldMessage.author.username}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل تعديل رسالة:', error);
    }
});

// 5. الرومات
client.on(Events.ChannelCreate, async (channel) => {
    try {
        const audit = await getAudit(channel.guild, AuditLogEvent.ChannelCreate);
        
        await sendLog(channel.guild, 'channelLog', {
            title: 'انشاء روم 📁',
            authorName: `تم إنشاء روم جديد ${channel.name}!`,
            fields: [
                { name: '💬 معلومات الروم', value: `**الروم:** <#${channel.id}>\n**اسم الروم:** ${channel.name}\n**نوع الروم:** ${channel.type === 0 ? 'Text Channel' : channel.type === 2 ? 'Voice Channel' : 'Category'}` },
                { name: '🛡️ الادمن', value: `**الادمن:** <@${audit?.executor.id}>\n**اسم الادمن:** ${audit?.executor.username}\n**معرّف الادمن:** ${audit?.executor.id}` },
                { name: '⏰ التوقيت', value: time(new Date(), 'F') }
            ]
        });
        
        console.log(`✅ تم تسجيل إنشاء روم ${channel.name}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل إنشاء روم:', error);
    }
});

client.on(Events.ChannelDelete, async (channel) => {
    try {
        const audit = await getAudit(channel.guild, AuditLogEvent.ChannelDelete);
        
        await sendLog(channel.guild, 'channelLog', {
            title: 'حذف روم 🗑️',
            authorName: `تم حذف الروم ${channel.name}!`,
            fields: [
                { name: '💬 معلومات الروم', value: `**اسم الروم:** ${channel.name}\n**نوع الروم:** ${channel.type === 0 ? 'Text Channel' : channel.type === 2 ? 'Voice Channel' : 'Category'}` },
                { name: '🛡️ الادمن', value: `**الادمن:** <@${audit?.executor.id}>\n**اسم الادمن:** ${audit?.executor.username}\n**معرّف الادمن:** ${audit?.executor.id}` },
                { name: '⏰ التوقيت', value: time(new Date(), 'F') }
            ]
        });
        
        console.log(`✅ تم تسجيل حذف روم ${channel.name}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل حذف روم:', error);
    }
});

client.on(Events.ChannelUpdate, async (oldChannel, newChannel) => {
    try {
        if (oldChannel.name !== newChannel.name) {
            const audit = await getAudit(newChannel.guild, AuditLogEvent.ChannelUpdate);
            
            await sendLog(newChannel.guild, 'channelLog', {
                title: 'تحديث اسم الروم 📝',
                authorName: `تم تحديث الروم ${newChannel.name}.`,
                fields: [
                    { name: '💬 معلومات الروم المحدثة', value: `**الروم:** <#${newChannel.id}>\n**الاسم:** ${newChannel.name}\n**النوع:** ${newChannel.type === 0 ? 'Text Channel' : newChannel.type === 2 ? 'Voice Channel' : 'Category'}` },
                    { name: '📝 تحديث اسم الروم', value: `**الاسم القديم:** ${oldChannel.name}\n**الاسم الجديد:** ${newChannel.name}` },
                    { name: '🛡️ تم التحديث بواسطة', value: `**الادمن:** <@${audit?.executor.id}>\n**اسم الادمن:** ${audit?.executor.username}\n**معرف الادمن:** ${audit?.executor.id}` },
                    { name: '⏰ وقت التحديث', value: time(new Date(), 'R') }
                ]
            });
            
            console.log(`✅ تم تسجيل تحديث روم ${oldChannel.name} إلى ${newChannel.name}`);
        }
    } catch (error) {
        console.error('❌ خطأ في تسجيل تحديث روم:', error);
    }
});

// 6. الرتب
client.on(Events.GuildMemberUpdate, async (oldMember, newMember) => {
    try {
        const audit = await getAudit(newMember.guild, AuditLogEvent.MemberRoleUpdate);
        
        // إضافة رتبة
        if (oldMember.roles.cache.size < newMember.roles.cache.size) {
            const addedRole = newMember.roles.cache.find(role => !oldMember.roles.cache.has(role.id));
            
            await sendLog(newMember.guild, 'roleLog', {
                title: 'اعطاء رتبة 🎖️',
                authorName: `تم اعطاء رتبة لعضو في ${newMember.guild.name}`,
                fields: [
                    { name: '👤 معلومات العضو', value: `**العضو:** <@${newMember.id}>\n**اسم العضو:** ${newMember.user.username}` },
                    { name: '🎖️ الرتبة المعطاة', value: `<@&${addedRole.id}>` },
                    { name: '🛡️ تم اعطاء الرتبة بواسطة', value: `**الادمن:** <@${audit?.executor.id}>\n**اسم الادمن:** ${audit?.executor.username}` },
                    { name: '📝 سبب الاعطاء', value: audit?.reason || 'لم يتم تقديم سبب' },
                    { name: '⏰ وقت الاعطاء', value: time(new Date(), 'F') }
                ]
            });
            
            console.log(`✅ تم تسجيل إعطاء رتبة للعضو ${newMember.user.username}`);
        }
        // إزالة رتبة
        else if (oldMember.roles.cache.size > newMember.roles.cache.size) {
            const removedRole = oldMember.roles.cache.find(role => !newMember.roles.cache.has(role.id));
            
            await sendLog(newMember.guild, 'roleLog', {
                title: 'ازالة رتبة ⬇️',
                authorName: `تم ازالة رتبة من عضو في ${newMember.guild.name}`,
                fields: [
                    { name: '👤 معلومات العضو', value: `**العضو:** <@${newMember.id}>\n**اسم العضو:** ${newMember.user.username}` },
                    { name: '🎖️ الرتبة المزالة', value: `<@&${removedRole.id}>` },
                    { name: '🛡️ تم الازالة بواسطة', value: `**الادمن:** <@${audit?.executor.id}>\n**اسم الادمن:** ${audit?.executor.username}` },
                    { name: '📝 سبب الازالة', value: audit?.reason || 'لم يتم تقديم سبب' },
                    { name: '⏰ وقت الازالة', value: time(new Date(), 'F') }
                ]
            });
            
            console.log(`✅ تم تسجيل إزالة رتبة من العضو ${newMember.user.username}`);
        }
    } catch (error) {
        console.error('❌ خطأ في تسجيل إدارة الرتب:', error);
    }
});

// 7. البان
client.on(Events.GuildBanAdd, async (ban) => {
    try {
        const audit = await getAudit(ban.guild, AuditLogEvent.MemberBanAdd);
        
        await sendLog(ban.guild, 'banLog', {
            title: 'لوج البان 🔨',
            authorName: `${ban.user.username} تم حظره من السيرفر`,
            thumbnail: ban.user.displayAvatarURL({ dynamic: true, size: 256 }),
            fields: [
                { name: '👤 معلومات العضو', value: `**العضو:** <@${ban.user.id}>\n**اسم العضو:** ${ban.user.username}\n**معرف العضو:** ${ban.user.id}` },
                { name: '📝 السبب', value: ban.reason || 'لم يُقدَّم سبب' },
                { name: '🛡️ الادمن', value: `**الادمن:** <@${audit?.executor.id}>\n**اسم الادمن:** ${audit?.executor.username}\n**معرف الادمن:** ${audit?.executor.id}` },
                { name: '⏰ التوقيت', value: time(new Date(), 'F') }
            ]
        });
        
        console.log(`✅ تم تسجيل بان للعضو ${ban.user.username}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل البان:', error);
    }
});

client.on(Events.GuildBanRemove, async (ban) => {
    try {
        const audit = await getAudit(ban.guild, AuditLogEvent.MemberBanRemove);
        
        await sendLog(ban.guild, 'banLog', {
            title: 'فك البان ✅',
            authorName: `تم ازالة الباند عن العضو ${ban.user.username} من السيرفر`,
            fields: [
                { name: '👤 معلومات العضو المرفوع عنه الباند', value: `**العضو:** <@${ban.user.id}>\n**اسم العضو:** ${ban.user.username}\n**معرف العضو:** ${ban.user.id}` },
                { name: '🛡️ تم ازالة الباند بواسطة', value: `**الادمن:** <@${audit?.executor.id}>\n**اسم الادمن:** ${audit?.executor.username}\n**معرف الادمن:** ${audit?.executor.id}` },
                { name: '⏰ وقت ازالة الباند', value: time(new Date(), 'F') }
            ]
        });
        
        console.log(`✅ تم تسجيل فك بان للعضو ${ban.user.username}`);
    } catch (error) {
        console.error('❌ خطأ في تسجيل فك البان:', error);
    }
});

// 8. الصوت
client.on(Events.VoiceStateUpdate, async (oldState, newState) => {
    try {
        // دخول صوتي
        if (!oldState.channelId && newState.channelId) {
            await sendLog(newState.guild, 'voiceLog', {
                title: 'انضمام عضو 🔊',
                authorName: 'معلومات العضو',
                fields: [
                    { name: '👤 المستخدم', value: `**المستخدم:** <@${newState.id}>\n**اسم المستخدم:** ${newState.member.user.username}\n**معرف المستخدم:** ${newState.id}` },
                    { name: '💬 الروم الصوتي المنضم إليها', value: `**الروم:** <#${newState.channelId}>\n**الاسم:** ${newState.channel?.name || 'غير معروف'}` },
                    { name: '⏰ وقت الانضمام', value: time(new Date(), 'F') }
                ]
            });
            
            console.log(`✅ تم تسجيل دخول صوتي للعضو ${newState.member.user.username}`);
        }
        // خروج صوتي
        else if (oldState.channelId && !newState.channelId) {
            await sendLog(oldState.guild, 'voiceLog', {
                title: 'خروج عضو 🔇',
                authorName: 'معلومات العضو',
                fields: [
                    { name: '👤 المستخدم', value: `**المستخدم:** <@${oldState.id}>\n**اسم المستخدم:** ${oldState.member.user.username}\n**معرف المستخدم:** ${oldState.id}` },
                    { name: '💬 الروم الصوتي المغادر', value: `**الروم:** <#${oldState.channelId}>\n**الاسم:** ${oldState.channel?.name || 'غير معروف'}` },
                    { name: '⏰ وقت المغادرة', value: time(new Date(), 'F') }
                ]
            });
            
            console.log(`✅ تم تسجيل خروج صوتي للعضو ${oldState.member.user.username}`);
        }
    } catch (error) {
        console.error('❌ خطأ في تسجيل الصوت:', error);
    }
});

// ================= [ بقية الملفات ] =================

// حفظ إعدادات السيرفر
app.post('/save-settings/:guildID', checkAdminAccess, async (req, res) => {
    if (!req.isAuthenticated() || !req.user || !req.session.isLogged) {
        console.log('❌ محاولة حفظ إعدادات بدون صلاحية');
        return res.status(401).json({ success: false, message: 'غير مصرح' });
    }
    
    const guildID = req.params.guildID;
    const data = req.body;
    
    console.log(`💾 محاولة حفظ إعدادات للسيرفر: ${guildID}`);
    
    const settings = {};
    
    // جميع أنواع اللوجات المتاحة
    const logTypes = [
        'memberJoin',    // دخول الأعضاء
        'memberLeave',   // خروج الأعضاء
        'msgDelete',     // حذف الرسائل
        'msgUpdate',     // تعديل الرسائل
        'channelLog',    // إدارة الرومات
        'roleLog',       // إدارة الرتب
        'banLog',        // البان وفك البان
        'timeoutLog',    // التايم أوت
        'voiceLog',      // اللوجات الصوتية
        'warnLog',       // التحذيرات
        'permissionLog'  // تحديث الصلاحيات
    ];
    
    // معالجة البيانات
    logTypes.forEach(t => {
        settings[t] = {
            enabled: data[`${t}_en`] === 'on',
            channel: data[`${t}_ch`],
            color: data[`${t}_col`] || '#D4AF37'
        };
    });
    
    try {
        await db.set(`logs_${guildID}`, settings);
        console.log(`✅ إعدادات السيرفر ${guildID} تم حفظها بنجاح`);
        res.json({ success: true, message: 'تم حفظ الإعدادات بنجاح' });
    } catch (error) {
        console.error('❌ خطأ في حفظ الإعدادات:', error);
        res.status(500).json({ success: false, message: 'حدث خطأ أثناء حفظ الإعدادات' });
    }
});

// تحديث بيانات الملف الشخصي
app.post('/update-profile', checkAdminAccess, async (req, res) => {
    if (!req.isAuthenticated() || !req.user || !req.session.isLogged) {
        console.log('❌ محاولة تحديث الملف الشخصي بدون صلاحية');
        return res.redirect('/verify');
    }
    
    const { new_u, new_p } = req.body;
    
    console.log(`👤 محاولة تحديث الملف الشخصي للمستخدم: ${req.user.username}`);
    
    // التحقق من صحة البيانات
    if (!new_u || !new_p || new_u.length < 3 || new_p.length < 6) {
        console.log('❌ بيانات تحديث غير صالحة');
        return res.redirect('/dashboard?error=يجب أن يكون اسم المستخدم 3 أحرف على الأقل وكلمة المرور 6 أحرف على الأقل');
    }
    
    try {
        await db.set(`acc_${req.user.id}.user`, new_u);
        await db.set(`acc_${req.user.id}.pass`, new_p);
        
        console.log(`✅ الملف الشخصي للمستخدم ${req.user.username} تم تحديثه`);
        
        res.redirect('/dashboard?success=تم تحديث البيانات بنجاح');
    } catch (error) {
        console.error('❌ خطأ في تحديث الملف الشخصي:', error);
        res.redirect('/dashboard?error=حدث خطأ أثناء تحديث البيانات');
    }
});

// تسجيل الخروج من الداشبورد فقط
app.get('/logout-dashboard', (req, res) => {
    console.log(`🚪 تسجيل خروج من الداشبورد للمستخدم: ${req.user?.username || 'غير معروف'}`);
    req.session.isLogged = false;
    req.session.loginTime = null;
    res.redirect('/verify');
});

// تسجيل الخروج الكامل
app.get('/logout-full', (req, res) => {
    console.log(`🚪🚪 تسجيل خروج كامل للمستخدم: ${req.user?.username || 'غير معروف'}`);
    req.logout((err) => {
        if (err) {
            console.error('❌ خطأ في تسجيل الخروج:', err);
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('❌ خطأ في تدمير الجلسة:', err);
            }
            res.redirect('/');
        });
    });
});

// صفحة 404
app.use((req, res) => {
    console.log(`❓ صفحة غير موجودة: ${req.url}`);
    res.status(404).render('404', { user: req.user || null });
});

// تشغيل البوت
client.once(Events.ClientReady, async () => {
    console.log(`✅ البوت جاهز: ${client.user.tag}`);
    console.log(`🌐 Dashboard Ready: http://localhost:${config.port || 3000}`);
    console.log(`🔗 رابط التسجيل: http://localhost:${config.port || 3000}/auth/discord`);
    console.log(`👑 لوحة الإدارة: http://localhost:${config.port || 3000}/admin/manage`);
    
    // تحميل قائمة المحظورين من قاعدة البيانات
    try {
        const bannedAccounts = await db.get('banned_accounts') || [];
        const bannedAdmins = await db.get('banned_admins') || [];
        
        bannedAccounts.forEach(id => BANNED_ACCOUNTS.add(id));
        console.log(`✅ تم تحميل ${BANNED_ACCOUNTS.size} حساب محظور من قاعدة البيانات`);
        console.log(`✅ تم تحميل ${bannedAdmins.length} مشرف محظور`);
        
        // إضافة المطور كمسؤول رئيسي إذا لم يكن موجوداً
        if (SUPER_ADMIN_IDS.length > 0) {
            for (const adminId of SUPER_ADMIN_IDS) {
                const discordData = await getDiscordUserData(adminId);
                if (discordData) {
                    await addAdmin(adminId, discordData.username, 'system');
                }
            }
        }
    } catch (error) {
        console.error('❌ خطأ في تحميل قائمة المحظورين:', error);
    }
    
    // حفظ بيانات الديسكورد
    setTimeout(async () => {
        await saveDiscordUserData();
    }, 5000);
    
    // تحديث كل ساعة
    setInterval(async () => {
        await saveDiscordUserData();
    }, 60 * 60 * 1000); // كل ساعة
});

client.login(config.token).catch(console.error);

const PORT = config.port || 3000;
app.listen(PORT, () => {
    console.log(`🚀 الخادم يعمل على المنفذ ${PORT}`);
});

// معالجة الأخطاء
process.on('unhandledRejection', (error) => {
    console.error('❌ خطأ غير معالج:', error);
});

process.on('uncaughtException', (error) => {
    console.error('❌ خطأ غير متوقع:', error);
});

// صفحة 404
app.get('/404', (req, res) => {
    res.render('404', { user: req.user || null });
});
