// worker.js

// 辅助函数模块
const utils = {
    /**
     * 从 Cookie 字符串中获取指定键的值
     * @param {string} cookieString
     * @param {string} key
     * @returns {string|null}
     */
    getCookieValue(cookieString, key) {
        if (!cookieString) return null;
        const match = cookieString.match(new RegExp('(^| )' + key + '=([^;]+)'));
        return match ? match[2] : null;
    },

    /**
     * 生成 JWT
     * @param {string} username - 用户名
     * @param {string} secret - JWT 密钥
     * @returns {Promise<string>}
     */
    async generateJWT(username, secret) {
        const header = { alg: 'HS256', typ: 'JWT' };
        const payload = { username, iat: Math.floor(Date.now() / 1000) };

        const headerBase64 = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const payloadBase64 = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        const textEncoder = new TextEncoder();
        const keyData = textEncoder.encode(secret);
        const messageData = textEncoder.encode(`${headerBase64}.${payloadBase64}`);

        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "HMAC", hash: { name: "SHA-256" } },
            false,
            ["sign"]
        );

        const signatureBuffer = await crypto.subtle.sign(
            "HMAC",
            cryptoKey,
            messageData
        );

        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        return `${headerBase64}.${payloadBase64}.${signatureBase64}`;
    },

    /**
     * 验证 JWT
     * @param {string} token - JWT 令牌
     * @param {string} secret - JWT 密钥
     * @returns {Promise<object|null>} - 返回 payload 或 null
     */
    async verifyJWT(token, secret) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;

            const [headerBase64, payloadBase64, signatureBase64] = parts;
            const signatureInput = `${headerBase64}.${payloadBase64}`;

            const textEncoder = new TextEncoder();
            const keyData = textEncoder.encode(secret);
            const messageData = textEncoder.encode(signatureInput);

            const cryptoKey = await crypto.subtle.importKey(
                "raw",
                keyData,
                { name: "HMAC", hash: { name: "SHA-256" } },
                false,
                ["verify"]
            );

            const decodedSignature = Uint8Array.from(atob(signatureBase64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

            const isValid = await crypto.subtle.verify(
                "HMAC",
                cryptoKey,
                decodedSignature,
                messageData
            );

            if (!isValid) return null;

            const payload = JSON.parse(atob(payloadBase64.replace(/-/g, '+').replace(/_/g, '/')));
            return payload;
        } catch (error) {
            console.error("JWT verification failed:", error);
            return null;
        }
    },

    /**
     * 对密码进行哈希
     * @param {string} password - 明文密码
     * @param {string} salt - 盐值
     * @returns {Promise<string>} - 哈希后的密码
     */
    async hashPassword(password, salt) {
        const textEncoder = new TextEncoder();
        const passwordData = textEncoder.encode(password);
        const saltData = textEncoder.encode(salt);

        // 使用 PBKDF2
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            passwordData,
            { name: "PBKDF2" },
            false,
            ["deriveBits"]
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: saltData,
                iterations: 100000, // 迭代次数，越高越安全但越慢
                hash: "SHA-256",
            },
            keyMaterial,
            256 // 256位输出
        );

        const hashArray = Array.from(new Uint8Array(derivedBits));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    /**
     * 验证密码
     * @param {string} password - 明文密码
     * @param {string} hashedPassword - 哈希后的密码
     * @param {string} salt - 盐值
     * @returns {Promise<boolean>}
     */
    async verifyPassword(password, hashedPassword, salt) {
        const newHash = await this.hashPassword(password, salt);
        return newHash === hashedPassword;
    },

    /**
     * 生成随机盐值
     * @param {number} length - 盐值长度
     * @returns {string}
     */
    generateSalt(length = 16) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0987654321';
        let result = '';
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
};

// 配置管理模块
const configManager = {
    /**
     * 从 KV 获取配置，并提供默认值
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<object>}
     */
    async getConfig(env) {
        let config = {};
        try {
            const data = await env.SUBSCRIPTIONS_KV.get('config');
            config = data ? JSON.parse(data) : {};
        } catch (error) {
            console.error("Failed to load config from KV:", error);
        }

        // 使用环境变量或 KV 默认值，JWT_SECRET 必须从 env.JWT_SECRET 获取
        return {
            ADMIN_USERNAME: config.ADMIN_USERNAME || 'admin',
            ADMIN_PASSWORD_HASH: config.ADMIN_PASSWORD_HASH || '', // 哈希后的密码
            ADMIN_PASSWORD_SALT: config.ADMIN_PASSWORD_SALT || '', // 密码盐
            JWT_SECRET: env.JWT_SECRET || 'please_set_your_jwt_secret_in_workers_environment_variables', // 强制从环境变量获取
            TG_BOT_TOKEN: config.TG_BOT_TOKEN || '',
            TG_CHAT_ID: config.TG_CHAT_ID || '',
            NOTIFYX_API_KEY: config.NOTIFYX_API_KEY || '',
            NOTIFICATION_TYPE: config.NOTIFICATION_TYPE || 'notifyx'
        };
    },

    /**
     * 更新并保存配置到 KV
     * @param {object} newConfig - 新的配置对象
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<boolean>}
     */
    async updateConfig(newConfig, env) {
        try {
            const currentConfig = await this.getConfig(env);
            const updatedConfig = { ...currentConfig };

            // 更新管理员用户名
            if (newConfig.ADMIN_USERNAME && newConfig.ADMIN_USERNAME.trim() !== '') {
                updatedConfig.ADMIN_USERNAME = newConfig.ADMIN_USERNAME.trim();
            }

            // 更新密码 (如果提供)
            if (newConfig.ADMIN_PASSWORD) {
                const newSalt = utils.generateSalt();
                updatedConfig.ADMIN_PASSWORD_SALT = newSalt;
                updatedConfig.ADMIN_PASSWORD_HASH = await utils.hashPassword(newConfig.ADMIN_PASSWORD, newSalt);
            }

            // 更新通知设置
            updatedConfig.TG_BOT_TOKEN = newConfig.TG_BOT_TOKEN !== undefined ? newConfig.TG_BOT_TOKEN.trim() : updatedConfig.TG_BOT_TOKEN;
            updatedConfig.TG_CHAT_ID = newConfig.TG_CHAT_ID !== undefined ? newConfig.TG_CHAT_ID.trim() : updatedConfig.TG_CHAT_ID;
            updatedConfig.NOTIFYX_API_KEY = newConfig.NOTIFYX_API_KEY !== undefined ? newConfig.NOTIFYX_API_KEY.trim() : updatedConfig.NOTIFYX_API_KEY;
            updatedConfig.NOTIFICATION_TYPE = newConfig.NOTIFICATION_TYPE !== undefined ? newConfig.NOTIFICATION_TYPE : updatedConfig.NOTIFICATION_TYPE;

            // 移除 JWT_SECRET 等敏感信息，它们不应存储在 KV 中
            delete updatedConfig.JWT_SECRET;

            await env.SUBSCRIPTIONS_KV.put('config', JSON.stringify(updatedConfig));
            return true;
        } catch (error) {
            console.error("Failed to update config:", error);
            return false;
        }
    }
};

// 通知服务模块
const notificationService = {
    /**
     * 发送 Telegram 通知
     * @param {string} message - 通知内容
     * @param {object} config - 配置对象
     * @returns {Promise<boolean>}
     */
    async sendTelegramNotification(message, config) {
        try {
            if (!config.TG_BOT_TOKEN || !config.TG_CHAT_ID) {
                console.warn('[Telegram] 通知未配置，缺少Bot Token或Chat ID');
                return false;
            }

            const url = `https://api.telegram.org/bot${config.TG_BOT_TOKEN}/sendMessage`;
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: config.TG_CHAT_ID,
                    text: message,
                    parse_mode: 'Markdown'
                })
            });

            const result = await response.json();
            if (!result.ok) {
                console.error('[Telegram] 发送失败:', result);
            }
            return result.ok;
        } catch (error) {
            console.error('[Telegram] 发送通知失败:', error);
            return false;
        }
    },

    /**
     * 发送 NotifyX 通知
     * @param {string} title - 标题
     * @param {string} content - 内容 (支持 Markdown)
     * @param {string} description - 描述
     * @param {object} config - 配置对象
     * @returns {Promise<boolean>}
     */
    async sendNotifyXNotification(title, content, description, config) {
        try {
            if (!config.NOTIFYX_API_KEY) {
                console.warn('[NotifyX] 通知未配置，缺少API Key');
                return false;
            }

            const url = `https://www.notifyx.cn/api/v1/send/${config.NOTIFYX_API_KEY}`;
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: title,
                    content: content,
                    description: description || ''
                })
            });

            const result = await response.json();
            if (result.status !== 'queued') {
                console.error('[NotifyX] 发送失败:', result);
            }
            return result.status === 'queued';
        } catch (error) {
            console.error('[NotifyX] 发送通知失败:', error);
            return false;
        }
    },

    /**
     * 根据配置发送通知
     * @param {string} title - 标题
     * @param {string} content - 内容
     * @param {string} description - 描述
     * @param {object} config - 配置对象
     * @returns {Promise<boolean>}
     */
    async sendNotification(title, content, description, config) {
        if (config.NOTIFICATION_TYPE === 'notifyx') {
            return await this.sendNotifyXNotification(title, content, description, config);
        } else {
            // Telegram 不支持独立的 title 和 description，内容全部放在 content
            return await this.sendTelegramNotification(content, config);
        }
    }
};

// 订阅数据管理模块
const subscriptionData = {
    /**
     * 获取所有订阅
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<Array<object>>}
     */
    async getAllSubscriptions(env) {
        try {
            const data = await env.SUBSCRIPTIONS_KV.get('subscriptions');
            return data ? JSON.parse(data) : [];
        } catch (error) {
            console.error("Failed to get all subscriptions from KV:", error);
            return [];
        }
    },

    /**
     * 获取单个订阅
     * @param {string} id - 订阅 ID
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<object|undefined>}
     */
    async getSubscription(id, env) {
        const subscriptions = await this.getAllSubscriptions(env);
        return subscriptions.find(s => s.id === id);
    },

    /**
     * 创建订阅
     * @param {object} subData - 订阅数据
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<object>}
     */
    async createSubscription(subData, env) {
        try {
            if (!subData.name || !subData.expiryDate || !subData.periodValue || !subData.periodUnit) {
                return { success: false, message: '名称、到期日期、周期数值和周期单位是必填项' };
            }

            const subscriptions = await this.getAllSubscriptions(env);
            let expiryDateObj = new Date(subData.expiryDate);
            const now = new Date();

            // 如果设置了周期且到期日期在过去，则推算到未来最近的周期
            if (expiryDateObj < now && subData.periodValue > 0) {
                while (expiryDateObj < now) {
                    if (subData.periodUnit === 'day') {
                        expiryDateObj.setDate(expiryDateObj.getDate() + subData.periodValue);
                    } else if (subData.periodUnit === 'month') {
                        expiryDateObj.setMonth(expiryDateObj.getMonth() + subData.periodValue);
                    } else if (subData.periodUnit === 'year') {
                        expiryDateObj.setFullYear(expiryDateObj.getFullYear() + subData.periodValue);
                    } else {
                        break; // 无效单位，停止循环
                    }
                }
                console.log(`[Create] Subscription ${subData.name} expiry date adjusted to future: ${expiryDateObj.toISOString()}`);
            }

            const newSubscription = {
                id: crypto.randomUUID(), // 使用更安全的 UUID 生成
                name: subData.name.trim(),
                customType: (subData.customType || '').trim(),
                startDate: subData.startDate ? new Date(subData.startDate).toISOString().split('T')[0] : null,
                expiryDate: expiryDateObj.toISOString().split('T')[0], // 存储为 YYYY-MM-DD
                periodValue: parseInt(subData.periodValue),
                periodUnit: subData.periodUnit,
                reminderDays: parseInt(subData.reminderDays) || 0,
                notes: (subData.notes || '').trim(),
                isActive: subData.isActive !== false, // 默认启用
                autoRenew: subData.autoRenew !== false, // 默认自动续订
                createdAt: new Date().toISOString()
            };

            subscriptions.push(newSubscription);
            await env.SUBSCRIPTIONS_KV.put('subscriptions', JSON.stringify(subscriptions));
            return { success: true, subscription: newSubscription };
        } catch (error) {
            console.error("Failed to create subscription:", error);
            return { success: false, message: '创建订阅失败: ' + error.message };
        }
    },

    /**
     * 更新订阅
     * @param {string} id - 订阅 ID
     * @param {object} subData - 订阅数据
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<object>}
     */
    async updateSubscription(id, subData, env) {
        try {
            const subscriptions = await this.getAllSubscriptions(env);
            const index = subscriptions.findIndex(s => s.id === id);

            if (index === -1) {
                return { success: false, message: '订阅不存在' };
            }

            if (!subData.name || !subData.expiryDate || !subData.periodValue || !subData.periodUnit) {
                return { success: false, message: '名称、到期日期、周期数值和周期单位是必填项' };
            }

            let expiryDateObj = new Date(subData.expiryDate);
            const now = new Date();

            // 如果设置了周期且到期日期在过去，则推算到未来最近的周期
            if (expiryDateObj < now && subData.periodValue > 0) {
                while (expiryDateObj < now) {
                    if (subData.periodUnit === 'day') {
                        expiryDateObj.setDate(expiryDateObj.getDate() + subData.periodValue);
                    } else if (subData.periodUnit === 'month') {
                        expiryDateObj.setMonth(expiryDateObj.getMonth() + subData.periodValue);
                    } else if (subData.periodUnit === 'year') {
                        expiryDateObj.setFullYear(expiryDateObj.getFullYear() + subData.periodValue);
                    } else {
                        break; // 无效单位，停止循环
                    }
                }
                console.log(`[Update] Subscription ${subData.name} expiry date adjusted to future: ${expiryDateObj.toISOString()}`);
            }

            subscriptions[index] = {
                ...subscriptions[index],
                name: subData.name.trim(),
                customType: (subData.customType || '').trim(),
                startDate: subData.startDate ? new Date(subData.startDate).toISOString().split('T')[0] : null,
                expiryDate: expiryDateObj.toISOString().split('T')[0],
                periodValue: parseInt(subData.periodValue),
                periodUnit: subData.periodUnit,
                reminderDays: parseInt(subData.reminderDays) || 0,
                notes: (subData.notes || '').trim(),
                isActive: subData.isActive !== undefined ? subData.isActive : subscriptions[index].isActive,
                autoRenew: subData.autoRenew !== undefined ? subData.autoRenew : subscriptions[index].autoRenew,
                updatedAt: new Date().toISOString()
            };

            await env.SUBSCRIPTIONS_KV.put('subscriptions', JSON.stringify(subscriptions));
            return { success: true, subscription: subscriptions[index] };
        } catch (error) {
            console.error("Failed to update subscription:", error);
            return { success: false, message: '更新订阅失败: ' + error.message };
        }
    },

    /**
     * 删除订阅
     * @param {string} id - 订阅 ID
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<object>}
     */
    async deleteSubscription(id, env) {
        try {
            const subscriptions = await this.getAllSubscriptions(env);
            const initialLength = subscriptions.length;
            const filteredSubscriptions = subscriptions.filter(s => s.id !== id);

            if (filteredSubscriptions.length === initialLength) {
                return { success: false, message: '订阅不存在' };
            }

            await env.SUBSCRIPTIONS_KV.put('subscriptions', JSON.stringify(filteredSubscriptions));
            return { success: true };
        } catch (error) {
            console.error("Failed to delete subscription:", error);
            return { success: false, message: '删除订阅失败: ' + error.message };
        }
    },

    /**
     * 切换订阅状态 (启用/停用)
     * @param {string} id - 订阅 ID
     * @param {boolean} isActive - 是否启用
     * @param {Env} env - Cloudflare Workers 环境变量
     * @returns {Promise<object>}
     */
    async toggleSubscriptionStatus(id, isActive, env) {
        try {
            const subscriptions = await this.getAllSubscriptions(env);
            const index = subscriptions.findIndex(s => s.id === id);

            if (index === -1) {
                return { success: false, message: '订阅不存在' };
            }

            subscriptions[index] = {
                ...subscriptions[index],
                isActive: isActive,
                updatedAt: new Date().toISOString()
            };

            await env.SUBSCRIPTIONS_KV.put('subscriptions', JSON.stringify(subscriptions));
            return { success: true, subscription: subscriptions[index] };
        } catch (error) {
            console.error("Failed to toggle subscription status:", error);
            return { success: false, message: '更新订阅状态失败: ' + error.message };
        }
    }
};

// API 路由处理
const apiRouter = {
    async handle(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname.replace(/^\/api/, ''); // 移除 /api 前缀
        const method = request.method;

        // 特殊处理登录和登出，不需要认证
        if (path === '/login' && method === 'POST') {
            return this.handleLogin(request, env);
        }
        if (path === '/logout' && (method === 'GET' || method === 'POST')) {
            return this.handleLogout(request);
        }

        // 所有其他 API 请求需要认证
        const token = utils.getCookieValue(request.headers.get('Cookie'), 'token');
        const config = await configManager.getConfig(env);
        const user = token ? await utils.verifyJWT(token, config.JWT_SECRET) : null;

        if (!user) {
            return new Response(
                JSON.stringify({ success: false, message: '未授权访问' }),
                { status: 401, headers: { 'Content-Type': 'application/json' } }
            );
        }

        // 根据路径和方法分发请求
        if (path === '/config') {
            if (method === 'GET') return this.handleGetConfig(env);
            if (method === 'POST') return this.handleUpdateConfig(request, env);
        } else if (path === '/test-notification' && method === 'POST') {
            return this.handleTestNotification(request, env);
        } else if (path === '/subscriptions') {
            if (method === 'GET') return this.handleGetSubscriptions(env);
            if (method === 'POST') return this.handleCreateSubscription(request, env);
        } else if (path.startsWith('/subscriptions/')) {
            const parts = path.split('/');
            const id = parts[2]; // /subscriptions/{id}

            if (parts[3] === 'toggle-status' && method === 'POST') { // /subscriptions/{id}/toggle-status
                return this.handleToggleSubscriptionStatus(id, request, env);
            }
            if (method === 'GET') return this.handleGetSubscription(id, env);
            if (method === 'PUT') return this.handleUpdateSubscription(id, request, env);
            if (method === 'DELETE') return this.handleDeleteSubscription(id, env);
        }

        return new Response(
            JSON.stringify({ success: false, message: '未找到请求的 API 资源' }),
            { status: 404, headers: { 'Content-Type': 'application/json' } }
        );
    },

    async handleLogin(request, env) {
        const { username, password } = await request.json();
        const config = await configManager.getConfig(env);

        if (!config.ADMIN_USERNAME || !config.ADMIN_PASSWORD_HASH || !config.ADMIN_PASSWORD_SALT) {
            return new Response(
                JSON.stringify({ success: false, message: '管理员账户未初始化，请联系管理员' }),
                { status: 500, headers: { 'Content-Type': 'application/json' } }
            );
        }

        const isValid = await utils.verifyPassword(password, config.ADMIN_PASSWORD_HASH, config.ADMIN_PASSWORD_SALT);

        if (username === config.ADMIN_USERNAME && isValid) {
            const token = await utils.generateJWT(username, config.JWT_SECRET);
            return new Response(
                JSON.stringify({ success: true }),
                {
                    headers: {
                        'Content-Type': 'application/json',
                        // Secure 标志建议在 HTTPS 环境下添加
                        'Set-Cookie': `token=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400;` // Secure
                    }
                }
            );
        } else {
            return new Response(
                JSON.stringify({ success: false, message: '用户名或密码错误' }),
                { status: 401, headers: { 'Content-Type': 'application/json' } }
            );
        }
    },

    handleLogout(request) {
        return new Response('', {
            status: 302,
            headers: {
                'Location': '/',
                'Set-Cookie': 'token=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0'
            }
        });
    },

    async handleGetConfig(env) {
        const config = await configManager.getConfig(env);
        // 返回时，不包含敏感信息，如密码哈希和 JWT 密钥
        const { ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT, JWT_SECRET, ...safeConfig } = config;
        return new Response(
            JSON.stringify(safeConfig),
            { headers: { 'Content-Type': 'application/json' } }
        );
    },

    async handleUpdateConfig(request, env) {
        try {
            const newConfig = await request.json();
            const success = await configManager.updateConfig(newConfig, env);
            if (success) {
                return new Response(
                    JSON.stringify({ success: true }),
                    { headers: { 'Content-Type': 'application/json' } }
                );
            } else {
                return new Response(
                    JSON.stringify({ success: false, message: '更新配置失败' }),
                    { status: 500, headers: { 'Content-Type': 'application/json' } }
                );
            }
        } catch (error) {
            return new Response(
                JSON.stringify({ success: false, message: '请求体格式错误或处理失败' }),
                { status: 400, headers: { 'Content-Type': 'application/json' } }
            );
        }
    },

    async handleTestNotification(request, env) {
        try {
            const body = await request.json();
            const config = await configManager.getConfig(env); // 获取当前配置
            let success = false;
            let message = '';

            // 临时覆盖配置中的通知凭据，用于测试
            const testConfig = { ...config };
            if (body.type === 'telegram') {
                testConfig.TG_BOT_TOKEN = body.TG_BOT_TOKEN || config.TG_BOT_TOKEN;
                testConfig.TG_CHAT_ID = body.TG_CHAT_ID || config.TG_CHAT_ID;
                if (!testConfig.TG_BOT_TOKEN || !testConfig.TG_CHAT_ID) {
                    return new Response(
                        JSON.stringify({ success: false, message: '请先填写 Telegram Bot Token 和 Chat ID' }),
                        { status: 400, headers: { 'Content-Type': 'application/json' } }
                    );
                }
                const content = '*测试通知*\n\n这是一条测试通知，用于验证Telegram通知功能是否正常工作。\n\n发送时间: ' + new Date().toLocaleString();
                success = await notificationService.sendTelegramNotification(content, testConfig);
                message = success ? 'Telegram通知发送成功' : 'Telegram通知发送失败，请检查配置或网络';
            } else if (body.type === 'notifyx') {
                testConfig.NOTIFYX_API_KEY = body.NOTIFYX_API_KEY || config.NOTIFYX_API_KEY;
                if (!testConfig.NOTIFYX_API_KEY) {
                    return new Response(
                        JSON.stringify({ success: false, message: '请先填写 NotifyX API Key' }),
                        { status: 400, headers: { 'Content-Type': 'application/json' } }
                    );
                }
                const title = '测试通知';
                const content = '## 这是一条测试通知\n\n用于验证NotifyX通知功能是否正常工作。\n\n发送时间: ' + new Date().toLocaleString();
                const description = '测试NotifyX通知功能';
                success = await notificationService.sendNotifyXNotification(title, content, description, testConfig);
                message = success ? 'NotifyX通知发送成功' : 'NotifyX通知发送失败，请检查配置或网络';
            } else {
                return new Response(
                    JSON.stringify({ success: false, message: '不支持的通知类型' }),
                    { status: 400, headers: { 'Content-Type': 'application/json' } }
                );
            }

            return new Response(
                JSON.stringify({ success, message }),
                { headers: { 'Content-Type': 'application/json' } }
            );
        } catch (error) {
            console.error('测试通知失败:', error);
            return new Response(
                JSON.stringify({ success: false, message: '测试通知失败: ' + error.message }),
                { status: 500, headers: { 'Content-Type': 'application/json' } }
            );
        }
    },

    async handleGetSubscriptions(env) {
        const subscriptions = await subscriptionData.getAllSubscriptions(env);
        return new Response(
            JSON.stringify(subscriptions),
            { headers: { 'Content-Type': 'application/json' } }
        );
    },

    async handleCreateSubscription(request, env) {
        try {
            const subscription = await request.json();
            const result = await subscriptionData.createSubscription(subscription, env);
            return new Response(
                JSON.stringify(result),
                { status: result.success ? 201 : 400, headers: { 'Content-Type': 'application/json' } }
            );
        } catch (error) {
            return new Response(
                JSON.stringify({ success: false, message: '请求体格式错误或创建失败' }),
                { status: 400, headers: { 'Content-Type': 'application/json' } }
            );
        }
    },

    async handleGetSubscription(id, env) {
        const subscription = await subscriptionData.getSubscription(id, env);
        if (subscription) {
            return new Response(
                JSON.stringify(subscription),
                { headers: { 'Content-Type': 'application/json' } }
            );
        } else {
            return new Response(
                JSON.stringify({ success: false, message: '订阅不存在' }),
                { status: 404, headers: { 'Content-Type': 'application/json' } }
            );
        }
    },

    async handleUpdateSubscription(id, request, env) {
        try {
            const subscription = await request.json();
            const result = await subscriptionData.updateSubscription(id, subscription, env);
            return new Response(
                JSON.stringify(result),
                { status: result.success ? 200 : 400, headers: { 'Content-Type': 'application/json' } }
            );
        } catch (error) {
            return new Response(
                JSON.stringify({ success: false, message: '请求体格式错误或更新失败' }),
                { status: 400, headers: { 'Content-Type': 'application/json' } }
            );
        }
    },

    async handleDeleteSubscription(id, env) {
        const result = await subscriptionData.deleteSubscription(id, env);
        return new Response(
            JSON.stringify(result),
            { status: result.success ? 200 : 400, headers: { 'Content-Type': 'application/json' } }
        );
    },

    async handleToggleSubscriptionStatus(id, request, env) {
        try {
            const { isActive } = await request.json();
            const result = await subscriptionData.toggleSubscriptionStatus(id, isActive, env);
            return new Response(
                JSON.stringify(result),
                { status: result.success ? 200 : 400, headers: { 'Content-Type': 'application/json' } }
            );
        } catch (error) {
            return new Response(
                JSON.stringify({ success: false, message: '请求体格式错误或更新状态失败' }),
                { status: 400, headers: { 'Content-Type': 'application/json' } }
            );
        }
    }
};

// 定时任务逻辑
const scheduledTask = {
    async run(env) {
        console.log('[定时任务] 开始检查即将到期的订阅: ' + new Date().toISOString());

        const subscriptions = await subscriptionData.getAllSubscriptions(env);
        console.log(`[定时任务] 共找到 ${subscriptions.length} 个订阅`);

        const config = await configManager.getConfig(env);
        const now = new Date();
        const expiringSubscriptionsToNotify = [];
        const updatedSubscriptionsForKv = new Map(); // 用于存储需要更新的订阅，避免重复

        for (const subscription of subscriptions) {
            if (subscription.isActive === false) {
                console.log(`[定时任务] 订阅 "${subscription.name}" 已停用，跳过`);
                continue;
            }

            let currentExpiryDate = new Date(subscription.expiryDate);
            let daysDiff = Math.ceil((currentExpiryDate - now) / (1000 * 60 * 60 * 24));

            console.log(`[定时任务] 订阅 "${subscription.name}" (ID: ${subscription.id}) 到期日期: ${currentExpiryDate.toISOString().split('T')[0]}, 剩余天数: ${daysDiff}`);

            // 如果已过期，且设置了周期和自动续订，则自动更新到下一个周期
            if (daysDiff < 0 && subscription.periodValue && subscription.periodUnit && subscription.autoRenew === true) {
                console.log(`[定时任务] 订阅 "${subscription.name}" 已过期 (${daysDiff}天) 且启用自动续订，正在更新到下一个周期`);

                let nextExpiryDate = new Date(currentExpiryDate);
                // 循环推算到期日期直到未来
                while (nextExpiryDate < now) {
                    if (subscription.periodUnit === 'day') {
                        nextExpiryDate.setDate(nextExpiryDate.getDate() + subscription.periodValue);
                    } else if (subscription.periodUnit === 'month') {
                        nextExpiryDate.setMonth(nextExpiryDate.getMonth() + subscription.periodValue);
                    } else if (subscription.periodUnit === 'year') {
                        nextExpiryDate.setFullYear(nextExpiryDate.getFullYear() + subscription.periodValue);
                    } else {
                        console.warn(`[定时任务] 订阅 "${subscription.name}" 发现无效周期单位: ${subscription.periodUnit}`);
                        break; // 无效单位，停止循环
                    }
                }

                console.log(`[定时任务] 订阅 "${subscription.name}" 更新到期日期: ${nextExpiryDate.toISOString().split('T')[0]}`);

                const updatedSubscription = {
                    ...subscription,
                    expiryDate: nextExpiryDate.toISOString().split('T')[0],
                    updatedAt: new Date().toISOString()
                };
                updatedSubscriptionsForKv.set(subscription.id, updatedSubscription); // 记录待更新的订阅
                
                // 重新计算更新后的剩余天数，用于判断是否需要立即通知
                daysDiff = Math.ceil((nextExpiryDate - now) / (1000 * 60 * 60 * 24));
            }

            // 判断是否需要发送提醒通知
            const reminderDays = subscription.reminderDays !== undefined ? subscription.reminderDays : 7;
            let shouldRemind = false;

            if (daysDiff < 0) { // 已过期
                shouldRemind = true; // 过期就提醒
            } else if (reminderDays === 0) { // 仅到期日提醒
                shouldRemind = daysDiff === 0;
            } else { // 提前N天提醒
                shouldRemind = daysDiff <= reminderDays;
            }

            if (shouldRemind) {
                console.log(`[定时任务] 订阅 "${subscription.name}" 在提醒范围内，将发送通知`);
                expiringSubscriptionsToNotify.push({
                    ...subscription,
                    daysRemaining: daysDiff,
                    // 如果已在 updatedSubscriptionsForKv 中，则使用最新的到期日期
                    expiryDate: (updatedSubscriptionsForKv.get(subscription.id) || subscription).expiryDate
                });
            }
        }

        // 批量更新 KV
        if (updatedSubscriptionsForKv.size > 0) {
            console.log(`[定时任务] 有 ${updatedSubscriptionsForKv.size} 个订阅需要更新到下一个周期`);
            const finalSubscriptions = subscriptions.map(sub => updatedSubscriptionsForKv.get(sub.id) || sub);
            await env.SUBSCRIPTIONS_KV.put('subscriptions', JSON.stringify(finalSubscriptions));
            console.log('[定时任务] 已更新 KV 中的订阅列表');
        }

        if (expiringSubscriptionsToNotify.length > 0) {
            console.log(`[定时任务] 有 ${expiringSubscriptionsToNotify.length} 个订阅需要发送通知`);

            let title = '订阅到期提醒';
            let content = '';
            let description = `共有 ${expiringSubscriptionsToNotify.length} 个订阅即将到期`;

            if (config.NOTIFICATION_TYPE === 'notifyx') {
                content = '## 订阅到期提醒\n\n';
                for (const subscription of expiringSubscriptionsToNotify) {
                    const typeText = subscription.customType || '其他';
                    let periodText = '';
                    if (subscription.periodValue && subscription.periodUnit) {
                        const unitMap = { day: '天', month: '月', year: '年' };
                        periodText = `(周期: ${subscription.periodValue} ${unitMap[subscription.periodUnit] || subscription.periodUnit})`;
                    }

                    if (subscription.daysRemaining === 0) {
                        content += `⚠️ **${subscription.name}** (${typeText}) ${periodText} 今天到期！\n`;
                    } else if (subscription.daysRemaining < 0) {
                        content += `🚨 **${subscription.name}** (${typeText}) ${periodText} 已过期 ${Math.abs(subscription.daysRemaining)} 天\n`;
                    } else {
                        content += `📅 **${subscription.name}** (${typeText}) ${periodText} 将在 ${subscription.daysRemaining} 天后到期\n`;
                    }

                    if (subscription.notes) {
                        content += `备注: ${subscription.notes}\n`;
                    }
                    content += '\n';
                }
            } else { // Telegram
                content = '*订阅到期提醒*\n\n';
                for (const subscription of expiringSubscriptionsToNotify) {
                    const typeText = subscription.customType || '其他';
                    let periodText = '';
                    if (subscription.periodValue && subscription.periodUnit) {
                        const unitMap = { day: '天', month: '月', year: '年' };
                        periodText = `(周期: ${subscription.periodValue} ${unitMap[subscription.periodUnit] || subscription.periodUnit})`;
                    }

                    if (subscription.daysRemaining === 0) {
                        content += `⚠️ *${subscription.name}* (${typeText}) ${periodText} 今天到期！\n`;
                    } else if (subscription.daysRemaining < 0) {
                        content += `🚨 *${subscription.name}* (${typeText}) ${periodText} 已过期 ${Math.abs(subscription.daysRemaining)} 天\n`;
                    } else {
                        content += `📅 *${subscription.name}* (${typeText}) ${periodText} 将在 ${subscription.daysRemaining} 天后到期\n`;
                    }

                    if (subscription.notes) {
                        content += `备注: ${subscription.notes}\n`;
                    }
                    content += '\n';
                }
            }

            const success = await notificationService.sendNotification(title, content, description, config);
            console.log(`[定时任务] 发送通知 ${success ? '成功' : '失败'}`);
        } else {
            console.log('[定时任务] 没有需要提醒的订阅');
        }

        console.log('[定时任务] 检查完成');
    }
};

// Workers 入口
export default {
    /**
     * @param {Request} request
     * @param {Env} env
     * @param {ExecutionContext} ctx
     */
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // 如果路径以 /api 开头，则交给 API 路由器处理
        if (url.pathname.startsWith('/api')) {
            return apiRouter.handle(request, env, ctx);
        }
        
        // 对于其他路径，重定向到前端页面 (例如 Cloudflare Pages 或其他静态托管)
        // 或者您可以在这里返回默认的登录页面 HTML，如果您的前端是托管在 Worker 内部。
        // 为了简化和推荐的部署方式，这里假设前端是独立托管的。
        // 例如，如果您的前端部署在 Cloudflare Pages 上并绑定到 workers.dev 路由或您的自定义域名，
        // 则此 Worker 仅处理 /api 请求，其他请求会自动路由到 Pages。
        // 如果您确实想在 Worker 中提供 HTML，则需要在这里处理并返回 loginPage 或 adminPage
        // 但这会使得 Workers Bundle Size 变大，并且每次修改前端都要重新部署 Worker。
        
        // 示例：如果前端由 Pages 托管，Workers 仅处理 API。
        // 否则，你可以像原来一样返回 HTML。
        // return new Response(loginPage, {
        //   headers: { 'Content-Type': 'text/html; charset=utf-8' }
        // });
        
        // 建议：如果 Workers 只是 API 层，前端由 Pages 等独立服务。
        // 这里返回 404 或重定向到您的前端URL。
        return new Response('Not Found', { status: 404 });
    },

    /**
     * 定时任务处理
     * @param {ScheduledController} controller
     * @param {Env} env
     * @param {ExecutionContext} ctx
     */
    async scheduled(controller, env, ctx) {
        ctx.waitUntil(scheduledTask.run(env));
    }
};

// 定义 Env 接口以获得类型提示 (在实际部署时不需要)
/**
 * @typedef {Object} Env
 * @property {KVNamespace} SUBSCRIPTIONS_KV - KV Namespace 绑定
 * @property {string} JWT_SECRET - JWT 密钥 Secret 环境变量
 * // 其他环境变量
 */