'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ===================== НАСТРОЙКИ =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';

const THREADS = 25;           
const TIMEOUT_MS = 10000;     // Чуть увеличил таймаут для стабильности
const MAX_LATENCY_MS = 9000;

// ИСПОЛЬЗУЕМ ipwho.is (Он лояльнее к бесплатным запросам, чем ip-api)
const CHECK_URL = 'http://ipwho.is/';

// Стоп-слова (Датацентры)
const BLACKLIST_KEYWORDS = [
   'tor', 'vpn'
];

// Глобальная переменная для хранения результатов в реальном времени
let VALID_PROXIES_CACHE = [];

// Axios для скачивания источников
const sourceLoader = axios.create({ timeout: 15000 });

// Axios для проверки (User-Agent важен, чтобы не блокировали)
const checkerAxios = axios.create({
    timeout: TIMEOUT_MS,
    validateStatus: () => true, 
    proxy: false,
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' }
});

// ===================== ФУНКЦИЯ СОХРАНЕНИЯ =====================
function saveAndExit() {
    console.log('\n💾 ЭКСТРЕННОЕ СОХРАНЕНИЕ...');
    if (VALID_PROXIES_CACHE.length > 0) {
        // Читаем старый файл, если нужно объединить, но мы перезаписываем
        // Чтобы сохранить только живые на данный момент
        fs.writeFileSync(OUTPUT_FILE, VALID_PROXIES_CACHE.join('\n'));
        console.log(`✅ Успешно сохранено ${VALID_PROXIES_CACHE.length} прокси в ${OUTPUT_FILE}`);
    } else {
        console.log('⚠️ Нет валидных прокси для сохранения.');
    }
    process.exit(0);
}

// Перехват сигналов остановки (если GitHub отменит задачу)
process.on('SIGINT', saveAndExit);
process.on('SIGTERM', saveAndExit);

// ===================== УТИЛИТЫ =====================

function normalizeProxyLine(line) {
    const raw = (line || '').trim();
    if (!raw || raw.length < 5) return null;
    if (raw.startsWith('#') || raw.startsWith('//')) return null;
    if (raw.toLowerCase().includes('socks4')) return null;

    let withScheme = raw;
    if (!raw.includes('://')) {
        withScheme = `http://${raw}`;
    }

    try {
        const u = new URL(withScheme);
        if (!u.hostname || !u.port) return null;
        u.protocol = u.protocol.toLowerCase();
        if (!['http:', 'https:', 'socks5:', 'socks5h:'].includes(u.protocol)) return null;
        return u.toString().replace(/\/$/, '');
    } catch {
        return null;
    }
}

function buildAgents(proxyUrl) {
    try {
        const u = new URL(proxyUrl);
        const protocol = u.protocol.replace(':', '');
        const opts = { keepAlive: false, timeout: TIMEOUT_MS };

        if (protocol.startsWith('socks')) {
            const agent = new SocksProxyAgent(proxyUrl, opts);
            return { http: agent, https: agent, cleanup: () => {} };
        }
        if (protocol === 'http') {
            const httpAgent = new HttpProxyAgent(proxyUrl, opts);
            const httpsAgent = new HttpsProxyAgent(proxyUrl, opts);
            return { 
                http: httpAgent, 
                https: httpsAgent, 
                cleanup: () => { httpAgent.destroy(); httpsAgent.destroy(); } 
            };
        }
        if (protocol === 'https') {
            const agent = new HttpsProxyAgent(proxyUrl, opts);
            return { http: agent, https: agent, cleanup: () => agent.destroy() };
        }
    } catch (e) { return null; }
    return null;
}

// ===================== ЛОГИКА ПРОВЕРКИ (UPDATED) =====================

async function checkResidential(proxyUrl) {
    const agents = buildAgents(proxyUrl);
    if (!agents) return null;

    const start = Date.now();

    try {
        const res = await checkerAxios.get(CHECK_URL, {
            httpAgent: agents.http,
            httpsAgent: agents.https
        });

        const latency = Date.now() - start;

        if (latency > MAX_LATENCY_MS) return null;
        if (res.status !== 200) return null;

        // Обработка ответа ipwho.is
        const data = res.data || {};
        
        // ipwho.is возвращает success: true/false
        if (!data.success) return null;

        // Данные соединения
        const connection = data.connection || {};
        const isp = String(connection.isp || '');
        const org = String(connection.org || '');
        const country = String(data.country_code || '??'); // ipwho.is пишет country_code
        
        // Проверка: Это жилой IP?
        // ipwho.is не имеет поля "hosting", поэтому фильтруем только по стоп-словам
        const fullInfo = `${isp} ${org}`.toLowerCase();
        if (BLACKLIST_KEYWORDS.some(w => fullInfo.includes(w))) return null;

        // УСПЕХ
        const icon = latency < 1500 ? '🚀' : '🐢';
        console.log(`✅ RESIDENTIAL | ${country} | ${icon} ${latency}ms | ${isp}`);
        
        // Добавляем в глобальный кэш сразу
        VALID_PROXIES_CACHE.push(proxyUrl);
        
        return proxyUrl;

    } catch (e) {
        return null;
    } finally {
        if (agents.cleanup) agents.cleanup();
    }
}

// ===================== WORKER POOL =====================
async function mapWithConcurrency(items, concurrency, workerFn) {
    const results = [];
    let idx = 0;

    const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (idx < items.length) {
            const i = idx++; 
            const result = await workerFn(items[i]);
            if (result) results.push(result);
        }
    });

    await Promise.all(workers);
    return results;
}

// ===================== MAIN =====================
async function main() {
    console.log('--- HYBRID PROXY CHECKER (Powered by ipwho.is) ---\n');

    // 1. Load Sources
    const rawProxies = await loadSources();
    if (rawProxies.length === 0) {
        console.log('❌ Sources empty.');
        return;
    }

    const normalized = rawProxies.map(normalizeProxyLine).filter(Boolean);
    const unique = [...new Set(normalized)];

    console.log(`📥 Total Unique: ${unique.length}`);
    console.log(`🚀 Starting threads: ${THREADS}`);
    
    // ПРЕДОХРАНИТЕЛЬ: 20 минут (GitHub Free Limit friendly)
    // Если время выйдет, вызовется saveAndExit()
    const scriptTimeout = setTimeout(() => {
         console.log('⚠️ Global timeout reached!');
         saveAndExit();
    }, 20 * 60 * 1000);

    await mapWithConcurrency(unique, THREADS, checkResidential);

    clearTimeout(scriptTimeout);
    
    // Финальное сохранение (если скрипт дошел до конца сам)
    saveAndExit();
}

async function loadSources() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    
    const urls = fs.readFileSync(SOURCES_FILE, 'utf-8')
        .split('\n').map(l => l.trim()).filter(l => l.length > 4 && !l.startsWith('#'));

    console.log(`📡 Downloading from ${urls.length} links...`);
    const allProxies = new Set();

    const tasks = urls.map(url => sourceLoader.get(url)
        .then(res => {
            const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
            const lines = text.split(/\r?\n/);
            lines.forEach(line => {
                const match = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
                if (match) {
                    let fullLine = match[0];
                    if (line.includes('socks5://')) fullLine = 'socks5://' + match[0];
                    else if (line.includes('http://')) fullLine = 'http://' + match[0];
                    allProxies.add(fullLine);
                }
            });
        })
        .catch(err => console.log(`⚠️ Source error: ${err.message}`))
    );

    await Promise.all(tasks);
    return Array.from(allProxies);
}

main().catch(err => {
    console.error('FATAL:', err);
    process.exit(1);
});
