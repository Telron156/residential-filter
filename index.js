'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ===================== НАСТРОЙКИ (V5 PARANOID) =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';
const OUTPUT_FILE_RU = 'valid_proxies_ru.txt';

// Тайм-аут 5 секунд.
const TIMEOUT_MS = 5000; 
const THREADS = 180;

// ЧЕРНЫЙ СПИСОК ASN (ULTIMATE - Все враги здесь)
const CRITICAL_ASNS = [
    'AS174',   // Cogent (Ваш кошмар)
    'AS9009',  // M247
    'AS53667', // FranTech / BuyVM
    'AS36352', // ColoCrossing
    'AS46606', // Unified Layer (Bluehost)
    'AS46562', // Total Server Solutions
    'AS29802', // Hivelocity
    'AS20473', 'AS63949', // Choopa, Vultr
    'AS400304', // Redwillow
    'AS54290', // Hostwinds
    'AS60068', // Datacamp
    'AS14061', // DigitalOcean
    'AS24940', // Hetzner
    'AS16276', 'AS12876', // OVH
    'AS16509', 'AS14618', // Amazon
    'AS15169', 'AS396982', // Google
    'AS8075',  // Microsoft
    'AS45102', // Alibaba
    'AS132203', 'AS45090', // Tencent
    'AS13335', // Cloudflare
    'AS20940', // Akamai
    'AS32934'  // Facebook
];

// ЧЕРНЫЙ СПИСОК БРЕНДОВ
const BAD_WORDS = [
    'cogent', 'frantech', 'buyvm', 'colocrossing', 'bluehost', 'unified layer',
    'total server', 'server solutions', 'digitalocean', 'hetzner', 'ovh', 
    'linode', 'vultr', 'contabo', 'leaseweb', 'hostinger', 'selectel', 
    'timeweb', 'aeza', 'firstbyte', 'myarena', 'beget', 'reg.ru', 'mchost',
    'fly servers', 'profit server', 'mevspace', 'pq hosting', 'smartape',
    'hosting', 'vps', 'cloud', 'datacenter', 'dedic', 'colocation'
];

let VALID_PROXIES_CACHE = [];
let VALID_PROXIES_RU_CACHE = [];
const sourceLoader = axios.create({ timeout: 10000 });

// AXIOS
const http = axios.create({
    proxy: false, // Мы сами управляем агентами
    headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
});

function saveAndExit() {
    console.log('\n💾 СОХРАНЕНИЕ РЕЗУЛЬТАТОВ...');
    if (VALID_PROXIES_CACHE.length > 0) {
        const unique = [...new Set(VALID_PROXIES_CACHE)];
        fs.writeFileSync(OUTPUT_FILE, unique.join('\n'));
        console.log(`✅ [ALL] Итого: ${unique.length} шт. -> ${OUTPUT_FILE}`);
    } else { console.log('⚠️ [ALL] Нет рабочих прокси.'); }
    
    if (VALID_PROXIES_RU_CACHE.length > 0) {
        const uniqueRu = [...new Set(VALID_PROXIES_RU_CACHE)];
        fs.writeFileSync(OUTPUT_FILE_RU, uniqueRu.join('\n'));
        console.log(`🇷🇺 [RU]  Российские: ${uniqueRu.length} шт. -> ${OUTPUT_FILE_RU}`);
    }
    process.exit(0);
}

process.on('SIGINT', saveAndExit);
process.on('SIGTERM', saveAndExit);

function buildAgents(proxyUrl) {
    try {
        const opts = { keepAlive: false };
        if (proxyUrl.startsWith('socks')) {
            const agent = new SocksProxyAgent(proxyUrl, { ...opts, resolveProxy: true });
            return { http: agent, https: agent, cleanup: () => {} };
        }
        const h = new HttpProxyAgent(proxyUrl, opts);
        const hs = new HttpsProxyAgent(proxyUrl, opts);
        return { http: h, https: hs, cleanup: () => { h.destroy(); hs.destroy(); } };
    } catch { return null; }
}

async function checkWithProtocol(host, port, protocol) {
    const proxyUrl = `${protocol}://${host}:${port}`;
    const agents = buildAgents(proxyUrl);
    if (!agents) throw new Error('Agent Fail');
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
        const start = Date.now();
        // 1. Проверка жизни (Ya.ru)
        await http.get('https://ya.ru', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            signal: controller.signal
        });
        
        const latency = Date.now() - start;
        return { protocol, latency, agents };
    } catch (e) {
        if (agents.cleanup) agents.cleanup();
        throw e;
    } finally {
        clearTimeout(timeoutId);
    }
}

async function checkResidential(rawLine) {
    const clean = rawLine.replace(/^(http|https|socks4|socks5|socks5h):\/\//, '').trim();
    if (!clean || clean.length < 5) return;
    const parts = clean.split(':');
    if (parts.length < 2) return;
    const port = parts.pop();
    const host = parts.join(':');

    let candidates = ['socks5']; 
    if (rawLine.startsWith('http')) candidates = ['http'];
    else if (!rawLine.startsWith('socks')) candidates = ['socks5', 'http'];

    let winner = null;
    try {
        winner = await Promise.any(candidates.map(p => checkWithProtocol(host, port, p)));
    } catch { return; }

    const { protocol, latency, agents } = winner;

    try {
        // 2. ПРОВЕРКА IP + ASN + LEAK DETECTION
        // Добавили поле 'query', которое возвращает IP, с которого пришел запрос
        const infoRes = await http.get('http://ip-api.com/json/?fields=status,countryCode,isp,org,as,mobile,proxy,hosting,query', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            timeout: 5000
        });

        const data = infoRes.data || {};
        if (data.status !== 'success') return;

        // === ГЛАВНАЯ ЗАЩИТА: ПРОВЕРКА НА УТЕЧКУ ===
        // Если API видит IP, отличный от того, к которому мы подключились - это "дырявый" прокси.
        // Он подставляет наш реальный IP (сервера), поэтому Cogent проходил проверку.
        if (data.query !== host) {
            // console.log(`❌ LEAK: ${host} (Real: ${data.query})`); 
            return; 
        }

        const isp = String(data.isp || '').toLowerCase();
        const org = String(data.org || '').toLowerCase();
        const asInfo = String(data.as || '');

        // ФАЗА 1: ASN KILL (Проверяем уже подтвержденный IP)
        if (CRITICAL_ASNS.some(bad => asInfo.includes(bad))) return;

        // ФАЗА 2: BRAND KILL
        const isBadWord = BAD_WORDS.some(w => 
            isp.includes(w) || org.includes(w) || asInfo.toLowerCase().includes(w)
        );
        const isMobile = data.mobile === true || isp.includes('mobile') || isp.includes('telecom') || isp.includes('cable') || isp.includes('home');

        if (isBadWord && !isMobile) return;

        // ФИНАЛ
        const isRu = data.countryCode === 'RU';
        const icon = latency < 1500 ? '🚀' : '🐢';
        const type = isMobile ? '📱 MOB' : (data.hosting ? '🏢 VPS' : '🏠 HOME');
        
        console.log(`✅ OK | ${data.countryCode} | ${type} | ${icon} ${latency}ms | ${data.isp.substring(0, 25)}`);
        
        const validProxy = `${protocol}://${host}:${port}`;
        VALID_PROXIES_CACHE.push(validProxy);
        if (isRu) VALID_PROXIES_RU_CACHE.push(validProxy);

    } catch (e) { return; } 
    finally { if (agents.cleanup) agents.cleanup(); }
}

async function mapWithConcurrency(items, concurrency, workerFn) {
    const results = [];
    let idx = 0;
    const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (idx < items.length) {
            const i = idx++;
            await workerFn(items[i]);
        }
    });
    await Promise.all(workers);
}

function parseAndAdd(text, setCollection) {
    text.split(/\r?\n/).forEach(l => {
        const m = l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
        if (m) {
            let p = m[0];
            if (l.includes('socks5://')) p = 'socks5://' + m[0];
            else if (l.includes('http://')) p = 'http://' + m[0];
            setCollection.add(p);
        }
    });
}

async function loadSources() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    const rawLines = fs.readFileSync(SOURCES_FILE, 'utf-8')
        .split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('#'));
    console.log(`📡 Sources: ${rawLines.length}`);
    const all = new Set();
    const urlTasks = [];
    for (const line of rawLines) {
        if (line.startsWith('http')) {
            urlTasks.push(sourceLoader.get(line).then(r => {
                const txt = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
                parseAndAdd(txt, all);
            }).catch(() => {}));
        } else { parseAndAdd(line, all); }
    }
    if (urlTasks.length > 0) await Promise.all(urlTasks);
    return Array.from(all);
}

async function main() {
    console.log('--- SNIPER PROXY CHECKER (V5 PARANOID) ---\n');
    const raw = await loadSources();
    if(raw.length===0) return;
    const unique = [...new Set(raw)];
    console.log(`📥 Unique IPs: ${unique.length} | Threads: ${THREADS} | Timeout: ${TIMEOUT_MS}ms`);
    const t = setTimeout(() => { console.log('HARD TIMEOUT'); saveAndExit(); }, 45*60000);
    await mapWithConcurrency(unique, THREADS, checkResidential);
    clearTimeout(t);
    saveAndExit();
}

main().catch(e => { console.error(e); process.exit(1); });
