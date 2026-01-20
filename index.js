'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ===================== НАСТРОЙКИ (V6.1 SINGLE FILE + RU FIRST) =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';

// Тайм-аут 6 секунд
const TIMEOUT_MS = 6000; 
// 200 потоков
const THREADS = 200;

// 1. HARD BAN ПОДCЕТЕЙ (Главная защита от Cogent/ColoCrossing)
const BANNED_RANGES = [
    /^154\.3\./,      // Cogent
    /^38\.154\./,     // Cogent
    /^192\.145\./,    // ColoCrossing
    /^23\.148\./,     // ColoCrossing
    /^198\.12\./,     // ColoCrossing
    /^146\.235\./,    // Redwillow
    /^104\.129\./,    // FranTech
    /^198\.98\./,     // FranTech
    /^107\.17\./      // ColoCrossing
];

// 2. ЧЕРНЫЙ СПИСОК ASN
const CRITICAL_ASNS = [
    'AS174',   // Cogent
    'AS9009',  // M247
    'AS14061', // DigitalOcean
    'AS16509', 'AS14618', // Amazon
    'AS24940', // Hetzner
    'AS16276', 'AS12876', // OVH
    'AS15169', 'AS396982', // Google
    'AS45102', // Alibaba
    'AS132203', 'AS45090', // Tencent
    'AS8075',  // Microsoft Azure
    'AS53667', // FranTech
    'AS36352', // ColoCrossing
    'AS46606'  // Unified Layer
];

// 3. ЧЕРНЫЙ СПИСОК БРЕНДОВ
const BAD_WORDS = [
    'cogent', 'frantech', 'buyvm', 'colocrossing', 'bluehost', 'unified layer',
    'total server', 'digitalocean', 'hetzner', 'ovh', 'linode', 'vultr', 
    'contabo', 'leaseweb', 'hostinger', 'selectel', 'timeweb', 'aeza', 
    'firstbyte', 'myarena', 'beget', 'reg.ru', 'mchost', 'fly servers', 
    'profit server', 'mevspace', 'pq hosting', 'smartape', 'firstvds'
];

// Разделяем хранение, чтобы потом склеить в нужном порядке
let PROXIES_RU = [];
let PROXIES_GLOBAL = [];

const sourceLoader = axios.create({ timeout: 15000 });

// AXIOS
const http = axios.create({
    proxy: false,
    validateStatus: () => true, 
    headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
});

function saveAndExit() {
    console.log('\n💾 СОХРАНЕНИЕ РЕЗУЛЬТАТОВ (RU FIRST)...');
    
    // Склеиваем: Сначала RU, потом остальные
    const finalChain = [...new Set(PROXIES_RU), ...new Set(PROXIES_GLOBAL)];
    // Убираем возможные дубликаты, если IP попал в оба списка (маловероятно, но для надежности)
    const uniqueFinal = [...new Set(finalChain)];

    if (uniqueFinal.length > 0) {
        fs.writeFileSync(OUTPUT_FILE, uniqueFinal.join('\n'));
        console.log(`✅ [TOTAL] Сохранено: ${uniqueFinal.length} шт. -> ${OUTPUT_FILE}`);
        console.log(`   ├─ 🇷🇺 RU: ${PROXIES_RU.length}`);
        console.log(`   └─ 🌍 Other: ${PROXIES_GLOBAL.length}`);
    } else { 
        console.log('⚠️ Нет рабочих прокси.'); 
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

    // 0. HARD BAN
    if (BANNED_RANGES.some(regex => regex.test(host))) return;

    let candidates = ['http', 'socks5'];
    if (rawLine.startsWith('socks')) candidates = ['socks5'];
    else if (rawLine.startsWith('http')) candidates = ['http'];

    let winner = null;
    try {
        winner = await Promise.any(candidates.map(p => checkWithProtocol(host, port, p)));
    } catch { return; }

    const { protocol, latency, agents } = winner;

    try {
        const infoRes = await http.get('http://ip-api.com/json/?fields=status,countryCode,isp,org,as,mobile,proxy,hosting', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            timeout: 5000
        });

        const data = infoRes.data || {};
        if (data.status !== 'success') return;

        const isp = String(data.isp || '').toLowerCase();
        const org = String(data.org || '').toLowerCase();
        const asInfo = String(data.as || '');

        // 1. ASN BAN
        if (CRITICAL_ASNS.some(bad => asInfo.includes(bad))) return;

        // 2. BRAND BAN
        const isBadBrand = BAD_WORDS.some(w => 
            isp.includes(w) || org.includes(w) || asInfo.toLowerCase().includes(w)
        );

        if (isBadBrand) return;

        // ВЫВОД И СОРТИРОВКА
        const isRu = data.countryCode === 'RU';
        const icon = latency < 1500 ? '🚀' : '🐢';
        const type = data.mobile ? '📱 MOB' : (data.hosting ? '🏢 BIZ' : '🏠 HOME');
        const flag = isRu ? '🇷🇺 RU' : data.countryCode;
        
        console.log(`✅ ADDED | ${flag} | ${type} | ${icon} ${latency}ms | ${data.isp.substring(0, 25)}`);
        
        const validProxy = `${protocol}://${host}:${port}`;
        
        // РАСПРЕДЕЛЯЕМ ПО СПИСКАМ
        if (isRu) {
            PROXIES_RU.push(validProxy);
        } else {
            PROXIES_GLOBAL.push(validProxy);
        }

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
            else if (l.includes('socks4://')) p = 'socks4://' + m[0]; // (socks4 отсеется при проверке)
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
    console.log('--- PROXY CHECKER (V6.1 RU FIRST) ---\n');
    const raw = await loadSources();
    if(raw.length===0) return;
    const unique = [...new Set(raw)];
    console.log(`📥 Candidates: ${unique.length} | Threads: ${THREADS} | Timeout: ${TIMEOUT_MS}ms`);
    const t = setTimeout(() => { console.log('HARD TIMEOUT'); saveAndExit(); }, 45*60000);
    await mapWithConcurrency(unique, THREADS, checkResidential);
    clearTimeout(t);
    saveAndExit();
}

main().catch(e => { console.error(e); process.exit(1); });
