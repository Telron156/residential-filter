'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const https = require('https');

// ===================== НАСТРОЙКИ (V6.8.1 PRIORITIZED) =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';

const TIMEOUT_MS = 10000;
const THREADS = 250; 

// 1. HARD BAN
const BANNED_RANGES = [
    /^154\.3\./, /^38\.154\./, /^192\.145\./, /^23\.148\./, 
    /^198\.12\./, /^146\.235\./, /^104\.129\./, /^198\.98\./, /^107\.17\./
];

// 2. ASN BAN
const CRITICAL_ASNS = [
    'AS174', 'AS9009', 'AS14061', 'AS16509', 'AS14618', 'AS24940',
    'AS16276', 'AS12876', 'AS15169', 'AS396982', 'AS45102', 'AS132203',
    'AS45090', 'AS8075', 'AS53667', 'AS36352', 'AS46606'
];

// 3. ISP BAN
const BAD_WORDS = [
    'amazon', 'google cloud', 'azure', 'digitalocean', 'hetzner', 'ovh', 
    'linode', 'vultr', 'contabo', 'leaseweb', 'hostinger', 'selectel', 
    'timeweb', 'aeza', 'firstbyte', 'myarena', 'beget', 'reg.ru', 'mchost', 
    'activecloud', 'inferno', 'firstvds', 'vdsina', 'clouvider',
    'alibaba', 'tencent', 'oracle', 'ibm cloud', 'scaleway', 'kamatera',
    'waicore', 'emerald onion', 'datawagon', 'g-core', 'gcore', 'cloud assets', 
    'jsc iot', 'serv.host', 'oc networks', 'reliablesite', 'namecheap', 
    'godaddy', 'ionos', 'cloudflare', 'internet names', 'tierpoint', 
    'gigahost', 'green floid', 'packethub', 'cdn77', 'datacamp', 'm247', 
    'performive', 'tzulo', 'psychz', 'choopa', 'creanova', 'pfcloud', 
    'quadranet', 'colocrossing', 'buyvm', 'frantech', 'cogent', 'terrahost', 
    'ip volume', 'ipvolume', 'servers.com', 'servers tech', 'chinanet', 
    'china unicom', 'china mobile', 'tor exit', 'tor node', 'onion', 
    'opera', 'opera software', 'zscaler', 'vpn', 'hosting', 'data center', 
    'dedicated', 'cdn', 'vps', 'webnx', 'tier.net', 'hostpapa', 'coloup', 
    'worktitans', 'wholesale internet', 'llc horizon', 'llc "horizon"', 
    'radist ltd', 'hnns', 'tyo1', 'sgp1', 'digital energy', 'fozzy', 
    'zomro', 'pq hosting', 'baykov', 'mulgin', 'reznichenko'
];

// Массивы для разделения по приоритетам
let PROXIES_RU_MOBILE = [];
let PROXIES_RU_OTHER = [];
let PROXIES_GLOBAL_MOBILE = [];
let PROXIES_GLOBAL_OTHER = [];

const sourceLoader = axios.create({ timeout: 15000, httpsAgent: new https.Agent({ rejectUnauthorized: false }) });

const http = axios.create({
    proxy: false,
    timeout: TIMEOUT_MS,
    validateStatus: () => true, 
    headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
    },
    maxRedirects: 5,
    httpsAgent: new https.Agent({ rejectUnauthorized: false })
});

function saveAndExit() {
    console.log('\n💾 СОХРАНЕНИЕ С ПРИОРИТЕТОМ (RU + MOBILE TOP)...');

    // Сборка в порядке: RU Mob -> RU Other -> Global Mob -> Global Other
    const combined = [
        ...PROXIES_RU_MOBILE,
        ...PROXIES_RU_OTHER,
        ...PROXIES_GLOBAL_MOBILE,
        ...PROXIES_GLOBAL_OTHER
    ];

    const unique = [...new Set(combined)];

    if (unique.length > 0) {
        fs.writeFileSync(OUTPUT_FILE, unique.join('\n'));
        console.log(`✅ TOTAL: ${unique.length}`);
        console.log(`📊 RU: ${PROXIES_RU_MOBILE.length} Mob / ${PROXIES_RU_OTHER.length} Other`);
        console.log(`📊 GLOBAL: ${PROXIES_GLOBAL_MOBILE.length} Mob / ${PROXIES_GLOBAL_OTHER.length} Other`);
    } else { 
        console.log('⚠️ Пусто.'); 
    }
    process.exit(0);
}

process.on('SIGINT', saveAndExit);
process.on('SIGTERM', saveAndExit);

function getAgents(protocol, host, port) {
    const proxyUrl = `${protocol}://${host}:${port}`;
    try {
        const opts = { keepAlive: false, timeout: TIMEOUT_MS };
        if (protocol.startsWith('socks')) {
            const agent = new SocksProxyAgent(proxyUrl, { ...opts, resolveProxy: true });
            return { http: agent, https: agent };
        } else {
            return { 
                http: new HttpProxyAgent(proxyUrl, opts),
                https: new HttpsProxyAgent(proxyUrl, opts)
            };
        }
    } catch { return null; }
}

async function checkWithProtocol(host, port, protocol) {
    const agents = getAgents(protocol, host, port);
    if (!agents) throw new Error('Agent Error');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
        const start = Date.now();
        const res = await http.get('https://ya.ru', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            signal: controller.signal,
            responseType: 'text'
        });
        const latency = Date.now() - start;

        if (res.status !== 200 && res.status !== 403) throw new Error(`Bad Status: ${res.status}`);
        if (res.status === 200) {
            const body = String(res.data || '').toLowerCase();
            if (body.length < 300) throw new Error('Too Short');
            const isYandex = body.includes('yandex') || body.includes('яндекс') || body.includes('dzen') || body.includes('captcha') || body.includes('sso');
            if (!isYandex) throw new Error('Fake Content');
        }
        return { protocol, latency, agents };
    } catch (e) {
        if(agents.http?.destroy) agents.http.destroy();
        if(agents.https?.destroy) agents.https.destroy();
        throw e;
    } finally {
        clearTimeout(timeout);
    }
}

async function checkResidential(rawLine) {
    let clean = rawLine.trim();
    if (clean.length < 5) return;

    let protocolHint = null;
    if (clean.includes('://')) {
        const split = clean.split('://');
        protocolHint = split[0].toLowerCase();
        clean = split[1];
    }

    const lastColonIndex = clean.lastIndexOf(':');
    if (lastColonIndex === -1) return;

    const port = clean.substring(lastColonIndex + 1);
    const host = clean.substring(0, lastColonIndex);

    if (!host.includes('@') && BANNED_RANGES.some(r => r.test(host))) return;

    let candidates = protocolHint ? (protocolHint.startsWith('socks') ? ['socks5'] : ['http']) : ['http', 'socks5'];

    let winner = null;
    try {
        winner = await Promise.any(candidates.map(p => checkWithProtocol(host, port, p)));
    } catch { return; }

    const { protocol, latency, agents } = winner;

    try {
        const info = await http.get('http://ip-api.com/json/?fields=status,countryCode,isp,org,as,mobile,hosting', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            timeout: 8000
        });

        const d = info.data || {};
        if (d.status !== 'success') return;

        const ispFull = `${d.isp || ''} ${d.org || ''} ${d.as || ''}`.toLowerCase();
        if (CRITICAL_ASNS.some(a => ispFull.includes(a.toLowerCase()))) return;
        if (BAD_WORDS.some(w => ispFull.includes(w))) return;

        const isRu = d.countryCode === 'RU';
        const typeIcon = d.mobile ? '📱' : (d.hosting ? '🏢' : '🏠');
        
        console.log(`✅ [${protocol.toUpperCase()}] ${d.countryCode} ${typeIcon} ${latency}ms | ${(d.isp || '').substring(0, 25)}`);

        const res = `${protocol}://${host}:${port}`;
        
        // Распределение по приоритетным массивам
        if (isRu) {
            if (d.mobile) PROXIES_RU_MOBILE.push(res);
            else PROXIES_RU_OTHER.push(res);
        } else {
            if (d.mobile) PROXIES_GLOBAL_MOBILE.push(res);
            else PROXIES_GLOBAL_OTHER.push(res);
        }

    } catch (e) { 
    } finally {
        if(agents.http?.destroy) agents.http.destroy();
        if(agents.https?.destroy) agents.https.destroy();
    }
}

async function runner(items) {
    const chunk = [...items];
    let active = 0;
    return new Promise(resolve => {
        const next = () => {
            if (chunk.length === 0 && active === 0) return resolve();
            while (active < THREADS && chunk.length > 0) {
                active++;
                const item = chunk.shift();
                checkResidential(item).finally(() => {
                    active--;
                    next();
                });
            }
        };
        next();
    });
}

async function main() {
    console.log('--- SCANNER V6.8.1 PRIORITIZED ---');
    if (!fs.existsSync(SOURCES_FILE)) {
        console.log(`❌ Файл ${SOURCES_FILE} не найден!`);
        return;
    }
    
    const lines = fs.readFileSync(SOURCES_FILE, 'utf-8').split(/\r?\n/);
    const set = new Set();
    
    for (const l of lines) {
        const trimmed = l.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        if (trimmed.startsWith('http') && !trimmed.match(/\s/) && !trimmed.match(/\d:\d/)) {
            try {
                console.log(`Скачиваю: ${trimmed.substring(0,40)}...`);
                const r = await sourceLoader.get(trimmed);
                const text = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
                text.split(/\r?\n/).forEach(proxyLine => {
                    const clean = proxyLine.trim();
                    if (clean.length > 6 && clean.includes(':') && /\d/.test(clean)) set.add(clean);
                });
            } catch (e) { console.log(`Ошибка источника: ${e.message}`); }
        } else {
             if (trimmed.length > 6 && trimmed.includes(':')) set.add(trimmed);
        }
    }

    const tasks = Array.from(set);
    console.log(`\n🔎 ЗАДАЧА: ${tasks.length} адресов. Старт через 2 сек...`);
    await new Promise(r => setTimeout(r, 2000));
    
    await runner(tasks);
    saveAndExit();
}

main().catch(e => {
    console.error('FATAL ERROR:', e);
    process.exit(1);
});
