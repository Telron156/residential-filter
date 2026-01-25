'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const https = require('https');

// ===================== НАСТРОЙКИ (V8.9 UPDATED FILTERS) =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt'; // Сюда будут падать прокси сразу

const TIMEOUT_MS = 10000;
const THREADS = 200; 

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

// 3. ISP BAN (V8.2 - RESELLER PATCH)
const BAD_WORDS = [
    // === ГИГАНТЫ ХОСТИНГА ===
    'amazon', 'google cloud', 'azure', 'digitalocean', 'hetzner', 'ovh', 
    'linode', 'vultr', 'contabo', 'leaseweb', 'hostinger', 'selectel', 
    'timeweb', 'aeza', 'firstbyte', 'myarena', 'beget', 'reg.ru', 'mchost', 
    'activecloud', 'inferno', 'firstvds', 'vdsina', 'clouvider',
    'alibaba', 'tencent', 'oracle', 'ibm cloud', 'scaleway', 'kamatera',

    // === ТОКСИЧНЫЕ, НАЙДЕННЫЕ В ЛОГАХ ===
    'waicore',
    'emerald onion',  // 🚨 TOR Exit Node
    'datawagon',      // Хостинг
    'g-core',         // CDN/Hosting
    'gcore',          // CDN/Hosting
    'cloud assets',   // Хостинг
    'jsc iot',        // IoT шлюзы
    'serv.host',      // Хостинг
    'oc networks',    // Хостинг

    // === ПРЕДЫДУЩИЕ УСПЕШНЫЕ ФИЛЬТРЫ ===
    'reliablesite', 'namecheap', 'godaddy', 'ionos', 'cloudflare', 
    'internet names', 'tierpoint', 'gigahost', 'green floid',
    'packethub', 'cdn77', 'datacamp', 'm247', 'performive', 'tzulo', 
    'psychz', 'choopa', 'creanova', 'pfcloud', 'quadranet', 'colocrossing', 
    'buyvm', 'frantech', 'cogent', 'terrahost', 'ip volume', 'ipvolume', 
    'servers.com', 'servers tech', 'llc vk',

    // === ГЕО И МУСОР ===
    'chinanet', 'china unicom', 'china mobile', 
    'tor exit', 'tor node', 'onion', 
    'opera', 'opera software',
    'zscaler', 

    // === СТОП-СЛОВА ===
    'vpn', 'hosting', 'data center', 'dedicated', 'cdn', 'vps',

    // === НОВЫЕ (ПАТЧ ИЗ ТВОИХ ЛОГОВ - УТОЧНЕННЫЕ) ===
    'webnx',            // Хостинг
    'tier.net',         // Хостинг
    'hostpapa',         // Хостинг
    'coloup',           // Хостинг
    'worktitans',       // Хостинг
    'wholesale internet', // Исправлено (полное название)
    'llc horizon',      // Исправлено (RU хостинг)
    'llc "horizon"',    
    'radist ltd',       // Исправлено (точное название)
    'hnns', 
    'tyo1',             // Тег датацентра
    'sgp1',             // Тег датацентра
    'digital energy',
    'fozzy', 'zomro', 'pq hosting',

    // Блокировка Yandex Cloud
    'yandex', 'yandex cloud', 'yandex.cloud', 'yandex llc',

    // === РЕСЕЛЛЕРЫ (ИМЕННЫЕ ПОДСЕТИ) ===
    'baykov',           // Baykov Ilya Sergeevich
    'mulgin',           // Mulgin Alexander Sergeevich
    'miglovets',        // Miglovets Egor Andreevich
    'reznichenko'       // Reznichenko Sergey Mykolayovich
];

// Переменные для статистики
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
    console.log('\n🛑 ЗАВЕРШЕНИЕ РАБОТЫ СКРИПТА...');
    console.log('✅ ИТОГОВАЯ СТАТИСТИКА (Все найденные прокси уже в файле):');
    
    // Считаем общее количество для отчета
    const total = PROXIES_RU_MOBILE.length + PROXIES_RU_OTHER.length + PROXIES_GLOBAL_MOBILE.length + PROXIES_GLOBAL_OTHER.length;

    if (total > 0) {
        console.log(`✅ ВСЕГО НАЙДЕНО: ${total}`);
        console.log(`📊 RU: ${PROXIES_RU_MOBILE.length} Mob / ${PROXIES_RU_OTHER.length} Other`);
        console.log(`📊 GLOBAL: ${PROXIES_GLOBAL_MOBILE.length} Mob / ${PROXIES_GLOBAL_OTHER.length} Other`);
    } else { 
        console.log('⚠️ Ничего не найдено.'); 
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
    
    // Чистим еще раз на всякий случай, если пришло из другого места
    if (clean.includes('://')) clean = clean.split('://')[1];

    const lastColonIndex = clean.lastIndexOf(':');
    if (lastColonIndex === -1) return;

    const port = clean.substring(lastColonIndex + 1);
    const host = clean.substring(0, lastColonIndex);

    if (!host.includes('@') && BANNED_RANGES.some(r => r.test(host))) return;

    let candidates = ['http', 'socks5'];
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
        
        // ==========================================
        // 🔥 МГНОВЕННАЯ ЗАПИСЬ В ФАЙЛ
        // ==========================================
        try {
            fs.appendFileSync(OUTPUT_FILE, res + '\n');
        } catch (fileErr) {
            console.error('❌ Ошибка записи в файл:', fileErr.message);
        }

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
    console.log('--- SCANNER V8.9 STREAM SAVE (UPDATED FILTERS) ---');
    if (!fs.existsSync(SOURCES_FILE)) {
        console.log(`❌ Файл ${SOURCES_FILE} не найден!`);
        return;
    }
    
    // =======================================
    // 🔥 ОЧИСТКА ФАЙЛА НА СТАРТЕ
    // =======================================
    try {
        fs.writeFileSync(OUTPUT_FILE, ''); 
        console.log(`🗑️  Файл ${OUTPUT_FILE} очищен и готов к записи.`);
    } catch (e) {
        console.log(`⚠️ Ошибка очистки файла: ${e.message}`);
    }

    const lines = fs.readFileSync(SOURCES_FILE, 'utf-8').split(/\r?\n/);
    const set = new Set();
    
    const ipPortRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/;
    
    for (const l of lines) {
        const trimmed = l.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        if (trimmed.startsWith('http') && !trimmed.match(/\s/) && !trimmed.match(/\d:\d/)) {
            try {
                console.log(`Скачиваю: ${trimmed.substring(0,40)}...`);
                const r = await sourceLoader.get(trimmed);
                const text = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
                
                text.split(/\r?\n/).forEach(proxyLine => {
                    const match = proxyLine.match(ipPortRegex);
                    if (match) {
                        set.add(match[1]); 
                    }
                });
                
            } catch (e) { console.log(`Ошибка источника: ${e.message}`); }
        } else {
             const match = trimmed.match(ipPortRegex);
             if (match) set.add(match[1]);
        }
    }

    const tasks = Array.from(set);
    console.log(`\n🔎 ЗАДАЧА: ${tasks.length} уникальных IP (Очищенных). Старт через 2 сек...`);
    await new Promise(r => setTimeout(r, 2000));
    
    await runner(tasks);
    saveAndExit();
}

main().catch(e => {
    console.error('FATAL ERROR:', e);
    process.exit(1);
});
