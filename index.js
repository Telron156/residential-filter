'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const https = require('https'); // Нужно для настройки агента

// ===================== НАСТРОЙКИ (V6.5 HTTPS ELITE) =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';

// Тайм-аут 
const TIMEOUT_MS = 12000; 
// 200 потоков
const THREADS = 200;

// 1. HARD BAN ПОДCЕТЕЙ (Защита от Cogent/ColoCrossing/DataCenters)
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
    'waicore', 'akamai', 'servers tech', 'reliable', 
    'alibaba', 'datacamp', 'oracle', 'ipxo',
    'cloudinow', 'arvancloud',
    'cogent', 'frantech', 'buyvm', 'colocrossing', 'bluehost', 'unified layer',
    'total server', 'digitalocean', 'hetzner', 'ovh', 'linode', 'vultr', 
    'contabo', 'leaseweb', 'hostinger', 'selectel', 'timeweb', 'aeza', 
    'firstbyte', 'myarena', 'beget', 'reg.ru', 'mchost', 'fly servers', 
    'profit server', 'mevspace', 'pq hosting', 'smartape', 'firstvds'
];

// Разделяем хранение
let PROXIES_RU = [];
let PROXIES_GLOBAL = [];

const sourceLoader = axios.create({ timeout: 15000 });

// === [FIX] ОБНОВЛЕННЫЙ AXIOS ДЛЯ ПРОВЕРКИ HTTPS ===
const http = axios.create({
    proxy: false,
    timeout: TIMEOUT_MS,
    // Принимаем только 200 (ОК) и 403 (Капча Яндекса - значит достучались)
    // Остальные (500, 502, 407, 405) считаем ошибкой
    validateStatus: (status) => {
        return status === 200 || status === 403;
    },
    headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
    },
    // Важно: Игнорируем ошибки SSL сертификатов самого прокси, 
    // но при этом проверяем возможность установки HTTPS соединения
    httpsAgent: new https.Agent({ rejectUnauthorized: false })
});

function saveAndExit() {
    console.log('\n💾 СОХРАНЕНИЕ РЕЗУЛЬТАТОВ (HTTPS READY)...');
    
    const finalChain = [...new Set(PROXIES_RU), ...new Set(PROXIES_GLOBAL)];
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

// === [FIX] ПРОВЕРКА СТРОГО HTTPS ===
async function checkWithProtocol(host, port, protocol) {
    const proxyUrl = `${protocol}://${host}:${port}`;
    const agents = buildAgents(proxyUrl);
    if (!agents) throw new Error('Agent Fail');
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
        const start = Date.now();
        
        // Запрос строго на HTTPS. Если прокси не поддерживает CONNECT - упадет с ошибкой.
        const response = await http.get('https://ya.ru', {
            httpAgent: agents.http,
            httpsAgent: agents.https, // Используется для HTTPS
            signal: controller.signal
        });

        // [FIX] Защита от "Фейковых 200"
        // Некоторые прокси отдают код 200, но возвращают страницу логина провайдера или заглушку.
        // Главная Яндекса обычно весит больше 500 байт.
        const dataLength = response.data ? String(response.data).length : 0;
        if (response.status === 200 && dataLength < 500) {
            throw new Error('Fake 200 Response (Too short)');
        }

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

    // 0. HARD BAN (IP Ranges)
    if (BANNED_RANGES.some(regex => regex.test(host))) return;

    // === [FIX] УЛУЧШЕННЫЙ ВЫБОР КАНДИДАТОВ ===
    let candidates = [];
    
    if (rawLine.includes('socks')) {
        // Если в источнике указано socks - проверяем 5 и 4 (многие путают)
        candidates = ['socks5'];
    } else {
        // Если указано http или ничего - проверяем ВСЁ.
        // Часто socks4/5 лежат в списках http.
        candidates = ['http', 'socks5'];
    }

    let winner = null;
    try {
        // Гонка протоколов: кто первый успешно откроет HTTPS Яндекс
        winner = await Promise.any(candidates.map(p => checkWithProtocol(host, port, p)));
    } catch { return; }

    const { protocol, latency, agents } = winner;

    try {
        // Проверка ГЕО (Хостинг/Мобайл)
        // Тут оставляем http, так как API может быть без https, нам главное инфу получить
        const infoRes = await http.get('http://ip-api.com/json/?fields=status,countryCode,isp,org,as,mobile,proxy,hosting', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            timeout: 10000 // Чуть больше времени на ГЕО
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

        // ВЫВОД
        const isRu = data.countryCode === 'RU';
        const icon = latency < 1500 ? '🚀' : '🐢';
        const type = data.mobile ? '📱 MOB' : (data.hosting ? '🏢 BIZ' : '🏠 HOME');
        const flag = isRu ? '🇷🇺 RU' : data.countryCode;
        
        console.log(`✅ ADDED | ${flag} | ${type} | ${icon} ${latency}ms | [${protocol.toUpperCase()}] ${data.isp.substring(0, 20)}`);
        
        // Важно: сохраняем с правильным протоколом
        const validProxy = `${protocol}://${host}:${port}`;
        
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
            // Если в строке есть явный протокол - берем его, если нет - просто IP:PORT
            let p = m[0];
            if (l.includes('socks5://')) p = 'socks5://' + m[0];
            else if (l.includes('socks4://')) p = 'socks4://' + m[0];
            else if (l.includes('http://')) p = 'http://' + m[0];
            // Если протокола нет, checkResidential сам переберет все варианты
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
    console.log('--- PROXY CHECKER (V6.5 HTTPS ELITE) ---\n');
    const raw = await loadSources();
    if(raw.length===0) return;
    const unique = [...new Set(raw)];
    console.log(`📥 Candidates: ${unique.length} | Threads: ${THREADS} | Timeout: ${TIMEOUT_MS}ms`);
    
    // Тайм-аут на всю работу (чтобы не висеть вечно)
    const t = setTimeout(() => { console.log('HARD TIMEOUT'); saveAndExit(); }, 60*60000); // 1 час
    
    await mapWithConcurrency(unique, THREADS, checkResidential);
    clearTimeout(t);
    saveAndExit();
}

main().catch(e => { console.error(e); process.exit(1); });
