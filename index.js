'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ===================== НАСТРОЙКИ (GITHUB ACTIONS EDITION) =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';       // Общий список
const OUTPUT_FILE_RU = 'valid_proxies_ru.txt'; // Только Россия

// 6 секунд - оптимально для GitHub Actions (защита от лагов CPU)
const TIMEOUT_MS = 6000; 
// 250 потоков - предел стабильности для 2 vCPU на GitHub
const THREADS = 180;

// Фильтр хостингов (Hostings filter)
const BAD_WORDS = [
  // 1. Явные признаки сервера (Строго)
  'hosting', 'datacenter', 'vps', 'cloud', 'dedic', 'colocation', 'colo', 'server',
  
  // 2. Главные враги (Облачные гиганты)
  'amazon', 'aws', 'google', 'azure', 'oracle', 
  'digitalocean', 'hetzner', 'ovh', 'linode', 'vultr',
  
  // 3. Азия и Китай (Те самые "призраки")
  'alibaba', 'aliyun', 'tencent', 'aceville', 'huawei', 'chinanet', 'baiduspider', 'ucloud',
  
  // 4. Токсичные магистрали и дешевые VPS
  'cogent', 'choopa', 'm247', 'clouvider', 'gtt', 'leaseweb', 'hostinger', 'contabo', 
  'kamatera', 'colocrossing', 'frantech',
  
  // 5. Локальные маркеры (Из ваших логов)
  'waltham' // Город-датацентр в США, откуда шел бот
];

let VALID_PROXIES_CACHE = [];
let VALID_PROXIES_RU_CACHE = [];
const sourceLoader = axios.create({ timeout: 15000 });

// AXIOS (Маскировка под Chrome)
const http = axios.create({
    validateStatus: () => true,
    proxy: false,
    headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
    }
});

function saveAndExit() {
    console.log('\n💾 СОХРАНЕНИЕ РЕЗУЛЬТАТОВ...');
    
    // 1. Сохраняем общий список
    if (VALID_PROXIES_CACHE.length > 0) {
        const unique = [...new Set(VALID_PROXIES_CACHE)];
        fs.writeFileSync(OUTPUT_FILE, unique.join('\n'));
        console.log(`✅ [ALL] Общий список: ${unique.length} шт. -> ${OUTPUT_FILE}`);
    } else {
        console.log('⚠️ [ALL] Нет рабочих прокси.');
    }

    // 2. Сохраняем RU список
    if (VALID_PROXIES_RU_CACHE.length > 0) {
        const uniqueRu = [...new Set(VALID_PROXIES_RU_CACHE)];
        fs.writeFileSync(OUTPUT_FILE_RU, uniqueRu.join('\n'));
        console.log(`🇷🇺 [RU]  Российские: ${uniqueRu.length} шт. -> ${OUTPUT_FILE_RU}`);
    } else {
        console.log('⚠️ [RU]  Русских прокси не найдено.');
    }

    process.exit(0);
}

process.on('SIGINT', saveAndExit);
process.on('SIGTERM', saveAndExit);

function buildAgents(proxyUrl) {
    try {
        const u = new URL(proxyUrl);
        const protocol = u.protocol.replace(':', '');
        const opts = { keepAlive: false };

        if (protocol.startsWith('socks')) {
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
        // Стучимся на ya.ru
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

    let candidates = ['http', 'socks5'];
    if (rawLine.startsWith('socks')) candidates = ['socks5'];
    else if (rawLine.startsWith('http')) candidates = ['http'];

    let winner = null;
    try {
        winner = await Promise.any(candidates.map(p => checkWithProtocol(host, port, p)));
    } catch { return; }

    const { protocol, latency, agents } = winner;

    // ПРОВЕРКА НА ХОСТИНГ И ГЕО
    try {
        const infoRes = await http.get('http://ip-api.com/json/?fields=status,countryCode,isp,org,proxy,hosting', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            timeout: 5000
        });

        const data = infoRes.data || {};
        if (data.status !== 'success') return;

        const isp = String(data.isp || '');
        const org = String(data.org || '');
        
        const isHosting = data.hosting === true || 
                          BAD_WORDS.some(w => isp.toLowerCase().includes(w) || org.toLowerCase().includes(w));

        if (isHosting) return;

        const isRu = data.countryCode === 'RU';
        const icon = latency < 1500 ? '🚀' : '🐢';
        const flag = isRu ? '🇷🇺 RUSSIA' : data.countryCode; 
        
        console.log(`✅ YA.RU ALIVE | ${flag} | ${icon} ${latency}ms | ${isp} [${protocol.toUpperCase()}]`);
        
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

// === УНИВЕРСАЛЬНЫЙ ПАРСЕР (Для URL и для RAW данных) ===
function parseAndAdd(text, setCollection) {
    text.split(/\r?\n/).forEach(l => {
        const m = l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
        if (m) {
            let p = m[0];
            if (l.includes('socks5://')) p = 'socks5://' + m[0];
            else if (l.includes('socks4://')) p = 'socks4://' + m[0];
            else if (l.includes('http://')) p = 'http://' + m[0];
            setCollection.add(p);
        }
    });
}

async function loadSources() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    
    // Читаем файл (в нем могут быть и URL, и готовые IP от curl)
    const rawLines = fs.readFileSync(SOURCES_FILE, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 0 && !l.startsWith('#'));

    console.log(`📡 Raw lines loaded: ${rawLines.length}`);
    
    const all = new Set();
    const urlTasks = [];

    for (const line of rawLines) {
        // Если это URL - качаем
        if (line.startsWith('http://') || line.startsWith('https://')) {
            urlTasks.push(sourceLoader.get(line).then(r => {
                const txt = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
                parseAndAdd(txt, all);
            }).catch(() => {}));
        } else {
            // Если это просто IP:PORT - парсим сразу
            parseAndAdd(line, all);
        }
    }

    if (urlTasks.length > 0) {
        console.log(`🔄 Downloading content from ${urlTasks.length} URLs...`);
        await Promise.all(urlTasks);
    }

    return Array.from(all);
}

async function main() {
    console.log('--- YANDEX RESIDENTIAL FILTER (For index.js) ---\n');
    const raw = await loadSources();
    if(raw.length===0) { console.log('Нет источников!'); return; }
    
    const unique = [...new Set(raw)];
    console.log(`📥 Candidates: ${unique.length} | Threads: ${THREADS}`);
    
    // Таймаут для GitHub Actions
    const t = setTimeout(() => { console.log('HARD TIMEOUT'); saveAndExit(); }, 50*60000);
    
    await mapWithConcurrency(unique, THREADS, checkResidential);
    
    clearTimeout(t);
    saveAndExit();
}

main().catch(e => { console.error(e); process.exit(1); });
