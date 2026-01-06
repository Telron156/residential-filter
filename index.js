'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ===================== НАСТРОЙКИ =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';

// Таймаут пожестче (6 сек), так как Яндекс должен открываться быстро
const TIMEOUT_MS = 6000; 
const THREADS = 50;

// Черный список провайдеров (Дата-центры)
const BAD_WORDS = [
  'hosting', 'cloud', 'datacenter', 'vps', 'server', 'ovh', 'hetzner',
  'digitalocean', 'amazon', 'aws', 'google', 'microsoft', 'azure', 'oracle',
  'alibaba', 'tencent', 'linode', 'vultr', 'm247', 'choopa', 'tor', 'vpn',
  'dedicated', 'leaseweb', 'clouvider', 'cogent', 'gtt', 'ipxo'
];

let VALID_PROXIES_CACHE = [];
const sourceLoader = axios.create({ timeout: 15000 });

// AXIOS (Маскировка под браузер Chrome)
const http = axios.create({
    validateStatus: () => true,
    proxy: false,
    headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cache-Control': 'no-cache',
        'Upgrade-Insecure-Requests': '1'
    }
});

// ===================== СОХРАНЕНИЕ =====================
function saveAndExit() {
    console.log('\n💾 СОХРАНЕНИЕ...');
    if (VALID_PROXIES_CACHE.length > 0) {
        const unique = [...new Set(VALID_PROXIES_CACHE)];
        fs.writeFileSync(OUTPUT_FILE, unique.join('\n'));
        console.log(`✅ Найдено чистых прокси: ${unique.length}`);
    } else {
        console.log('⚠️ Нет прокси, прошедших фильтр Яндекса.');
    }
    process.exit(0);
}

process.on('SIGINT', saveAndExit);
process.on('SIGTERM', saveAndExit);

// ===================== АГЕНТЫ =====================
function buildAgents(proxyUrl) {
    try {
        const u = new URL(proxyUrl);
        const protocol = u.protocol.replace(':', '');
        const opts = { keepAlive: false };

        if (protocol.startsWith('socks')) {
            // resolveProxy: true - скрывает DNS сервера Гитхаба от Яндекса
            const agent = new SocksProxyAgent(proxyUrl, { ...opts, resolveProxy: true });
            return { http: agent, https: agent, cleanup: () => {} };
        }
        
        const h = new HttpProxyAgent(proxyUrl, opts);
        const hs = new HttpsProxyAgent(proxyUrl, opts);
        return { http: h, https: hs, cleanup: () => { h.destroy(); hs.destroy(); } };
    } catch { return null; }
}

// ===================== ЯДРО ПРОВЕРКИ =====================

async function checkWithProtocol(host, port, protocol) {
    const proxyUrl = `${protocol}://${host}:${port}`;
    const agents = buildAgents(proxyUrl);
    if (!agents) throw new Error('Agent Fail');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
        const start = Date.now();
        
        // ШАГ 1: ЗАПРОС К YA.RU
        const res = await http.get('https://ya.ru', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            signal: controller.signal
        });

        const latency = Date.now() - start;

        // ШАГ 2: АНАЛИЗ ОТВЕТА НА КАПЧУ
        // Яндекс часто отдает 200 OK, но внутри HTML лежит капча
        if (res.status !== 200) throw new Error(`Status ${res.status}`);
        
        const body = typeof res.data === 'string' ? res.data : '';
        // Ключевые слова капчи Яндекса
        if (body.includes('showcaptcha') || 
            body.includes('smart-captcha') || 
            body.includes('checkbox-captcha')) {
            throw new Error('YANDEX_CAPTCHA');
        }

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

    // Кандидаты (Гонка протоколов)
    let candidates = ['http', 'socks5'];
    if (rawLine.startsWith('socks')) candidates = ['socks5'];
    else if (rawLine.startsWith('http')) candidates = ['http'];

    let winner = null;
    
    // Пытаемся подключиться к ya.ru через разные протоколы
    try {
        winner = await Promise.any(candidates.map(p => checkWithProtocol(host, port, p)));
    } catch { return; }

    const { protocol, latency, agents } = winner;

    // ШАГ 3: ФИЛЬТР "РОБОТНОСТИ" (Хостинги)
    try {
        // Используем того же агента для проверки IP
        const infoRes = await http.get('http://ip-api.com/json/?fields=status,countryCode,isp,org,proxy,hosting', {
            httpAgent: agents.http,
            httpsAgent: agents.https,
            timeout: 5000
        });

        const data = infoRes.data || {};
        if (data.status !== 'success') return;

        const isp = String(data.isp || '');
        const org = String(data.org || '');
        
        // Отсекаем серверные IP (они бесполезны для Метрики)
        const isHosting = data.hosting === true || 
                          BAD_WORDS.some(w => isp.toLowerCase().includes(w) || org.toLowerCase().includes(w));

        if (isHosting) return;

        const icon = latency < 1500 ? '🚀' : '🐢';
        console.log(`✅ YA.RU CLEAN | ${data.countryCode} | ${icon} ${latency}ms | ${isp} [${protocol.toUpperCase()}]`);
        
        VALID_PROXIES_CACHE.push(`${protocol}://${host}:${port}`);

    } catch (e) { return; } 
    finally { if (agents.cleanup) agents.cleanup(); }
}

// ===================== ЗАГРУЗКА И ВОРКЕРЫ =====================
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

async function loadSources() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    const urls = fs.readFileSync(SOURCES_FILE, 'utf-8').split('\n').map(l=>l.trim()).filter(l=>l.length>4 && !l.startsWith('#'));
    console.log(`📡 Sources: ${urls.length}`);
    const all = new Set();
    const tasks = urls.map(url => sourceLoader.get(url).then(r => {
        const txt = typeof r.data==='string'?r.data:JSON.stringify(r.data);
        txt.split(/\r?\n/).forEach(l => {
            const m = l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
            if(m) {
                let p = m[0];
                if(l.includes('socks5://')) p = 'socks5://'+m[0];
                else if(l.includes('http://')) p = '<http://'+m>[0];
                all.add(p);
            }
        });
    }).catch(()=>{}));
    await Promise.all(tasks);
    return Array.from(all);
}

// ===================== MAIN =====================
async function main() {
    console.log('--- YANDEX GATEKEEPER CHECKER (v7.0) ---\n');
    
    const raw = await loadSources();
    if(raw.length===0) return;
    
    const unique = [...new Set(raw)];
    console.log(`📥 Candidates: ${unique.length} | Threads: ${THREADS}`);

    const t = setTimeout(() => { console.log('TIMEOUT'); saveAndExit(); }, 45*60000);

    await mapWithConcurrency(unique, THREADS, checkResidential);

    clearTimeout(t);
    saveAndExit();
}

main().catch(e => process.exit(1));
