'use strict';

const fs = require('fs');
const axios = require('axios');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ===================== НАСТРОЙКИ =====================
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';

// Настройки потоков
// Для ip-api free лучше не ставить больше 20-25, иначе забанят IP
const THREADS = 20;           
const TIMEOUT_MS = 10000;
const MAX_LATENCY_MS = 8000;

// API для проверки резидентности (из первого скрипта)
const CHECK_URL = 'http://ip-api.com/json/?fields=status,message,countryCode,isp,org,proxy,hosting';

// Стоп-слова (Датацентры)
const BLACKLIST_KEYWORDS = [
    'hosting', 'cloud', 'datacenter', 'vps', 'server', 'ovh', 'hetzner',
    'digitalocean', 'amazon', 'aws', 'google', 'microsoft', 'azure', 'oracle',
    'alibaba', 'tencent', 'linode', 'vultr', 'lease', 'm247', 'dedi',
    'fly.io', 'contabo', 'godaddy', 'aceville', 'waicore', 'cdn',
    'performive', 'gtt', 'cogent', 'choopa', 'solutions', 'host',
    'onion', 'tor', 'stiftung', 'emerald', 'anonymizer', 'vpn'
];

// Axios для скачивания источников (без прокси)
const sourceLoader = axios.create({ timeout: 15000 });

// Axios для проверки прокси
const checkerAxios = axios.create({
    timeout: TIMEOUT_MS,
    validateStatus: () => true, // Не падать на ошибках 4xx/5xx
    proxy: false,
    headers: { 'User-Agent': 'Mozilla/5.0 (Residential Checker/3.0)' }
});

// ===================== УТИЛИТЫ (ВЗЯТЫ ИЗ ВАШЕГО ПРИМЕРА) =====================

// 1. Нормализация строки (делает из "1.1.1.1:80" -> "http://1.1.1.1:80")
function normalizeProxyLine(line) {
    const raw = (line || '').trim();
    if (!raw || raw.length < 5) return null;
    if (raw.startsWith('#') || raw.startsWith('//')) return null;

    // Игнорируем socks4, так как они редко бывают резидентными
    if (raw.toLowerCase().includes('socks4')) return null;

    let withScheme = raw;
    if (!raw.includes('://')) {
        // Если протокол не указан, по умолчанию ставим http
        withScheme = `http://${raw}`;
    }

    try {
        const u = new URL(withScheme);
        if (!u.hostname || !u.port) return null;
        
        u.protocol = u.protocol.toLowerCase();
        // Убедимся, что протокол поддерживается
        if (!['http:', 'https:', 'socks5:', 'socks5h:'].includes(u.protocol)) return null;

        return u.toString().replace(/\/$/, '');
    } catch {
        return null;
    }
}

// 2. Фабрика агентов с очисткой (Prevent Memory Leaks)
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

// ===================== ЛОГИКА ПРОВЕРКИ =====================

async function checkResidential(proxyUrl) {
    const agents = buildAgents(proxyUrl);
    if (!agents) return null;

    const start = Date.now();

    try {
        // Запрос к ip-api через прокси
        // Используем HTTP агента, т.к. ip-api (free) работает по HTTP
        const res = await checkerAxios.get(CHECK_URL, {
            httpAgent: agents.http,
            httpsAgent: agents.https
        });

        const latency = Date.now() - start;

        // Фильтры
        if (latency > MAX_LATENCY_MS) return null;
        if (res.status !== 200) return null;

        const data = res.data || {};
        if (data.status !== 'success') return null;

        // === ГЛАВНАЯ ПРОВЕРКА (Резидентность) ===
        // 1. Флаги базы данных
        if (data.hosting === true || data.proxy === true) return null;

        // 2. Проверка по имени провайдера (ISP)
        const isp = String(data.isp || '');
        const org = String(data.org || '');
        const country = String(data.countryCode || '??');
        const fullInfo = `${isp} ${org}`.toLowerCase();

        if (BLACKLIST_KEYWORDS.some(w => fullInfo.includes(w))) return null;

        // Если прошли все проверки
        const icon = latency < 1500 ? '🚀' : '🐢';
        console.log(`✅ RESIDENTIAL | ${country} | ${icon} ${latency}ms | ${isp}`);
        
        return proxyUrl;

    } catch (e) {
        return null;
    } finally {
        // Обязательно закрываем соединение
        if (agents.cleanup) agents.cleanup();
    }
}

// ===================== МЕНЕДЖЕР ПОТОКОВ (WORKER POOL) =====================
// Это оптимизированная версия из вашего примера
async function mapWithConcurrency(items, concurrency, workerFn) {
    const results = [];
    let idx = 0;

    // Создаем N воркеров, которые разбирают общую очередь по индексу
    const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (idx < items.length) {
            const i = idx++; // Забираем индекс атомарно
            const result = await workerFn(items[i]);
            if (result) results.push(result); // Сохраняем только валидные
        }
    });

    await Promise.all(workers);
    return results;
}

// ===================== ЗАГРУЗЧИК ССЫЛОК =====================
async function loadSources() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    
    const urls = fs.readFileSync(SOURCES_FILE, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 4 && !l.startsWith('#'));

    console.log(`📡 Загрузка списков прокси из ${urls.length} источников...`);
    const allProxies = new Set();

    const tasks = urls.map(url => sourceLoader.get(url)
        .then(res => {
            const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
            const lines = text.split(/\r?\n/);
            lines.forEach(line => {
                // Извлекаем IP:PORT регуляркой, чтобы отсеять мусор
                const match = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
                if (match) {
                    // Если в строке есть явное указание протокола, сохраняем его
                    let fullLine = match[0];
                    if (line.includes('socks5://')) fullLine = 'socks5://' + match[0];
                    else if (line.includes('http://')) fullLine = 'http://' + match[0];
                    
                    allProxies.add(fullLine);
                }
            });
        })
        .catch(err => console.log(`⚠️ Ошибка источника: ${err.message}`))
    );

    await Promise.all(tasks);
    return Array.from(allProxies);
}

// ===================== MAIN =====================
async function main() {
    console.log('--- ADVANCED GITHUB PROXY SCANNER (Residential) ---\n');

    // 1. Загрузка
    const rawProxies = await loadSources();
    if (rawProxies.length === 0) {
        console.log('❌ Источники пусты или недоступны.');
        return;
    }

    // 2. Нормализация (приводим к единому формату)
    const normalized = rawProxies.map(normalizeProxyLine).filter(Boolean);
    const unique = [...new Set(normalized)];

    console.log(`📥 Загружено сырых: ${rawProxies.length}`);
    console.log(`✨ Уникальных и валидных: ${unique.length}`);
    console.log(`🚀 Запуск проверки в ${THREADS} потоков...`);
    
    // Глобальный таймаут (25 минут), чтобы GitHub Actions не висел вечно
    const scriptTimeout = setTimeout(() => {
         console.log('⚠️ Время вышло. Сохраняем то, что есть...');
         process.exit(0);
    }, 25 * 60 * 1000);

    // 3. Запуск пула потоков
    const validProxies = await mapWithConcurrency(unique, THREADS, checkResidential);

    // 4. Сохранение
    fs.writeFileSync(OUTPUT_FILE, validProxies.join('\n'));
    
    clearTimeout(scriptTimeout);

    console.log('\n--- ГОТОВО ---');
    console.log(`💎 Найдено Резидентных: ${validProxies.length}`);
    console.log(`📂 Сохранено в: ${OUTPUT_FILE}`);
}

main().catch(err => {
    console.error('FATAL ERROR:', err);
    process.exit(1);
});
