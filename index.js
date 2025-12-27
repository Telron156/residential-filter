const fs = require('fs');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// === НАСТРОЙКИ ===
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';
const TIMEOUT = 10000;      // Таймаут проверки (10 сек)
const PING_TIMEOUT = 4000;  // Таймаут пинга Google (4 сек)
const THREADS = 100;        // Количество потоков (Для сервера можно 100-200)

// Расширенный список слов-паразитов (Хостинги/Датацентры)
const BLOCK_KEYWORDS = [
    'cloud', 'host', 'vps', 'amazon', 'aws', 'digitalocean', 
    'google', 'microsoft', 'azure', 'hetzner', 'ovh', 
    'm247', 'choopa', 'vultr', 'leaseweb', 'datacenter', 'dedi',
    'alibaba', 'oracle', 'linode', 'contabo', 'godaddy', 'fly.io',
    'aceville', 'tencent', 'server', 'solutions', 'cdn', 'waicore',
    'performive', 'gtt', 'cogent'
];

const CHECK_URL = 'http://ip-api.com/json';  // Лучшая база ISP
const PING_URL = 'http://www.google.com';    // Проверка на жизнь

// === 1. ЗАГРУЗКА И ПАРСИНГ ССЫЛОК ===
async function fetchProxies() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    
    // Читаем ссылки из файла
    const urls = fs.readFileSync(SOURCES_FILE, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 4 && !l.startsWith('#'));

    console.log(`📡 Loading sources from ${urls.length} links...`);
    const allProxies = new Set();

    const tasks = urls.map(url => axios.get(url, { timeout: 5000 })
        .then(res => {
            const lines = (typeof res.data === 'string' ? res.data : JSON.stringify(res.data)).split(/\r?\n/);
            lines.forEach(line => {
                const clean = line.trim();
                
                // ЖЕСТКИЙ ФИЛЬТР: Убираем SOCKS4
                if (clean.toLowerCase().includes('socks4')) return; 
                
                // Ищем IP:PORT
                const match = clean.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
                if (match) {
                    let ipPort = match[0];
                    if (clean.includes('socks5://')) allProxies.add(`socks5://${ipPort}`);
                    else if (clean.includes('http')) allProxies.add(`http://${ipPort}`);
                    else allProxies.add(ipPort); 
                }
            });
        })
        .catch(err => console.log(`⚠️ Error loading source: ${err.message}`))
    );

    await Promise.all(tasks);
    return Array.from(allProxies);
}

// === 2. ФУНКЦИИ ПРОВЕРКИ ===

// Быстрый Ping (жив или нет)
async function checkAlive(agent) {
    try {
        await axios.get(PING_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            timeout: PING_TIMEOUT,
            validateStatus: () => true 
        });
        return true;
    } catch (e) {
        return false;
    }
}

// Глубокая проверка (Datacenter или Residential)
async function checkGeoAndType(agent) {
    try {
        const response = await axios.get(CHECK_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            timeout: TIMEOUT
        });
        
        if (response.data && response.data.status === 'success') {
            const isp = (response.data.isp || '').toLowerCase();
            const org = (response.data.org || '').toLowerCase();
            const fullInfo = `${isp} ${org}`;
            
            // Если найдено стоп-слово — это плохой прокси
            if (BLOCK_KEYWORDS.some(word => fullInfo.includes(word))) {
                return false; 
            }
            return true; // Это Residential (Хороший)
        }
    } catch (e) {
        return false;
    }
    return false;
}

// Логика проверки одного прокси
async function checkProxy(proxyStr) {
    if (proxyStr.includes('socks4')) return null;

    let technicalUrl = proxyStr.includes('://') ? proxyStr : `http://${proxyStr}`;
    let ipPort = technicalUrl.split('://')[1];
    
    let workingAgent = null;
    let finalProxyString = '';

    try {
        // Подбор протокола + Пинг
        if (proxyStr.includes('://')) {
            const agent = proxyStr.startsWith('socks') ? new SocksProxyAgent(proxyStr) : new HttpsProxyAgent(proxyStr);
            if (await checkAlive(agent)) {
                workingAgent = agent;
                finalProxyString = proxyStr;
            }
        } else {
            // Если протокол не указан, пробуем SOCKS5, потом HTTP
            const socksUrl = `socks5://${ipPort}`;
            const socksAgent = new SocksProxyAgent(socksUrl);
            if (await checkAlive(socksAgent)) {
                workingAgent = socksAgent;
                finalProxyString = socksUrl;
            } else {
                const httpUrl = `http://${ipPort}`;
                const httpAgent = new HttpsProxyAgent(httpUrl);
                if (await checkAlive(httpAgent)) {
                    workingAgent = httpAgent;
                    finalProxyString = httpUrl;
                }
            }
        }

        if (!workingAgent) return null;

        // Проверка на ISP
        const isClean = await checkGeoAndType(workingAgent);
        
        if (isClean) {
            return finalProxyString;
        }

    } catch (globalError) {
        return null;
    }
    return null;
}

// === 3. УПРАВЛЕНИЕ ПОТОКАМИ (Без p-limit) ===
async function runWithLimit(items, limit, fn) {
    const results = [];
    const executing = [];
    let completed = 0;

    for (const item of items) {
        const p = Promise.resolve().then(() => fn(item));
        results.push(p);

        const e = p.then(() => {
            executing.splice(executing.indexOf(e), 1);
            completed++;
            if (completed % 50 === 0) {
                // Вывод прогресса в лог Actions
                console.log(`Checked: ${completed}/${items.length}`);
            }
        });
        executing.push(e);

        if (executing.length >= limit) {
            await Promise.race(executing);
        }
    }
    return Promise.all(results);
}

// === MAIN ===
async function main() {
    console.log('--- STARTING GITHUB SCANNER (Residential Only) ---');
    const proxies = await fetchProxies();
    
    if (proxies.length === 0) {
        console.log('No proxies found in sources.');
        return;
    }

    console.log(`Unique candidates: ${proxies.length}`);
    console.log(`Starting checkers (${THREADS} threads)...`);
    
    const results = await runWithLimit(proxies, THREADS, checkProxy);
    const valid = results.filter(r => r !== null);

    fs.writeFileSync(OUTPUT_FILE, valid.join('\n'));
    
    console.log('\n--- DONE ---');
    console.log(`Valid Resident/Mobile Proxies: ${valid.length}`);
    console.log(`Saved to: ${OUTPUT_FILE}`);
}

main();
