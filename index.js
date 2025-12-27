const fs = require('fs');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

// === НАСТРОЙКИ ===
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';
const TIMEOUT = 10000;      // Таймаут проверки (10 сек)
const PING_TIMEOUT = 5000;  // Таймаут пинга (чуть увеличил)
const THREADS = 50;         // СНИЗИЛ ДО 50 (чтобы не банили API)

// Список стоп-слов (Хостинги/Датацентры)
const BLOCK_KEYWORDS = [
    'cloud', 'host', 'vps', 'amazon', 'aws', 'digitalocean', 
    'google', 'microsoft', 'azure', 'hetzner', 'ovh', 
    'm247', 'choopa', 'vultr', 'leaseweb', 'datacenter', 'dedi',
    'alibaba', 'oracle', 'linode', 'contabo', 'godaddy', 'fly.io',
    'aceville', 'tencent', 'server', 'solutions', 'cdn', 'waicore',
    'performive', 'gtt', 'cogent'
];

// Используем ipwho.is (он лояльнее к бесплатным запросам чем ip-api)
const CHECK_URL = 'https://ipwho.is/'; 
const PING_URL = 'http://www.google.com';

// Заголовки, чтобы притворяться браузером
const HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
};

// === 1. ЗАГРУЗКА И ПАРСИНГ ССЫЛОК ===
async function fetchProxies() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    
    const urls = fs.readFileSync(SOURCES_FILE, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 4 && !l.startsWith('#'));

    console.log(`📡 Loading sources from ${urls.length} links...`);
    const allProxies = new Set();

    const tasks = urls.map(url => axios.get(url, { timeout: 8000, headers: HEADERS })
        .then(res => {
            const lines = (typeof res.data === 'string' ? res.data : JSON.stringify(res.data)).split(/\r?\n/);
            lines.forEach(line => {
                const clean = line.trim();
                if (clean.toLowerCase().includes('socks4')) return; 
                
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

// Быстрый Ping
async function checkAlive(agent) {
    try {
        // AbortSignal гарантирует, что запрос умрет через 5 сек
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), PING_TIMEOUT);

        await axios.get(PING_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            signal: controller.signal, // Жесткий обрыв
            validateStatus: () => true 
        });
        
        clearTimeout(timeoutId);
        return true;
    } catch (e) {
        return false;
    }
}

// Глубокая проверка (Datacenter или Residential)
async function checkGeoAndType(agent) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT);

        const response = await axios.get(CHECK_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            signal: controller.signal, // Жесткий обрыв
            headers: HEADERS
        });
        
        clearTimeout(timeoutId);

        if (response.data && response.data.success) { // ipwho.is возвращает success: true
            // Для ipwho.is структура connection: { isp: "...", org: "..." }
            const connection = response.data.connection || {};
            const isp = (connection.isp || '').toLowerCase();
            const org = (connection.org || '').toLowerCase();
            const fullInfo = `${isp} ${org}`;
            
            if (BLOCK_KEYWORDS.some(word => fullInfo.includes(word))) {
                return false; 
            }
            return true; 
        }
    } catch (e) {
        return false;
    }
    return false;
}

// Логика проверки
async function checkProxy(proxyStr) {
    if (proxyStr.includes('socks4')) return null;

    let technicalUrl = proxyStr.includes('://') ? proxyStr : `http://${proxyStr}`;
    let ipPort = technicalUrl.split('://')[1];
    
    let workingAgent = null;
    let finalProxyString = '';

    try {
        if (proxyStr.includes('://')) {
            const agent = proxyStr.startsWith('socks') ? new SocksProxyAgent(proxyStr) : new HttpsProxyAgent(proxyStr);
            if (await checkAlive(agent)) {
                workingAgent = agent;
                finalProxyString = proxyStr;
            }
        } else {
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

        const isClean = await checkGeoAndType(workingAgent);
        
        if (isClean) {
            return finalProxyString;
        }

    } catch (globalError) {
        return null;
    }
    return null;
}

// === 3. УПРАВЛЕНИЕ ПОТОКАМИ ===
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
            if (completed % 20 === 0) {
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
    try {
        const proxies = await fetchProxies();
        
        if (proxies.length === 0) {
            console.log('No proxies found in sources.');
            return;
        }

        console.log(`Unique candidates: ${proxies.length}`);
        console.log(`Starting checkers (${THREADS} threads)...`);
        
        // Добавил общий таймаут для всей работы скрипта (25 минут), чтобы GitHub не убивал его ошибкой
        const scriptTimeout = setTimeout(() => {
             console.log('⚠️ Global script timeout reached. Saving current results...');
             process.exit(0);
        }, 25 * 60 * 1000);

        const results = await runWithLimit(proxies, THREADS, checkProxy);
        const valid = results.filter(r => r !== null);

        fs.writeFileSync(OUTPUT_FILE, valid.join('\n'));
        
        clearTimeout(scriptTimeout);
        console.log('\n--- DONE ---');
        console.log(`Valid Resident/Mobile Proxies: ${valid.length}`);
        console.log(`Saved to: ${OUTPUT_FILE}`);
        
    } catch (error) {
        console.error("FATAL ERROR:", error);
        process.exit(1);
    }
}

main();
