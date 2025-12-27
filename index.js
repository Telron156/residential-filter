const fs = require('fs');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const pLimit = require('p-limit');

// === НАСТРОЙКИ ===
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';
const TIMEOUT = 10000;      // Таймаут для проверки API (10 сек)
const PING_TIMEOUT = 4000;  // Таймаут для быстрого пинга (4 сек)
const THREADS = 100;        // Количество потоков

// Ключевые слова для бана (датацентры)
const BLOCK_KEYWORDS = [
    'cloud', 'host', 'vps', 'amazon', 'aws', 'digitalocean', 
    'google', 'microsoft', 'azure', 'hetzner', 'ovh', 
    'm247', 'choopa', 'vultr', 'leaseweb', 'datacenter', 'dedi',
    'alibaba', 'oracle', 'linode'
];

const CHECK_URL = 'https://ipwho.is/';       // Проверка ГЕО (Лимитировано!)
const PING_URL = 'http://www.google.com';    // Быстрая проверка "на жизнь"

const limit = pLimit(THREADS);

// 1. Загрузка и очистка (Убираем SOCKS4)
async function fetchProxies() {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    
    const urls = fs.readFileSync(SOURCES_FILE, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 4 && !l.startsWith('#'));

    console.log(`Loading sources from ${urls.length} links...`);
    const allProxies = new Set();

    const tasks = urls.map(url => axios.get(url, { timeout: 5000 })
        .then(res => {
            const lines = (typeof res.data === 'string' ? res.data : JSON.stringify(res.data)).split(/\r?\n/);
            lines.forEach(line => {
                const clean = line.trim();
                
                // === ФИЛЬТР SOCKS4 ===
                if (clean.toLowerCase().includes('socks4')) return; 
                
                // Регулярка для поиска IP:PORT
                const match = clean.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
                
                if (match) {
                    let ipPort = match[0];
                    // Если протокол указан явно — сохраняем
                    if (clean.includes('socks5://')) {
                        allProxies.add(`socks5://${ipPort}`);
                    } else if (clean.includes('https://') || clean.includes('http://')) {
                        allProxies.add(`http://${ipPort}`);
                    } else {
                        // Если голый IP:PORT — добавляем как есть (протокол определим при проверке)
                        allProxies.add(ipPort); 
                    }
                }
            });
        })
        .catch(err => console.log(`Error loading source: ${err.message}`))
    );

    await Promise.all(tasks);
    return Array.from(allProxies);
}

// Легкая проверка (Ping) — чтобы не тратить лимиты API на мертвые прокси
async function checkAlive(agent) {
    try {
        await axios.get(PING_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            timeout: PING_TIMEOUT,
            validateStatus: () => true // Любой статус ответа (200, 404, 403) означает, что прокси жив
        });
        return true;
    } catch (e) {
        return false;
    }
}

// Тяжелая проверка (Geo + Datacenter check)
async function checkGeoAndType(agent) {
    try {
        const response = await axios.get(CHECK_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            timeout: TIMEOUT
        });
        
        if (response.data && response.data.success) {
            // Проверка на датацентр
            const connection = response.data.connection || {};
            const isp = (connection.isp || '').toLowerCase();
            const org = (connection.org || '').toLowerCase();
            const fullInfo = `${isp} ${org}`;
            
            if (BLOCK_KEYWORDS.some(word => fullInfo.includes(word))) {
                return false; // Это датацентр
            }
            return true; // Это резидентный/мобильный (хороший)
        }
    } catch (e) {
        return false;
    }
    return false;
}

// 2. Основная логика проверки
async function checkProxy(proxyStr) {
    // Если каким-то чудом socks4 просочился — убиваем
    if (proxyStr.includes('socks4')) return null;

    let technicalUrl = proxyStr.includes('://') ? proxyStr : `http://${proxyStr}`;
    let ipPort = technicalUrl.split('://')[1];
    
    let workingAgent = null;
    let finalProxyString = '';

    try {
        // --- ЭТАП 1: Определение протокола и ПИНГ ---
        
        // Сценарий А: Протокол уже был в списке
        if (proxyStr.includes('://')) {
            const agent = proxyStr.startsWith('socks') 
                ? new SocksProxyAgent(proxyStr) 
                : new HttpsProxyAgent(proxyStr);
            
            if (await checkAlive(agent)) {
                workingAgent = agent;
                finalProxyString = proxyStr;
            }
        } 
        // Сценарий Б: Голый IP:PORT (Пробуем подобрать)
        else {
            // 1. Пробуем как SOCKS5
            const socksUrl = `socks5://${ipPort}`;
            const socksAgent = new SocksProxyAgent(socksUrl);
            if (await checkAlive(socksAgent)) {
                workingAgent = socksAgent;
                finalProxyString = socksUrl;
            } 
            // 2. Если не вышло — пробуем как HTTP
            else {
                const httpUrl = `http://${ipPort}`;
                const httpAgent = new HttpsProxyAgent(httpUrl);
                if (await checkAlive(httpAgent)) {
                    workingAgent = httpAgent;
                    finalProxyString = httpUrl;
                }
            }
        }

        // Если пинг не прошел ни по одному протоколу — выходим
        if (!workingAgent) return null;

        // --- ЭТАП 2: Проверка на Датацентр (Тяжелый запрос) ---
        const isClean = await checkGeoAndType(workingAgent);
        
        if (isClean) {
            return finalProxyString;
        }

    } catch (globalError) {
        return null;
    }
    return null;
}

async function main() {
    console.log('--- STARTING (NO SOCKS4 | Smart Check) ---');
    const proxies = await fetchProxies();
    
    if (proxies.length === 0) {
        console.log('No proxies found in sources.');
        return;
    }

    console.log(`Unique candidates: ${proxies.length}`);
    console.log(`Starting checkers (${THREADS} threads)...`);
    
    let completed = 0;
    const checkPromises = proxies.map(p => limit(async () => {
        const res = await checkProxy(p);
        completed++;
        if (completed % 50 === 0) process.stdout.write(`Checked: ${completed}/${proxies.length}\r`);
        return res;
    }));

    const results = await Promise.all(checkPromises);
    const valid = results.filter(r => r !== null);

    fs.writeFileSync(OUTPUT_FILE, valid.join('\n'));
    
    console.log('\n--- DONE ---');
    console.log(`Valid Resident/Mobile Proxies: ${valid.length}`);
    console.log(`Saved to: ${OUTPUT_FILE}`);
}

main();
