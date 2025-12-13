const fs = require('fs');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const pLimit = require('p-limit');

// === НАСТРОЙКИ ===
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';
const TIMEOUT = 10000;
const MAX_LATENCY = 2500;
const THREADS = 100;

// Список стоп-слов (дата-центры)
const BLOCK_KEYWORDS = [
    'cloud', 'host', 'vps', 'amazon', 'aws', 'digitalocean', 
    'google', 'microsoft', 'azure', 'hetzner', 'ovh', 
    'm247', 'choopa', 'vultr', 'leaseweb', 'datacenter', 'dedi',
    'alibaba', 'oracle', 'linode'
];

// Ссылка ОБЯЗАТЕЛЬНО c HTTPS. 
// Если прокси не поддерживает HTTPS, запрос не пройдет и прокси отсеется.
const CHECK_URL = 'https://ipwho.is/'; 

const limit = pLimit(THREADS);

// 1. Загрузка (Скачивание списков)
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
                // Фильтр 1: Сразу убираем SOCKS4 по названию, если оно есть
                if (clean.toLowerCase().includes('socks4')) return; 
                
                if (clean.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/)) {
                    allProxies.add(clean);
                }
            });
        })
        .catch(err => console.log(`Error loading ${url}: ${err.message}`))
    );

    await Promise.all(tasks);
    return Array.from(allProxies);
}

// Вспомогательная функция запроса
async function tryRequest(agent) {
    const start = Date.now();
    try {
        const response = await axios.get(CHECK_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            timeout: TIMEOUT,
            validateStatus: () => true
        });
        const latency = Date.now() - start;
        
        // Проверяем статус 200 и задержку
        if (response.status === 200 && response.data && latency <= MAX_LATENCY) {
            return { success: true, data: response.data };
        }
    } catch (e) {
        return { success: false };
    }
    return { success: false };
}

// 2. Логика проверки (HTTPS & SOCKS5 Only)
async function checkProxy(proxyStr) {
    // Подготовка: если протокол не указан, считаем это "технической строкой"
    let technicalUrl = proxyStr;
    if (!technicalUrl.includes('://')) {
        technicalUrl = `http://${technicalUrl}`;
    }

    let agent;
    let finalProxyName = ''; // То, что запишем в файл

    // --- СЦЕНАРИЙ А: Протокол уже указан в файле ---
    if (proxyStr.includes('://')) {
        if (proxyStr.startsWith('socks5')) {
            // Если это SOCKS5 -> проверяем
            agent = new SocksProxyAgent(proxyStr);
            const result = await tryRequest(agent);
            if (result.success && !isDatacenter(result.data)) return proxyStr;
        } 
        else if (proxyStr.startsWith('http')) {
            // Если это HTTP -> проверяем, тянет ли он HTTPS
            agent = new HttpsProxyAgent(proxyStr);
            const result = await tryRequest(agent);
            if (result.success && !isDatacenter(result.data)) return proxyStr;
        }
        // Если socks4 -> игнорируем
        return null;
    }

    // --- СЦЕНАРИЙ Б: Голый IP:PORT (автоопределение) ---
    
    // Попытка 1: Пробуем как SOCKS5
    const ipPort = technicalUrl.split('://')[1];
    const socksUrl = `socks5://${ipPort}`;
    agent = new SocksProxyAgent(socksUrl);
    let result = await tryRequest(agent);
    
    if (result.success) {
        finalProxyName = socksUrl; // Ура, это SOCKS5
    } else {
        // Попытка 2: Пробуем как HTTPS (через http-агент)
        // (Примечание: http-прокси записываются как http://, но мы проверяем их на https ссылке)
        const httpUrl = `http://${ipPort}`;
        agent = new HttpsProxyAgent(httpUrl);
        result = await tryRequest(agent);
        
        if (result.success) {
            finalProxyName = httpUrl; // Ура, это HTTPS-совместимый прокси
        }
    }

    if (!result || !result.success) return null; // Не подошло ничего

    // Фильтр дата-центров
    if (isDatacenter(result.data)) return null;

    return finalProxyName;
}

// Проверка на стоп-слова
function isDatacenter(data) {
    const connection = data.connection || {};
    const isp = (connection.isp || '').toLowerCase();
    const org = (connection.org || '').toLowerCase();
    const fullInfo = `${isp} ${org}`;
    
    return BLOCK_KEYWORDS.some(word => fullInfo.includes(word));
}

async function main() {
    console.log('--- STARTING (Mode: SOCKS5 & HTTPS-Capable) ---');
    const proxies = await fetchProxies();
    
    if (proxies.length === 0) {
        console.log('No proxies found.');
        return;
    }

    console.log(`Checking ${proxies.length} candidates...`);
    
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
    console.log(`Valid Proxies: ${valid.length}`);
    console.log(`Saved to: ${OUTPUT_FILE}`);
}

main();
