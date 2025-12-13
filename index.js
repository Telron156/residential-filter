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

const BLOCK_KEYWORDS = [
    'cloud', 'host', 'vps', 'amazon', 'aws', 'digitalocean', 
    'google', 'microsoft', 'azure', 'hetzner', 'ovh', 
    'm247', 'choopa', 'vultr', 'leaseweb', 'datacenter', 'dedi',
    'alibaba', 'oracle', 'linode'
];

const CHECK_URL = 'https://ipwho.is/'; 

const limit = pLimit(THREADS);

// 1. Загрузка и ЖЕСТКАЯ очистка
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
                if (clean.toLowerCase().includes('socks4')) return; 
                
                // ИСПРАВЛЕНИЕ 1: Регулярка теперь вытаскивает только IP:PORT
                // Игнорируя всё, что написано после (страны, комментарии)
                // Находит 1.1.1.1:80 даже если строка "1.1.1.1:80 United States"
                const match = clean.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)/);
                
                if (match) {
                    // Если в исходной строке был протокол, пробуем его сохранить
                    let ipPort = match[0];
                    if (clean.includes('socks5://')) {
                        allProxies.add(`socks5://${ipPort}`);
                    } else if (clean.includes('https://') || clean.includes('http://')) {
                        allProxies.add(`http://${ipPort}`);
                    } else {
                        allProxies.add(ipPort); // Просто IP:PORT
                    }
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
        
        if (response.status === 200 && response.data && latency <= MAX_LATENCY) {
            return { success: true, data: response.data };
        }
    } catch (e) {
        return { success: false };
    }
    return { success: false };
}

// 2. Логика проверки
async function checkProxy(proxyStr) {
    // Подготовка технической строки
    let technicalUrl = proxyStr;
    if (!technicalUrl.includes('://')) {
        technicalUrl = `http://${technicalUrl}`;
    }

    let agent;
    let finalProxyName = '';

    // ИСПРАВЛЕНИЕ 2: Оборачиваем создание агентов в try-catch,
    // чтобы кривой URL не ронял весь скрипт
    try {
        // --- СЦЕНАРИЙ А: Протокол уже указан ---
        if (proxyStr.includes('://')) {
            if (proxyStr.startsWith('socks5')) {
                agent = new SocksProxyAgent(proxyStr);
                const result = await tryRequest(agent);
                if (result.success && !isDatacenter(result.data)) return proxyStr;
            } 
            else if (proxyStr.startsWith('http')) {
                agent = new HttpsProxyAgent(proxyStr);
                const result = await tryRequest(agent);
                if (result.success && !isDatacenter(result.data)) return proxyStr;
            }
            return null;
        }

        // --- СЦЕНАРИЙ Б: Голый IP:PORT ---
        const ipPort = technicalUrl.split('://')[1];
        
        // Попытка 1: SOCKS5
        const socksUrl = `socks5://${ipPort}`;
        // ВАЖНО: new SocksProxyAgent может упасть, если url кривой
        try { agent = new SocksProxyAgent(socksUrl); } catch(e) { return null; }
        
        let result = await tryRequest(agent);
        if (result.success) {
            finalProxyName = socksUrl;
        } else {
            // Попытка 2: HTTPS
            const httpUrl = `http://${ipPort}`;
            try { agent = new HttpsProxyAgent(httpUrl); } catch(e) { return null; }
            
            result = await tryRequest(agent);
            if (result.success) {
                finalProxyName = httpUrl;
            }
        }

        if (!result || !result.success) return null;
        if (isDatacenter(result.data)) return null;

        return finalProxyName;

    } catch (globalError) {
        // Если что-то пошло совсем не так с этим конкретным прокси — просто пропускаем его
        return null;
    }
}

function isDatacenter(data) {
    const connection = data.connection || {};
    const isp = (connection.isp || '').toLowerCase();
    const org = (connection.org || '').toLowerCase();
    const fullInfo = `${isp} ${org}`;
    
    return BLOCK_KEYWORDS.some(word => fullInfo.includes(word));
}

async function main() {
    console.log('--- STARTING (Mode: Robust SOCKS5 & HTTPS) ---');
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
