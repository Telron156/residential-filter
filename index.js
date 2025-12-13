const fs = require('fs');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const pLimit = require('p-limit');

// === НАСТРОЙКИ ===
const SOURCES_FILE = 'sources.txt';
const OUTPUT_FILE = 'valid_proxies.txt';
const TIMEOUT = 10000;      // 10 секунд на соединение
const MAX_LATENCY = 2500;   // Максимум 2.5 сек отклик
const THREADS = 100;        // Количество одновременных проверок

// Стоп-слова (фильтр дата-центров)
const BLOCK_KEYWORDS = [
    'cloud', 'host', 'vps', 'amazon', 'aws', 'digitalocean', 
    'google', 'microsoft', 'azure', 'hetzner', 'ovh', 
    'm247', 'choopa', 'vultr', 'leaseweb', 'datacenter', 'dedi',
    'alibaba', 'oracle', 'linode'
];

const CHECK_URL = 'http://ip-api.com/json';
const limit = pLimit(THREADS);

// 1. Функция получения прокси из ссылок
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
                // Ищем строки похожие на IP:PORT
                if (clean.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/)) {
                    allProxies.add(clean);
                }
            });
            console.log(`Fetched from: ${url}`);
        })
        .catch(err => console.log(`Error loading ${url}: ${err.message}`))
    );

    await Promise.all(tasks);
    return Array.from(allProxies);
}

// 2. Функция проверки одного прокси
async function checkProxy(proxyStr) {
    let agent;
    let proxyUrl = proxyStr;

    // Добавляем http:// если протокол не указан
    if (!proxyUrl.includes('://')) {
        proxyUrl = `http://${proxyUrl}`;
    }

    try {
        if (proxyUrl.startsWith('socks')) {
            agent = new SocksProxyAgent(proxyUrl);
        } else {
            agent = new HttpsProxyAgent(proxyUrl);
        }

        const start = Date.now();
        const response = await axios.get(CHECK_URL, {
            httpAgent: agent,
            httpsAgent: agent,
            timeout: TIMEOUT,
            validateStatus: () => true
        });
        const latency = Date.now() - start;

        // Фильтр 1: Доступность
        if (response.status !== 200 || !response.data) return null;
        
        // Фильтр 2: Пинг
        if (latency > MAX_LATENCY) return null;

        const isp = (response.data.isp || '').toLowerCase();
        const org = (response.data.org || '').toLowerCase();
        const fullInfo = `${isp} ${org}`;

        // Фильтр 3: Стоп-слова
        const isBad = BLOCK_KEYWORDS.some(word => fullInfo.includes(word));
        if (isBad) return null;

        // Если всё ок
        return proxyStr;

    } catch (e) {
        return null;
    }
}

// Главный запуск
async function main() {
    console.log('--- STARTING ---');
    
    // Шаг 1: Скачиваем
    const proxies = await fetchProxies();
    console.log(`Unique proxies found: ${proxies.length}`);
    
    if (proxies.length === 0) {
        console.log('No proxies found. Check sources.txt');
        return;
    }

    // Шаг 2: Проверяем
    console.log('Checking proxies (this may take time)...');
    let completed = 0;
    
    const checkPromises = proxies.map(p => limit(async () => {
        const res = await checkProxy(p);
        completed++;
        if (completed % 50 === 0) process.stdout.write(`Checked: ${completed}/${proxies.length}\r`);
        return res;
    }));

    const results = await Promise.all(checkPromises);
    const valid = results.filter(r => r !== null);

    // Шаг 3: Сохраняем
    fs.writeFileSync(OUTPUT_FILE, valid.join('\n'));
    
    console.log('\n--- DONE ---');
    console.log(`Valid Residential IPs: ${valid.length}`);
    console.log(`Saved to: ${OUTPUT_FILE}`);
}

main();
