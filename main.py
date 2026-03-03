import asyncio, os, re, json, time, subprocess
from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector

TEST_URL = "https://www.gstatic.com"
TIMEOUT = ClientTimeout(total=3.0, connect=1.5)

async def check(name, port):
    conn = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
    try:
        start = time.monotonic()
        async with ClientSession(connector=conn) as session:
            async with session.get(TEST_URL, timeout=TIMEOUT) as r:
                if r.status == 204:
                    ms = int((time.monotonic() - start) * 1000)
                    return {"name": name, "ms": ms}
    except: return None

async def main():
    # --- ШАГ 1: СБОР ССЫЛОК ---
    all_links = []
    async with ClientSession() as session:
        with open("sources.txt", "r") as f:
            sources = [l.strip() for l in f if l.strip()]
        
        for url in sources:
            try:
                async with session.get(url, timeout=15) as resp:
                    text = await resp.text()
                    found = re.findall(r'(?:vless|trojan|ss|hy2|tuic)://[^\s]+', text)
                    all_links.extend(found)
            except: print(f"Ошибка загрузки: {url}")

    with open("raw_collected.txt", "w") as f: f.write("\n".join(all_links))

    # --- ШАГ 2: ФИЛЬТРАЦИЯ (Твой filter.py) ---
    # Предполагаем, что filter.py берет raw_collected.txt и выдает filtered.txt
    if os.path.exists("filter.py"):
        print("Запуск фильтрации...")
        os.system("python filter.py") 
    else:
        # Если фильтра нет, просто копируем
        os.rename("raw_collected.txt", "filtered.txt")

    # --- ШАГ 3: КОНВЕРТАЦИЯ И ПРОВЕРКА ---
    os.system("./sub2sing-box convert --input filtered.txt --output config.json --method sing-box --socks-only")
    
    sb = subprocess.Popen(["sing-box", "run", "-c", "config.json"], stdout=subprocess.DEVNULL)
    time.sleep(5)

    with open("config.json", "r") as f: config = json.load(f)
    tasks = [check(inv["tag"], inv["listen_port"]) for inv in config.get("inbounds", [])]
    results = await asyncio.gather(*tasks)
    sb.terminate()

    # --- ШАГ 4: ЗАПИСЬ В ALL.TXT ---
    alive = sorted([r for r in results if r], key=lambda x: x["ms"])
    with open("all.txt", "w", encoding="utf-8") as f:
        for res in alive:
            f.write(f"[{res['ms']}ms] {res['name']}\n")
    print(f"Готово! Рабочих: {len(alive)}")

if __name__ == "__main__":
    asyncio.run(main())
