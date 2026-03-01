#!/usr/bin/env python3
"""
Filter - извлекает и проверяет прокси из YAML подписок
Вход: файл 'list.txt' со списком URL YAML подписок
Выход: out.yaml (живые VLESS), trash.txt (мертвые), stat.txt (статистика)
"""

import yaml
import requests
import sys
import os
import threading
import time
import socket
from collections import Counter
from typing import List, Dict, Any, Tuple, Set
from datetime import datetime

# Версия: 3.2
# Изменения:
# - заменена фильтрация: теперь пропускаются ВСЕ прокси типа VLESS (любой транспорт)
# - функция is_target_proxy() заменена на is_vless_proxy()
# - остальная логика без изменений

# Конфигурация
TIMEOUT = 3
MAX_WORKERS = 5
TRASH_FILE = "trash.txt"
OUTPUT_FILE = "out.yaml"
STAT_FILE = "stat.txt"
MAX_RUNTIME = 60 * 60

# GeoIP
try:
    import geoip2.database
    GEOIP_READER = None
    if os.path.exists("country.mmdb"):
        GEOIP_READER = geoip2.database.Reader("country.mmdb")
except ImportError:
    GEOIP_READER = None
    print("⚠️ geoip2 не установлен. Установите: pip install geoip2")

# Кэш для GeoIP
GEOIP_CACHE = {}

# Карта флагов
FLAG_MAP = {
    'us': '🇺🇸', 'uk': '🇬🇧', 'gb': '🇬🇧', 'de': '🇩🇪', 'fr': '🇫🇷',
    'nl': '🇳🇱', 'sg': '🇸🇬', 'jp': '🇯🇵', 'ca': '🇨🇦', 'au': '🇦🇺',
    'ru': '🇷🇺', 'cn': '🇨🇳', 'br': '🇧🇷', 'in': '🇮🇳', 'kr': '🇰🇷',
    'it': '🇮🇹', 'es': '🇪🇸', 'se': '🇸🇪', 'no': '🇳🇴', 'dk': '🇩🇰',
    'fi': '🇫🇮', 'ch': '🇨🇭', 'at': '🇦🇹', 'be': '🇧🇪', 'pl': '🇵🇱',
    'cz': '🇨🇿', 'za': '🇿🇦', 'mx': '🇲🇽', 'ar': '🇦🇷', 'il': '🇮🇱',
    'tr': '🇹🇷', 'ae': '🇦🇪', 'sa': '🇸🇦', 'cy': '🇨🇾'
}

def get_country(host: str) -> str:
    """Определяет страну по IP или домену"""
    if host in GEOIP_CACHE:
        return GEOIP_CACHE[host]
    
    # Пытаемся через GeoIP
    if GEOIP_READER and not host.replace('.', '').isdigit():
        try:
            ip = socket.gethostbyname(host)
            response = GEOIP_READER.country(ip)
            code = response.country.iso_code.lower()
            flag = FLAG_MAP.get(code, '🌍')
            name = response.country.name
            result = f"{flag} {name}"
            GEOIP_CACHE[host] = result
            return result
        except Exception:
            pass
    
    # Пробуем по TLD
    if '.' in host:
        tld = host.split('.')[-1].lower()
        if tld in FLAG_MAP:
            result = f"{FLAG_MAP[tld]} {tld.upper()}"
            GEOIP_CACHE[host] = result
            return result
    
    result = '🌍 Unknown'
    GEOIP_CACHE[host] = result
    return result

def fetch_yaml(url: str) -> Dict[str, Any]:
    """Скачивает и парсит YAML подписку"""
    try:
        print(f"📥 Загрузка: {url}")
        resp = requests.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        return yaml.safe_load(resp.text)
    except Exception as e:
        print(f"❌ Ошибка загрузки {url}: {e}")
        return {}

def is_vless_proxy(proxy: Dict[str, Any]) -> bool:
    """Пропускает любые прокси типа VLESS (vless)"""
    return proxy.get('type') == 'vless'

def check_proxy(server: str, port: int) -> Tuple[bool, float]:
    """
    Проверяет доступность прокси
    Возвращает (жив, время_ответа)
    """
    try:
        start = time.time()
        # Пробуем HTTP соединение
        resp = requests.get(
            f"http://{server}:{port}",
            timeout=TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=False
        )
        elapsed = time.time() - start
        
        # Любой ответ - считаем живым (кроме явных ошибок)
        if resp.status_code < 400 or resp.status_code >= 500:
            return True, elapsed
        return False, elapsed
        
    except requests.exceptions.Timeout:
        return False, TIMEOUT
    except requests.exceptions.ConnectionError:
        return False, TIMEOUT
    except Exception:
        return False, TIMEOUT

def load_trash() -> Set[str]:
    """Загружает список мертвых серверов"""
    trash = set()
    if not os.path.exists(TRASH_FILE):
        return trash
    
    try:
        with open(TRASH_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    trash.add(line)
    except Exception as e:
        print(f"⚠️ Ошибка загрузки trash: {e}")
    
    return trash

def save_to_trash(server: str, port: int):
    """Добавляет сервер в trash"""
    entry = f"{server}:{port}"
    try:
        with open(TRASH_FILE, 'a', encoding='utf-8') as f:
            if os.path.getsize(TRASH_FILE) == 0:
                f.write("# Dead servers\n")
            f.write(f"{entry}\n")
    except Exception as e:
        print(f"⚠️ Ошибка записи в trash: {e}")

def check_proxies_parallel(proxies: List[Dict[str, Any]], trash_set: Set[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, float]]:
    """Параллельная проверка прокси"""
    if not proxies:
        return [], [], {}
    
    alive = []
    dead = []
    response_times = {}
    lock = threading.Lock()
    start_time = time.time()
    
    def check_single(proxy):
        if time.time() - start_time > MAX_RUNTIME:
            return
            
        server = proxy.get('server', '')
        port = proxy.get('port', 443)
        proxy_key = f"{server}:{port}"
        
        # Пропускаем заведомо мертвые
        if proxy_key in trash_set:
            with lock:
                dead.append(proxy)
            return
        
        # Проверяем
        is_alive, response_time = check_proxy(server, port)
        
        with lock:
            if is_alive:
                alive.append(proxy)
                response_times[server] = response_time
                print(f"  ✅ {server}:{port} - {response_time*1000:.0f}ms")
            else:
                dead.append(proxy)
                print(f"  ❌ {server}:{port}")
                save_to_trash(server, port)
    
    # Запускаем потоки
    threads = []
    for proxy in proxies:
        if time.time() - start_time > MAX_RUNTIME:
            print(f"\n⏱️ Лимит времени")
            break
            
        thread = threading.Thread(target=check_single, args=(proxy,))
        thread.start()
        threads.append(thread)
        
        # Контроль количества потоков
        while len([t for t in threads if t.is_alive()]) >= MAX_WORKERS:
            time.sleep(0.1)
            if time.time() - start_time > MAX_RUNTIME:
                break
    
    # Ждем завершения
    remaining = max(0, MAX_RUNTIME - (time.time() - start_time))
    for thread in threads:
        thread.join(timeout=remaining)
    
    return alive, dead, response_times

def read_list_file(list_file: str = "list.txt") -> List[str]:
    """Читает список подписок"""
    sources = []
    
    if not os.path.exists(list_file):
        print(f"❌ Файл {list_file} не найден")
        return []
    
    try:
        with open(list_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith(('http://', 'https://')):
                    sources.append(line)
                else:
                    print(f"⚠️ Строка {line_num} пропущена: {line[:50]}")
    except Exception as e:
        print(f"❌ Ошибка чтения {list_file}: {e}")
        return []
    
    return sources

def generate_statistics(alive_proxies: List[Dict[str, Any]], response_times: Dict[str, float]) -> str:
    """Генерирует статистику"""
    if not alive_proxies:
        return "Нет живых прокси"
    
    # Статистика по времени
    times = list(response_times.values())
    fast = len([t for t in times if t < 0.1])
    medium = len([t for t in times if 0.1 <= t < 0.3])
    slow = len([t for t in times if t >= 0.3])
    
    # Статистика по транспорту (для VLESS)
    transports = Counter()
    for p in alive_proxies:
        transport = p.get('network', 'tcp')
        transports[transport] += 1
    
    # Статистика по странам
    countries = Counter()
    for p in alive_proxies:
        server = p.get('server', '')
        countries[get_country(server)] += 1
    
    total = len(alive_proxies)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    lines = []
    lines.append("=" * 50)
    lines.append("📊 STATISTICS (VLESS only)")
    lines.append("=" * 50)
    lines.append(f"Generated: {now}")
    lines.append(f"Total: {total} VLESS proxies")
    lines.append("")
    
    # По времени
    lines.append("⚡ BY RESPONSE TIME:")
    if total > 0:
        lines.append(f"< 100ms:   {fast:3d} ({fast/total*100:5.1f}%)")
        lines.append(f"100-300ms: {medium:3d} ({medium/total*100:5.1f}%)")
        lines.append(f"> 300ms:   {slow:3d} ({slow/total*100:5.1f}%)")
    lines.append("")
    
    # По транспорту
    lines.append("🚀 BY TRANSPORT:")
    for transport, count in transports.most_common():
        lines.append(f"{transport:10}: {count:3d} ({count/total*100:5.1f}%)")
    lines.append("")
    
    # По странам
    lines.append("🌍 BY COUNTRY:")
    for country, count in countries.most_common(15):
        lines.append(f"{country:20}: {count:3d}")
    lines.append("")
    
    # Топ-10 быстрых
    lines.append("⚡ TOP 10 FASTEST:")
    sorted_proxies = sorted(alive_proxies, key=lambda p: response_times.get(p.get('server', ''), 999))[:10]
    for i, p in enumerate(sorted_proxies, 1):
        server = p.get('server', '')
        name = p.get('name', server)[:30]
        time_ms = response_times.get(server, 0) * 1000
        country = get_country(server)
        transport = p.get('network', 'tcp')
        lines.append(f"{i:2}. {country} {time_ms:4.0f}ms {transport:6} - {name}")
    
    return "\n".join(lines)

def main(list_file: str = "list.txt"):
    """Основная функция"""
    
    print(f"\n🔍 Читаем {list_file}...")
    sources = read_list_file(list_file)
    
    if not sources:
        print("❌ Нет источников")
        return
    
    print(f"📋 Найдено {len(sources)} источников")
    
    # Загружаем trash
    trash_set = load_trash()
    print(f"🗑️ В trash: {len(trash_set)} серверов\n")
    
    # Собираем все VLESS прокси
    all_proxies = []
    
    for i, url in enumerate(sources, 1):
        print(f"[{i}/{len(sources)}] {url[:60]}...")
        data = fetch_yaml(url)
        
        if not data:
            continue
            
        if 'proxies' in data:
            # Фильтруем только VLESS
            vless_proxies = [p for p in data['proxies'] if is_vless_proxy(p)]
            all_proxies.extend(vless_proxies)
            print(f"   → {len(data['proxies'])} всего, {len(vless_proxies)} VLESS")
        else:
            print(f"   → нет поля 'proxies', пропускаем")
    
    print(f"\n📦 Всего VLESS кандидатов: {len(all_proxies)}")
    
    if not all_proxies:
        print("❌ Нет VLESS прокси для проверки")
        return
    
    # Проверяем
    print(f"\n🔄 Проверка {len(all_proxies)} прокси...")
    alive, dead, times = check_proxies_parallel(all_proxies, trash_set)
    
    # Сохраняем результаты
    if alive:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': alive}, f, allow_unicode=True, sort_keys=False)
        print(f"\n✅ Сохранено {len(alive)} живых VLESS в {OUTPUT_FILE}")
        
        # Статистика
        stats = generate_statistics(alive, times)
        with open(STAT_FILE, 'w', encoding='utf-8') as f:
            f.write(stats)
        print(f"📊 Статистика в {STAT_FILE}")
        
        # Краткий отчет
        print(f"\n📈 Итого:")
        print(f"   Живые VLESS: {len(alive)}")
        print(f"   Мертвые: {len(dead)}")
        
    else:
        print("\n❌ Нет живых VLESS прокси")
        if dead:
            print(f"   {len(dead)} мертвых добавлены в {TRASH_FILE}")

if __name__ == "__main__":
    list_file = sys.argv[1] if len(sys.argv) > 1 else "list.txt"
    print("=" * 50)
    print("🔍 Filter v3.2 - VLESS only")
    print("=" * 50)
    main(list_file)
