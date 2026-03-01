#!/usr/bin/env python3
"""
Filter - извлекает и проверяет прокси из YAML подписок
Вход: файл 'list.txt' со списком URL YAML подписок
Выход: out.yaml (только живые, в формате Clash), trash.txt (мертвые), stat.txt (статистика)
"""

import yaml
import requests
import sys
import os
import threading
import time
import json
import socket
import struct
from collections import Counter
from typing import List, Dict, Any, Tuple, Set, Optional
from datetime import datetime
from urllib.parse import urlparse

# Версия: 3.1
# Изменения: 
# - заменен внешний API GeoIP на локальную базу .mmdb
# - добавлено авто-обновление GeoIP из внешнего репозитория
# - убраны внешние запросы при проверке (только локальная работа)

# Конфигурация
TIMEOUT = 3  # таймаут проверки в секундах
MAX_WORKERS = 5  # уменьшено для GitHub Actions
TRASH_FILE = "trash.txt"
OUTPUT_FILE = "out.yaml"
STAT_FILE = "stat.txt"
MAX_RUNTIME = 60 * 60  # максимальное время выполнения в секундах (1 час)

# GeoIP конфигурация
GEOIP_REPO = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release"  # публичный репозиторий с GeoIP
GEOIP_FILES = {
    "country.mmdb": f"{GEOIP_REPO}/country.mmdb",
    "GeoIP2-Country.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"  # резервный источник
}
GEOIP_LOCAL = "country.mmdb"  # локальный файл базы

# Попытка импорта GeoIP2 (необязательная зависимость)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("⚠️  geoip2 не установлен. Установите: pip install geoip2")
    print("   Без GeoIP страны будут определяться по TLD\n")

# Типы транспорта для VLESS
TRANSPORT_PATTERNS = {
    'reality_tcp': {
        'name': 'VLESS + TCP + Reality (+ Vision)',
        'check': lambda p: (
            p.get('type') == 'vless' and 
            p.get('network', 'tcp') == 'tcp' and
            p.get('security') == 'reality' and
            p.get('flow') in ['xtls-rprx-vision', 'xtls-rprx-vision-udp443']
        )
    },
    'reality_grpc': {
        'name': 'VLESS + gRPC / HTTP2 (H2)',
        'check': lambda p: (
            p.get('type') == 'vless' and 
            p.get('network') == 'grpc' and
            p.get('security') == 'reality'
        )
    },
    'reality_xhttp': {
        'name': 'VLESS + xHTTP',
        'check': lambda p: (
            p.get('type') == 'vless' and 
            p.get('network') == 'xhttp' and
            p.get('security') == 'reality'
        )
    }
}

# Кэш для GeoIP
geoip_cache = {}
geoip_reader = None

def init_geoip():
    """Инициализирует GeoIP базу (загружает если нет)"""
    global geoip_reader
    
    if not GEOIP_AVAILABLE:
        return False
    
    # Проверяем наличие локального файла
    if os.path.exists(GEOIP_LOCAL):
        try:
            geoip_reader = geoip2.database.Reader(GEOIP_LOCAL)
            print(f"✅ GeoIP база загружена: {GEOIP_LOCAL}")
            return True
        except Exception as e:
            print(f"⚠️  Ошибка загрузки GeoIP: {e}")
    
    # Если файла нет, пробуем скачать
    print(f"📥 GeoIP база не найдена, пробуем скачать...")
    return download_geoip()

def download_geoip() -> bool:
    """Скачивает GeoIP базу из репозитория"""
    global geoip_reader
    
    for filename, url in GEOIP_FILES.items():
        try:
            print(f"   Пробуем {url}...")
            resp = requests.get(url, timeout=30, stream=True)
            resp.raise_for_status()
            
            # Сохраняем файл
            with open(GEOIP_LOCAL, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"✅ Скачано: {GEOIP_LOCAL}")
            
            # Загружаем базу
            if GEOIP_AVAILABLE:
                geoip_reader = geoip2.database.Reader(GEOIP_LOCAL)
            return True
            
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
            continue
    
    print("⚠️  Не удалось скачать GeoIP базу. Будет использовано определение по TLD.")
    return False

def get_domain_tld(domain: str) -> str:
    """Извлекает TLD из домена для приблизительного определения страны"""
    try:
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = parts[-1].lower()
            # Специальные домены верхнего уровня
            if tld in ['com', 'org', 'net', 'info']:
                # Для популярных TLD пытаемся определить по второму уровню
                if len(parts) >= 3:
                    return parts[-2].lower()[:2]  # example.com.ru -> ru
                return 'unknown'
            return tld
    except:
        pass
    return 'unknown'

def get_country_from_ip(ip_or_domain: str) -> str:
    """Определяет страну по IP или домену используя локальную GeoIP базу"""
    global geoip_reader
    
    # Проверяем кэш
    if ip_or_domain in geoip_cache:
        return geoip_cache[ip_or_domain]
    
    # Пытаемся получить IP если это домен
    ip_address = ip_or_domain
    if not ip_or_domain.replace('.', '').isdigit():  # это домен, не IP
        try:
            ip_address = socket.gethostbyname(ip_or_domain)
        except:
            # Если не получаем IP, используем TLD
            tld = get_domain_tld(ip_or_domain)
            result = get_country_by_tld(tld)
            geoip_cache[ip_or_domain] = result
            return result
    
    # Используем GeoIP если доступен
    if geoip_reader:
        try:
            response = geoip_reader.country(ip_address)
            country_code = response.country.iso_code
            country_name = response.country.name
            flag = get_flag_from_code(country_code)
            result = f"{flag} {country_name}" if flag else country_name
            geoip_cache[ip_or_domain] = result
            return result
        except Exception:
            pass
    
    # Если GeoIP не сработал, пробуем TLD
    if not ip_or_domain.replace('.', '').isdigit():
        tld = get_domain_tld(ip_or_domain)
        result = get_country_by_tld(tld)
        geoip_cache[ip_or_domain] = result
        return result
    
    geoip_cache[ip_or_domain] = '🌍 Unknown'
    return '🌍 Unknown'

def get_country_by_tld(tld: str) -> str:
    """Определяет страну по TLD домена (заглушка для случаев без GeoIP)"""
    tld_map = {
        'us': '🇺🇸 USA', 'uk': '🇬🇧 UK', 'gb': '🇬🇧 UK', 'de': '🇩🇪 Germany',
        'fr': '🇫🇷 France', 'nl': '🇳🇱 Netherlands', 'sg': '🇸🇬 Singapore',
        'jp': '🇯🇵 Japan', 'ca': '🇨🇦 Canada', 'au': '🇦🇺 Australia',
        'ru': '🇷🇺 Russia', 'cn': '🇨🇳 China', 'br': '🇧🇷 Brazil',
        'in': '🇮🇳 India', 'kr': '🇰🇷 Korea', 'it': '🇮🇹 Italy',
        'es': '🇪🇸 Spain', 'se': '🇸🇪 Sweden', 'no': '🇳🇴 Norway',
        'dk': '🇩🇰 Denmark', 'fi': '🇫🇮 Finland', 'ch': '🇨🇭 Switzerland',
        'at': '🇦🇹 Austria', 'be': '🇧🇪 Belgium', 'pl': '🇵🇱 Poland',
        'cz': '🇨🇿 Czech', 'za': '🇿🇦 South Africa', 'mx': '🇲🇽 Mexico'
    }
    return tld_map.get(tld, '🌍 Unknown')

def get_flag_from_code(code: str) -> str:
    """Конвертирует код страны в эмодзи флага"""
    flag_map = {
        'US': '🇺🇸', 'GB': '🇬🇧', 'DE': '🇩🇪', 'FR': '🇫🇷', 'NL': '🇳🇱',
        'SG': '🇸🇬', 'JP': '🇯🇵', 'CA': '🇨🇦', 'AU': '🇦🇺', 'RU': '🇷🇺',
        'CN': '🇨🇳', 'BR': '🇧🇷', 'IN': '🇮🇳', 'KR': '🇰🇷', 'IT': '🇮🇹',
        'ES': '🇪🇸', 'SE': '🇸🇪', 'NO': '🇳🇴', 'DK': '🇩🇰', 'FI': '🇫🇮',
        'CH': '🇨🇭', 'AT': '🇦🇹', 'BE': '🇧🇪', 'PL': '🇵🇱', 'CZ': '🇨🇿',
        'ZA': '🇿🇦', 'MX': '🇲🇽', 'AR': '🇦🇷', 'IL': '🇮🇱', 'TR': '🇹🇷'
    }
    return flag_map.get(code, '')

def detect_transport_type(proxy: Dict[str, Any]) -> str:
    """Определяет тип транспорта прокси"""
    for key, pattern in TRANSPORT_PATTERNS.items():
        if pattern['check'](proxy):
            return pattern['name']
    return 'Unknown'

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

def is_target_proxy(proxy: Dict[str, Any]) -> bool:
    """Проверяет, подходит ли прокси под критерии отбора (Reality)"""
    if proxy.get('type') != 'vless':
        return False
    if proxy.get('port') != 443:
        return False
    
    if 'reality-opts' in proxy:
        opts = proxy['reality-opts']
        if opts.get('public-key') and opts.get('short-id'):
            return True
    
    if proxy.get('reality', False):
        return True
    
    return False

def check_proxy_connectivity(server: str, port: int) -> Tuple[bool, float]:
    """
    Проверяет доступность прокси через HTTP запрос.
    Возвращает (жив, время_ответа)
    """
    try:
        start = time.time()
        resp = requests.get(
            f"http://{server}:{port}",
            timeout=TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=False
        )
        elapsed = time.time() - start
        
        if resp.status_code == 204 or (200 <= resp.status_code < 300):
            return True, elapsed
        return False, elapsed
        
    except Exception:
        return False, TIMEOUT

def load_trash() -> Set[str]:
    """Загружает список мертвых серверов из trash.txt"""
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
        print(f"⚠️  Ошибка загрузки trash.txt: {e}")
    
    return trash

def save_to_trash(server: str, port: int):
    """Добавляет сервер в trash.txt"""
    entry = f"{server}:{port}"
    try:
        existing = load_trash()
        if entry in existing:
            return
        
        with open(TRASH_FILE, 'a', encoding='utf-8') as f:
            if os.path.getsize(TRASH_FILE) == 0:
                f.write("# Мертвые серверы (автоматически добавляются filter.py)\n")
                f.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{entry}\n")
    except Exception as e:
        print(f"⚠️  Ошибка записи в trash.txt: {e}")

def generate_statistics(alive_proxies: List[Dict[str, Any]], response_times: Dict[str, float]) -> str:
    """Генерирует статистику по живым серверам"""
    if not alive_proxies:
        return "Нет живых серверов для статистики"
    
    # Подсчет по времени ответа
    times = list(response_times.values())
    time_stats = {
        'fast': len([t for t in times if t < 0.1]),      # < 100ms
        'medium': len([t for t in times if 0.1 <= t < 0.3]),  # 100-300ms
        'slow': len([t for t in times if t >= 0.3])      # > 300ms
    }
    
    # Подсчет по транспорту
    transport_counter = Counter()
    for proxy in alive_proxies:
        transport_type = detect_transport_type(proxy)
        transport_counter[transport_type] += 1
    
    # Подсчет по странам
    country_counter = Counter()
    for proxy in alive_proxies:
        server = proxy.get('server', '')
        country = get_country_from_ip(server)
        country_counter[country] += 1
    
    # Формируем таблицу
    total = len(alive_proxies)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    lines = []
    lines.append("=" * 50)
    lines.append("📊 FILTER STATISTICS")
    lines.append("=" * 50)
    lines.append(f"Generated: {timestamp}")
    lines.append("")
    lines.append(f"📋 TOTAL: {total} servers")
    lines.append("")
    
    # Статистика по времени
    lines.append("⚡ BY RESPONSE TIME:")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    if total > 0:
        lines.append(f"< 100ms:    {time_stats['fast']:3d} servers ({time_stats['fast']/total*100:5.1f}%)")
        lines.append(f"100-300ms:  {time_stats['medium']:3d} servers ({time_stats['medium']/total*100:5.1f}%)")
        lines.append(f"> 300ms:    {time_stats['slow']:3d} servers ({time_stats['slow']/total*100:5.1f}%)")
    lines.append("")
    
    # Статистика по транспорту
    lines.append("🚀 BY TRANSPORT:")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    for transport, count in transport_counter.most_common():
        if transport != 'Unknown':
            lines.append(f"{transport}: {count:3d} servers ({count/total*100:5.1f}%)")
    if transport_counter.get('Unknown', 0) > 0:
        lines.append(f"Unknown: {transport_counter['Unknown']:3d} servers ({transport_counter['Unknown']/total*100:5.1f}%)")
    lines.append("")
    
    # Статистика по странам
    lines.append("🌍 BY COUNTRY:")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    for country, count in country_counter.most_common(15):  # топ-15
        lines.append(f"{country}: {count:3d} servers ({count/total*100:5.1f}%)")
    lines.append("")
    
    # Детальный список (топ-20 по скорости)
    lines.append("📈 TOP 20 FASTEST SERVERS:")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"{'Name':30} │ {'Country':15} │ {'Time':6} │ Transport")
    lines.append("─" * 70)
    
    # Сортируем прокси по времени ответа
    sorted_proxies = sorted(alive_proxies, key=lambda p: response_times.get(p.get('server', ''), float('inf')))[:20]
    
    for proxy in sorted_proxies:
        server = proxy.get('server', '')
        name = proxy.get('name', server)[:28] + ".." if len(proxy.get('name', server)) > 28 else proxy.get('name', server)
        country = get_country_from_ip(server)
        resp_time = response_times.get(server, 0) * 1000  # в миллисекундах
        transport = detect_transport_type(proxy)[:20]  # обрезаем для таблицы
        lines.append(f"{name:30} │ {country:15} │ {resp_time:4.0f}ms │ {transport}")
    
    lines.append("=" * 50)
    
    return "\n".join(lines)

def save_statistics(alive_proxies: List[Dict[str, Any]], response_times: Dict[str, float]):
    """Сохраняет статистику в stat.txt"""
    try:
        stats = generate_statistics(alive_proxies, response_times)
        with open(STAT_FILE, 'w', encoding='utf-8') as f:
            f.write(stats)
        print(f"📊 Статистика сохранена в {STAT_FILE}")
    except Exception as e:
        print(f"⚠️  Ошибка сохранения статистики: {e}")

def check_proxies_parallel(proxies: List[Dict[str, Any]], trash_set: Set[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, float]]:
    """
    Параллельная проверка списка прокси с ограничением по времени.
    Возвращает (живые, мертвые, словарь времени ответа по серверам)
    """
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
        
        if proxy_key in trash_set:
            with lock:
                dead.append(proxy)
            return
        
        is_alive, response_time = check_proxy_connectivity(server, port)
        
        with lock:
            if is_alive:
                alive.append(proxy)
                response_times[server] = response_time
                print(f"  ✅ {server}:{port} - {response_time*1000:.0f}ms")
            else:
                dead.append(proxy)
                print(f"  ❌ {server}:{port} - мертв")
                save_to_trash(server, port)
    
    threads = []
    for proxy in proxies:
        if time.time() - start_time > MAX_RUNTIME:
            print(f"\n⏱️  Достигнут лимит времени выполнения ({MAX_RUNTIME/60:.0f} мин). Прерывание...")
            break
            
        thread = threading.Thread(target=check_single, args=(proxy,))
        thread.start()
        threads.append(thread)
        
        while len([t for t in threads if t.is_alive()]) >= MAX_WORKERS:
            time.sleep(0.1)
            if time.time() - start_time > MAX_RUNTIME:
                print(f"\n⏱️  Достигнут лимит времени. Прерывание...")
                break
    
    remaining_time = max(0, MAX_RUNTIME - (time.time() - start_time))
    for thread in threads:
        thread.join(timeout=remaining_time)
    
    return alive, dead, response_times

def read_list_file(list_file: str = "list.txt") -> List[str]:
    """Читает список подписок из файла"""
    sources = []
    
    if not os.path.exists(list_file):
        print(f"❌ Файл '{list_file}' не найден!")
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
                    print(f"⚠️  Строка {line_num} пропущена: {line[:50]}")
    except Exception as e:
        print(f"❌ Ошибка чтения {list_file}: {e}")
        return []
    
    return sources

def estimate_time(proxies_count: int) -> str:
    """Приблизительная оценка времени проверки"""
    if proxies_count == 0:
        return "0 сек"
    
    est_seconds = (proxies_count / MAX_WORKERS) * TIMEOUT
    if est_seconds < 60:
        return f"{est_seconds:.0f} сек"
    else:
        return f"{est_seconds/60:.1f} мин"

def process_sources(list_file: str = "list.txt"):
    """Основная функция"""
    
    print(f"\n🔍 Загрузка списка подписок из {list_file}...")
    sources = read_list_file(list_file)
    
    if not sources:
        print("❌ Нет URL для обработки!")
        return
    
    print(f"📋 Найдено {len(sources)} источников\n")
    
    # Инициализируем GeoIP
    print("🌍 Инициализация GeoIP...")
    geoip_ok = init_geoip()
    if geoip_ok:
        print("✅ GeoIP готов к работе")
    else:
        print("⚠️  Будет использовано определение по TLD")
    print()
    
    print(f"📂 Загрузка {TRASH_FILE}...")
    trash_set = load_trash()
    print(f"   {len(trash_set)} серверов в черном списке\n")
    
    all_candidates = []
    
    for i, url in enumerate(sources, 1):
        print(f"[{i}/{len(sources)}] ", end="")
        data = fetch_yaml(url)
        if not data or 'proxies' not in data:
            continue
        
        found = 0
        for proxy in data['proxies']:
            if is_target_proxy(proxy):
                if 'name' in proxy:
                    name = proxy['name']
                    if len(name) > 2 and name[0] in '🇺🇸🇨🇾🇩🇪🇫🇷':
                        proxy['name'] = name[2:].strip()
                all_candidates.append(proxy)
                found += 1
        
        print(f"  Найдено кандидатов: {found} (всего: {len(all_candidates)})")
    
    if not all_candidates:
        print("\n❌ Кандидаты не найдены")
        return
    
    est_time = estimate_time(len(all_candidates))
    print(f"\n🔄 Проверка {len(all_candidates)} кандидатов...")
    print(f"   Параллельно: {MAX_WORKERS} потоков")
    print(f"   Таймаут: {TIMEOUT} сек")
    print(f"   Примерное время: {est_time}")
    print(f"   Лимит выполнения: {MAX_RUNTIME/60:.0f} мин\n")
    
    alive_proxies, dead_proxies, response_times = check_proxies_parallel(all_candidates, trash_set)
    
    # Сохраняем результат в Clash-формате
    if alive_proxies:
        output = {'proxies': alive_proxies}
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(output, f, allow_unicode=True, sort_keys=False)
        
        # Сохраняем статистику
        save_statistics(alive_proxies, response_times)
        
        print(f"\n✅ РЕЗУЛЬТАТЫ:")
        print(f"   Живые: {len(alive_proxies)} (сохранены в {OUTPUT_FILE})")
        print(f"   Мертвые: {len(dead_proxies)} (добавлены в {TRASH_FILE})")
        print(f"   Статистика: сохранена в {STAT_FILE}")
        
        # Показываем быстрые сервера
        print(f"\n⚡ Топ-5 самых быстрых:")
        sorted_proxies = sorted(alive_proxies, key=lambda p: response_times.get(p.get('server', ''), float('inf')))[:5]
        for i, p in enumerate(sorted_proxies, 1):
            server = p.get('server', '')
            time_ms = response_times.get(server, 0) * 1000
            country = get_country_from_ip(server)
            print(f"   {i}. {country} - {time_ms:.0f}ms")
            
    else:
        print("\n❌ Нет живых прокси")
        if dead_proxies:
            print(f"   {len(dead_proxies)} мертвых добавлены в {TRASH_FILE}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        list_file = sys.argv[1]
    else:
        list_file = "list.txt"
    
    print("=" * 50)
    print("🔍 Filter v3.1 - проверка прокси со статистикой")
    print("=" * 50)
    print(f"Таймаут: {TIMEOUT} сек | Потоков: {MAX_WORKERS} | Лимит: {MAX_RUNTIME/60:.0f} мин")
    print("=" * 50)
    
    process_sources(list_file)
