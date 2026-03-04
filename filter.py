#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Power v8.1
====================================
- Исправлена статистика дубликатов
- Анализ теперь использует уникальные конфиги
====================================
"""

import re
import time
import urllib.request
import urllib.error
import logging
from typing import List, Set, Dict, Tuple, Optional
import os
from datetime import datetime
import json
import base64
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl
import asyncio
import tempfile
import subprocess

# Импорт модулей
from xray_tester import XrayTester
from geoip import GeoIP

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class VlessCollector:
    """Двухэтапный сборщик подписок с двухуровневой Xray проверкой и GeoIP."""
    
    def __init__(self,
                 sources_file: str = 'sources.txt',
                 list_file: str = 'list.txt',
                 all_file: str = 'all.txt',
                 out_file: str = 'out.txt',
                 ru_file: str = 'ru.txt',
                 stat_file: str = 'stat.txt',
                 top500_file: str = '500.txt',
                 speed_threshold: float = 800.0,
                 download_timeout: int = 10,
                 check_timeout: float = 2.0,
                 quick_timeout: float = 1.0,
                 download_workers: int = 10,
                 check_workers: int = 50):
        
        self.sources_file = sources_file
        self.list_file = list_file
        self.all_file = all_file
        self.out_file = out_file
        self.ru_file = ru_file
        self.stat_file = stat_file
        self.top500_file = top500_file
        self.speed_threshold = speed_threshold
        self.download_timeout = download_timeout
        self.check_timeout = check_timeout
        self.quick_timeout = quick_timeout
        self.download_workers = download_workers
        self.check_workers = check_workers
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Xray тестер
        self.tester = XrayTester(
            timeout=self.check_timeout,
            max_workers=self.check_workers
        )
        self.xray_path = self.tester.xray_path
        
        # GeoIP определитель
        self.geoip = GeoIP()
        
        # Статистика по источникам
        self.source_stats = {}
        
    def read_sources(self) -> List[str]:
        """Читает список RAW-ссылок из sources.txt."""
        if not os.path.exists(self.sources_file):
            logger.error(f"Файл {self.sources_file} не найден")
            return []
        
        sources = []
        with open(self.sources_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    sources.append(line)
        
        logger.info(f"📋 Загружено {len(sources)} RAW-ссылок из {self.sources_file}")
        return sources
    
    def download_subscription(self, url: str) -> Tuple[str, List[str]]:
        """Скачивает одну подписку и извлекает ВСЕ конфиги (любые протоколы)."""
        try:
            req = urllib.request.Request(url, headers={'User-Agent': self.user_agent})
            with urllib.request.urlopen(req, timeout=self.download_timeout) as response:
                content = response.read()
                
                try:
                    text = content.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        text = content.decode('latin-1')
                    except:
                        text = content.decode('utf-8', errors='ignore')
                
                # Проверяем base64
                if re.match(r'^[A-Za-z0-9+/=]+$', text[:100].replace('\n', '')):
                    try:
                        text = base64.b64decode(text).decode('utf-8', errors='ignore')
                    except:
                        pass
                
                # Извлекаем ВСЕ ссылки (любые протоколы)
                all_patterns = [
                    r'vless://[^\s]+',
                    r'vmess://[^\s]+', 
                    r'trojan://[^\s]+',
                    r'ss://[^\s]+',
                    r'ssr://[^\s]+',
                    r'hy2://[^\s]+',
                    r'hysteria2://[^\s]+',
                    r'wireguard://[^\s]+'
                ]
                
                configs = []
                for pattern in all_patterns:
                    configs.extend(re.findall(pattern, text))
                
                # Убираем дубликаты в рамках одной подписки
                configs = list(set(configs))
                
                logger.debug(f"  {url}: {len(configs)} конфигов (все протоколы)")
                return url, configs
                
        except Exception as e:
            logger.warning(f"⚠️ Ошибка загрузки {url}: {e}")
            return url, []
    
    def step1_collect_all(self) -> Dict[str, List[str]]:
        """ШАГ 1: Собирает все сервера в list.txt."""
        print("\n" + "="*70)
        print("🔍 ШАГ 1: СБОР ВСЕХ СЕРВЕРОВ В list.txt")
        print("="*70)
        
        sources = self.read_sources()
        if not sources:
            logger.error("❌ Нет источников для обработки")
            return {}
        
        logger.info(f"📥 Скачивание {len(sources)} подписок ({self.download_workers} потоков)...")
        
        results = {}
        total_configs = 0
        successful = 0
        
        # Очищаем list.txt
        with open(self.list_file, 'w', encoding='utf-8') as f:
            f.write(f"# СЫРЫЕ НЕПРОВЕРЕННЫЕ СЕРВЕРА\n")
            f.write(f"# Собрано из sources.txt: {datetime.now().isoformat()}\n")
            f.write("#" + "="*70 + "\n\n")
        
        # Параллельное скачивание
        with ThreadPoolExecutor(max_workers=self.download_workers) as executor:
            future_to_url = {executor.submit(self.download_subscription, url): url for url in sources}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url, configs = future.result()
                    results[url] = configs
                    
                    if configs:
                        successful += 1
                        with open(self.list_file, 'a', encoding='utf-8') as f:
                            f.write(f"\n# ИСТОЧНИК: {url}\n")
                            for config in configs:
                                f.write(config + '\n')
                            f.write("#" + "="*50 + "\n")
                        
                        logger.info(f"  ✅ {url}: {len(configs)} конфигов")
                    else:
                        logger.warning(f"  ⚠️ {url}: 0 конфигов")
                    
                    total_configs += len(configs)
                    
                except Exception as e:
                    logger.error(f"  ❌ Ошибка при обработке {url}: {e}")
                    results[url] = []
        
        print("\n" + "="*70)
        print(f"✅ СБОР ЗАВЕРШЁН:")
        print(f"   - Источников: {len(sources)}")
        print(f"   - Всего серверов: {total_configs}")
        print(f"   - Сохранено в: {self.list_file}")
        print("="*70)
        
        return results
    
    def extract_host_port(self, config: str) -> Tuple[Optional[str], Optional[int]]:
        """Извлекает host и port из конфига любого типа."""
        try:
            # Ищем паттерн @host:port
            match = re.search(r'@([^:?]+):(\d+)', config)
            if match:
                host, port = match.groups()
                return host, int(port)
            
            # Ищем паттерн ://host:port
            match = re.search(r'://([^:?]+):(\d+)', config)
            if match:
                host, port = match.groups()
                return host, int(port)
                
        except Exception:
            pass
        return None, None
    
    def quick_xray_test(self, config_str: str, index: int, total: int) -> bool:
        """
        Быстрый тест через Xray - проверяет, запускается ли процесс (1 секунда).
        """
        logger.info(f"⚡ [{index}/{total}] Быстрый тест: {config_str[:50]}...")
        
        config_data = self.tester.parse_config(config_str)
        if not config_data:
            return False
        
        temp_config = None
        process = None
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(config_data, f, indent=2)
                temp_config = f.name
            
            process = subprocess.Popen(
                [self.xray_path, '-config', temp_config],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(self.quick_timeout)
            
            is_alive = process.poll() is None
            if is_alive:
                logger.info(f"✅ [{index}/{total}] Быстрый тест пройден")
            
            return is_alive
            
        except Exception as e:
            return False
            
        finally:
            if process:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except:
                    process.kill()
            
            if temp_config and os.path.exists(temp_config):
                try:
                    os.unlink(temp_config)
                except:
                    pass
    
    def is_valid_config(self, config: str) -> Tuple[bool, str, int]:
        """Проверяет валидность конфига (любого протокола)."""
        try:
            if '://' in config:
                after_proto = config.split('://', 1)[1]
                if '@' in after_proto:
                    after_at = after_proto.split('@', 1)[1]
                    host_part = after_at.split('?')[0].split('#')[0]
                else:
                    host_part = after_proto.split('?')[0].split('#')[0]
                
                if ':' in host_part:
                    host, port_str = host_part.split(':')[:2]
                    port = int(port_str)
                else:
                    host = host_part
                    port = 443
                
                return True, host, port
            return False, "", 0
        except:
            return False, "", 0
    
    def get_config_key(self, config: str) -> str:
        """Ключ для сравнения дубликатов (без тега и параметров)."""
        return config.split('#')[0].split('?')[0]
    
    def normalize_config(self, config: str, speed: float) -> str:
        """Исправляет &; на &, остальное без изменений."""
        return config.replace('&;', '&')
    
    def step2_check_all(self, sources_data: Dict[str, List[str]]) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, List[str]], Dict]:
        """ШАГ 2: Двухуровневая Xray проверка (быстрый + полный)."""
        print("\n" + "="*70)
        print("⚡ ШАГ 2: ПРОВЕРКА СЕРВЕРОВ (быстрый Xray → полный Xray)")
        print("="*70)
        
        if not os.path.exists(self.list_file):
            return {}, {}, {}, {}
        
        source_configs = defaultdict(list)
        current_source = None
        
        with open(self.list_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('# ИСТОЧНИК:'):
                    current_source = line.replace('# ИСТОЧНИК:', '').strip()
                elif line and not line.startswith('#') and current_source:
                    source_configs[current_source].append(line)
        
        all_configs_with_sources = []
        source_totals = defaultdict(int)
        
        for source_url, configs in source_configs.items():
            for config in configs:
                if config.startswith('vless://') and self.is_valid_config(config)[0]:
                    all_configs_with_sources.append((source_url, config))
                    source_totals[source_url] += 1
        
        logger.info(f"🌍 Найдено vless серверов (с дубликатами): {len(all_configs_with_sources)}")
        
        if not all_configs_with_sources:
            return {}, {}, {}, {}
        
        # === ДЕДУПЛИКАЦИЯ ===
        unique_configs_map = {}
        for source_url, config in all_configs_with_sources:
            key = self.get_config_key(config)
            if key not in unique_configs_map:
                unique_configs_map[key] = (source_url, config)
        
        all_items = list(unique_configs_map.values())
        logger.info(f"🎯 После удаления дубликатов: {len(all_items)} уникальных vless серверов")
        
        # === УРОВЕНЬ 1: БЫСТРЫЙ XRAY ТЕСТ ===
        logger.info(f"⚡ Запуск быстрого Xray теста ({self.check_workers} потоков, таймаут={self.quick_timeout}c)...")
        
        quick_alive = []
        quick_dead = 0
        total = len(all_items)
        
        with ThreadPoolExecutor(max_workers=self.check_workers) as executor:
            future_to_item = {}
            for i, (source_url, config) in enumerate(all_items):
                future = executor.submit(self.quick_xray_test, config, i+1, total)
                future_to_item[future] = (source_url, config)
            
            for future in as_completed(future_to_item):
                source_url, config = future_to_item[future]
                if future.result():
                    quick_alive.append((source_url, config))
                else:
                    quick_dead += 1
        
        logger.info(f"📊 Быстрый Xray тест: выжило {len(quick_alive)} из {len(all_items)} (отсеяно {quick_dead})")
        
        if not quick_alive:
            logger.warning("⚠️ Нет живых серверов после быстрого теста")
            return {}, {}, source_configs, unique_configs_map
        
        config_list = [config for source_url, config in quick_alive]
        
        logger.info(f"🚀 Запуск полного Xray теста ({self.tester.max_workers} процессов, таймаут={self.tester.timeout}c)...")
        
        start_time = time.time()
        alive_results = self.tester.test_many(config_list)
        
        alive_dict = {config: speed for config, speed in alive_results}
        
        working_all = {}
        working_fast = {}
        source_passed = defaultdict(int)
        source_pings = defaultdict(list)
        
        for source_url, config in quick_alive:
            if config in alive_dict:
                speed = alive_dict[config]
                working_all[config] = speed
                if speed <= self.speed_threshold:
                    working_fast[config] = speed
                    source_passed[source_url] += 1
                    source_pings[source_url].append(speed)
        
        elapsed = time.time() - start_time
        
        for source_url in source_totals:
            total = source_totals[source_url]
            passed = source_passed[source_url]
            pings = source_pings[source_url]
            avg_ping = sum(pings)/len(pings) if pings else 0
            self.source_stats[source_url] = {
                'total': total,
                'passed': passed,
                'avg_ping': avg_ping
            }
        
        print("\n" + "="*70)
        print(f"✅ ПРОВЕРКА ЗАВЕРШЕНА:")
        print(f"   - Уникальных vless серверов: {len(all_items)}")
        print(f"   - Прошли быстрый тест: {len(quick_alive)}")
        print(f"   - Прошли полный тест: {len(working_all)}")
        print(f"   - Быстрых (<{self.speed_threshold}ms): {len(working_fast)}")
        print(f"   - Время: {elapsed:.1f} сек")
        print("="*70)
        
        return working_all, working_fast, source_configs, unique_configs_map
    
    def save_stats(self, working_fast: Dict[str, float], source_configs: Dict[str, List[str]], unique_configs_map: Dict):
        """Сохраняет статистику с полным анализом."""
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            # ========== ОСНОВНАЯ СТАТИСТИКА ==========
            f.write("="*70 + "\n")
            f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ ПРОКСИ\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Таймауты: быстрый={self.quick_timeout}c, полный={self.check_timeout}c\n\n")
            
            total_all = 0
            passed_all = 0
            
            sorted_sources = sorted(
                self.source_stats.items(),
                key=lambda x: (x[1]['passed'] / x[1]['total']) if x[1]['total'] > 0 else 0,
                reverse=True
            )
            
            for url, stats in sorted_sources:
                if stats['total'] == 0:
                    continue
                
                total_all += stats['total']
                passed_all += stats['passed']
                percent = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
                
                f.write(f"📌 {url}\n")
                f.write(f"   Total vless: {stats['total']}\n")
                f.write(f"   ✅ Прошли полный тест: {stats['passed']} ({percent:.1f}%)\n")
                f.write(f"   ⚡ Avg ping: {stats['avg_ping']:.0f}ms\n\n")
            
            f.write("="*70 + "\n")
            f.write("📈 ОБЩАЯ СТАТИСТИКА\n")
            f.write("="*70 + "\n")
            
            total_percent = (passed_all / total_all * 100) if total_all > 0 else 0
            f.write(f"Всего vless серверов: {total_all}\n")
            f.write(f"✅ Прошли полный тест: {passed_all} ({total_percent:.1f}%)\n\n")
            
            # ========== АНАЛИЗ ДУБЛИКАТОВ ==========
            if unique_configs_map:
                f.write("\n" + "="*70 + "\n")
                f.write("🔍 АНАЛИЗ ДУБЛИКАТОВ И УНИКАЛЬНОСТИ ИСТОЧНИКОВ\n")
                f.write("="*70 + "\n\n")
                
                # Собираем все конфиги с привязкой к источникам (из unique_configs_map)
                config_sources = defaultdict(set)
                source_totals = defaultdict(int)
                
                for key, (source_url, config) in unique_configs_map.items():
                    base_config = re.sub(r'#.*', '', config)
                    config_sources[base_config].add(source_url)
                    source_totals[source_url] += 1
                
                # Считаем уникальные и дублирующиеся для каждого источника
                source_unique = defaultdict(int)
                source_shared = defaultdict(int)
                
                for base_config, sources in config_sources.items():
                    for source in sources:
                        if len(sources) == 1:
                            source_unique[source] += 1
                        else:
                            source_shared[source] += 1
                
                # Общая статистика по пулу
                unique_total = len(config_sources)
                total_with_dupes = sum(source_totals.values())
                
                f.write(f"📊 Всего уникальных vless конфигов в пуле: {unique_total:,}\n")
                f.write(f"📊 Всего vless конфигов с учётом дублей: {total_with_dupes:,}\n")
                if unique_total > 0:
                    f.write(f"📊 Коэффициент дублирования: {total_with_dupes/unique_total:.2f}x\n\n")
                
                # Таблица источников (только те, у которых есть уникальные)
                f.write("📌 ДЕТАЛЬНАЯ СТАТИСТИКА ПО ИСТОЧНИКАМ:\n")
                f.write("-" * 120 + "\n")
                f.write("   {:<80} {:>8} {:>8} {:>8} {:>10} {:>10} {:>12}\n".format(
                    "Источник", "Всего", "Уник.", "Дублей", "% уник.", "Пинг%", "Статус"
                ))
                f.write("-" * 120 + "\n")
                
                # Сортируем по проценту уникальности
                sorted_for_analysis = sorted(
                    source_totals.keys(),
                    key=lambda x: (source_unique[x] / source_totals[x]) if source_totals[x] > 0 else 0,
                    reverse=True
                )
                
                for source in sorted_for_analysis:
                    total = source_totals[source]
                    if total == 0:
                        continue
                    
                    unique = source_unique[source]
                    shared = source_shared[source]
                    unique_pct = (unique / total * 100)
                    
                    ping_passed = self.source_stats.get(source, {}).get('passed', 0)
                    ping_total = self.source_stats.get(source, {}).get('total', 0)
                    ping_pct = (ping_passed / ping_total * 100) if ping_total > 0 else 0
                    
                    # Определяем статус источника
                    if unique_pct >= 70 and ping_pct >= 50:
                        status = "🟢 ОТЛИЧНЫЙ"
                    elif unique_pct >= 30 and ping_pct >= 30:
                        status = "🟡 СРЕДНИЙ"
                    elif unique_pct >= 15 and ping_pct >= 10:
                        status = "🟠 СОМНИТЕЛЬНЫЙ"
                    else:
                        status = "🔴 МУСОР"
                    
                    short_url = source if len(source) <= 80 else source[:77] + "..."
                    
                    f.write("   {:<80} {:8d} {:8d} {:8d} {:9.1f}% {:9.1f}%  {}\n".format(
                        short_url, total, unique, shared, unique_pct, ping_pct, status
                    ))
                
                # ========== РЕКОМЕНДАЦИИ ==========
                f.write("\n💡 РЕКОМЕНДАЦИИ ПО ОПТИМИЗАЦИИ:\n")
                f.write("-"*70 + "\n")
                
                sources_to_remove = []
                unique_loss = 0
                total_checks = 0
                
                for source in source_totals.keys():
                    total = source_totals[source]
                    unique = source_unique[source]
                    unique_pct = (unique / total * 100) if total > 0 else 0
                    ping_pct = self.source_stats.get(source, {}).get('passed', 0) / max(1, self.source_stats.get(source, {}).get('total', 1)) * 100
                    
                    if unique_pct < 15 or ping_pct < 10:
                        sources_to_remove.append((source, unique, total))
                        unique_loss += unique
                        total_checks += total
                
                if sources_to_remove:
                    f.write(f"\n🔴 КАНДИДАТЫ НА УДАЛЕНИЕ ИЗ sources.txt:\n")
                    for source, unique, total in sources_to_remove[:5]:
                        short_url = source if len(source) <= 80 else source[:77] + "..."
                        f.write(f"   • {short_url}\n")
                        f.write(f"     (уникальных: {unique}, проверок: {total})\n")
                    
                    # Расчёт экономии времени
                    current_time = total_with_dupes / 43.6
                    new_time = (total_with_dupes - total_checks) / 43.6
                    
                    f.write(f"\n📊 ПОТЕНЦИАЛЬНАЯ ЭКОНОМИЯ:\n")
                    f.write(f"   • Удаляется источников: {len(sources_to_remove)}\n")
                    f.write(f"   • Потеряется уникальных: {unique_loss} ({unique_loss/unique_total*100:.1f}%)\n")
                    f.write(f"   • Освободится проверок: {total_checks} ({total_checks/total_with_dupes*100:.1f}%)\n")
                    f.write(f"   • НОВОЕ ВРЕМЯ: ~{new_time:.0f} сек (было {current_time:.0f} сек)\n")
                else:
                    f.write("\n✅ Все источники качественные, удалять нечего!\n")
                
                f.write("="*70 + "\n")
    
    def save_results(self, working_all: Dict[str, float], working_fast: Dict[str, float]):
        """
        Сохраняет результаты с GeoIP разделением.
        """
        # all.txt (все сервера)
        if working_all:
            unique_all = {}
            for c, s in working_all.items():
                k = self.get_config_key(c)
                if k not in unique_all or s < unique_all[k][1]:
                    unique_all[k] = (c, s)
            
            with open(self.all_file, 'w', encoding='utf-8') as f:
                for c, _ in unique_all.values():
                    f.write(c + '\n')
            logger.info(f"✅ Сохранено {len(unique_all)} серверов в all.txt")
            
            # Разделяем по странам
            ru_configs = []
            foreign_fast = []
            
            for config, speed in unique_all.values():
                host, _ = self.extract_host_port(config)
                if host:
                    country = self.geoip.get_country(host)
                    if country == 'RU':
                        ru_configs.append(config)
                        logger.debug(f"🇷🇺 Российский: {config[:50]}...")
                    elif speed <= self.speed_threshold:
                        foreign_fast.append(config)
                elif speed <= self.speed_threshold:
                    # Если не удалось извлечь host, считаем зарубежным
                    foreign_fast.append(config)
            
            # ru.txt (российские)
            if ru_configs:
                with open(self.ru_file, 'w', encoding='utf-8') as f:
                    for config in ru_configs:
                        f.write(config + '\n')
                logger.info(f"✅ Сохранено {len(ru_configs)} российских серверов в {self.ru_file}")
            else:
                logger.info("🇷🇺 Российских серверов не найдено")
            
            # out.txt (быстрые зарубежные)
            if foreign_fast:
                with open(self.out_file, 'w', encoding='utf-8') as f:
                    for config in foreign_fast:
                        f.write(config + '\n')
                logger.info(f"✅ Сохранено {len(foreign_fast)} быстрых зарубежных серверов в {self.out_file}")
                
                # 500.txt (топ из out.txt)
                foreign_fast_with_speed = []
                for config in foreign_fast:
                    key = self.get_config_key(config)
                    if key in unique_all:
                        foreign_fast_with_speed.append((config, unique_all[key][1]))
                
                top = sorted(foreign_fast_with_speed, key=lambda x: x[1])[:500]
                with open(self.top500_file, 'w', encoding='utf-8') as f:
                    for config, speed in top:
                        f.write(config + '\n')
                logger.info(f"✅ Сохранено топ-{len(top)} в {self.top500_file}")
            else:
                logger.warning("⚠️ Нет быстрых зарубежных серверов")
    
    def run(self):
        """Основной процесс."""
        print("="*70)
        print("🚀 POWER v8.1")
        print("="*70)
        print("ФАЙЛЫ: sources.txt → list.txt → all.txt, out.txt, ru.txt, 500.txt, stat.txt")
        print(f"ТАЙМАУТЫ: быстрый Xray={self.quick_timeout}c | полный Xray={self.check_timeout}c")
        print("ПРОВЕРКА: быстрый Xray (рукопожатие) → полный Xray (реальный запрос)")
        print(f"ПРОТОКОЛЫ: ТОЛЬКО VLESS")
        print(f"ПАРАЛЛЕЛЬНОСТЬ: {self.check_workers} потоков")
        print("🌍 GeoIP: runetfreedom/russia-blocked-geoip")
        print("   - ru.txt: российские сервера")
        print("   - out.txt: быстрые зарубежные")
        print("="*70)
        
        start = time.time()
        sources = self.step1_collect_all()
        if sources:
            all_cfg, fast_cfg, src_cfg, unique_map = self.step2_check_all(sources)
            self.save_results(all_cfg, fast_cfg)
            self.save_stats(fast_cfg, src_cfg, unique_map)
        
        # Закрываем GeoIP базу
        self.geoip.close()
        
        print(f"\n🎯 ГОТОВО! Время: {time.time()-start:.1f} сек")
        print("="*70)


if __name__ == "__main__":
    collector = VlessCollector()
    collector.run()
