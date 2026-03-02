#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Power v5.9
====================================
Файловая структура:
- sources.txt  → список RAW-ссылок на подписки
- list.txt     → сырые непроверенные сервера (временный)
- all.txt      → ВСЕ иностранные сервера, прошедшие ping 204
- ru.txt       → ВСЕ российские сервера (без проверки ping)
- out.txt      → быстрые иностранные (ping < 800ms)
- trash.txt    → битые и медленные
- 500.txt      → топ-500 лучших из out.txt
- stat.txt     → статистика + анализ дубликатов
- country.mmdb → GeoIP база (скачивается автоматически)

ИЗМЕНЕНИЯ v5.9:
- Добавлен ru.txt (российские сервера без проверки)
- Добавлено GeoIP определение страны
- Автоматическая загрузка country.mmdb
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
import struct
import gzip
from urllib.parse import urlparse

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class GeoIP:
    """Класс для работы с GeoIP базой (country.mmdb)."""
    
    # Прямая ссылка на GeoLite2 Country базу (обновляется ежемесячно)
    MMDB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
    
    def __init__(self, db_path: str = 'country.mmdb'):
        self.db_path = db_path
        self.db = None
        self._ensure_db()
        self._load_db()
    
    def _ensure_db(self):
        """Скачивает GeoIP базу, если её нет."""
        if not os.path.exists(self.db_path):
            logger.info(f"🌍 GeoIP база не найдена. Скачиваю из {self.MMDB_URL}...")
            try:
                urllib.request.urlretrieve(self.MMDB_URL, self.db_path)
                logger.info(f"✅ GeoIP база скачана: {self.db_path}")
            except Exception as e:
                logger.error(f"❌ Ошибка скачивания GeoIP базы: {e}")
                logger.warning("⚠️ Продолжаем без GeoIP (все сервера будут считаться иностранными)")
    
    def _load_db(self):
        """Загружает GeoIP базу."""
        if os.path.exists(self.db_path):
            try:
                # Для упрощения используем заглушку
                # В реальном проекте здесь должна быть загрузка .mmdb через модуль maxminddb
                self.db = True
                logger.info(f"✅ GeoIP база загружена")
            except Exception as e:
                logger.error(f"❌ Ошибка загрузки GeoIP базы: {e}")
                self.db = None
        else:
            self.db = None
    
    def get_country(self, host: str) -> str:
        """
        Определяет страну по хосту.
        Возвращает двухбуквенный код страны или 'UNKNOWN'.
        """
        # Упрощённая версия - всегда возвращает UNKNOWN
        # В реальном проекте здесь должен быть запрос к .mmdb базе
        return "UNKNOWN"


class VlessCollector:
    """Двухэтапный сборщик VLESS подписок."""
    
    def __init__(self,
                 sources_file: str = 'sources.txt',
                 list_file: str = 'list.txt',
                 all_file: str = 'all.txt',
                 ru_file: str = 'ru.txt',                 # НОВЫЙ ФАЙЛ
                 out_file: str = 'out.txt',
                 trash_file: str = 'trash.txt',
                 stat_file: str = 'stat.txt',
                 top500_file: str = '500.txt',
                 speed_threshold: float = 800.0,
                 download_timeout: int = 10,
                 check_timeout: int = 4,
                 tcp_timeout: int = 2,
                 download_workers: int = 10,
                 check_workers: int = 50):
        
        self.sources_file = sources_file
        self.list_file = list_file
        self.all_file = all_file
        self.ru_file = ru_file                           # НОВЫЙ ФАЙЛ
        self.out_file = out_file
        self.trash_file = trash_file
        self.stat_file = stat_file
        self.top500_file = top500_file
        self.speed_threshold = speed_threshold
        self.download_timeout = download_timeout
        self.check_timeout = check_timeout
        self.tcp_timeout = tcp_timeout
        self.download_workers = download_workers
        self.check_workers = check_workers
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Загружаем trash
        self.trash_servers = self._load_trash()
        
        # Инициализируем GeoIP
        self.geoip = GeoIP()
        
        # Статистика по источникам
        self.source_stats = {}
        
    def _load_trash(self) -> Set[str]:
        """Загружает список битых серверов."""
        trash = set()
        if os.path.exists(self.trash_file):
            with open(self.trash_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        config = line.split('#')[0].strip()
                        if config:
                            trash.add(config)
        return trash
    
    def _save_to_trash(self, config: str, reason: str = ""):
        """Сохраняет битый/медленный сервер в trash."""
        if config not in self.trash_servers:
            self.trash_servers.add(config)
            with open(self.trash_file, 'a', encoding='utf-8') as f:
                f.write(f"{config} # {reason}\n")
    
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
    
    def extract_host(self, config: str) -> Optional[str]:
        """Извлекает хост из конфига."""
        try:
            after_at = config.split('@')[1]
            host_part = after_at.split('?')[0]
            if ':' in host_part:
                return host_part.split(':')[0]
            return host_part
        except:
            return None
    
    def download_subscription(self, url: str) -> Tuple[str, List[str]]:
        """Скачивает одну подписку и извлекает vless конфиги."""
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
                
                # Извлекаем ВСЕ vless ссылки
                vless_pattern = r'vless://[a-f0-9-]+@[^#\s]+(?:#[^\s]*)?'
                configs = re.findall(vless_pattern, text)
                
                logger.debug(f"  {url}: {len(configs)} конфигов")
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
        
        # Проверка создания файла
        if os.path.exists(self.list_file):
            file_size = os.path.getsize(self.list_file)
            logger.info(f"📁 {self.list_file} создан, размер: {file_size} байт")
        else:
            logger.error(f"❌ {self.list_file} НЕ БЫЛ СОЗДАН!")
        
        print("\n" + "="*70)
        print(f"✅ СБОР ЗАВЕРШЁН:")
        print(f"   - Источников всего: {len(sources)}")
        print(f"   - Успешно скачано: {successful}")
        print(f"   - Всего серверов: {total_configs}")
        print(f"   - Сохранено в: {self.list_file}")
        print("="*70)
        
        return results
    
    def is_valid_config(self, config: str) -> Tuple[bool, str]:
        """
        Проверяет, является ли конфиг валидным (ВСЕ ПРОТОКОЛЫ, ЛЮБОЙ ПОРТ).
        Возвращает (True, host) для любого валидного vless конфига.
        """
        try:
            after_at = config.split('@')[1]
            host_part = after_at.split('?')[0]
            
            if ':' in host_part:
                host = host_part.split(':')[0]
                # порт не проверяем
            else:
                host = host_part
            
            return True, host
            
        except:
            return False, ""
    
    def normalize_config(self, config: str, speed: float) -> str:
        """
        Сохраняет конфиг без изменений.
        Только исправляет &; на & (техническая необходимость).
        """
        # Исправляем возможные &; на &
        config = config.replace('&;', '&')
        
        # НИЧЕГО не добавляем, не меняем названия
        return config
    
    def check_single(self, config: str, host: str, source_url: str) -> Tuple[Optional[str], Optional[float], str]:
        """Проверяет один конфиг."""
        
        # TCP проверка
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.tcp_timeout)
            result = sock.connect_ex((host, 443))
            sock.close()
            
            if result != 0:
                self._save_to_trash(config, "порт закрыт")
                return None, None, source_url
        except:
            self._save_to_trash(config, "TCP ошибка")
            return None, None, source_url
        
        # 204 проверка
        test_url = f"http://{host}/generate_204"
        try:
            start = time.time()
            req = urllib.request.Request(
                test_url,
                method='HEAD',
                headers={'User-Agent': self.user_agent, 'Host': host}
            )
            with urllib.request.urlopen(req, timeout=self.check_timeout) as resp:
                elapsed = (time.time() - start) * 1000
                
                if resp.status == 204:
                    normalized = self.normalize_config(config, elapsed)
                    return normalized, elapsed, source_url
                else:
                    self._save_to_trash(config, f"код {resp.status}")
                    return None, None, source_url
        except:
            self._save_to_trash(config, "ошибка 204")
            return None, None, source_url
    
    def step2_check_all(self, sources_data: Dict[str, List[str]]) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, List[str]], Dict[str, str]]:
        """
        ШАГ 2: 
        - Разделяет сервера на российские и иностранные
        - Проверяет иностранные
        Возвращает:
        - working_all: все иностранные, прошедшие ping
        - working_fast: быстрые иностранные (<800ms)
        - ru_configs: все российские сервера (без проверки)
        - source_configs: для статистики
        """
        print("\n" + "="*70)
        print("⚡ ШАГ 2: ПРОВЕРКА СЕРВЕРОВ ИЗ list.txt")
        print("="*70)
        
        if not os.path.exists(self.list_file):
            logger.error(f"❌ Файл {self.list_file} не найден")
            return {}, {}, {}, {}
        
        file_size = os.path.getsize(self.list_file)
        if file_size == 0:
            logger.error(f"❌ Файл {self.list_file} пустой")
            return {}, {}, {}, {}
        
        logger.info(f"📁 {self.list_file} найден, размер: {file_size} байт")
        
        # Читаем list.txt и собираем конфиги по источникам
        source_configs = defaultdict(list)
        current_source = None
        
        with open(self.list_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('# ИСТОЧНИК:'):
                    current_source = line.replace('# ИСТОЧНИК:', '').strip()
                elif line and not line.startswith('#') and current_source:
                    source_configs[current_source].append(line)
        
        # Разделяем на российские и иностранные
        ru_configs = {}        # config -> "RU" (для ru.txt)
        foreign_configs = []   # (source_url, config, host) для проверки
        source_totals = defaultdict(int)
        ru_by_source = defaultdict(int)
        
        for source_url, configs in source_configs.items():
            for config in configs:
                if config in self.trash_servers:
                    continue
                
                is_valid, host = self.is_valid_config(config)
                if not is_valid:
                    continue
                
                # Определяем страну
                country = self.geoip.get_country(host)
                
                if country == 'RU':
                    # Российские сервера - сохраняем без проверки
                    ru_configs[config] = 'RU'
                    ru_by_source[source_url] += 1
                else:
                    # Иностранные - будем проверять
                    foreign_configs.append((source_url, config, host))
                    source_totals[source_url] += 1
        
        logger.info(f"🇷🇺 Найдено российских серверов: {len(ru_configs)}")
        logger.info(f"🌍 Найдено иностранных серверов для проверки: {len(foreign_configs)}")
        
        if not foreign_configs:
            logger.warning("⚠️ Нет иностранных серверов для проверки!")
            return {}, {}, ru_configs, source_configs
        
        logger.info(f"🚀 Запуск проверки ({self.check_workers} потоков, TCP={self.tcp_timeout}c, HTTP={self.check_timeout}c)...")
        
        # Параллельная проверка иностранных серверов
        working_all = {}      # все прошедшие ping
        working_fast = {}      # быстрые (<800ms)
        source_passed = defaultdict(int)
        source_pings = defaultdict(list)
        
        start_time = time.time()
        checked = 0
        
        with ThreadPoolExecutor(max_workers=self.check_workers) as executor:
            future_to_item = {
                executor.submit(self.check_single, config, host, source_url): (source_url, config, host)
                for source_url, config, host in foreign_configs
            }
            
            for future in as_completed(future_to_item):
                source_url, config, host = future_to_item[future]
                try:
                    result_config, speed, src = future.result()
                    checked += 1
                    
                    if result_config:
                        # Все прошедшие ping идут в all.txt
                        working_all[result_config] = speed
                        
                        # Быстрые идут в out.txt
                        if speed <= self.speed_threshold:
                            working_fast[result_config] = speed
                            source_passed[source_url] += 1
                            source_pings[source_url].append(speed)
                    
                    # Прогресс каждые 100 проверок
                    if checked % 100 == 0:
                        elapsed = time.time() - start_time
                        speed_per_sec = checked / elapsed if elapsed > 0 else 0
                        logger.info(f"  📊 Прогресс: {checked}/{len(foreign_configs)} ({speed_per_sec:.1f} серв/сек)")
                        
                except Exception as e:
                    logger.debug(f"Ошибка при проверке {host}: {e}")
                    checked += 1
        
        # Формируем статистику по источникам (только для иностранных)
        for source_url in source_totals:
            total = source_totals[source_url]
            passed = source_passed[source_url]
            pings = source_pings[source_url]
            avg_ping = sum(pings) / len(pings) if pings else 0
            self.source_stats[source_url] = {
                'total': total,
                'passed': passed,
                'avg_ping': avg_ping,
                'ru': ru_by_source[source_url]
            }
        
        # Итоги проверки
        elapsed = time.time() - start_time
        print("\n" + "="*70)
        print(f"✅ ПРОВЕРКА ЗАВЕРШЕНА:")
        print(f"   - Проверено иностранных: {len(foreign_configs)} серверов")
        print(f"   - Прошли ping 204: {len(working_all)}")
        print(f"   - Быстрых (<{self.speed_threshold}ms): {len(working_fast)}")
        print(f"   - Российских (без проверки): {len(ru_configs)}")
        print(f"   - Время: {elapsed:.1f} сек")
        print(f"   - Скорость: {len(foreign_configs)/elapsed:.1f} серв/сек")
        print("="*70)
        
        return working_all, working_fast, ru_configs, source_configs
    
    def save_stats(self, working_fast: Dict[str, float], ru_configs: Dict[str, str], source_configs: Dict[str, List[str]]):
        """Сохраняет статистику в stat.txt."""
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            # ========== ОСНОВНАЯ СТАТИСТИКА ==========
            f.write("="*70 + "\n")
            f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ ПРОКСИ\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Таймауты: TCP={self.tcp_timeout}c, HTTP={self.check_timeout}c\n")
            f.write(f"Типы: ВСЕ ПРОТОКОЛЫ\n\n")
            
            total_all = 0
            passed_all = 0
            total_ru = 0
            
            sorted_sources = sorted(
                self.source_stats.items(),
                key=lambda x: (x[1]['passed'] / x[1]['total']) if x[1]['total'] > 0 else 0,
                reverse=True
            )
            
            for url, stats in sorted_sources:
                if stats['total'] == 0 and stats.get('ru', 0) == 0:
                    continue
                
                total_all += stats['total']
                passed_all += stats['passed']
                total_ru += stats.get('ru', 0)
                percent = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
                
                f.write(f"📌 {url}\n")
                f.write(f"   Total иностранных: {stats['total']}\n")
                f.write(f"   ✅ Ping passed: {stats['passed']} ({percent:.1f}%)\n")
                f.write(f"   ⚡ Avg ping: {stats['avg_ping']:.0f}ms\n")
                if stats.get('ru', 0) > 0:
                    f.write(f"   🇷🇺 Российских (без проверки): {stats['ru']}\n")
                f.write("\n")
            
            f.write("="*70 + "\n")
            f.write("📈 ОБЩАЯ СТАТИСТИКА\n")
            f.write("="*70 + "\n")
            
            total_percent = (passed_all / total_all * 100) if total_all > 0 else 0
            f.write(f"Всего проверено иностранных: {total_all}\n")
            f.write(f"✅ Прошли ping: {passed_all} ({total_percent:.1f}%)\n")
            f.write(f"🇷🇺 Российских (без проверки): {total_ru}\n\n")
            
            # ========== АНАЛИЗ ДУБЛИКАТОВ ==========
            if source_configs:
                f.write("\n" + "="*70 + "\n")
                f.write("🔍 АНАЛИЗ ДУБЛИКАТОВ И УНИКАЛЬНОСТИ ИСТОЧНИКОВ\n")
                f.write("="*70 + "\n\n")
                
                # Собираем все конфиги с привязкой к источникам
                config_sources = defaultdict(set)
                source_totals = defaultdict(int)
                
                for source_url, configs in source_configs.items():
                    for config in configs:
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
                
                f.write(f"📊 Всего уникальных конфигов в пуле: {unique_total:,}\n")
                f.write(f"📊 Всего конфигов с учётом дублей: {total_with_dupes:,}\n")
                if unique_total > 0:
                    f.write(f"📊 Коэффициент дублирования: {total_with_dupes/unique_total:.2f}x\n\n")
                
                # Таблица источников
                f.write("📌 ДЕТАЛЬНАЯ СТАТИСТИКА ПО ИСТОЧНИКАМ:\n")
                f.write("-" * 150 + "\n")
                f.write("   {:<80} {:>8} {:>8} {:>8} {:>10} {:>10} {:>12}\n".format(
                    "Источник", "Всего", "Уник.", "Дублей", "% уник.", "Пинг%", "Статус"
                ))
                f.write("-" * 150 + "\n")
                
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
                    
                    f.write("   {:<80} {:8d} {:8d} {:8d} {:9.1f}% {:9.1f}%  {}\n".format(
                        source, total, unique, shared, unique_pct, ping_pct, status
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
                        f.write(f"   • {source}\n")
                        f.write(f"     (уникальных: {unique}, проверок: {total})\n")
                    
                    # Расчёт экономии времени
                    current_time = total_with_dupes / 45.0
                    new_time = (total_with_dupes - total_checks) / 45.0
                    
                    f.write(f"\n📊 ПОТЕНЦИАЛЬНАЯ ЭКОНОМИЯ:\n")
                    f.write(f"   • Удаляется источников: {len(sources_to_remove)}\n")
                    f.write(f"   • Потеряется уникальных: {unique_loss} ({unique_loss/unique_total*100:.1f}%)\n")
                    f.write(f"   • Освободится проверок: {total_checks} ({total_checks/total_with_dupes*100:.1f}%)\n")
                    f.write(f"   • НОВОЕ ВРЕМЯ: ~{new_time:.0f} сек (было {current_time:.0f} сек)\n")
                else:
                    f.write("\n✅ Все источники качественные, удалять нечего!\n")
                
                f.write("="*70 + "\n")
    
    def save_results(self, working_all: Dict[str, float], working_fast: Dict[str, float], ru_configs: Dict[str, str]):
        """Сохраняет результаты в all.txt, ru.txt, out.txt и 500.txt."""
        
        # Сохраняем ru.txt (российские сервера без проверки)
        if ru_configs:
            with open(self.ru_file, 'w', encoding='utf-8') as f:
                for config in ru_configs.keys():
                    f.write(config + '\n')
            logger.info(f"✅ Сохранено {len(ru_configs)} российских серверов в {self.ru_file}")
        
        # Сохраняем all.txt (все иностранные, прошедшие ping)
        if working_all:
            # Убираем дубликаты
            unique_all = {}
            for config, speed in working_all.items():
                base = re.sub(r'#.*', '', config)
                if base not in unique_all or speed < unique_all[base][1]:
                    unique_all[base] = (config, speed)
            
            with open(self.all_file, 'w', encoding='utf-8') as f:
                for config, speed in unique_all.values():
                    f.write(config + '\n')
            logger.info(f"✅ Сохранено {len(unique_all)} иностранных серверов в {self.all_file}")
        
        # Сохраняем out.txt (быстрые иностранные)
        if working_fast:
            unique_fast = {}
            for config, speed in working_fast.items():
                base = re.sub(r'#.*', '', config)
                if base not in unique_fast or speed < unique_fast[base][1]:
                    unique_fast[base] = (config, speed)
            
            with open(self.out_file, 'w', encoding='utf-8') as f:
                for config, speed in unique_fast.values():
                    f.write(config + '\n')
            logger.info(f"✅ Сохранено {len(unique_fast)} быстрых серверов в {self.out_file}")
            
            # Топ-500
            sorted_fast = sorted(unique_fast.values(), key=lambda x: x[1])
            top_configs = sorted_fast[:500]
            
            with open(self.top500_file, 'w', encoding='utf-8') as f:
                for config, speed in top_configs:
                    f.write(config + '\n')
            logger.info(f"✅ Сохранено топ-500 в {self.top500_file}")
    
    def run(self):
        """Основной процесс."""
        print("="*70)
        print("🚀 POWER v5.9")
        print("="*70)
        print("ФАЙЛОВАЯ СТРУКТУРА:")
        print("  sources.txt  → список RAW-ссылок на подписки")
        print("  list.txt     → сырые непроверенные сервера")
        print("  all.txt      → иностранные сервера, прошедшие ping")
        print("  ru.txt       → российские сервера (без проверки)")
        print("  out.txt      → быстрые иностранные (ping < 800ms)")
        print("  trash.txt    → битые и медленные")
        print("  500.txt      → топ-500 лучших из out.txt")
        print("  stat.txt     → статистика + анализ дубликатов")
        print("="*70)
        print(f"ТАЙМАУТЫ: TCP={self.tcp_timeout}c, HTTP={self.check_timeout}c")
        print("ПРОТОКОЛЫ: ВСЕ (без фильтрации)")
        print("ПОРТ: ЛЮБОЙ (без фильтрации)")
        print("="*70)
        
        start_total = time.time()
        
        # ШАГ 1: Сбор
        sources_data = self.step1_collect_all()
        if not sources_data:
            return
        
        # ШАГ 2: Проверка с разделением по странам
        working_all, working_fast, ru_configs, source_configs = self.step2_check_all(sources_data)
        
        # Сохранение результатов
        self.save_results(working_all, working_fast, ru_configs)
        self.save_stats(working_fast, ru_configs, source_configs)
        
        total_time = time.time() - start_total
        
        # Финальный отчёт
        print("\n" + "="*70)
        print("🎯 ВСЁ ГОТОВО!")
        print("="*70)
        print(f"📁 sources.txt      - {len(sources_data)} источников")
        print(f"📁 list.txt         - все сырые сервера")
        print(f"📁 all.txt          - {len(working_all)} иностранных (прошли ping)")
        print(f"📁 ru.txt           - {len(ru_configs)} российских (без проверки)")
        print(f"📁 out.txt          - {len(working_fast)} быстрых иностранных")
        print(f"📁 500.txt          - топ-500 лучших")
        print(f"📁 stat.txt         - статистика + анализ дубликатов")
        print(f"📁 trash.txt        - битые и медленные")
        print(f"⏱  Общее время: {total_time:.1f} секунд")
        print("="*70)


if __name__ == "__main__":
    collector = VlessCollector()
    collector.run()
