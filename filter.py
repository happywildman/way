#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VLESS+Reality Collector v5.3
====================================
ИСПРАВЛЕНИЯ:
- 500.txt теперь только ссылки (совместимо с v2ray)
- Убраны дубликаты серверов
- Явная проверка создания list.txt
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

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class VlessCollector:
    """Двухэтапный сборщик VLESS подписок."""
    
    def __init__(self,
                 sources_file: str = 'sources.txt',
                 list_file: str = 'list.txt',
                 out_file: str = 'out.txt',
                 trash_file: str = 'trash.txt',
                 stat_file: str = 'stat.txt',
                 top500_file: str = '500.txt',
                 speed_threshold: float = 800.0,
                 download_timeout: int = 10,
                 check_timeout: int = 6,
                 download_workers: int = 10,
                 check_workers: int = 50):
        
        self.sources_file = sources_file
        self.list_file = list_file
        self.out_file = out_file
        self.trash_file = trash_file
        self.stat_file = stat_file
        self.top500_file = top500_file
        self.speed_threshold = speed_threshold
        self.download_timeout = download_timeout
        self.check_timeout = check_timeout
        self.download_workers = download_workers
        self.check_workers = check_workers
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Загружаем trash
        self.trash_servers = self._load_trash()
        
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
        
        logger.info(f"Загружено {len(sources)} RAW-ссылок из {self.sources_file}")
        return sources
    
    def download_subscription(self, url: str) -> Tuple[str, List[str]]:
        """
        Скачивает одну подписку и извлекает vless конфиги.
        Возвращает (url, list_of_configs)
        """
        try:
            req = urllib.request.Request(url, headers={'User-Agent': self.user_agent})
            with urllib.request.urlopen(req, timeout=self.download_timeout) as response:
                content = response.read()
                
                # Декодируем
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
                
                # Извлекаем vless
                vless_pattern = r'vless://[a-f0-9-]+@[^#\s]+(?:#[^\s]*)?'
                configs = re.findall(vless_pattern, text)
                
                return url, configs
                
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")
            return url, []
    
    def step1_collect_all(self) -> Dict[str, List[str]]:
        """
        ШАГ 1: Собирает все сервера из всех подписок в list.txt.
        Возвращает словарь {url: [configs]} для статистики.
        """
        print("\n" + "="*60)
        print("🔍 ШАГ 1: СБОР ВСЕХ СЕРВЕРОВ В list.txt")
        print("="*60)
        
        sources = self.read_sources()
        if not sources:
            logger.error("Нет источников для обработки")
            return {}
        
        logger.info(f"Скачивание {len(sources)} подписок ({self.download_workers} потоков)...")
        
        results = {}
        total_configs = 0
        
        # Очищаем list.txt
        with open(self.list_file, 'w', encoding='utf-8') as f:
            f.write(f"# СЫРЫЕ НЕПРОВЕРЕННЫЕ СЕРВЕРА\n")
            f.write(f"# Собрано из sources.txt: {datetime.now().isoformat()}\n")
            f.write("#" + "="*60 + "\n\n")
        
        # Параллельное скачивание
        with ThreadPoolExecutor(max_workers=self.download_workers) as executor:
            future_to_url = {executor.submit(self.download_subscription, url): url for url in sources}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url, configs = future.result()
                    results[url] = configs
                    
                    # Записываем в list.txt
                    with open(self.list_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n# ИСТОЧНИК: {url}\n")
                        for config in configs:
                            f.write(config + '\n')
                        f.write("#" + "="*50 + "\n")
                    
                    logger.info(f"  ✓ {url}: {len(configs)} конфигов")
                    total_configs += len(configs)
                    
                except Exception as e:
                    logger.error(f"  ✗ Ошибка при обработке {future_to_url[future]}: {e}")
                    results[url] = []
        
        # ПРОВЕРКА: существует ли файл и не пустой ли он
        if os.path.exists(self.list_file):
            file_size = os.path.getsize(self.list_file)
            logger.info(f"📁 {self.list_file} создан, размер: {file_size} байт")
        else:
            logger.error(f"❌ {self.list_file} НЕ БЫЛ СОЗДАН!")
        
        print("\n" + "="*60)
        print(f"✅ СБОР ЗАВЕРШЁН:")
        print(f"   - Источников: {len(sources)}")
        print(f"   - Всего серверов: {total_configs}")
        print(f"   - Сохранено в: {self.list_file}")
        print("="*60)
        
        return results
    
    def is_reality_port443(self, config: str) -> Tuple[bool, str]:
        """Проверяет vless+reality и порт 443."""
        try:
            if 'security=reality' not in config and 'reality' not in config:
                return False, ""
            
            after_at = config.split('@')[1]
            host_part = after_at.split('?')[0]
            
            if ':' in host_part:
                host, port = host_part.split(':')[:2]
                return port == '443', host
            return False, ""
        except:
            return False, ""
    
    def normalize_config(self, config: str, speed: float) -> str:
        """
        Приводит конфиг к нормальному виду:
        - Убирает лишние символы (&; вместо &)
        - Добавляет скорость в тег
        """
        # Исправляем возможные &; на &
        config = config.replace('&;', '&')
        
        # Добавляем скорость в тег
        if '#' in config:
            # Заменяем существующий тег
            config = re.sub(r'#.*', f'#{speed:.0f}ms', config)
        else:
            config = f"{config}#{speed:.0f}ms"
        
        return config
    
    def check_single(self, config: str, host: str, source_url: str) -> Tuple[Optional[str], Optional[float], str]:
        """
        Проверяет один конфиг.
        Возвращает (config, speed, source_url) если рабочий, иначе (None, None, source_url)
        """
        # TCP проверка
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, 443))
            sock.close()
            
            if result != 0:
                self._save_to_trash(config, "порт закрыт")
                return None, None, source_url
        except Exception as e:
            self._save_to_trash(config, f"TCP ошибка")
            return None, None, source_url
        
        # Проверка 204
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
                    if elapsed <= self.speed_threshold:
                        # Нормализуем конфиг перед возвратом
                        normalized = self.normalize_config(config, elapsed)
                        return normalized, elapsed, source_url
                    else:
                        self._save_to_trash(config, f"медленный {elapsed:.0f}ms")
                        return None, None, source_url
                else:
                    self._save_to_trash(config, f"код {resp.status}")
                    return None, None, source_url
        except Exception as e:
            self._save_to_trash(config, f"ошибка 204")
            return None, None, source_url
    
    def step2_check_all(self) -> Dict[str, float]:
        """
        ШАГ 2: Проверяет все сервера из list.txt.
        Возвращает {config: speed} для рабочих.
        """
        print("\n" + "="*60)
        print("⚡ ШАГ 2: ПРОВЕРКА СЕРВЕРОВ ИЗ list.txt")
        print("="*60)
        
        if not os.path.exists(self.list_file):
            logger.error(f"❌ Файл {self.list_file} не найден! Сначала выполните ШАГ 1.")
            return {}
        
        # Проверяем размер файла
        file_size = os.path.getsize(self.list_file)
        if file_size == 0:
            logger.error(f"❌ Файл {self.list_file} пустой!")
            return {}
        
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
        
        # Собираем все конфиги для проверки
        all_items = []  # (source_url, config, host)
        source_totals = defaultdict(int)
        
        for source_url, configs in source_configs.items():
            for config in configs:
                if config in self.trash_servers:
                    continue
                
                is_valid, host = self.is_reality_port443(config)
                if is_valid:
                    all_items.append((source_url, config, host))
                    source_totals[source_url] += 1
        
        logger.info(f"Найдено {len(all_items)} reality:443 конфигов для проверки")
        logger.info(f"Запуск проверки ({self.check_workers} потоков, TCP=3c, HTTP=6c)...")
        
        # Параллельная проверка
        working = {}
        source_passed = defaultdict(int)
        source_pings = defaultdict(list)
        
        start_time = time.time()
        checked = 0
        
        with ThreadPoolExecutor(max_workers=self.check_workers) as executor:
            future_to_item = {
                executor.submit(self.check_single, config, host, source_url): (source_url, config, host)
                for source_url, config, host in all_items
            }
            
            for future in as_completed(future_to_item):
                source_url, config, host = future_to_item[future]
                try:
                    result_config, speed, src = future.result()
                    checked += 1
                    
                    if result_config:
                        working[result_config] = speed
                        source_passed[source_url] += 1
                        source_pings[source_url].append(speed)
                    
                    # Прогресс каждые 100 проверок
                    if checked % 100 == 0:
                        elapsed = time.time() - start_time
                        speed_per_sec = checked / elapsed if elapsed > 0 else 0
                        logger.info(f"  Прогресс: {checked}/{len(all_items)} ({speed_per_sec:.1f} серверов/сек)")
                        
                except Exception as e:
                    logger.debug(f"Ошибка при проверке {host}: {e}")
        
        # Формируем статистику по источникам
        for source_url in source_totals:
            total = source_totals[source_url]
            passed = source_passed[source_url]
            pings = source_pings[source_url]
            avg_ping = sum(pings) / len(pings) if pings else 0
            
            self.source_stats[source_url] = {
                'total': total,
                'passed': passed,
                'avg_ping': avg_ping
            }
        
        # Итоги проверки
        elapsed = time.time() - start_time
        print("\n" + "="*60)
        print(f"✅ ПРОВЕРКА ЗАВЕРШЕНА:")
        print(f"   - Проверено: {len(all_items)} серверов")
        print(f"   - Рабочих: {len(working)}")
        print(f"   - Время: {elapsed:.1f} сек")
        print(f"   - Скорость: {len(all_items)/elapsed:.1f} серверов/сек")
        print("="*60)
        
        return working
    
    def save_results(self, working: Dict[str, float]):
        """Сохраняет результаты в out.txt, 500.txt и stat.txt."""
        
        # Сохраняем out.txt (все рабочие)
        if working:
            with open(self.out_file, 'w', encoding='utf-8') as f:
                f.write(f"# VLESS+Reality:443 с хорошей скоростью (<={self.speed_threshold}ms)\n")
                f.write(f"# Проверено: {datetime.now().isoformat()}\n")
                f.write(f"# Таймауты: TCP=3c, HTTP=6c\n")
                f.write("#" + "="*50 + "\n\n")
                
                for config, speed in working.items():
                    f.write(config + '\n')
            
            logger.info(f"Сохранено {len(working)} рабочих серверов в {self.out_file}")
        
        # Сохраняем топ-500 (ТОЛЬКО ССЫЛКИ, БЕЗ КОММЕНТАРИЕВ)
        if working:
            # Убираем дубликаты (оставляем уникальные конфиги с наименьшим пингом)
            unique_configs = {}
            for config, speed in working.items():
                # Извлекаем базовый конфиг без тега скорости для сравнения
                base_config = re.sub(r'#\d+ms', '', config)
                if base_config not in unique_configs or speed < unique_configs[base_config][1]:
                    unique_configs[base_config] = (config, speed)
            
            # Сортируем по скорости
            sorted_configs = sorted(unique_configs.values(), key=lambda x: x[1])
            top_configs = sorted_configs[:500]
            
            # Сохраняем ТОЛЬКО ссылки, каждая с новой строки
            with open(self.top500_file, 'w', encoding='utf-8') as f:
                for config, speed in top_configs:
                    f.write(config + '\n')
            
            logger.info(f"Сохранено топ-500 в {self.top500_file} (только ссылки)")
        
        # Сохраняем статистику
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ ПРОКСИ\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Таймауты: TCP=3c, HTTP=6c\n\n")
            
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
                f.write(f"   Total: {stats['total']}\n")
                f.write(f"   ✅ Ping passed: {stats['passed']} ({percent:.1f}%)\n")
                f.write(f"   ⚡ Avg ping: {stats['avg_ping']:.0f}ms\n\n")
            
            f.write("="*60 + "\n")
            f.write("📈 ОБЩАЯ СТАТИСТИКА\n")
            f.write("="*60 + "\n")
            
            total_percent = (passed_all / total_all * 100) if total_all > 0 else 0
            f.write(f"Всего прокси (reality:443): {total_all}\n")
            f.write(f"✅ Прошли ping: {passed_all} ({total_percent:.1f}%)\n")
        
        logger.info(f"Статистика сохранена в {self.stat_file}")
    
    def run(self):
        """Основной процесс."""
        print("="*70)
        print("🚀 VLESS+REALITY COLLECTOR v5.3")
        print("="*70)
        print("ФАЙЛОВАЯ СТРУКТУРА:")
        print("  sources.txt  → список RAW-ссылок на подписки")
        print("  list.txt     → сырые непроверенные сервера")
        print("  out.txt      → проверенные рабочие")
        print("  trash.txt    → битые и медленные")
        print("  500.txt      → топ-500 лучших (ТОЛЬКО ССЫЛКИ)")
        print("  stat.txt     → статистика по источникам")
        print("-"*70)
        print("ТАЙМАУТЫ: TCP=3c, HTTP=6c")
        print("="*70)
        
        # ШАГ 1: Сбор
        start_total = time.time()
        sources_data = self.step1_collect_all()
        
        if not sources_data:
            logger.error("Не удалось собрать сервера. Завершение.")
            return
        
        # ШАГ 2: Проверка
        working = self.step2_check_all()
        
        # Сохранение результатов
        self.save_results(working)
        
        # Финальный отчёт
        total_time = time.time() - start_total
        print("\n" + "="*70)
        print("🎯 ВСЁ ГОТОВО!")
        print("="*70)
        print(f"📁 sources.txt      - {len(sources_data)} источников")
        print(f"📁 list.txt         - все сырые сервера")
        print(f"📁 out.txt          - {len(working)} рабочих серверов")
        print(f"📁 500.txt          - топ-500 лучших (только ссылки)")
        print(f"📁 stat.txt         - статистика по источникам")
        print(f"📁 trash.txt        - битые и медленные")
        print(f"⏱  Общее время: {total_time:.1f} секунд")
        print("="*70)


if __name__ == "__main__":
    collector = VlessCollector()
    collector.run()
