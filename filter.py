#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Power v5.13
====================================
Файловая структура:
- sources.txt  → список RAW-ссылок на подписки
- list.txt     → сырые непроверенные сервера
- all.txt      → ВСЕ сервера, прошедшие ping 204
- out.txt      → быстрые сервера (ping < 800ms)
- 500.txt      → топ-500 лучших из out.txt
- stat.txt     → статистика + анализ дубликатов

GeoIP ПОЛНОСТЬЮ УДАЛЕН
trash.txt ПОЛНОСТЬЮ УДАЛЕН
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
                 all_file: str = 'all.txt',
                 out_file: str = 'out.txt',
                 stat_file: str = 'stat.txt',
                 top500_file: str = '500.txt',
                 speed_threshold: float = 800.0,
                 download_timeout: int = 10,
                 check_timeout: int = 5,           # УВЕЛИЧЕНО
                 tcp_timeout: int = 3,              # УВЕЛИЧЕНО
                 download_workers: int = 10,
                 check_workers: int = 50):
        
        self.sources_file = sources_file
        self.list_file = list_file
        self.all_file = all_file
        self.out_file = out_file
        self.stat_file = stat_file
        self.top500_file = top500_file
        self.speed_threshold = speed_threshold
        self.download_timeout = download_timeout
        self.check_timeout = check_timeout
        self.tcp_timeout = tcp_timeout
        self.download_workers = download_workers
        self.check_workers = check_workers
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
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
                
                return url, configs
                
        except Exception as e:
            logger.warning(f"⚠️ Ошибка загрузки {url}: {e}")
            return url, []
    
    def step1_collect_all(self) -> Dict[str, List[str]]:
        """ШАГ 1: Собирает все сервера в list.txt."""
        print("\n" + "="*70)
        print("🔍 ШАГ 1: СБОР ВСЕХ СЕРВЕРОВ В list.txt")
        print("="*70")
        
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
    
    def is_valid_config(self, config: str) -> Tuple[bool, str, int]:
        """Проверяет валидность конфига."""
        try:
            after_at = config.split('@')[1]
            host_part = after_at.split('?')[0]
            
            if ':' in host_part:
                host, port_str = host_part.split(':')[:2]
                port = int(port_str)
            else:
                host = host_part
                port = 443
            
            return True, host, port
            
        except:
            return False, "", 0
    
    def get_config_key(self, config: str) -> str:
        """Ключ для сравнения дубликатов (без тега)."""
        return config.split('#')[0] if '#' in config else config
    
    def normalize_config(self, config: str, speed: float) -> str:
        """Исправляет &; на &, остальное без изменений."""
        return config.replace('&;', '&')
    
    def check_single(self, config: str, host: str, port: int, source_url: str) -> Tuple[Optional[str], Optional[float], str]:
        """Проверяет один конфиг."""
        
        # TCP проверка
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.tcp_timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result != 0:
                return None, None, source_url
        except:
            return None, None, source_url
        
        # Пробуем HTTP и HTTPS
        for protocol in ['http', 'https']:
            test_url = f"{protocol}://{host}:{port}/generate_204"
            try:
                start = time.time()
                req = urllib.request.Request(
                    test_url,
                    method='HEAD',
                    headers={'User-Agent': self.user_agent, 'Host': host}
                )
                
                if protocol == 'https':
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(req, timeout=self.check_timeout, context=context) as resp:
                        elapsed = (time.time() - start) * 1000
                else:
                    with urllib.request.urlopen(req, timeout=self.check_timeout) as resp:
                        elapsed = (time.time() - start) * 1000
                
                if resp.status == 204:
                    return self.normalize_config(config, elapsed), elapsed, source_url
            except:
                continue
        
        return None, None, source_url
    
    def step2_check_all(self, sources_data: Dict[str, List[str]]) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, List[str]]]:
        """ШАГ 2: Проверяет все сервера без разделения."""
        print("\n" + "="*70)
        print("⚡ ШАГ 2: ПРОВЕРКА СЕРВЕРОВ")
        print("="*70)
        
        if not os.path.exists(self.list_file):
            return {}, {}, {}
        
        # Читаем list.txt
        source_configs = defaultdict(list)
        current_source = None
        
        with open(self.list_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('# ИСТОЧНИК:'):
                    current_source = line.replace('# ИСТОЧНИК:', '').strip()
                elif line and not line.startswith('#') and current_source:
                    source_configs[current_source].append(line)
        
        # Собираем все конфиги
        all_items = []
        source_totals = defaultdict(int)
        
        for source_url, configs in source_configs.items():
            for config in configs:
                is_valid, host, port = self.is_valid_config(config)
                if is_valid:
                    all_items.append((source_url, config, host, port))
                    source_totals[source_url] += 1
        
        logger.info(f"🌍 Найдено серверов: {len(all_items)}")
        
        if not all_items:
            return {}, {}, source_configs
        
        logger.info(f"🚀 Запуск проверки ({self.check_workers} потоков, TCP={self.tcp_timeout}c, HTTP/HTTPS={self.check_timeout}c)...")
        
        # Проверка
        working_all = {}
        working_fast = {}
        source_passed = defaultdict(int)
        source_pings = defaultdict(list)
        
        start_time = time.time()
        checked = 0
        
        with ThreadPoolExecutor(max_workers=self.check_workers) as executor:
            future_to_item = {
                executor.submit(self.check_single, config, host, port, source_url): (source_url, config, host, port)
                for source_url, config, host, port in all_items
            }
            
            for future in as_completed(future_to_item):
                source_url, config, host, port = future_to_item[future]
                result_config, speed, _ = future.result()
                checked += 1
                
                if result_config:
                    working_all[result_config] = speed
                    if speed <= self.speed_threshold:
                        working_fast[result_config] = speed
                        source_passed[source_url] += 1
                        source_pings[source_url].append(speed)
                
                if checked % 100 == 0:
                    elapsed = time.time() - start_time
                    logger.info(f"  📊 Прогресс: {checked}/{len(all_items)} ({checked/elapsed:.1f} серв/сек)")
        
        # Статистика
        for source_url in source_totals:
            total = source_totals[source_url]
            passed = source_passed[source_url]
            pings = source_pings[source_url]
            avg_ping = sum(pings)/len(pings) if pings else 0
            self.source_stats[source_url] = {'total': total, 'passed': passed, 'avg_ping': avg_ping}
        
        elapsed = time.time() - start_time
        print("\n" + "="*70)
        print(f"✅ ПРОВЕРКА ЗАВЕРШЕНА:")
        print(f"   - Проверено: {len(all_items)}")
        print(f"   - Прошли ping: {len(working_all)}")
        print(f"   - Быстрых (<{self.speed_threshold}ms): {len(working_fast)}")
        print(f"   - Время: {elapsed:.1f} сек")
        print("="*70)
        
        return working_all, working_fast, source_configs
    
    def save_stats(self, working_fast: Dict[str, float], source_configs: Dict[str, List[str]]):
        """Сохраняет статистику."""
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n📊 СТАТИСТИКА\n" + "="*70 + "\n\n")
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Таймауты: TCP={self.tcp_timeout}c, HTTP/HTTPS={self.check_timeout}c\n\n")
            
            total_all = passed_all = 0
            for url, stats in sorted(self.source_stats.items(), key=lambda x: x[1]['passed']/x[1]['total'] if x[1]['total'] else 0, reverse=True):
                if stats['total']:
                    total_all += stats['total']
                    passed_all += stats['passed']
                    f.write(f"📌 {url}\n   Total: {stats['total']}\n   ✅ Ping passed: {stats['passed']} ({stats['passed']/stats['total']*100:.1f}%)\n   ⚡ Avg ping: {stats['avg_ping']:.0f}ms\n\n")
            
            f.write("="*70 + "\n📈 ОБЩАЯ СТАТИСТИКА\n" + "="*70 + f"\nВсего проверено: {total_all}\n✅ Прошли ping: {passed_all} ({passed_all/total_all*100:.1f}%)\n")
    
    def save_results(self, working_all: Dict[str, float], working_fast: Dict[str, float]):
        """Сохраняет all.txt, out.txt, 500.txt."""
        if working_all:
            unique = {}
            for c, s in working_all.items():
                k = self.get_config_key(c)
                if k not in unique or s < unique[k][1]:
                    unique[k] = (c, s)
            with open(self.all_file, 'w') as f:
                for c, _ in unique.values():
                    f.write(c + '\n')
            logger.info(f"✅ Сохранено {len(unique)} в all.txt")
        
        if working_fast:
            unique = {}
            for c, s in working_fast.items():
                k = self.get_config_key(c)
                if k not in unique or s < unique[k][1]:
                    unique[k] = (c, s)
            with open(self.out_file, 'w') as f:
                for c, _ in unique.values():
                    f.write(c + '\n')
            logger.info(f"✅ Сохранено {len(unique)} в out.txt")
            
            top = sorted(unique.values(), key=lambda x: x[1])[:500]
            with open(self.top500_file, 'w') as f:
                for c, _ in top:
                    f.write(c + '\n')
            logger.info(f"✅ Сохранено топ-{len(top)} в 500.txt")
    
    def run(self):
        """Основной процесс."""
        print("="*70)
        print("🚀 POWER v5.13")
        print("="*70)
        print("ФАЙЛЫ: sources.txt → list.txt → all.txt, out.txt, 500.txt, stat.txt")
        print(f"ТАЙМАУТЫ: TCP={self.tcp_timeout}c, HTTP/HTTPS={self.check_timeout}c")
        print("GeoIP: УДАЛЕН | trash: УДАЛЕН")
        print("="*70)
        
        start = time.time()
        sources = self.step1_collect_all()
        if sources:
            all_cfg, fast_cfg, src_cfg = self.step2_check_all(sources)
            self.save_results(all_cfg, fast_cfg)
            self.save_stats(fast_cfg, src_cfg)
        print(f"\n🎯 ГОТОВО! Время: {time.time()-start:.1f} сек")
        print("="*70)


if __name__ == "__main__":
    collector = VlessCollector()
    collector.run()
