#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Power v5.7
====================================
Файловая структура:
- sources.txt  → список RAW-ссылок на подписки
- list.txt     → сырые непроверенные сервера
- out.txt      → проверенные рабочие (только ссылки)
- trash.txt    → битые и медленные
- 500.txt      → топ-500 лучших (только ссылки)
- stat.txt     → статистика + анализ дубликатов
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
        
        # Маркеры защищённых соединений
        self.protected_markers = [
            'security=reality',
            'pbk=',           # публичный ключ reality
            'fp=',            # fingerprint
            'sni=',           # Server Name Indication
            'flow=xtls-rprx-vision',
            'type=grpc',
            'type=ws',
            'type=xhttp',
            'mode=gun',       # grpc
            'mode=multi',
            'mode=packet',
            'mode=quic',
            'serviceName=',   # grpc
            'extra='
        ]
        
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
                
                if re.match(r'^[A-Za-z0-9+/=]+$', text[:100].replace('\n', '')):
                    try:
                        text = base64.b64decode(text).decode('utf-8', errors='ignore')
                    except:
                        pass
                
                vless_pattern = r'vless://[a-f0-9-]+@[^#\s]+(?:#[^\s]*)?'
                configs = re.findall(vless_pattern, text)
                
                return url, configs
                
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")
            return url, []
    
    def step1_collect_all(self) -> Dict[str, List[str]]:
        """ШАГ 1: Собирает все сервера в list.txt."""
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
        
        with open(self.list_file, 'w', encoding='utf-8') as f:
            f.write(f"# СЫРЫЕ НЕПРОВЕРЕННЫЕ СЕРВЕРА\n")
            f.write(f"# Собрано из sources.txt: {datetime.now().isoformat()}\n")
            f.write("#" + "="*60 + "\n\n")
        
        with ThreadPoolExecutor(max_workers=self.download_workers) as executor:
            future_to_url = {executor.submit(self.download_subscription, url): url for url in sources}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url, configs = future.result()
                    results[url] = configs
                    
                    with open(self.list_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n# ИСТОЧНИК: {url}\n")
                        for config in configs:
                            f.write(config + '\n')
                        f.write("#" + "="*50 + "\n")
                    
                    logger.info(f"  ✓ {url}: {len(configs)} конфигов")
                    total_configs += len(configs)
                    
                except Exception as e:
                    logger.error(f"  ✗ Ошибка при обработке {url}: {e}")
                    results[url] = []
        
        if os.path.exists(self.list_file):
            file_size = os.path.getsize(self.list_file)
            logger.info(f"📁 {self.list_file} создан, размер: {file_size} байт")
        
        print("\n" + "="*60)
        print(f"✅ СБОР ЗАВЕРШЁН: {len(sources)} источников, {total_configs} серверов")
        print("="*60)
        
        return results
    
    def is_protected_config(self, config: str) -> Tuple[bool, str]:
        """Проверяет защищённый конфиг."""
        try:
            after_at = config.split('@')[1]
            host_part = after_at.split('?')[0]
            
            if ':' in host_part:
                host, port = host_part.split(':')[:2]
                if port != '443':
                    return False, ""
            else:
                return False, ""
            
            for marker in self.protected_markers:
                if marker in config:
                    return True, host
            
            return False, ""
        except:
            return False, ""
    
    def extract_original_name(self, config: str) -> str:
        """Извлекает оригинальное название сервера."""
        match = re.search(r'#([^#]+)$', config)
        return match.group(1).strip() if match else ""
    
    def normalize_config(self, config: str, speed: float) -> str:
        """Нормализует конфиг, сохраняя название."""
        config = config.replace('&;', '&')
        original_name = self.extract_original_name(config)
        
        if original_name:
            new_name = f"{speed}ms {original_name}"
            config = re.sub(r'#.*', f'#{new_name}', config)
        else:
            config = f"{config}#{speed}ms"
        
        return config
    
    def check_single(self, config: str, host: str, source_url: str) -> Tuple[Optional[str], Optional[float], str]:
        """Проверяет один конфиг."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, 443))
            sock.close()
            
            if result != 0:
                self._save_to_trash(config, "порт закрыт")
                return None, None, source_url
        except:
            self._save_to_trash(config, "TCP ошибка")
            return None, None, source_url
        
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
                        normalized = self.normalize_config(config, elapsed)
                        return normalized, elapsed, source_url
                    else:
                        self._save_to_trash(config, f"медленный {elapsed:.0f}ms")
                        return None, None, source_url
                else:
                    self._save_to_trash(config, f"код {resp.status}")
                    return None, None, source_url
        except:
            self._save_to_trash(config, "ошибка 204")
            return None, None, source_url
    
    def step2_check_all(self, sources_data: Dict[str, List[str]]) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        """ШАГ 2: Проверяет сервера из list.txt."""
        print("\n" + "="*60)
        print("⚡ ШАГ 2: ПРОВЕРКА СЕРВЕРОВ ИЗ list.txt")
        print("="*60)
        
        if not os.path.exists(self.list_file):
            logger.error(f"❌ Файл {self.list_file} не найден")
            return {}, {}
        
        file_size = os.path.getsize(self.list_file)
        if file_size == 0:
            logger.error(f"❌ Файл {self.list_file} пустой")
            return {}, {}
        
        logger.info(f"📁 {self.list_file} найден, размер: {file_size} байт")
        
        source_configs = defaultdict(list)
        current_source = None
        
        with open(self.list_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('# ИСТОЧНИК:'):
                    current_source = line.replace('# ИСТОЧНИК:', '').strip()
                elif line and not line.startswith('#') and current_source:
                    source_configs[current_source].append(line)
        
        all_items = []
        source_totals = defaultdict(int)
        
        for source_url, configs in source_configs.items():
            for config in configs:
                if config in self.trash_servers:
                    continue
                is_valid, host = self.is_protected_config(config)
                if is_valid:
                    all_items.append((source_url, config, host))
                    source_totals[source_url] += 1
        
        logger.info(f"Найдено {len(all_items)} защищённых конфигов")
        
        if not all_items:
            return {}, source_configs
        
        logger.info(f"Запуск проверки ({self.check_workers} потоков)...")
        
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
                    
                    if checked % 100 == 0:
                        elapsed = time.time() - start_time
                        speed_per_sec = checked / elapsed if elapsed > 0 else 0
                        logger.info(f"  Прогресс: {checked}/{len(all_items)} ({speed_per_sec:.1f} серв/сек)")
                        
                except Exception as e:
                    logger.debug(f"Ошибка при проверке {host}: {e}")
        
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
        
        elapsed = time.time() - start_time
        print("\n" + "="*60)
        print(f"✅ ПРОВЕРКА ЗАВЕРШЕНА: {len(working)} рабочих из {len(all_items)}")
        print(f"   Время: {elapsed:.1f} сек, скорость: {len(all_items)/elapsed:.1f} серв/сек")
        print("="*60)
        
        return working, source_configs
    
    def save_stats(self, working: Dict[str, float], source_configs: Dict[str, List[str]]):
        """Сохраняет статистику."""
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Таймауты: TCP=3c, HTTP=6c\n\n")
            
            total_all = 0
            passed_all = 0
            
            for url, stats in self.source_stats.items():
                if stats['total'] == 0:
                    continue
                total_all += stats['total']
                passed_all += stats['passed']
                percent = (stats['passed'] / stats['total'] * 100)
                f.write(f"📌 {url}\n")
                f.write(f"   Total: {stats['total']}\n")
                f.write(f"   ✅ Ping passed: {stats['passed']} ({percent:.1f}%)\n")
                f.write(f"   ⚡ Avg ping: {stats['avg_ping']:.0f}ms\n\n")
            
            f.write("="*60 + "\n")
            f.write("📈 ОБЩАЯ СТАТИСТИКА\n")
            f.write("="*60 + "\n")
            f.write(f"Всего защищённых прокси: {total_all}\n")
            f.write(f"✅ Прошли ping: {passed_all} ({(passed_all/total_all*100):.1f}%)\n\n")
    
    def save_results(self, working: Dict[str, float]):
        """Сохраняет out.txt и 500.txt (только ссылки)."""
        if working:
            with open(self.out_file, 'w', encoding='utf-8') as f:
                for config in working.keys():
                    f.write(config + '\n')
            logger.info(f"Сохранено {len(working)} серверов в {self.out_file}")
            
            unique_configs = {}
            for config, speed in working.items():
                base = re.sub(r'#.*', '', config)
                if base not in unique_configs or speed < unique_configs[base][1]:
                    unique_configs[base] = (config, speed)
            
            sorted_configs = sorted(unique_configs.values(), key=lambda x: x[1])
            top_configs = sorted_configs[:500]
            
            with open(self.top500_file, 'w', encoding='utf-8') as f:
                for config, _ in top_configs:
                    f.write(config + '\n')
            logger.info(f"Сохранено топ-500 в {self.top500_file}")
    
    def run(self):
        """Основной процесс."""
        print("="*70)
        print("🚀 POWER v5.7")
        print("="*70)
        
        start_total = time.time()
        sources_data = self.step1_collect_all()
        
        if not sources_data:
            return
        
        working, source_configs = self.step2_check_all(sources_data)
        self.save_results(working)
        self.save_stats(working, source_configs)
        
        total_time = time.time() - start_total
        print("\n" + "="*70)
        print(f"🎯 ГОТОВО! Время: {total_time:.1f} сек")
        print("="*70)


if __name__ == "__main__":
    collector = VlessCollector()
    collector.run()
