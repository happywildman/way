#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VLESS+Reality Collector v4.0
====================================
Файл: filter.py

1. Чтение list.txt (СПИСОК RAW-ССЫЛОК на подписки)
2. Скачивание каждой подписки
3. Извлечение всех vless конфигов
4. Фильтр vless+reality:443 + тест 204
5. Сохранение результатов и статистики
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

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class VlessCollector:
    """Сборщик VLESS подписок из списка RAW-ссылок."""
    
    def __init__(self,
                 sources_file: str = 'list.txt',
                 out_file: str = 'out.txt',
                 trash_file: str = 'trash.txt',
                 stat_file: str = 'stat.txt',
                 top500_file: str = '500.txt',
                 speed_threshold: float = 800.0,
                 timeout: int = 10):
        
        self.sources_file = sources_file
        self.out_file = out_file
        self.trash_file = trash_file
        self.stat_file = stat_file
        self.top500_file = top500_file
        self.speed_threshold = speed_threshold
        self.timeout = timeout
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
        """Читает список RAW-ссылок из list.txt."""
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
    
    def fetch_subscription(self, url: str) -> Optional[str]:
        """Скачивает подписку по URL."""
        try:
            req = urllib.request.Request(url, headers={'User-Agent': self.user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read()
                
                # Пробуем декодировать
                try:
                    return content.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        return content.decode('latin-1')
                    except:
                        return content.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")
            return None
    
    def extract_vless_configs(self, content: str) -> List[str]:
        """Извлекает все vless ссылки из текста."""
        vless_pattern = r'vless://[a-f0-9-]+@[^#\s]+(?:#[^\s]*)?'
        
        # Проверяем, не base64 ли весь контент
        if re.match(r'^[A-Za-z0-9+/=]+$', content[:100].replace('\n', '')):
            try:
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except:
                pass
        
        return re.findall(vless_pattern, content)
    
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
    
    def test_204_speed(self, host: str) -> Tuple[bool, float]:
        """Тестирует скорость ответа 204."""
        test_url = f"http://{host}/generate_204"
        
        try:
            start = time.time()
            req = urllib.request.Request(
                test_url,
                method='HEAD',
                headers={'User-Agent': self.user_agent, 'Host': host}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                elapsed = (time.time() - start) * 1000
                return resp.status == 204, elapsed
        except Exception:
            return False, float('inf')
    
    def process_source(self, url: str) -> Dict[str, float]:
        """
        Обрабатывает один источник.
        Возвращает словарь {config: speed_ms} для рабочих конфигов.
        """
        logger.info(f"Обработка источника: {url}")
        
        content = self.fetch_subscription(url)
        if not content:
            self.source_stats[url] = {
                'total': 0,
                'passed': 0,
                'avg_ping': 0,
                'error': 'download_failed'
            }
            return {}
        
        # Извлекаем все vless конфиги
        all_configs = self.extract_vless_configs(content)
        logger.info(f"  Найдено vless конфигов: {len(all_configs)}")
        
        # Фильтруем reality:443 и проверяем
        working = {}
        total_valid = 0
        pings = []
        
        for config in all_configs:
            if config in self.trash_servers:
                continue
            
            is_valid, host = self.is_reality_port443(config)
            if not is_valid:
                continue
            
            total_valid += 1
            is_working, speed = self.test_204_speed(host)
            
            if is_working and speed <= self.speed_threshold:
                working[config] = speed
                pings.append(speed)
                logger.debug(f"    ✅ {host} - {speed:.0f}ms")
            else:
                reason = "битый" if not is_working else f"медленный {speed:.0f}ms"
                self._save_to_trash(config, reason)
                logger.debug(f"    ❌ {host} - {reason}")
        
        # Сохраняем статистику источника
        avg_ping = sum(pings) / len(pings) if pings else 0
        self.source_stats[url] = {
            'total': total_valid,
            'passed': len(working),
            'avg_ping': avg_ping
        }
        
        logger.info(f"  Прошло: {len(working)}/{total_valid} (avg {avg_ping:.0f}ms)")
        
        return working
    
    def save_stats(self, all_working: Dict[str, float]):
        """Сохраняет статистику в stat.txt."""
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ ПРОКСИ\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            total_all = 0
            passed_all = 0
            
            # Сортируем источники по проценту прохождения
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
    
    def save_top500(self, all_working: Dict[str, float]):
        """Сохраняет топ-500 лучших в 500.txt."""
        if not all_working:
            return
        
        # Сортируем по скорости
        sorted_configs = sorted(all_working.items(), key=lambda x: x[1])
        top_configs = sorted_configs[:500]
        
        with open(self.top500_file, 'w', encoding='utf-8') as f:
            f.write(f"# ТОП-500 лучших серверов\n")
            f.write(f"# Сформировано: {datetime.now().isoformat()}\n")
            f.write("#" + "="*50 + "\n\n")
            
            for i, (config, speed) in enumerate(top_configs, 1):
                # Добавляем скорость в тег
                if '#' in config:
                    config = re.sub(r'#.*', f'#{speed:.0f}ms', config)
                else:
                    config = f"{config}#{speed:.0f}ms"
                f.write(f"# {i:3d} | {speed:.0f}ms\n")
                f.write(config + '\n\n')
    
    def run(self):
        """Основной процесс."""
        print("="*70)
        print("VLESS+REALITY COLLECTOR v4.0")
        print("="*70)
        print("1. Чтение list.txt (RAW-ссылки на подписки)")
        print("2. Скачивание каждой подписки")
        print("3. Фильтр vless+reality:443 + тест 204")
        print("4. Сохранение результатов")
        print("="*70)
        
        # Читаем источники
        sources = self.read_sources()
        if not sources:
            logger.error("Нет источников для обработки")
            return
        
        # Словарь всех рабочих конфигов {config: speed}
        all_working = {}
        
        # Обрабатываем каждый источник
        for i, url in enumerate(sources, 1):
            logger.info(f"[{i}/{len(sources)}] Обработка источника")
            working = self.process_source(url)
            all_working.update(working)
            
            # Задержка между запросами
            if i < len(sources):
                time.sleep(2)
        
        # Убираем дубликаты (оставляем с наименьшим пингом)
        unique_working = {}
        for config, speed in all_working.items():
            if config not in unique_working or speed < unique_working[config]:
                unique_working[config] = speed
        
        # Сохраняем out.txt (все рабочие)
        if unique_working:
            with open(self.out_file, 'w', encoding='utf-8') as f:
                f.write(f"# VLESS+Reality:443 с хорошей скоростью (<={self.speed_threshold}ms)\n")
                f.write(f"# Проверено: {datetime.now().isoformat()}\n")
                f.write("#" + "="*50 + "\n\n")
                
                for config, speed in unique_working.items():
                    if '#' in config:
                        config = re.sub(r'#.*', f'#{speed:.0f}ms', config)
                    else:
                        config = f"{config}#{speed:.0f}ms"
                    f.write(config + '\n')
            
            logger.info(f"Сохранено {len(unique_working)} рабочих серверов в {self.out_file}")
        
        # Сохраняем статистику
        self.save_stats(unique_working)
        
        # Сохраняем топ-500
        self.save_top500(unique_working)
        
        # Итог
        print("="*70)
        print("ГОТОВО!")
        print(f"- Источников обработано: {len(sources)}")
        print(f"- Всего рабочих серверов: {len(unique_working)}")
        print(f"- out.txt: все рабочие")
        print(f"- 500.txt: топ-500 лучших")
        print(f"- stat.txt: статистика по источникам")
        print(f"- trash.txt: битые и медленные")
        print("="*70)


if __name__ == "__main__":
    collector = VlessCollector()
    collector.run()
