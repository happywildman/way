#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VLESS+Reality Collector v3.2
====================================
Файл: filter.py
Структура: way/filter.py

1. Чтение list.txt (сырые подписки)
2. Фильтр vless+reality:443 + тест 204 (только хорошие) → out.txt
3. Битые/медленные → trash.txt
4. Топ-500 лучших из out.txt → 500.txt
5. Детальная статистика по каждому источнику → stat.txt (с эмодзи)
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
from urllib.parse import urlparse, quote
import socket
from collections import defaultdict

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class StatsManager:
    """Управление статистикой по источникам между запусками."""
    
    def __init__(self, history_file: str = 'stats_history.json'):
        self.history_file = history_file
        self.stats = self._load_history()
    
    def _load_history(self) -> Dict:
        """Загружает историю статистики из JSON."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_history(self):
        """Сохраняет историю статистики в JSON."""
        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2, ensure_ascii=False)
    
    def update_source_stats(self, source_url: str, total: int, passed: int, avg_ping: float):
        """Обновляет статистику для одного источника."""
        if source_url not in self.stats:
            self.stats[source_url] = []
        
        # Добавляем новую запись
        self.stats[source_url].append({
            'timestamp': datetime.now().isoformat(),
            'total': total,
            'passed': passed,
            'avg_ping': round(avg_ping, 1) if avg_ping > 0 else 0
        })
        
        # Оставляем только последние 30 записей (месяц при ежедневном запуске)
        if len(self.stats[source_url]) > 30:
            self.stats[source_url] = self.stats[source_url][-30:]
        
        self._save_history()
    
    def get_last_stats(self, source_url: str) -> Optional[Dict]:
        """Возвращает последнюю статистику для источника."""
        if source_url in self.stats and self.stats[source_url]:
            return self.stats[source_url][-1]
        return None


class VlessProcessor:
    """Обработка list.txt: фильтр vless+reality:443 + тест 204."""
    
    def __init__(self, 
                 input_file: str = 'list.txt',
                 out_file: str = 'out.txt',
                 trash_file: str = 'trash.txt',
                 stat_file: str = 'stat.txt',
                 speed_threshold: float = 800.0):
        self.input_file = input_file
        self.out_file = out_file
        self.trash_file = trash_file
        self.stat_file = stat_file
        self.speed_threshold = speed_threshold
        self.trash_servers = self._load_trash()
        self.timeout = 5
        self.user_agent = 'Mozilla/5.0'
        
        # Менеджер статистики
        self.stats_manager = StatsManager()
        
        # Статистика по источникам для текущего запуска
        self.source_stats = defaultdict(lambda: {'total': 0, 'passed': 0, 'pings': []})
        
    def _load_trash(self) -> Set[str]:
        """Загружает trash.txt."""
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
    
    def _extract_source_url(self, content_block: str) -> Optional[str]:
        """Извлекает URL источника из комментария в list.txt."""
        match = re.search(r'# ИСТОЧНИК:\s*(.+)', content_block)
        return match.group(1) if match else None
    
    def parse_list_file(self) -> Dict[str, List[str]]:
        """
        Парсит list.txt, возвращает словарь {источник: [конфиги]}.
        Учитывает разделители между источниками.
        """
        if not os.path.exists(self.input_file):
            logger.error(f"{self.input_file} не найден")
            return {}
        
        with open(self.input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Разделяем по блокам источников (разделитель "#"*50)
        blocks = re.split(r'#{50,}', content)
        
        sources = {}
        vless_pattern = r'vless://[a-f0-9-]+@[^#\s]+(?:#[^\s]*)?'
        
        for block in blocks:
            if not block.strip():
                continue
            
            # Извлекаем URL источника из первой строки блока
            source_url = self._extract_source_url(block)
            
            # Ищем все vless ссылки в блоке
            configs = re.findall(vless_pattern, block)
            
            if source_url and configs:
                sources[source_url] = list(set(configs))  # уникальные
                logger.debug(f"Источник {source_url}: {len(configs)} конфигов")
        
        logger.info(f"Найдено {len(sources)} источников в {self.input_file}")
        return sources
    
    def is_reality_port443(self, config: str) -> Tuple[bool, str]:
        """Проверка vless+reality и порт 443, возвращает хост."""
        try:
            if 'security=reality' not in config and 'reality' not in config:
                return False, ""
            
            after_at = config.split('@')[1]
            host_part = after_at.split('?')[0]
            
            if ':' in host_part:
                host, port = host_part.split(':')[:2]
                return port == '443', host
            else:
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
                
                if resp.status == 204:
                    return True, elapsed
                else:
                    return False, elapsed
        except Exception as e:
            return False, float('inf')
    
    def process_source(self, source_url: str, configs: List[str]) -> List[str]:
        """
        Обрабатывает один источник:
        - фильтр reality:443
        - тест скорости
        - собирает статистику
        Возвращает список рабочих конфигов из этого источника.
        """
        working = []
        
        # Собираем статистику по источнику
        source_total = 0
        source_passed = 0
        source_pings = []
        
        for config in configs:
            # Пропускаем если уже в trash
            if config in self.trash_servers:
                continue
            
            # Проверка reality:443
            is_valid, host = self.is_reality_port443(config)
            if not is_valid:
                continue
            
            source_total += 1
            
            # Тест скорости
            is_working, speed = self.test_204_speed(host)
            
            if is_working and speed <= self.speed_threshold:
                working.append(config)
                source_passed += 1
                source_pings.append(speed)
                logger.debug(f"  ✅ {host} - {speed:.0f}ms")
            else:
                reason = "битый" if not is_working else f"медленный {speed:.0f}ms"
                self._save_to_trash(config, reason)
                logger.debug(f"  ❌ {host} - {reason}")
        
        # Сохраняем статистику источника
        avg_ping = sum(source_pings) / len(source_pings) if source_pings else 0
        self.source_stats[source_url] = {
            'total': source_total,
            'passed': source_passed,
            'avg_ping': avg_ping
        }
        
        # Обновляем историю
        self.stats_manager.update_source_stats(source_url, source_total, source_passed, avg_ping)
        
        logger.info(f"Источник {source_url}: {source_passed}/{source_total} прошли (avg {avg_ping:.0f}ms)")
        
        return working
    
    def _save_stats(self, all_working: List[str]):
        """Сохраняет статистику в stat.txt в формате с эмодзи."""
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ ПРОКСИ\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            total_all = 0
            passed_all = 0
            
            # Сортируем источники по проценту прошедших (для удобства)
            sorted_sources = sorted(
                self.source_stats.items(),
                key=lambda x: (x[1]['passed'] / x[1]['total']) if x[1]['total'] > 0 else 0,
                reverse=True
            )
            
            for source_url, stats in sorted_sources:
                total = stats['total']
                passed = stats['passed']
                avg_ping = stats['avg_ping']
                
                if total == 0:
                    continue
                
                percent = (passed / total * 100) if total > 0 else 0
                total_all += total
                passed_all += passed
                
                f.write(f"📌 {source_url}\n")
                f.write(f"   Total: {total}\n")
                f.write(f"   ✅ Ping passed: {passed} ({percent:.1f}%)\n")
                f.write(f"   ⚡ Avg ping: {avg_ping:.0f}ms\n\n")
            
            f.write("="*60 + "\n")
            f.write("📈 ОБЩАЯ СТАТИСТИКА\n")
            f.write("="*60 + "\n")
            
            total_percent = (passed_all / total_all * 100) if total_all > 0 else 0
            f.write(f"Всего прокси: {total_all}\n")
            f.write(f"✅ Прошли ping: {passed_all} ({total_percent:.1f}%)\n")
            
            # Информация о лучших источниках
            if self.source_stats:
                best_source = max(
                    self.source_stats.items(),
                    key=lambda x: (x[1]['passed'] / x[1]['total']) if x[1]['total'] > 0 else 0
                )
                best_url, best_stats = best_source
                best_percent = (best_stats['passed'] / best_stats['total'] * 100) if best_stats['total'] > 0 else 0
                
                f.write(f"\n🏆 Лучший источник: {best_percent:.1f}% прохождения\n")
                f.write(f"   {best_url}\n")
        
        logger.info(f"Статистика сохранена в {self.stat_file}")
    
    def process(self) -> List[str]:
        """
        Основной процесс обработки.
        Возвращает список всех рабочих конфигов.
        """
        # Парсим list.txt по источникам
        sources = self.parse_list_file()
        if not sources:
            logger.error("Нет источников для обработки")
            return []
        
        all_working = []
        
        # Обрабатываем каждый источник
        for source_url, configs in sources.items():
            logger.info(f"Обработка источника: {source_url}")
            working = self.process_source(source_url, configs)
            all_working.extend(working)
        
        # Убираем дубликаты между источниками
        all_working = list(set(all_working))
        
        # Сохраняем out.txt (все рабочие)
        if all_working:
            # Сортируем по скорости (нужно будет извлечь из тегов)
            with open(self.out_file, 'w', encoding='utf-8') as f:
                f.write(f"# VLESS+Reality:443 с хорошей скоростью (<={self.speed_threshold}ms)\n")
                f.write(f"# Проверено: {datetime.now().isoformat()}\n")
                f.write("#" + "="*50 + "\n\n")
                
                for config in all_working:
                    f.write(config + '\n')
            
            logger.info(f"Сохранено {len(all_working)} рабочих серверов в {self.out_file}")
        
        # Сохраняем статистику
        self._save_stats(all_working)
        
        return all_working


class TopSelector:
    """Отбор топ-500 из out.txt в 500.txt."""
    
    @staticmethod
    def select_top(input_file: str = 'out.txt', 
                   output_file: str = '500.txt',
                   top_n: int = 500):
        """Берет топ-N самых быстрых из out.txt."""
        if not os.path.exists(input_file):
            logger.error(f"{input_file} не найден")
            return
        
        configs = []
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Извлекаем скорость из тега (если есть)
                    speed_match = re.search(r'#(\d+)ms', line)
                    if speed_match:
                        speed = int(speed_match.group(1))
                        configs.append((line, speed))
        
        # Сортируем по скорости
        configs.sort(key=lambda x: x[1])
        top_configs = configs[:top_n]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# ТОП-{top_n} лучших серверов из {input_file}\n")
            f.write(f"# Сформировано: {datetime.now().isoformat()}\n")
            f.write("#" + "="*50 + "\n\n")
            
            for i, (config, speed) in enumerate(top_configs, 1):
                f.write(f"# {i:3d} | {speed}ms\n")
                f.write(config + '\n\n')
        
        logger.info(f"Сохранено топ-{len(top_configs)} в {output_file}")


def main():
    """Главная функция."""
    print("="*70)
    print("VLESS+REALITY COLLECTOR v3.2")
    print("="*70)
    print("Файл: filter.py")
    print("Структура: way/filter.py")
    print("-"*70)
    print("1. Чтение list.txt (сырые подписки)")
    print("2. Фильтр vless+reality:443 + тест 204 → out.txt")
    print("3. Битые/медленные → trash.txt")
    print("4. Топ-500 лучших → 500.txt")
    print("5. Детальная статистика по источникам → stat.txt (с эмодзи)")
    print("="*70)
    
    # Проверяем наличие list.txt
    if not os.path.exists('list.txt'):
        logger.error("Файл list.txt не найден!")
        return
    
    # Обработка
    processor = VlessProcessor()
    working_configs = processor.process()
    
    # Формирование топ-500
    if working_configs:
        TopSelector.select_top()
    
    print("="*70)
    print("ГОТОВО!")
    print(f"- list.txt: сырые подписки ({len(processor.parse_list_file())} источников)")
    print(f"- out.txt: {len(working_configs)} хороших серверов")
    print(f"- trash.txt: битые и медленные")
    print(f"- 500.txt: топ-500 лучших")
    print(f"- stat.txt: детальная статистика по источникам")
    print(f"- stats_history.json: история статистики (для анализа динамики)")
    print("="*70)


if __name__ == "__main__":
    main()
