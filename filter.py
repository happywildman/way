#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VLESS+Reality Collector v3.1
====================================
Файл: filter.py
Структура: way/filter.py

1. Сбор ВСЕХ vless подписок с GitHub → list.txt
2. Фильтр vless+reality:443 + тест 204 (только хорошие) → out.txt
3. Битые/медленные → trash.txt
4. Топ-500 лучших из out.txt → 500.txt
5. Статистика → stat.txt
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

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class GitHubCrawler:
    """Сборщик vless подписок с GitHub."""
    
    GITHUB_RAW_PATTERNS = [
        'https://raw.githubusercontent.com/{repo}/main/{path}',
        'https://raw.githubusercontent.com/{repo}/master/{path}',
        'https://github.com/{repo}/raw/main/{path}',
        'https://github.com/{repo}/raw/master/{path}'
    ]
    
    def __init__(self, timeout: int = 10, user_agent: str = 'Mozilla/5.0'):
        self.timeout = timeout
        self.user_agent = user_agent
        self.found_subscriptions: Set[str] = set()
        
    def search_gitlab(self):
        """Поиск по GitLab (альтернативный источник)."""
        gitlab_search_urls = [
            'https://gitlab.com/api/v4/projects?search=vless',
            'https://gitlab.com/api/v4/projects?search=reality',
            'https://gitlab.com/api/v4/projects?search=subscription'
        ]
        
        for url in gitlab_search_urls:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    projects = json.loads(response.read())
                    for project in projects[:10]:
                        if 'vless' in project['name'].lower() or 'subscription' in project['name'].lower():
                            for ext in ['.txt', '.yaml', '.yml', '.json']:
                                raw_url = f"https://gitlab.com/{project['path_with_namespace']}/-/raw/main/sub{ext}"
                                self.found_subscriptions.add(raw_url)
                                raw_url = f"https://gitlab.com/{project['path_with_namespace']}/-/raw/master/config{ext}"
                                self.found_subscriptions.add(raw_url)
            except Exception as e:
                logger.debug(f"GitLab search error: {e}")
    
    def search_common_repos(self):
        """Поиск по известным репозиториям."""
        known_repos = [
            ('v2ray-config', 'vless'),
            ('v2ray-subscription', 'main'),
            ('v2ray-configs', 'master'),
            ('free-v2ray', 'main'),
            ('v2ray-collector', 'master'),
            ('vless-reality', 'main'),
            ('v2ray-sub', 'master'),
            ('v2ray-config-list', 'main')
        ]
        
        keywords = ['sub', 'vless', 'config', 'subscription', 'v2ray', 'reality']
        extensions = ['.txt', '.yaml', '.yml', '.json']
        
        for repo, branch in known_repos:
            for keyword in keywords:
                for ext in extensions:
                    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{keyword}{ext}"
                    self.found_subscriptions.add(url)
                    url = f"https://raw.githubusercontent.com/{repo}/{branch}/v2ray{ext}"
                    self.found_subscriptions.add(url)
                    url = f"https://raw.githubusercontent.com/{repo}/{branch}/config{ext}"
                    self.found_subscriptions.add(url)
    
    def crawl(self) -> List[str]:
        """Запуск поиска подписок на GitHub."""
        logger.info("Начинаю поиск vless подписок на GitHub...")
        
        self.search_common_repos()
        self.search_gitlab()
        
        public_subs = [
            'https://raw.githubusercontent.com/v2ray-config/v2ray-config/main/vless.txt',
            'https://raw.githubusercontent.com/free-v2ray-config/free-v2ray-config/main/sub.txt',
            'https://raw.githubusercontent.com/v2ray-subscription/v2ray-subscription/master/config.txt'
        ]
        self.found_subscriptions.update(public_subs)
        
        logger.info(f"Найдено {len(self.found_subscriptions)} потенциальных подписок")
        return list(self.found_subscriptions)


class SubscriptionDownloader:
    """Скачивание подписок в list.txt."""
    
    def __init__(self, output_file: str = 'list.txt', timeout: int = 10):
        self.output_file = output_file
        self.timeout = timeout
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
    def download_subscription(self, url: str) -> Optional[str]:
        """Скачивает одну подписку."""
        try:
            req = urllib.request.Request(url, headers={'User-Agent': self.user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read()
                
                try:
                    return content.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        return content.decode('latin-1')
                    except:
                        return content.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Не удалось скачать {url}: {e}")
            return None
    
    def download_all(self, urls: List[str]) -> int:
        """Скачивает все найденные подписки в list.txt."""
        downloaded = 0
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Сырые vless подписки с GitHub\n")
            f.write(f"# Собрано: {datetime.now().isoformat()}\n")
            f.write("#" + "="*50 + "\n\n")
        
        for i, url in enumerate(urls, 1):
            logger.info(f"[{i}/{len(urls)}] Скачиваю: {url}")
            
            content = self.download_subscription(url)
            if content:
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n# ИСТОЧНИК: {url}\n")
                    f.write(content)
                    if not content.endswith('\n'):
                        f.write('\n')
                    f.write("\n" + "#"*50 + "\n")
                downloaded += 1
            
            if i < len(urls):
                time.sleep(2)
        
        logger.info(f"Скачано {downloaded} подписок в {self.output_file}")
        return downloaded


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
        
        # Статистика
        self.stats = {
            'timestamp': datetime.now().isoformat(),
            'total_vless_found': 0,
            'reality_port443': 0,
            'tested': 0,
            'good': 0,
            'bad': 0,
            'slow': 0,
            'avg_speed_good': 0,
            'min_speed_good': 0,
            'max_speed_good': 0,
            'threshold_ms': speed_threshold
        }
        
    def _load_trash(self) -> Set[str]:
        """Загружает trash.txt."""
        trash = set()
        if os.path.exists(self.trash_file):
            with open(self.trash_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Убираем комментарии после ссылки
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
    
    def _save_stats(self):
        """Сохраняет статистику в stat.txt."""
        with open(self.stat_file, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("СТАТИСТИКА VLESS+REALITY COLLECTOR\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Время проверки: {self.stats['timestamp']}\n")
            f.write(f"Порог скорости: {self.stats['threshold_ms']}ms\n\n")
            
            f.write(f"Всего vless ссылок найдено: {self.stats['total_vless_found']}\n")
            f.write(f"Из них reality:443: {self.stats['reality_port443']}\n")
            f.write(f"Протестировано: {self.stats['tested']}\n")
            f.write(f"  ✅ Хороших: {self.stats['good']}\n")
            f.write(f"  ❌ Битых: {self.stats['bad']}\n")
            f.write(f"  ⚠ Медленных (>={self.stats['threshold_ms']}ms): {self.stats['slow']}\n\n")
            
            if self.stats['good'] > 0:
                f.write(f"Средняя скорость хороших: {self.stats['avg_speed_good']:.0f}ms\n")
                f.write(f"Минимальная: {self.stats['min_speed_good']:.0f}ms\n")
                f.write(f"Максимальная: {self.stats['max_speed_good']:.0f}ms\n")
    
    def extract_vless_from_file(self) -> List[str]:
        """Извлекает ВСЕ vless ссылки из list.txt."""
        if not os.path.exists(self.input_file):
            logger.error(f"{self.input_file} не найден")
            return []
        
        vless_pattern = r'vless://[a-f0-9-]+@[^#\s]+(?:#[^\s]*)?'
        all_vless = []
        
        with open(self.input_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            if re.match(r'^[A-Za-z0-9+/=]+$', content[:100].replace('\n', '')):
                try:
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except:
                    pass
            
            found = re.findall(vless_pattern, content)
            all_vless.extend(found)
        
        unique_vless = list(set(all_vless))
        self.stats['total_vless_found'] = len(unique_vless)
        logger.info(f"Найдено {len(unique_vless)} уникальных vless ссылок в {self.input_file}")
        return unique_vless
    
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
    
    def process(self) -> Dict[str, float]:
        """Обрабатывает list.txt и возвращает хорошие конфиги."""
        all_vless = self.extract_vless_from_file()
        
        # Фильтр reality:443
        candidates = []
        for config in all_vless:
            if config in self.trash_servers:
                continue
                
            is_valid, host = self.is_reality_port443(config)
            if is_valid:
                candidates.append((config, host))
        
        self.stats['reality_port443'] = len(candidates)
        logger.info(f"После фильтра reality:443 осталось {len(candidates)} кандидатов")
        
        # Тест скорости
        good_configs = {}
        speeds = []
        bad_count = 0
        slow_count = 0
        
        for i, (config, host) in enumerate(candidates, 1):
            logger.info(f"[{i}/{len(candidates)}] Тест {host}")
            
            is_working, speed = self.test_204_speed(host)
            self.stats['tested'] += 1
            
            if is_working:
                if speed <= self.speed_threshold:
                    good_configs[config] = speed
                    speeds.append(speed)
                    logger.info(f"  ✅ {speed:.0f}ms (ХОРОШИЙ)")
                else:
                    slow_count += 1
                    self._save_to_trash(config, f"медленный {speed:.0f}ms")
                    logger.info(f"  ⚠ {speed:.0f}ms (МЕДЛЕННЫЙ)")
            else:
                bad_count += 1
                self._save_to_trash(config, "битый")
                logger.info(f"  ❌ БИТЫЙ")
        
        self.stats['good'] = len(good_configs)
        self.stats['bad'] = bad_count
        self.stats['slow'] = slow_count
        
        if speeds:
            self.stats['avg_speed_good'] = sum(speeds) / len(speeds)
            self.stats['min_speed_good'] = min(speeds)
            self.stats['max_speed_good'] = max(speeds)
        
        # Сохраняем хорошие в out.txt
        if good_configs:
            sorted_good = dict(sorted(good_configs.items(), key=lambda x: x[1]))
            
            with open(self.out_file, 'w', encoding='utf-8') as f:
                f.write(f"# VLESS+Reality:443 с хорошей скоростью (<={self.speed_threshold}ms)\n")
                f.write(f"# Проверено: {datetime.now().isoformat()}\n")
                f.write("#" + "="*50 + "\n\n")
                
                for config, speed in sorted_good.items():
                    if '#' in config:
                        config = re.sub(r'#.*', f'#{speed:.0f}ms', config)
                    else:
                        config = f"{config}#{speed:.0f}ms"
                    f.write(config + '\n')
            
            logger.info(f"Сохранено {len(sorted_good)} хороших серверов в {self.out_file}")
        
        # Сохраняем статистику
        self._save_stats()
        
        return good_configs


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
                    speed_match = re.search(r'#(\d+)ms', line)
                    if speed_match:
                        speed = int(speed_match.group(1))
                        configs.append((line, speed))
        
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
    print("VLESS+REALITY COLLECTOR v3.1")
    print("="*70)
    print("Файл: filter.py")
    print("Структура: way/filter.py")
    print("-"*70)
    print("1. Поиск подписок на GitHub → list.txt")
    print("2. Фильтр vless+reality:443 + тест 204 → out.txt (только хорошие)")
    print("3. Битые/медленные → trash.txt")
    print("4. Топ-500 лучших → 500.txt")
    print("5. Статистика → stat.txt")
    print("="*70)
    
    # ШАГ 1: Поиск подписок на GitHub
    crawler = GitHubCrawler()
    subscription_urls = crawler.crawl()
    
    if subscription_urls:
        downloader = SubscriptionDownloader()
        downloader.download_all(subscription_urls)
    else:
        logger.warning("Не найдено подписок на GitHub. Использую существующий list.txt если есть")
    
    # ШАГ 2: Обработка list.txt
    processor = VlessProcessor()
    good_configs = processor.process()
    
    # ШАГ 3: Формирование топ-500
    if good_configs:
        TopSelector.select_top()
    
    print("="*70)
    print("ГОТОВО!")
    print(f"- list.txt: сырые подписки с GitHub")
    print(f"- out.txt: {len(good_configs)} хороших серверов")
    print(f"- trash.txt: битые и медленные")
    print(f"- 500.txt: топ-500 лучших")
    print(f"- stat.txt: статистика")
    print("="*70)


if __name__ == "__main__":
    main()
