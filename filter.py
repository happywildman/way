#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VLESS+Reality Collector v3.0
====================================
1. Сбор ВСЕХ vless подписок с GitHub → list.txt
2. Фильтр vless+reality:443 + тест 204 (только хорошие) → out.txt
3. Битые/медленные → trash.txt
4. Топ-500 лучших из out.txt → 500.txt
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
        # GitLab API поиска
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
                    for project in projects[:10]:  # Лимит 10 проектов
                        if 'vless' in project['name'].lower() or 'subscription' in project['name'].lower():
                            # Формируем ссылки на raw файлы
                            for ext in ['.txt', '.yaml', '.yml', '.json']:
                                raw_url = f"https://gitlab.com/{project['path_with_namespace']}/-/raw/main/sub{ext}"
                                self.found_subscriptions.add(raw_url)
                                raw_url = f"https://gitlab.com/{project['path_with_namespace']}/-/raw/master/config{ext}"
                                self.found_subscriptions.add(raw_url)
            except Exception as e:
                logger.debug(f"GitLab search error: {e}")
    
    def search_common_repos(self):
        """Поиск по известным репозиториям."""
        # Список известных репозиториев с подписками
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
                    
                    # Альтернативные имена файлов
                    url = f"https://raw.githubusercontent.com/{repo}/{branch}/v2ray{ext}"
                    self.found_subscriptions.add(url)
                    
                    url = f"https://raw.githubusercontent.com/{repo}/{branch}/config{ext}"
                    self.found_subscriptions.add(url)
    
    def search_code(self):
        """Поиск через GitHub code search (ограничено без токена)."""
        # Без токена GitHub ограничивает поиск, но попробуем базовые запросы
        search_queries = [
            'https://github.com/search?q=vless+extension:txt&type=Code',
            'https://github.com/search?q=reality+extension:txt&type=Code',
            'https://github.com/search?q=v2ray+subscription&type=Code'
        ]
        
        # Здесь нужен парсинг HTML, что сложно без токена
        # В реальном проекте лучше использовать GitHub API с токеном
    
    def crawl(self) -> List[str]:
        """Запуск поиска подписок на GitHub."""
        logger.info("Начинаю поиск vless подписок на GitHub...")
        
        self.search_common_repos()
        self.search_gitlab()
        # self.search_code()  # Закомментировано т.к. требует парсинга HTML
        
        # Добавляем известные публичные подписки (для примера)
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
                
                # Пробуем декодировать
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
        
        # Очищаем или создаем файл
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
            
            # Задержка между запросами
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
                 speed_threshold: float = 800.0):  # Хорошая скорость = до 800ms
        self.input_file = input_file
        self.out_file = out_file
        self.trash_file = trash_file
        self.speed_threshold = speed_threshold
        self.trash_servers = self._load_trash()
        self.timeout = 5
        self.user_agent = 'Mozilla/5.0'
        
    def _load_trash(self) -> Set[str]:
        """Загружает trash.txt."""
        trash = set()
        if os.path.exists(self.trash_file):
            with open(self.trash_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        trash.add(line)
        return trash
    
    def _save_to_trash(self, config: str, reason: str = ""):
        """Сохраняет битый/медленный сервер в trash."""
        if config not in self.trash_servers:
            self.trash_servers.add(config)
            with open(self.trash_file, 'a', encoding='utf-8') as f:
                f.write(f"{config} # {reason}\n")
    
    def extract_vless_from_file(self) -> List[str]:
        """Извлекает ВСЕ vless ссылки из list.txt."""
        if not os.path.exists(self.input_file):
            logger.error(f"{self.input_file} не найден")
            return []
        
        vless_pattern = r'vless://[a-f0-9-]+@[^#\s]+(?:#[^\s]*)?'
        all_vless = []
        
        with open(self.input_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Проверяем, не base64 ли весь файл
            if re.match(r'^[A-Za-z0-9+/=]+$', content[:100].replace('\n', '')):
                try:
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except:
                    pass
            
            # Ищем все vless ссылки
            found = re.findall(vless_pattern, content)
            all_vless.extend(found)
        
        # Убираем дубликаты
        unique_vless = list(set(all_vless))
        logger.info(f"Найдено {len(unique_vless)} уникальных vless ссылок в {self.input_file}")
        return unique_vless
    
    def is_reality_port443(self, config: str) -> Tuple[bool, str]:
        """Проверка vless+reality и порт 443, возвращает хост."""
        try:
            # Извлекаем параметры
            if 'security=reality' not in config and 'reality' not in config:
                return False, ""
            
            # Извлекаем хост и порт
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
            # Замеряем время
            start = time.time()
            
            req = urllib.request.Request(
                test_url,
                method='HEAD',
                headers={'User-Agent': self.user_agent, 'Host': host}
            )
            
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                elapsed = (time.time() - start) * 1000  # в ms
                
                if resp.status == 204:
                    return True, elapsed
                else:
                    return False, elapsed
        except Exception as e:
            return False, float('inf')
    
    def process(self) -> Dict[str, float]:
        """
        Обрабатывает list.txt:
        - фильтр vless+reality:443
        - тест 204 скорости
        - возвращает {config: speed_ms} для хороших
        """
        all_vless = self.extract_vless_from_file()
        
        # Фильтр 1: vless+reality:443
        candidates = []
        for config in all_vless:
            # Пропускаем если уже в trash
            if config in self.trash_servers:
                continue
                
            is_valid, host = self.is_reality_port443(config)
            if is_valid:
                candidates.append((config, host))
        
        logger.info(f"После фильтра reality:443 осталось {len(candidates)} кандидатов")
        
        # Тест 204 скорости
        good_configs = {}  # config -> speed_ms
        bad_configs = []   # для trash
        
        for i, (config, host) in enumerate(candidates, 1):
            logger.info(f"[{i}/{len(candidates)}] Тест {host}")
            
            is_working, speed = self.test_204_speed(host)
            
            if is_working and speed <= self.speed_threshold:
                good_configs[config] = speed
                logger.info(f"  ✅ {speed:.0f}ms (ХОРОШИЙ)")
            else:
                reason = f"битый" if not is_working else f"медленный {speed:.0f}ms"
                bad_configs.append((config, reason))
                logger.info(f"  ❌ {reason}")
        
        # Сохраняем битые/медленные в trash
        for config, reason in bad_configs:
            self._save_to_trash(config, reason)
        
        # Сортируем хорошие по скорости
        sorted_good = dict(sorted(good_configs.items(), key=lambda x: x[1]))
        
        # Сохраняем в out.txt (только хорошие)
        if sorted_good:
            with open(self.out_file, 'w', encoding='utf-8') as f:
                f.write(f"# VLESS+Reality:443 с хорошей скоростью (<={self.speed_threshold}ms)\n")
                f.write(f"# Проверено: {datetime.now().isoformat()}\n")
                f.write("#" + "="*50 + "\n\n")
                
                for config, speed in sorted_good.items():
                    # Добавляем скорость в тег
                    if '#' in config:
                        config = re.sub(r'#.*', f'#{speed:.0f}ms', config)
                    else:
                        config = f"{config}#{speed:.0f}ms"
                    f.write(config + '\n')
            
            logger.info(f"Сохранено {len(sorted_good)} хороших серверов в {self.out_file}")
        
        return sorted_good


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
        
        # Читаем все конфиги
        configs = []
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Извлекаем скорость из тега
                    speed_match = re.search(r'#(\d+)ms', line)
                    if speed_match:
                        speed = int(speed_match.group(1))
                        configs.append((line, speed))
        
        # Сортируем по скорости и берем топ
        configs.sort(key=lambda x: x[1])
        top_configs = configs[:top_n]
        
        # Сохраняем
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# ТОП-{top_n} лучших серверов из {input_file}\n")
            f.write(f"# Сформировано: {datetime.now().isoformat()}\n")
            f.write("#" + "="*50 + "\n\n")
            
            for i, (config, speed) in enumerate(top_configs, 1):
                f.write(f"#{i} {speed}ms\n")
                f.write(config + '\n\n')
        
        logger.info(f"Сохранено топ-{len(top_configs)} в {output_file}")


def main():
    """Главная функция."""
    print("="*70)
    print("VLESS+Reality COLLECTOR v3.0")
    print("="*70)
    print("1. Поиск подписок на GitHub → list.txt")
    print("2. Фильтр vless+reality:443 + тест 204 → out.txt (только хорошие)")
    print("3. Битые/медленные → trash.txt")
    print("4. Топ-500 лучших → 500.txt")
    print("="*70)
    
    # ШАГ 1: Поиск подписок на GitHub
    crawler = GitHubCrawler()
    subscription_urls = crawler.crawl()
    
    if subscription_urls:
        # ШАГ 2: Скачивание в list.txt
        downloader = SubscriptionDownloader()
        downloader.download_all(subscription_urls)
    else:
        logger.warning("Не найдено подписок на GitHub. Использую существующий list.txt если есть")
    
    # ШАГ 3: Обработка list.txt
    processor = VlessProcessor()
    good_configs = processor.process()
    
    # ШАГ 4: Формирование топ-500
    if good_configs:
        TopSelector.select_top()
    
    print("="*70)
    print("ГОТОВО!")
    print(f"- list.txt: сырые подписки с GitHub")
    print(f"- out.txt: {len(good_configs)} хороших серверов")
    print(f"- trash.txt: битые и медленные (чтобы не перепроверять)")
    print(f"- 500.txt: топ-500 лучших")
    print("="*70)


if __name__ == "__main__":
    main()
