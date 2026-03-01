#!/usr/bin/env python3
"""
Filter - извлекает прокси определённого типа из YAML подписок
Вход: файл 'list.txt' со списком URL YAML подписок (по одному на строку)
Выход: out.yaml с отфильтрованными прокси
"""

import yaml
import requests
import sys
import os
from typing import List, Dict, Any

# Версия: 1.1
# Изменения: переименование выходного файла в out.yaml, удаление упоминаний Reality из комментариев

def fetch_yaml(url: str) -> Dict[str, Any]:
    """Скачивает и парсит YAML подписку"""
    try:
        print(f"📥 Загрузка: {url}")
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return yaml.safe_load(resp.text)
    except Exception as e:
        print(f"❌ Ошибка загрузки {url}: {e}")
        return {}

def is_target_proxy(proxy: Dict[str, Any]) -> bool:
    """Проверяет, подходит ли прокси под критерии отбора"""
    if proxy.get('type') != 'vless':
        return False
    if proxy.get('port') != 443:
        return False
    
    # Проверяем наличие специфических параметров
    if 'reality-opts' in proxy:
        opts = proxy['reality-opts']
        if opts.get('public-key') and opts.get('short-id'):
            return True
    
    # Альтернативная проверка
    if proxy.get('reality', False):
        return True
    
    return False

def read_list_file(list_file: str = "list.txt") -> List[str]:
    """
    Читает список подписок из файла.
    Поддерживает:
    - Пустые строки
    - Комментарии (строки, начинающиеся с #)
    """
    sources = []
    
    if not os.path.exists(list_file):
        print(f"❌ Файл '{list_file}' не найден!")
        return []
    
    try:
        with open(list_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Пропускаем пустые строки и комментарии
                if not line or line.startswith('#'):
                    continue
                # Проверяем, что строка похожа на URL
                if line.startswith(('http://', 'https://')):
                    sources.append(line)
                else:
                    print(f"⚠️  Строка {line_num} пропущена (не похоже на URL): {line[:50]}")
    except Exception as e:
        print(f"❌ Ошибка чтения файла {list_file}: {e}")
        return []
    
    return sources

def process_sources(list_file: str = "list.txt"):
    """Основная функция"""
    
    # Читаем список подписок
    sources = read_list_file(list_file)
    
    if not sources:
        print("❌ Нет URL для обработки!")
        print(f"Создайте файл '{list_file}' со списком подписок (по одной на строку)")
        return
    
    print(f"🔍 Найдено {len(sources)} источников\n")
    
    all_proxies = []
    
    for i, url in enumerate(sources, 1):
        print(f"[{i}/{len(sources)}] ", end="")
        data = fetch_yaml(url)
        if not data or 'proxies' not in data:
            continue
        
        # Фильтруем подходящие прокси
        found = 0
        for proxy in data['proxies']:
            if is_target_proxy(proxy):
                # Очищаем имя от мусора
                if 'name' in proxy:
                    name = proxy['name']
                    if len(name) > 2 and name[0] in '🇺🇸🇨🇾🇩🇪🇫🇷':
                        proxy['name'] = name[2:].strip()
                all_proxies.append(proxy)
                found += 1
        
        print(f"  Найдено подходящих: {found} (всего: {len(all_proxies)})")
    
    # Сохраняем результат
    if all_proxies:
        output = {'proxies': all_proxies}
        with open('out.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(output, f, allow_unicode=True, sort_keys=False)
        print(f"\n✅ Сохранено {len(all_proxies)} прокси в out.yaml")
    else:
        print("\n❌ Подходящие прокси не найдены")

if __name__ == "__main__":
    # Можно указать другой файл как аргумент командной строки
    if len(sys.argv) > 1:
        list_file = sys.argv[1]
    else:
        list_file = "list.txt"
    
    process_sources(list_file)
