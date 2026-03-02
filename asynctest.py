#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Асинхронный модуль проверки через curl_cffi
============================================
Основан на реальных проектах:
- yebekhe/TelegramV2rayCollector
- onlysniper
- curl_cffi документация

Параметры (согласованы):
- URL: https://www.gstatic.com/generate_204
- Таймаут: 2.5 секунды
- Конкурентность: 50
- Impersonate: chrome110 (имитация браузера)
============================================
"""

import asyncio
from curl_cffi.requests import AsyncSession
import time
from typing import List, Tuple, Optional

# ===== СОГЛАСОВАННЫЕ ПАРАМЕТРЫ =====
CHECK_URL = "https://www.gstatic.com/generate_204"
TIMEOUT = 2.5  # общий таймаут в секундах
CONCURRENT_CHECKS = 50  # максимум одновременных проверок
IMPERSONATE = "chrome110"  # имитация Chrome 110
# ====================================

class AsyncChecker:
    """
    Асинхронный проверщик через curl_cffi.
    Принимает оригинальные прокси-строки (vless://, ss://, trojan:// и т.д.)
    """
    
    def __init__(self, 
                 check_url: str = CHECK_URL, 
                 timeout: float = TIMEOUT,
                 concurrent: int = CONCURRENT_CHECKS,
                 impersonate: str = IMPERSONATE):
        
        self.check_url = check_url
        self.timeout = timeout
        self.concurrent = concurrent
        self.impersonate = impersonate
        
    async def check_one(self, session: AsyncSession, proxy_string: str, semaphore: asyncio.Semaphore) -> Optional[Tuple[str, float]]:
        """
        Проверяет один прокси через curl_cffi.
        Использует семафор для контроля конкурентности.
        """
        async with semaphore:  # ограничиваем количество одновременных запросов
            try:
                start = time.monotonic()
                
                # Выполняем запрос через прокси
                resp = await session.get(
                    self.check_url,
                    proxy=proxy_string,           # передаем оригинальную строку (vless://...)
                    timeout=self.timeout,
                    impersonate=self.impersonate   # имитация Chrome
                )
                
                if resp.status_code == 204:
                    elapsed = (time.monotonic() - start) * 1000
                    return (proxy_string, elapsed)
                    
            except Exception as e:
                # Любая ошибка = прокси не работает
                return None
        
        return None
    
    async def check_many(self, proxy_list: List[str]) -> List[Tuple[str, float]]:
        """
        Проверяет список прокси параллельно с ограничением конкурентности.
        """
        if not proxy_list:
            return []
        
        # Создаем семафор для ограничения количества одновременных запросов
        semaphore = asyncio.Semaphore(self.concurrent)
        
        # Используем AsyncSession для всех запросов
        async with AsyncSession() as session:
            # Создаем задачи для всех прокси
            tasks = [self.check_one(session, proxy, semaphore) for proxy in proxy_list]
            
            # Запускаем все задачи параллельно
            results = await asyncio.gather(*tasks)
        
        # Фильтруем успешные результаты
        alive = [r for r in results if r is not None]
        
        # Сортируем по скорости (самые быстрые первые)
        alive.sort(key=lambda x: x[1])
        
        return alive
    
    def check(self, proxy_list: List[str]) -> List[Tuple[str, float]]:
        """
        Синхронная обертка для вызова из обычного кода.
        """
        if not proxy_list:
            return []
        return asyncio.run(self.check_many(proxy_list))


# ===== ТЕСТОВЫЙ ЗАПУСК (если файл запущен напрямую) =====
if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("АСИНХРОННЫЙ ПРОВЕРЩИК v2.0 (curl_cffi)")
    print("="*60)
    print(f"URL: {CHECK_URL}")
    print(f"Таймаут: {TIMEOUT} сек")
    print(f"Конкурентность: {CONCURRENT_CHECKS}")
    print(f"Impersonate: {IMPERSONATE}")
    print("="*60)
    
    # Читаем прокси из файла или stdin
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        try:
            with open(filename, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"❌ Файл {filename} не найден")
            sys.exit(1)
    else:
        print("Введите прокси (по одному в строке, пустая строка для завершения):")
        proxies = []
        while True:
            line = sys.stdin.readline().strip()
            if not line:
                break
            proxies.append(line)
    
    if not proxies:
        print("❌ Нет прокси для проверки")
        sys.exit(0)
    
    print(f"\n🔍 Проверяю {len(proxies)} прокси...")
    
    checker = AsyncChecker()
    alive = checker.check(proxies)
    
    print(f"\n✅ Живых: {len(alive)} из {len(proxies)}")
    if alive:
        print("\n📊 Топ-10 самых быстрых:")
        for proxy, speed in alive[:10]:
            # Обрезаем длинные строки для читаемости
            short_proxy = proxy[:60] + "..." if len(proxy) > 60 else proxy
            print(f"   {short_proxy} | {speed:.0f}ms")
    
    print("="*60)
