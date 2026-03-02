#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Асинхронный модуль проверки прокси-серверов
============================================
Используется для проверки работоспособности серверов через эталонный URL.
Основан на реальных проектах: proxy-fetcher, ProxyBroker, Freedom-V2Ray.

Параметры (согласованы):
- CHECK_URL = "https://www.gstatic.com/generate_204"
- TIMEOUT = 3 секунды (общий таймаут)
- CONCURRENT_CHECKS = 200 (максимум одновременных проверок)
============================================
"""

import asyncio
import aiohttp
import time
from typing import List, Dict, Optional, Tuple

# ===== СОГЛАСОВАННЫЕ ПАРАМЕТРЫ =====
CHECK_URL = "https://www.gstatic.com/generate_204"
TIMEOUT = aiohttp.ClientTimeout(total=3)  # 3 секунды на весь запрос
CONCURRENT_CHECKS = 200  # максимум одновременных проверок
# ====================================

class ProxyChecker:
    """
    Асинхронный класс для проверки прокси-серверов.
    Отправляет запрос на эталонный URL через проверяемый прокси.
    """
    
    def __init__(self, 
                 check_url: str = CHECK_URL, 
                 timeout: aiohttp.ClientTimeout = TIMEOUT,
                 concurrent: int = CONCURRENT_CHECKS):
        
        self.check_url = check_url
        self.timeout = timeout
        self.concurrent = concurrent
        self.results = []
        
    async def check_single(self, session: aiohttp.ClientSession, proxy_string: str) -> Optional[Tuple[str, float]]:
        """
        Проверяет один прокси-сервер.
        Возвращает (proxy_string, скорость_в_ms) или None если не работает.
        """
        try:
            start = time.monotonic()
            async with session.get(self.check_url, proxy=proxy_string, timeout=self.timeout) as response:
                if response.status == 204:
                    elapsed = (time.monotonic() - start) * 1000
                    return (proxy_string, elapsed)
                else:
                    return None
        except Exception:
            return None
    
    async def check_many(self, proxy_list: List[str]) -> List[Tuple[str, float]]:
        """
        Проверяет список прокси параллельно с ограничением CONCURRENT_CHECKS.
        Возвращает список рабочих прокси с их скоростью.
        """
        # Ограничиваем количество одновременных подключений
        connector = aiohttp.TCPConnector(limit=self.concurrent, ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Создаем задачи для всех прокси
            tasks = [self.check_single(session, proxy) for proxy in proxy_list]
            
            # Запускаем все задачи параллельно и собираем результаты
            results = await asyncio.gather(*tasks)
        
        # Фильтруем только успешные результаты
        alive = [r for r in results if r is not None]
        
        # Сортируем по скорости (самые быстрые первые)
        alive.sort(key=lambda x: x[1])
        
        return alive
    
    def check(self, proxy_list: List[str]) -> List[Tuple[str, float]]:
        """
        Синхронная обертка для вызова из обычного кода.
        """
        return asyncio.run(self.check_many(proxy_list))


# ===== ТЕСТОВЫЙ ЗАПУСК (если файл запущен напрямую) =====
if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("АСИНХРОННЫЙ ПРОВЕРЩИК ПРОКСИ v1.0")
    print("="*60)
    print(f"URL: {CHECK_URL}")
    print(f"Таймаут: {TIMEOUT.total} сек")
    print(f"Одновременных проверок: {CONCURRENT_CHECKS}")
    print("="*60)
    
    # Читаем прокси из stdin или из файла
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        with open(filename, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    else:
        print("Введите прокси (по одному в строке, пустая строка для завершения):")
        proxies = []
        while True:
            line = sys.stdin.readline().strip()
            if not line:
                break
            proxies.append(line)
    
    if not proxies:
        print("Нет прокси для проверки")
        sys.exit(0)
    
    print(f"\n🔍 Проверяю {len(proxies)} прокси...")
    
    checker = ProxyChecker()
    alive = checker.check(proxies)
    
    print(f"\n✅ Живых: {len(alive)} из {len(proxies)}")
    if alive:
        print("\n📊 Топ-10 самых быстрых:")
        for proxy, speed in alive[:10]:
            print(f"   {proxy} | {speed:.0f}ms")
    
    print("="*60)
