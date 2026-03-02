#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Асинхронный модуль проверки
============================================
Параметры (согласованы):
- CHECK_URL = "https://www.gstatic.com/generate_204"
- TIMEOUT = 3 секунды
- CONCURRENT_CHECKS = 200
============================================
"""

import asyncio
import aiohttp
import time
from typing import List, Tuple, Optional

# ===== СОГЛАСОВАННЫЕ ПАРАМЕТРЫ =====
CHECK_URL = "https://www.gstatic.com/generate_204"
TIMEOUT = aiohttp.ClientTimeout(total=3)
CONCURRENT_CHECKS = 200
# ====================================

class AsyncChecker:
    def __init__(self, 
                 check_url: str = CHECK_URL, 
                 timeout: aiohttp.ClientTimeout = TIMEOUT,
                 concurrent: int = CONCURRENT_CHECKS):
        
        self.check_url = check_url
        self.timeout = timeout
        self.concurrent = concurrent
        
    async def check_single(self, session: aiohttp.ClientSession, proxy_string: str) -> Optional[Tuple[str, float]]:
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
        connector = aiohttp.TCPConnector(limit=self.concurrent, ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_single(session, proxy) for proxy in proxy_list]
            results = await asyncio.gather(*tasks)
        
        alive = [r for r in results if r is not None]
        alive.sort(key=lambda x: x[1])
        return alive
    
    def check(self, proxy_list: List[str]) -> List[Tuple[str, float]]:
        return asyncio.run(self.check_many(proxy_list))


if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("АСИНХРОННЫЙ МОДУЛЬ ПРОВЕРКИ v1.0")
    print("="*60)
    print(f"URL: {CHECK_URL}")
    print(f"Таймаут: {TIMEOUT.total} сек")
    print(f"Конкурентность: {CONCURRENT_CHECKS}")
    print("="*60)
    
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        with open(filename, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    else:
        print("Введите данные для проверки (по одному в строке, пустая строка для завершения):")
        proxies = []
        while True:
            line = sys.stdin.readline().strip()
            if not line:
                break
            proxies.append(line)
    
    if not proxies:
        print("Нет данных для проверки")
        sys.exit(0)
    
    print(f"\n🔍 Проверяю {len(proxies)}...")
    
    checker = AsyncChecker()
    alive = checker.check(proxies)
    
    print(f"\n✅ Рабочих: {len(alive)} из {len(proxies)}")
    if alive:
        print("\n📊 Топ-10 самых быстрых:")
        for proxy, speed in alive[:10]:
            print(f"   {proxy} | {speed:.0f}ms")
    
    print("="*60)
