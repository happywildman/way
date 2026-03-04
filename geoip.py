#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GeoIP Module v1.0
====================================
- Скачивает GeoIP базу из runetfreedom/russia-blocked-geoip
- Определяет страну по хосту
- Кэширует результаты для ускорения
====================================
"""

import os
import socket
import requests
import logging
from typing import Optional
import ipaddress
import struct
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class GeoIP:
    """
    Класс для определения страны по IP-адресу.
    Использует базу Country.mmdb из runetfreedom.
    """
    
    # Прямая ссылка на последнюю версию базы
    MMDB_URL = "https://github.com/runetfreedom/russia-blocked-geoip/releases/latest/download/Country.mmdb"
    
    def __init__(self, db_path: str = 'country.mmdb', update_days: int = 7):
        """
        Инициализация GeoIP.
        
        Args:
            db_path: путь к файлу базы
            update_days: обновлять базу раз в N дней
        """
        self.db_path = db_path
        self.update_days = update_days
        self.db = None
        self.cache = {}  # кэш результатов {host: country}
        
        self._ensure_db()
        self._load_db()
    
    def _ensure_db(self):
        """Проверяет наличие базы, скачивает если отсутствует или устарела."""
        need_download = False
        
        if not os.path.exists(self.db_path):
            logger.info("🌍 GeoIP база не найдена")
            need_download = True
        else:
            # Проверяем возраст файла
            mtime = datetime.fromtimestamp(os.path.getmtime(self.db_path))
            age = datetime.now() - mtime
            if age.days >= self.update_days:
                logger.info(f"🌍 GeoIP база устарела (старше {self.update_days} дней)")
                need_download = True
        
        if need_download:
            self._download_db()
    
    def _download_db(self):
        """Скачивает GeoIP базу из runetfreedom."""
        logger.info(f"📥 Скачиваю GeoIP базу из {self.MMDB_URL}")
        
        try:
            # Скачиваем с таймаутом 30 секунд
            response = requests.get(self.MMDB_URL, stream=True, timeout=30)
            response.raise_for_status()
            
            # Получаем размер файла
            total_size = int(response.headers.get('content-length', 0))
            logger.info(f"📦 Размер: {total_size / 1024 / 1024:.1f} MB")
            
            # Сохраняем
            with open(self.db_path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0 and downloaded % (1024*1024) < 8192:
                        percent = (downloaded / total_size) * 100
                        logger.info(f"⬇️ Загружено: {downloaded/1024/1024:.1f} MB ({percent:.1f}%)")
            
            logger.info(f"✅ GeoIP база скачана: {self.db_path}")
            
        except requests.Timeout:
            logger.error("❌ Таймаут при скачивании GeoIP базы")
            raise
        except requests.ConnectionError as e:
            logger.error(f"❌ Ошибка соединения: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Ошибка скачивания GeoIP базы: {e}")
            raise
    
    def _load_db(self):
        """Загружает GeoIP базу."""
        if not os.path.exists(self.db_path):
            logger.error("❌ GeoIP база не найдена")
            self.db = None
            return
        
        try:
            # Пробуем импортировать maxminddb (опционально)
            try:
                import maxminddb
                self.db = maxminddb.open_database(self.db_path)
                logger.info("✅ GeoIP база загружена (maxminddb)")
                return
            except ImportError:
                logger.warning("⚠️ maxminddb не установлен, использую упрощенный определитель")
                self.db = "simplified"
                return
                
        except Exception as e:
            logger.error(f"❌ Ошибка загрузки GeoIP базы: {e}")
            self.db = None
    
    def _is_ip(self, host: str) -> bool:
        """Проверяет, является ли строка IP-адресом."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    
    def _resolve_host(self, host: str) -> Optional[str]:
        """Разрешает доменное имя в IP-адрес."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None
    
    def _simplified_country(self, ip: str) -> str:
        """
        Упрощенный определитель страны (без maxminddb).
        Только для частных и зарезервированных адресов.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Частные диапазоны
            if ip_obj.is_private:
                return "PRIVATE"
            if ip_obj.is_loopback:
                return "LOOPBACK"
            if ip_obj.is_multicast:
                return "MULTICAST"
            
            # Если не удалось определить
            return "UNKNOWN"
            
        except:
            return "UNKNOWN"
    
    def get_country(self, host: str) -> str:
        """
        Определяет страну по хосту.
        
        Args:
            host: доменное имя или IP-адрес
            
        Returns:
            Двухбуквенный код страны (RU, US, DE и т.д.) или UNKNOWN
        """
        # Проверяем кэш
        if host in self.cache:
            return self.cache[host]
        
        # Получаем IP
        if self._is_ip(host):
            ip = host
        else:
            ip = self._resolve_host(host)
            if not ip:
                self.cache[host] = "UNKNOWN"
                return "UNKNOWN"
        
        # Определяем страну
        if self.db and self.db != "simplified":
            try:
                result = self.db.get(ip)
                if result and 'country' in result and 'iso_code' in result['country']:
                    country = result['country']['iso_code']
                    self.cache[host] = country
                    return country
            except:
                pass
        
        # Fallback на упрощенный определитель
        country = self._simplified_country(ip)
        self.cache[host] = country
        return country
    
    def close(self):
        """Закрывает базу данных."""
        if self.db and self.db != "simplified":
            try:
                self.db.close()
            except:
                pass


# ===== ТЕСТОВЫЙ ЗАПУСК =====
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    print("="*60)
    print("GEOIP MODULE v1.0")
    print("="*60)
    
    geo = GeoIP()
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
        country = geo.get_country(host)
        print(f"\n🌍 {host} → {country}")
    else:
        # Тестовые хосты
        test_hosts = [
            "185.22.153.77",      # RU
            "8.8.8.8",            # US
            "yandex.ru",           # RU
            "google.com",          # US
            "192.168.1.1",         # PRIVATE
            "несуществующий.ру"    # UNKNOWN
        ]
        
        print("\n🔍 Тестирование:")
        for host in test_hosts:
            country = geo.get_country(host)
            print(f"   {host:20} → {country}")
    
    geo.close()
    print("="*60)
