#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Xray Tester Module v1.1 (Diagnostic)
====================================
- Добавлено подробное логирование
- Проверка скачивания Xray
- Тестовый запуск Xray после скачивания
- Таймауты на все операции
====================================
"""

import os
import json
import time
import tempfile
import subprocess
import platform
import requests
import zipfile
import urllib.parse
import base64
from typing import List, Tuple, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import shutil
import concurrent.futures

logger = logging.getLogger(__name__)


class XrayTester:
    """
    Тестировщик конфигов через Xray-core.
    Использует готовые бинарники Xray.
    """
    
    def __init__(self, 
                 xray_dir: str = 'xray_bin',
                 timeout: float = 5.0,
                 max_workers: int = 3,
                 socks_port: int = 10808):
        
        self.xray_dir = xray_dir
        self.timeout = timeout
        self.max_workers = max_workers
        self.socks_port = socks_port
        self.xray_path = self._ensure_xray()
        
    def _ensure_xray(self) -> str:
        """
        Проверяет наличие Xray-core, скачивает если отсутствует.
        С подробным логированием каждого шага.
        """
        xray_path = os.path.join(self.xray_dir, 'xray')
        
        # Если уже есть - проверяем что работает
        if os.path.exists(xray_path):
            logger.info(f"✅ Xray-core найден: {xray_path}")
            # Проверяем что бинарник рабочий
            try:
                result = subprocess.run([xray_path, '-version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    version = result.stdout.splitlines()[0] if result.stdout else "unknown"
                    logger.info(f"✅ Xray работает: {version}")
                else:
                    logger.error(f"❌ Xray бинарник поврежден, перезагружаю...")
                    os.remove(xray_path)
                    return self._ensure_xray()
            except Exception as e:
                logger.error(f"❌ Ошибка проверки Xray: {e}, перезагружаю...")
                os.remove(xray_path)
                return self._ensure_xray()
            return xray_path
        
        logger.info("📥 Xray-core не найден. Начинаю скачивание...")
        
        # Определяем платформу
        system = platform.system().lower()
        logger.info(f"🔍 Определена платформа: {system}")
        
        if 'windows' in system:
            system = 'windows'
            ext = '.exe'
        elif 'darwin' in system:
            system = 'macos'
            ext = ''
        else:
            system = 'linux'
            ext = ''
        
        # Скачиваем последнюю версию
        url = f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-{system}-64.zip"
        zip_path = os.path.join(self.xray_dir, 'xray.zip')
        
        try:
            # Создаем директорию
            os.makedirs(self.xray_dir, exist_ok=True)
            logger.info(f"📁 Создана директория: {self.xray_dir}")
            
            # Скачиваем
            logger.info(f"⬇️ Скачиваю Xray для {system} с {url}...")
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            logger.info(f"📦 Размер файла: {total_size} байт")
            
            with open(zip_path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        if downloaded % (1024*1024) < 8192:  # Логируем каждый мегабайт
                            logger.info(f"⬇️ Загружено: {downloaded/(1024*1024):.1f} MB ({percent:.1f}%)")
            
            logger.info(f"✅ Скачивание завершено: {zip_path}")
            
            # Распаковываем
            logger.info("📦 Распаковываю...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                logger.info(f"📋 Файлы в архиве: {file_list}")
                zip_ref.extractall(self.xray_dir)
            
            # Делаем исполняемым на Unix
            if system != 'windows':
                logger.info(f"🔧 Устанавливаю права на исполнение: {xray_path}")
                os.chmod(xray_path, 0o755)
            
            # Удаляем zip
            os.remove(zip_path)
            logger.info(f"🗑️ Временный файл удален: {zip_path}")
            
            # Проверяем что скачалось
            if not os.path.exists(xray_path):
                raise Exception(f"Xray бинарник не найден после распаковки: {xray_path}")
            
            logger.info(f"✅ Xray-core готов: {xray_path}")
            
            # Тестовый запуск
            logger.info("🧪 Выполняю тестовый запуск Xray...")
            result = subprocess.run([xray_path, '-version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.splitlines()[0] if result.stdout else "unknown"
                logger.info(f"✅ Xray успешно запущен: {version}")
            else:
                logger.error(f"❌ Xray не запускается. STDERR: {result.stderr}")
                raise Exception("Xray не работает")
            
            return xray_path
            
        except requests.Timeout:
            logger.error("❌ Таймаут при скачивании Xray")
            raise
        except requests.ConnectionError as e:
            logger.error(f"❌ Ошибка соединения при скачивании: {e}")
            raise
        except zipfile.BadZipFile as e:
            logger.error(f"❌ Ошибка распаковки ZIP: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Неожиданная ошибка при подготовке Xray: {e}")
            raise
    
    def parse_config(self, config_str: str) -> Optional[Dict]:
        """
        Парсит конфиг любого типа в формат Xray.
        Поддерживает: vless, vmess, trojan, ss.
        Возвращает словарь с конфигурацией для Xray.
        """
        try:
            if config_str.startswith('vless://'):
                logger.debug(f"Парсинг vless: {config_str[:50]}...")
                return self._parse_vless(config_str)
            elif config_str.startswith('vmess://'):
                logger.debug(f"Парсинг vmess: {config_str[:50]}...")
                return self._parse_vmess(config_str)
            elif config_str.startswith('trojan://'):
                logger.debug(f"Парсинг trojan: {config_str[:50]}...")
                return self._parse_trojan(config_str)
            elif config_str.startswith('ss://'):
                logger.debug(f"Парсинг ss: {config_str[:50]}...")
                return self._parse_shadowsocks(config_str)
            else:
                logger.debug(f"Неподдерживаемый протокол: {config_str[:50]}...")
                return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга {config_str[:50]}...: {e}")
            return None
    
    def _parse_vless(self, vless_str: str) -> Dict:
        """Парсит vless:// ссылку в Xray JSON."""
        parsed = urllib.parse.urlparse(vless_str)
        
        # Извлекаем uuid@host:port
        user_info = parsed.netloc.split('@')
        uuid = user_info[0]
        host_port = user_info[1].split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        
        # Парсим параметры
        params = urllib.parse.parse_qs(parsed.query)
        
        # Базовый outbound
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": params.get('encryption', ['none'])[0],
                        "flow": params.get('flow', [''])[0]
                    }]
                }]
            },
            "streamSettings": {
                "network": params.get('type', ['tcp'])[0],
                "security": params.get('security', ['none'])[0]
            }
        }
        
        # Добавляем Reality параметры если есть
        if params.get('security', [''])[0] == 'reality':
            outbound['streamSettings']['realitySettings'] = {
                "serverName": params.get('sni', [''])[0],
                "fingerprint": params.get('fp', ['chrome'])[0],
                "publicKey": params.get('pbk', [''])[0],
                "shortId": params.get('sid', [''])[0]
            }
        
        # Добавляем WS параметры если есть
        if params.get('type', [''])[0] == 'ws':
            outbound['streamSettings']['wsSettings'] = {
                "path": params.get('path', ['/'])[0],
                "headers": {
                    "Host": params.get('host', [host])[0]
                }
            }
        
        return self._create_full_config(outbound)
    
    def _parse_vmess(self, vmess_str: str) -> Optional[Dict]:
        """Парсит vmess:// ссылку (base64 encoded)."""
        b64_part = vmess_str[8:]  # убираем 'vmess://'
        
        # Декодируем base64
        try:
            # Пробуем обычный base64
            decoded = base64.b64decode(b64_part).decode('utf-8')
            config_json = json.loads(decoded)
        except:
            # Пробуем url-safe base64
            try:
                b64_part = b64_part.replace('-', '+').replace('_', '/')
                while len(b64_part) % 4:
                    b64_part += '='
                decoded = base64.b64decode(b64_part).decode('utf-8')
                config_json = json.loads(decoded)
            except:
                logger.debug(f"Не удалось декодировать vmess: {vmess_str[:50]}...")
                return None
        
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config_json.get('add', ''),
                    "port": int(config_json.get('port', 443)),
                    "users": [{
                        "id": config_json.get('id', ''),
                        "alterId": int(config_json.get('aid', 0)),
                        "security": config_json.get('scy', 'auto')
                    }]
                }]
            },
            "streamSettings": {
                "network": config_json.get('net', 'tcp'),
                "security": config_json.get('tls', 'none')
            }
        }
        
        # Добавляем WS параметры
        if outbound['streamSettings']['network'] == 'ws':
            outbound['streamSettings']['wsSettings'] = {
                "path": config_json.get('path', '/'),
                "headers": {
                    "Host": config_json.get('host', '')
                }
            }
        
        return self._create_full_config(outbound)
    
    def _parse_trojan(self, trojan_str: str) -> Optional[Dict]:
        """Парсит trojan:// ссылку."""
        parsed = urllib.parse.urlparse(trojan_str)
        
        # Извлекаем password@host:port
        if '@' not in parsed.netloc:
            return None
        
        password = parsed.netloc.split('@')[0]
        host_port = parsed.netloc.split('@')[1].split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        
        # Парсим параметры
        params = urllib.parse.parse_qs(parsed.query)
        
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": {
                "network": params.get('type', ['tcp'])[0],
                "security": "tls"
            }
        }
        
        # Добавляем WS параметры если есть
        if outbound['streamSettings']['network'] == 'ws':
            outbound['streamSettings']['wsSettings'] = {
                "path": params.get('path', ['/'])[0],
                "headers": {
                    "Host": params.get('host', [host])[0]
                }
            }
        
        return self._create_full_config(outbound)
    
    def _parse_shadowsocks(self, ss_str: str) -> Optional[Dict]:
        """Парсит ss:// ссылку."""
        try:
            parsed = urllib.parse.urlparse(ss_str)
            
            # Может быть в формате ss://base64@host:port
            if '@' in parsed.netloc:
                b64_part, host_port = parsed.netloc.split('@', 1)
                try:
                    decoded = base64.b64decode(b64_part).decode('utf-8')
                    if ':' in decoded:
                        method, password = decoded.split(':', 1)
                    else:
                        method = 'chacha20-ietf-poly1305'
                        password = decoded
                except:
                    method = 'chacha20-ietf-poly1305'
                    password = b64_part
            else:
                # Формат ss://method:password@host:port
                auth, host_port = parsed.netloc.split('@', 1)
                if ':' in auth:
                    method, password = auth.split(':', 1)
                else:
                    method = 'chacha20-ietf-poly1305'
                    password = auth
            
            host = host_port.split(':')[0]
            port = int(host_port.split(':')[1]) if ':' in host_port else 443
            
            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "method": method,
                        "password": password
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none"
                }
            }
            
            return self._create_full_config(outbound)
            
        except Exception as e:
            logger.debug(f"Ошибка парсинга ss://: {e}")
            return None
    
    def _create_full_config(self, outbound: Dict) -> Dict:
        """Создает полный конфиг Xray с inbound для SOCKS5."""
        return {
            "log": {
                "loglevel": "error"
            },
            "inbounds": [{
                "port": self.socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                }
            }],
            "outbounds": [outbound, {
                "protocol": "freedom",
                "tag": "direct"
            }]
        }
    
    def _test_one_internal(self, config_str: str) -> Tuple[Optional[str], Optional[float]]:
        """
        Внутренняя функция тестирования одного конфига.
        Вынесена отдельно для возможности таймаута.
        """
        temp_config = None
        process = None
        
        try:
            # Парсим конфиг
            config_data = self.parse_config(config_str)
            if not config_data:
                logger.debug(f"Не удалось распарсить конфиг")
                return None, None
            
            # Сохраняем во временный файл
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(config_data, f, indent=2)
                temp_config = f.name
                logger.debug(f"📝 Временный конфиг: {temp_config}")
            
            # Запускаем Xray
            logger.debug(f"🚀 Запуск Xray с конфигом...")
            process = subprocess.Popen(
                [self.xray_path, '-config', temp_config],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Даем время на запуск
            time.sleep(1.5)
            
            # Проверяем что процесс жив
            if process.poll() is not None:
                # Процесс умер сразу
                stdout, stderr = process.communicate()
                logger.debug(f"❌ Xray умер сразу. STDERR: {stderr}")
                return None, None
            
            # Тестируем через SOCKS5 прокси
            logger.debug(f"🔍 Отправка запроса через SOCKS5 на 127.0.0.1:{self.socks_port}")
            start = time.time()
            
            proxies = {
                'http': f'socks5://127.0.0.1:{self.socks_port}',
                'https': f'socks5://127.0.0.1:{self.socks_port}'
            }
            
            response = requests.get(
                'https://www.gstatic.com/generate_204',
                proxies=proxies,
                timeout=self.timeout
            )
            
            if response.status_code == 204:
                elapsed = (time.time() - start) * 1000
                logger.debug(f"✅ Успех! Задержка: {elapsed:.2f}ms")
                return config_str, round(elapsed, 2)
            else:
                logger.debug(f"❌ Не 204 ответ: {response.status_code}")
                return None, None
                
        except requests.Timeout:
            logger.debug(f"⏱️ Таймаут при проверке")
            return None, None
        except requests.ConnectionError as e:
            logger.debug(f"🔌 Ошибка соединения через SOCKS5: {e}")
            return None, None
        except Exception as e:
            logger.debug(f"❌ Ошибка тестирования: {e}")
            return None, None
            
        finally:
            # Останавливаем процесс
            if process:
                logger.debug(f"🛑 Остановка Xray процесса...")
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    logger.debug(f"💥 Принудительное завершение Xray")
                    process.kill()
            
            # Удаляем временный файл
            if temp_config and os.path.exists(temp_config):
                try:
                    os.unlink(temp_config)
                    logger.debug(f"🗑️ Удален временный файл: {temp_config}")
                except:
                    pass
    
    def test_one(self, config_str: str) -> Tuple[Optional[str], Optional[float]]:
        """
        Тестирует один конфиг через Xray с общим таймаутом.
        Возвращает (config_str, задержка_в_мс) или (None, None) при ошибке.
        """
        # Добавляем общий таймаут на всю операцию
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(self._test_one_internal, config_str)
                return future.result(timeout=self.timeout + 5)  # таймаут + запас
        except concurrent.futures.TimeoutError:
            logger.warning(f"⏱️ Таймаут при тестировании конфига")
            return None, None
    
    def test_many(self, configs: List[str]) -> List[Tuple[str, float]]:
        """
        Тестирует множество конфигов параллельно.
        Xray процессы тяжелые, поэтому ограничиваем self.max_workers.
        Возвращает список (config, задержка) отсортированный по скорости.
        """
        if not configs:
            return []
        
        logger.info(f"🚀 Запуск Xray тестирования ({self.max_workers} процессов, таймаут={self.timeout}с)")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_config = {
                executor.submit(self.test_one, config): config 
                for config in configs
            }
            
            for future in as_completed(future_to_config):
                config, speed = future.result()
                if config:
                    results.append((config, speed))
                    logger.debug(f"✅ {config[:60]}... | {speed}ms")
        
        # Сортируем по скорости
        results.sort(key=lambda x: x[1])
        logger.info(f"📊 Найдено рабочих: {len(results)} из {len(configs)}")
        
        return results


# ===== ТЕСТОВЫЙ ЗАПУСК =====
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    print("="*60)
    print("XRAY TESTER MODULE v1.1 (Diagnostic)")
    print("="*60)
    
    # Тестируем один конфиг если передан аргументом
    if len(sys.argv) > 1:
        config = sys.argv[1]
        tester = XrayTester(max_workers=1)
        result, speed = tester.test_one(config)
        if result:
            print(f"\n✅ РАБОТАЕТ! Задержка: {speed}ms")
        else:
            print("\n❌ НЕ РАБОТАЕТ")
        sys.exit(0)
    
    # Иначе читаем из stdin
    print("Введите конфиги (по одному в строке, пустая строка для завершения):")
    configs = []
    while True:
        line = sys.stdin.readline().strip()
        if not line:
            break
        configs.append(line)
    
    if not configs:
        print("❌ Нет конфигов для проверки")
        sys.exit(0)
    
    print(f"\n🔍 Тестирую {len(configs)} конфигов через Xray...")
    
    tester = XrayTester(max_workers=3)
    results = tester.test_many(configs)
    
    print(f"\n✅ Рабочих: {len(results)} из {len(configs)}")
    if results:
        print("\n📊 Топ-10 самых быстрых:")
        for config, speed in results[:10]:
            short = config[:60] + "..." if len(config) > 60 else config
            print(f"   {short} | {speed}ms")
    
    print("="*60)
