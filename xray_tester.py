#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Xray Tester Module v1.4
====================================
- Исправлен парсер на основе python_v2ray и V2ray-Tester-Pro
- Добавлены все критические параметры (fp, alpn, allowInsecure, flow)
- Правильная обработка reality
- Улучшенное логирование
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

logger = logging.getLogger(__name__)


class XrayTester:
    """
    Тестировщик конфигов через Xray-core.
    Основан на лучших практиках из opensource проектов.
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
        (адаптировано из python_v2ray)
        """
        xray_path = os.path.join(self.xray_dir, 'xray')
        
        if os.path.exists(xray_path):
            logger.info(f"✅ Xray-core найден: {xray_path}")
            try:
                result = subprocess.run([xray_path, '-version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    version = result.stdout.splitlines()[0] if result.stdout else "unknown"
                    logger.info(f"✅ Xray работает: {version}")
                    return xray_path
                else:
                    logger.error(f"❌ Xray бинарник поврежден, перезагружаю...")
                    os.remove(xray_path)
            except Exception as e:
                logger.error(f"❌ Ошибка проверки Xray: {e}, перезагружаю...")
                os.remove(xray_path)
        
        logger.info("📥 Xray-core не найден. Начинаю скачивание...")
        
        system = platform.system().lower()
        logger.info(f"🔍 Определена платформа: {system}")
        
        if 'windows' in system:
            system = 'windows'
        elif 'darwin' in system:
            system = 'macos'
        else:
            system = 'linux'
        
        url = f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-{system}-64.zip"
        zip_path = os.path.join(self.xray_dir, 'xray.zip')
        
        try:
            os.makedirs(self.xray_dir, exist_ok=True)
            logger.info(f"⬇️ Скачиваю Xray с {url}...")
            
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            logger.info(f"📦 Размер: {total_size / 1024 / 1024:.1f} MB")
            
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info("📦 Распаковываю...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.xray_dir)
            
            if system != 'windows':
                os.chmod(xray_path, 0o755)
            
            os.remove(zip_path)
            
            # Проверка
            result = subprocess.run([xray_path, '-version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.splitlines()[0] if result.stdout else "unknown"
                logger.info(f"✅ Xray успешно установлен: {version}")
            else:
                logger.error(f"❌ Xray не запускается после установки")
                raise Exception("Xray не работает")
            
            return xray_path
            
        except Exception as e:
            logger.error(f"❌ Ошибка установки Xray: {e}")
            raise
    
    def parse_config(self, config_str: str) -> Optional[Dict]:
        """
        Парсит конфиг любого типа в формат Xray.
        Использует подход из python_v2ray.
        """
        try:
            if config_str.startswith('vless://'):
                return self._parse_vless(config_str)
            elif config_str.startswith('vmess://'):
                return self._parse_vmess(config_str)
            elif config_str.startswith('trojan://'):
                return self._parse_trojan(config_str)
            elif config_str.startswith('ss://'):
                return self._parse_shadowsocks(config_str)
            else:
                logger.debug(f"Неподдерживаемый протокол")
                return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга: {e}")
            return None
    
    def _parse_vless(self, vless_str: str) -> Dict:
        """
        Парсит vless:// ссылку со ВСЕМИ критическими параметрами.
        Основано на python_v2ray и V2ray-Tester-Pro.
        """
        parsed = urllib.parse.urlparse(vless_str)
        
        # Извлекаем uuid@host:port
        user_info = parsed.netloc.split('@')
        if len(user_info) != 2:
            logger.warning(f"Неверный формат vless: {vless_str[:50]}...")
            return None
        
        uuid = user_info[0]
        host_port = user_info[1].split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        
        # Парсим ВСЕ параметры
        params = urllib.parse.parse_qs(parsed.query)
        
        # Логируем найденные параметры для отладки
        logger.debug(f"📋 Параметры vless: {list(params.keys())}")
        
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
                        "flow": params.get('flow', [''])[0]  # xtls-rprx-vision
                    }]
                }]
            }
        }
        
        # StreamSettings
        streamSettings = {
            "network": params.get('type', ['tcp'])[0],
            "security": params.get('security', ['none'])[0]
        }
        
        # WebSocket параметры
        if streamSettings["network"] == "ws":
            streamSettings["wsSettings"] = {
                "path": params.get('path', ['/'])[0],
                "headers": {
                    "Host": params.get('host', [host])[0]
                }
            }
            logger.debug(f"🔧 WS: path={streamSettings['wsSettings']['path']}, host={streamSettings['wsSettings']['headers']['Host']}")
        
        # TLS параметры (критически важно!)
        if streamSettings["security"] == "tls":
            tlsSettings = {
                "serverName": params.get('sni', [host])[0],
                "fingerprint": params.get('fp', ['chrome'])[0],  # из params
                "allowInsecure": params.get('allowInsecure', ['0'])[0] == '1'
            }
            
            # ALPN - обязателен для HTTP/2
            if 'alpn' in params:
                tlsSettings["alpn"] = params['alpn'][0].split(',')
                logger.debug(f"🔧 ALPN из params: {tlsSettings['alpn']}")
            else:
                tlsSettings["alpn"] = ["h2", "http/1.1"]  # значение по умолчанию
                logger.debug(f"🔧 ALPN по умолчанию: {tlsSettings['alpn']}")
            
            streamSettings["tlsSettings"] = tlsSettings
            logger.debug(f"🔧 TLS: sni={tlsSettings['serverName']}, fp={tlsSettings['fingerprint']}")
        
        # Reality параметры
        if streamSettings["security"] == "reality":
            realitySettings = {
                "serverName": params.get('sni', [''])[0],
                "fingerprint": params.get('fp', ['chrome'])[0],
                "publicKey": params.get('pbk', [''])[0],
                "shortId": params.get('sid', [''])[0],
                "spiderX": params.get('spx', [''])[0]  # иногда есть
            }
            streamSettings["realitySettings"] = realitySettings
            logger.debug(f"🔧 Reality: sni={realitySettings['serverName']}, fp={realitySettings['fingerprint']}")
        
        outbound["streamSettings"] = streamSettings
        return self._create_full_config(outbound)
    
    def _parse_vmess(self, vmess_str: str) -> Optional[Dict]:
        """Парсит vmess:// ссылку (base64 encoded)."""
        b64_part = vmess_str[8:]
        
        # Декодируем base64
        try:
            decoded = base64.b64decode(b64_part).decode('utf-8')
            config_json = json.loads(decoded)
        except:
            try:
                b64_part = b64_part.replace('-', '+').replace('_', '/')
                while len(b64_part) % 4:
                    b64_part += '='
                decoded = base64.b64decode(b64_part).decode('utf-8')
                config_json = json.loads(decoded)
            except:
                logger.debug(f"Не удалось декодировать vmess")
                return None
        
        # Извлекаем параметры
        host = config_json.get('add', '')
        port = int(config_json.get('port', 443))
        uuid = config_json.get('id', '')
        aid = int(config_json.get('aid', 0))
        security = config_json.get('scy', 'auto')
        network = config_json.get('net', 'tcp')
        tls = config_json.get('tls', 'none')
        path = config_json.get('path', '/')
        host_header = config_json.get('host', '')
        
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "alterId": aid,
                        "security": security
                    }]
                }]
            },
            "streamSettings": {
                "network": network,
                "security": tls
            }
        }
        
        # WebSocket параметры
        if network == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": path,
                "headers": {
                    "Host": host_header if host_header else host
                }
            }
        
        # TLS параметры
        if tls == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": host_header if host_header else host,
                "allowInsecure": True,
                "fingerprint": "chrome"
            }
        
        return self._create_full_config(outbound)
    
    def _parse_trojan(self, trojan_str: str) -> Optional[Dict]:
        """Парсит trojan:// ссылку со всеми параметрами."""
        parsed = urllib.parse.urlparse(trojan_str)
        
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
        
        # WebSocket параметры
        if outbound["streamSettings"]["network"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": params.get('path', ['/'])[0],
                "headers": {
                    "Host": params.get('host', [host])[0]
                }
            }
        
        # TLS параметры
        tlsSettings = {
            "serverName": params.get('sni', [host])[0],
            "fingerprint": params.get('fp', ['chrome'])[0],
            "allowInsecure": params.get('allowInsecure', ['0'])[0] == '1'
        }
        
        if 'alpn' in params:
            tlsSettings["alpn"] = params['alpn'][0].split(',')
        
        outbound["streamSettings"]["tlsSettings"] = tlsSettings
        
        return self._create_full_config(outbound)
    
    def _parse_shadowsocks(self, ss_str: str) -> Optional[Dict]:
        """Парсит ss:// ссылку."""
        try:
            parsed = urllib.parse.urlparse(ss_str)
            
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
    
    def test_one(self, config_str: str, index: int, total: int) -> Tuple[Optional[str], Optional[float]]:
        """Тестирует один конфиг с детальным логированием."""
        temp_config = None
        process = None
        
        logger.info(f"🔍 [{index}/{total}] Тестирую: {config_str[:50]}...")
        
        try:
            # Парсим конфиг
            config_data = self.parse_config(config_str)
            if not config_data:
                logger.warning(f"❌ [{index}/{total}] Не удалось распарсить")
                return None, None
            
            # Сохраняем во временный файл
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(config_data, f, indent=2)
                temp_config = f.name
            
            # Запускаем Xray
            process = subprocess.Popen(
                [self.xray_path, '-config', temp_config],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Даем время на запуск (2 секунды как в V2ray-Tester-Pro)
            time.sleep(2)
            
            if process.poll() is not None:
                return None, None
            
            # Тестируем через SOCKS5
            start = time.time()
            
            proxies = {
                'http': f'socks5://127.0.0.1:{self.socks_port}',
                'https': f'socks5://127.0.0.1:{self.socks_port}'
            }
            
            try:
                response = requests.get(
                    'https://www.gstatic.com/generate_204',
                    proxies=proxies,
                    timeout=self.timeout
                )
                
                if response.status_code == 204:
                    elapsed = (time.time() - start) * 1000
                    logger.info(f"✅ [{index}/{total}] Успех! {elapsed:.2f}ms")
                    return config_str, round(elapsed, 2)
                else:
                    logger.warning(f"❌ [{index}/{total}] Не 204: {response.status_code}")
                    return None, None
                    
            except requests.Timeout:
                logger.warning(f"⏱️ [{index}/{total}] Таймаут")
                return None, None
            except requests.ConnectionError as e:
                logger.warning(f"🔌 [{index}/{total}] Ошибка соединения: {e}")
                return None, None
                
        except Exception as e:
            logger.error(f"💥 [{index}/{total}] Ошибка: {e}")
            return None, None
            
        finally:
            if process:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            
            if temp_config and os.path.exists(temp_config):
                try:
                    os.unlink(temp_config)
                except:
                    pass
    
    def test_many(self, configs: List[str]) -> List[Tuple[str, float]]:
        """Тестирует множество конфигов параллельно."""
        if not configs:
            return []
        
        logger.info(f"🚀 Запуск Xray: {len(configs)} конфигов, {self.max_workers} процессов")
        
        results = []
        total = len(configs)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_config = {
                executor.submit(self.test_one, config, i+1, total): config 
                for i, config in enumerate(configs)
            }
            
            for future in as_completed(future_to_config):
                config, speed = future.result()
                if config:
                    results.append((config, speed))
        
        results.sort(key=lambda x: x[1])
        logger.info(f"✅ Готово: {len(results)} рабочих из {total}")
        
        return results


# ===== ТЕСТОВЫЙ ЗАПУСК =====
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    print("="*60)
    print("XRAY TESTER MODULE v1.4")
    print("="*60)
    
    if len(sys.argv) > 1:
        config = sys.argv[1]
        tester = XrayTester(max_workers=1)
        result, speed = tester.test_one(config, 1, 1)
        if result:
            print(f"\n✅ РАБОТАЕТ! {speed}ms")
        else:
            print("\n❌ НЕ РАБОТАЕТ")
        sys.exit(0)
    
    print("Введите конфиги (по одному в строке):")
    configs = []
    while True:
        line = sys.stdin.readline().strip()
        if not line:
            break
        configs.append(line)
    
    if not configs:
        print("❌ Нет конфигов")
        sys.exit(0)
    
    tester = XrayTester(max_workers=3)
    results = tester.test_many(configs)
    
    print(f"\n✅ Рабочих: {len(results)} из {len(configs)}")
    if results:
        print("\n📊 Топ-10:")
        for config, speed in results[:10]:
            short = config[:60] + "..." if len(config) > 60 else config
            print(f"   {short} | {speed}ms")
    
    print("="*60)
