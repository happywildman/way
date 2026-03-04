#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Xray Tester Module v1.6
====================================
- Логирование конфигов при ошибках
- Видно, какие именно сервера отваливаются
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
        """Проверяет наличие Xray-core, скачивает если отсутствует."""
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
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.xray_dir)
            
            if system != 'windows':
                os.chmod(xray_path, 0o755)
            
            os.remove(zip_path)
            
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
        """Парсит конфиг любого типа в формат Xray."""
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
                return None
        except Exception as e:
            logger.debug(f"Ошибка парсинга: {e}")
            return None
    
    def _parse_vless(self, vless_str: str) -> Dict:
        """Парсит vless:// ссылку со всеми параметрами."""
        parsed = urllib.parse.urlparse(vless_str)
        
        user_info = parsed.netloc.split('@')
        if len(user_info) != 2:
            return None
        
        uuid = user_info[0]
        host_port = user_info[1].split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        
        params = urllib.parse.parse_qs(parsed.query)
        
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
            }
        }
        
        streamSettings = {
            "network": params.get('type', ['tcp'])[0],
            "security": params.get('security', ['none'])[0]
        }
        
        if streamSettings["network"] == "ws":
            streamSettings["wsSettings"] = {
                "path": params.get('path', ['/'])[0],
                "headers": {
                    "Host": params.get('host', [host])[0]
                }
            }
        
        if streamSettings["security"] == "tls":
            tlsSettings = {
                "serverName": params.get('sni', [host])[0],
                "fingerprint": params.get('fp', ['chrome'])[0],
                "allowInsecure": params.get('allowInsecure', ['0'])[0] == '1'
            }
            if 'alpn' in params:
                tlsSettings["alpn"] = params['alpn'][0].split(',')
            else:
                tlsSettings["alpn"] = ["h2", "http/1.1"]
            streamSettings["tlsSettings"] = tlsSettings
        
        if streamSettings["security"] == "reality":
            realitySettings = {
                "serverName": params.get('sni', [''])[0],
                "fingerprint": params.get('fp', ['chrome'])[0],
                "publicKey": params.get('pbk', [''])[0],
                "shortId": params.get('sid', [''])[0],
                "spiderX": params.get('spx', [''])[0]
            }
            streamSettings["realitySettings"] = realitySettings
        
        outbound["streamSettings"] = streamSettings
        return self._create_full_config(outbound)
    
    def _parse_vmess(self, vmess_str: str) -> Optional[Dict]:
        """Парсит vmess:// ссылку."""
        b64_part = vmess_str[8:]
        
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
        
        if outbound["streamSettings"]["network"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": config_json.get('path', '/'),
                "headers": {
                    "Host": config_json.get('host', '')
                }
            }
        
        if outbound["streamSettings"]["security"] == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": config_json.get('host', ''),
                "allowInsecure": True,
                "fingerprint": "chrome"
            }
        
        return self._create_full_config(outbound)
    
    def _parse_trojan(self, trojan_str: str) -> Optional[Dict]:
        """Парсит trojan:// ссылку."""
        parsed = urllib.parse.urlparse(trojan_str)
        
        if '@' not in parsed.netloc:
            return None
        
        password = parsed.netloc.split('@')[0]
        host_port = parsed.netloc.split('@')[1].split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        
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
        
        if outbound["streamSettings"]["network"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": params.get('path', ['/'])[0],
                "headers": {
                    "Host": params.get('host', [host])[0]
                }
            }
        
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
        """Тестирует один конфиг с логированием ошибок и самого конфига."""
        temp_config = None
        process = None
        
        logger.info(f"🔍 [{index}/{total}] Тестирую: {config_str[:50]}...")
        
        try:
            config_data = self.parse_config(config_str)
            if not config_data:
                logger.warning(f"❌ [{index}/{total}] Не удалось распарсить конфиг")
                return None, None
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(config_data, f, indent=2)
                temp_config = f.name
            
            # Запускаем Xray с захватом stderr
            process = subprocess.Popen(
                [self.xray_path, '-config', temp_config],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Даем время на запуск
            time.sleep(2)
            
            # Проверяем, жив ли процесс
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                logger.error(f"❌ [{index}/{total}] Xray error для конфига {config_str[:100]}...")
                logger.error(f"❌ [{index}/{total}] Ошибка Xray: {stderr[:200]}")
                return None, None
            
            # Тестируем через SOCKS5
            proxies = {
                'http': f'socks5://127.0.0.1:{self.socks_port}',
                'https': f'socks5://127.0.0.1:{self.socks_port}'
            }
            
            try:
                start = time.time()
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
                    logger.warning(f"❌ [{index}/{total}] Не 204: {response.status_code} для конфига {config_str[:100]}...")
                    return None, None
                    
            except requests.Timeout as e:
                logger.warning(f"⏱️ [{index}/{total}] Таймаут для конфига {config_str[:100]}...")
                return None, None
            except requests.ConnectionError as e:
                logger.warning(f"🔌 [{index}/{total}] Ошибка соединения для конфига {config_str[:100]}...")
                logger.warning(f"🔌 [{index}/{total}] Детали: {e}")
                return None, None
                
        except Exception as e:
            logger.error(f"💥 [{index}/{total}] Ошибка для конфига {config_str[:100]}...")
            logger.error(f"💥 [{index}/{total}] Детали: {e}")
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
    print("XRAY TESTER MODULE v1.6")
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
