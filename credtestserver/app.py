#!/usr/bin/env python3
"""
Default Credential Scanner
Çeşitli servislerde default credential'ları test eder
"""

import socket
import logging
import ssl
import json
import subprocess
import re
import os
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify

# Kütüphaneleri güvenli import et
try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("paramiko bulunamadı - SSH testi devre dışı")

try:
    import ftplib
    FTP_AVAILABLE = True
except ImportError:
    FTP_AVAILABLE = False
    print("ftplib bulunamadı - FTP testi devre dışı")

try:
    from smb.SMBConnection import SMBConnection
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False
    print("pysmb bulunamadı - SMB testi devre dışı")

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("redis bulunamadı - Redis testi devre dışı")

try:
    import pymongo
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("pymongo bulunamadı - MongoDB testi devre dışı")

try:
    import psycopg2
    POSTGRESQL_AVAILABLE = True
except ImportError:
    POSTGRESQL_AVAILABLE = False
    print("psycopg2 bulunamadı - PostgreSQL testi devre dışı")

try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    print("pymysql bulunamadı - MySQL testi devre dışı")

try:
    import pyodbc
    MSSQL_AVAILABLE = True
except ImportError:
    MSSQL_AVAILABLE = False
    print("pyodbc bulunamadı - MSSQL testi devre dışı")

try:
    import cx_Oracle
    ORACLE_AVAILABLE = True
except ImportError:
    ORACLE_AVAILABLE = False
    print("cx_Oracle bulunamadı - Oracle testi devre dışı")

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CredentialTest:
    service: str
    username: str
    password: str
    success: bool

@dataclass
class ServiceDetectionResult:
    service: str
    confidence: int
    version: Optional[str] = None
    description: Optional[str] = None

class DefaultCredentialScanner:
    def __init__(self):
        # Load service detection configuration
        self.service_config = self._load_service_config()
        
        # Yaygın default credential'lar
        self.default_credentials = {
            'ssh': [
                ('root', 'root'), ('admin', 'admin'), ('root', 'toor'), 
                ('root', '123456'), ('admin', 'password'), ('user', 'user'),
                ('pi', 'raspberry'), ('ubuntu', 'ubuntu'), ('centos', 'centos'),
                ('root', ''), ('admin', ''), ('guest', 'guest')
            ],
            'ftp': [
                ('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin'),
                ('root', 'root'), ('user', 'user'), ('guest', 'guest'),
                ('test', 'test'), ('admin', 'password'), ('admin', '123456')
            ],
            'smb': [
                ('guest', ''), ('admin', 'admin'), ('administrator', 'administrator'),
                ('root', 'root'), ('admin', 'password'), ('user', 'user'),
                ('test', 'test'), ('admin', '123456'), ('administrator', 'password')
            ],
            'redis': [
                ('', ''), ('admin', 'admin'), ('redis', 'redis'),
                ('root', 'root'), ('user', 'password')
            ],
            'postgresql': [
                ('postgres', 'postgres'), ('postgres', 'password'), 
                ('postgres', '123456'), ('postgres', 'admin'),
                ('admin', 'admin'), ('root', 'root'), ('postgres', '')
            ],
            'mysql': [
                ('root', ''), ('root', 'root'), ('root', 'password'),
                ('root', '123456'), ('admin', 'admin'), ('mysql', 'mysql'),
                ('user', 'user'), ('root', 'toor')
            ],
            'mssql': [
                ('sa', ''), ('sa', 'password'), ('sa', '123456'),
                ('sa', 'admin'), ('admin', 'admin'), ('root', 'root'),
                ('mssql', 'mssql'), ('sa', 'sa')
            ],
            'oracle': [
                ('system', 'oracle'), ('sys', 'sys'), ('scott', 'tiger'),
                ('oracle', 'oracle'), ('admin', 'admin'), ('hr', 'hr'),
                ('system', 'manager'), ('sys', 'change_on_install')
            ],
            'mongodb': [
                ('admin', ''), ('root', ''), ('admin', 'admin'),
                ('root', 'root'), ('mongodb', 'mongodb'), ('user', 'password')
            ],
            'rdp': [
                ('administrator', 'administrator'), ('admin', 'admin'),
                ('administrator', 'password'), ('administrator', '123456'),
                ('guest', ''), ('user', 'user'), ('root', 'root')
            ]
        }

    def _load_service_config(self) -> Dict:
        """Load service detection configuration from JSON file"""
        try:
            # Look for config file in the parent directory (relative to this script)
            config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'service-detection-config.json')
            
            if not os.path.exists(config_path):
                logger.warning(f"Service detection config not found at {config_path}, using fallback")
                return self._get_fallback_config()
                
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading service config: {e}, using fallback")
            return self._get_fallback_config()
    
    def _get_fallback_config(self) -> Dict:
        """Fallback service configuration if JSON file is not available"""
        return {
            "service_patterns": {},
            "port_service_mapping": {
                "21": "ftp", "22": "ssh", "139": "smb", "445": "smb",
                "1433": "mssql", "1521": "oracle", "3306": "mysql",
                "3389": "rdp", "5432": "postgresql", "6379": "redis", "27017": "mongodb"
            },
            "service_aliases": {"mariadb": "mysql", "postgres": "postgresql"}
        }

    def detect_service_with_confidence(self, ip: str, port: int, banner: str = None) -> ServiceDetectionResult:
        """Intelligent service detection using regex patterns and port mapping"""
        # Get banner if not provided
        if banner is None:
            banner = self._grab_banner(ip, port)
        
        best_match = None
        highest_confidence = 0
        
        # Try regex-based detection first (higher accuracy)
        if banner and len(banner.strip()) > 0:
            for service_name, service_data in self.service_config.get("service_patterns", {}).items():
                for pattern_data in service_data.get("patterns", []):
                    try:
                        match = re.search(pattern_data["regex"], banner)
                        if match:
                            confidence = pattern_data["confidence"]
                            version = None
                            
                            # Extract version if available in match groups
                            # Look for a version number in any of the captured groups
                            version = None
                            if len(match.groups()) > 0:
                                for group in match.groups():
                                    if group and re.match(r'^[\d\.][\d\.\-\w]*$', group):
                                        # Clean up version number (remove trailing hyphens, etc.)
                                        version = re.sub(r'[-]+$', '', group)
                                        break
                                # If no version pattern found, use first group as fallback
                                if not version:
                                    version = match.group(1)
                                    if version:
                                        version = re.sub(r'[-]+$', '', version)
                            
                            if confidence > highest_confidence:
                                credential_service = service_data.get("credential_service", service_name)
                                best_match = ServiceDetectionResult(
                                    service=credential_service,
                                    confidence=confidence,
                                    version=version,
                                    description=pattern_data.get("description", "")
                                )
                                highest_confidence = confidence
                    except re.error as e:
                        logger.warning(f"Regex error for {service_name}: {e}")
                        continue
        
        # If no high-confidence match, try port-based detection
        if highest_confidence < 85:
            port_service = self.service_config.get("port_service_mapping", {}).get(str(port))
            if port_service:
                # Apply service aliases
                port_service = self.service_config.get("service_aliases", {}).get(port_service, port_service)
                if best_match is None or best_match.confidence < 70:
                    best_match = ServiceDetectionResult(
                        service=port_service,
                        confidence=70,
                        description="Port-based detection"
                    )
        
        # Return best match or unknown service
        if best_match:
            return best_match
        else:
            return ServiceDetectionResult(
                service="unknown",
                confidence=0,
                description="Could not detect service"
            )

    def _grab_banner(self, ip: str, port: int) -> str:
        """Grab banner from service for detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Different banner grabbing strategies for different port ranges
                if port in [21, 25, 110, 143, 220]:  # Services that send greeting
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                elif port in [22]:  # SSH
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                elif port in [80, 443, 8080, 8443]:  # HTTP services
                    sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                else:  # Generic banner grab
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                sock.close()
                return banner
        except Exception as e:
            logger.debug(f"Banner grab failed for {ip}:{port} - {e}")
        
        return ""

    def detect_service(self, ip: str, port: int) -> str:
        """Legacy method for backward compatibility"""
        result = self.detect_service_with_confidence(ip, port)
        return result.service

    def test_ssh(self, ip: str, port: int, username: str, password: str) -> bool:
        """SSH bağlantısını test et"""
        if not SSH_AVAILABLE:
            logger.error("SSH testi kullanılamıyor - paramiko kurulu değil")
            return False
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=username, password=password, timeout=10)
            ssh.close()
            return True
        except:
            return False

    def test_ftp(self, ip: str, port: int, username: str, password: str) -> bool:
        """FTP bağlantısını test et"""
        if not FTP_AVAILABLE:
            logger.error("FTP testi kullanılamıyor - ftplib kurulu değil")
            return False
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=10)
            ftp.login(username, password)
            ftp.quit()
            return True
        except:
            return False

    def test_smb(self, ip: str, port: int, username: str, password: str) -> bool:
        """SMB bağlantısını test et"""
        if not SMB_AVAILABLE:
            logger.error("SMB testi kullanılamıyor - pysmb kurulu değil")
            return False
        try:
            conn = SMBConnection(username, password, "scanner", "target", use_ntlm_v2=True)
            result = conn.connect(ip, port, timeout=10)
            conn.close()
            return result
        except:
            return False

    def test_redis(self, ip: str, port: int, username: str, password: str) -> bool:
        """Redis bağlantısını test et"""
        if not REDIS_AVAILABLE:
            logger.error("Redis testi kullanılamıyor - redis kurulu değil")
            return False
        try:
            r = redis.Redis(host=ip, port=port, password=password if password else None, 
                          socket_timeout=10, socket_connect_timeout=10)
            r.ping()
            return True
        except:
            return False

    def test_postgresql(self, ip: str, port: int, username: str, password: str) -> bool:
        """PostgreSQL bağlantısını test et"""
        if not POSTGRESQL_AVAILABLE:
            logger.error("PostgreSQL testi kullanılamıyor - psycopg2 kurulu değil")
            return False
        try:
            conn = psycopg2.connect(
                host=ip, port=port, user=username, password=password,
                database='postgres', connect_timeout=10
            )
            conn.close()
            return True
        except:
            return False

    def test_mysql(self, ip: str, port: int, username: str, password: str) -> bool:
        """MySQL bağlantısını test et"""
        if not MYSQL_AVAILABLE:
            logger.error("MySQL testi kullanılamıyor - pymysql kurulu değil")
            return False
        try:
            conn = pymysql.connect(
                host=ip, port=port, user=username, password=password,
                connect_timeout=10
            )
            conn.close()
            return True
        except:
            return False

    def test_mssql(self, ip: str, port: int, username: str, password: str) -> bool:
        """MSSQL bağlantısını test et"""
        if not MSSQL_AVAILABLE:
            logger.error("MSSQL testi kullanılamıyor - pyodbc kurulu değil")
            return False
        try:
            conn_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={ip},{port};UID={username};PWD={password};Timeout=10"
            conn = pyodbc.connect(conn_str)
            conn.close()
            return True
        except:
            return False

    def test_oracle(self, ip: str, port: int, username: str, password: str) -> bool:
        """Oracle bağlantısını test et"""
        if not ORACLE_AVAILABLE:
            logger.error("Oracle testi kullanılamıyor - cx_Oracle kurulu değil")
            return False
        try:
            dsn = cx_Oracle.makedsn(ip, port, service_name='XE')
            conn = cx_Oracle.connect(username, password, dsn)
            conn.close()
            return True
        except:
            return False

    def test_mongodb(self, ip: str, port: int, username: str, password: str) -> bool:
        """MongoDB bağlantısını test et"""
        if not MONGODB_AVAILABLE:
            logger.error("MongoDB testi kullanılamıyor - pymongo kurulu değil")
            return False
        try:
            if username and password:
                client = pymongo.MongoClient(ip, port, username=username, password=password,
                                           serverSelectionTimeoutMS=10000)
            else:
                client = pymongo.MongoClient(ip, port, serverSelectionTimeoutMS=10000)
            
            client.server_info()
            client.close()
            return True
        except:
            return False

    def test_rdp(self, ip: str, port: int, username: str, password: str) -> bool:
        """RDP bağlantısını test et (xfreerdp kullanarak)"""
        try:
            cmd = [
                'xfreerdp', f'/v:{ip}:{port}', f'/u:{username}', f'/p:{password}',
                '/cert-ignore', '/timeout:10000', '+auth-only'
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=15)
            return result.returncode == 0
        except:
            return False

    def scan_service(self, ip: str, port: int, service: str = None) -> List[CredentialTest]:
        """Belirtilen servis için credential taraması yap"""
        results = []
        
        if not service:
            service = self.detect_service(ip, port)
        
        if service not in self.default_credentials:
            logger.warning(f"Bilinmeyen servis: {service}")
            return results
        
        # Test fonksiyonunu belirle
        test_func = getattr(self, f'test_{service}', None)
        if not test_func:
            logger.error(f"Test fonksiyonu bulunamadı: {service}")
            return results
        
        logger.info(f"{service.upper()} servisi için {ip}:{port} taranıyor...")
        
        for username, password in self.default_credentials[service]:
            try:
                success = test_func(ip, port, username, password)
                result = CredentialTest(
                    service=service,
                    username=username,
                    password=password,
                    success=success
                )
                results.append(result)
                
                if success:
                    logger.info(f"✓ Başarılı: {service} - {username}:{password}")
                else:
                    logger.debug(f"✗ Başarısız: {service} - {username}:{password}")
                    
            except Exception as e:
                logger.error(f"Test hatası {service} {username}:{password} - {e}")
                
        return results

# Flask API
app = Flask(__name__)
scanner = DefaultCredentialScanner()

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """Credential taraması endpoint'i"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        port = data.get('port')
        service = data.get('service', None)
        
        if not ip or not port:
            return jsonify({'error': 'IP ve port gerekli'}), 400
            
        # Port erişilebilirliğini kontrol et
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        
        if result != 0:
            return jsonify({'error': f'Port {ip}:{port} erişilebilir değil'}), 400
        
        # Taramayı başlat
        results = scanner.scan_service(ip, int(port), service)
        
        # Sadece başarılı olan credential'ları filtrele
        successful_results = [result for result in results if result.success]
        json_results = [asdict(result) for result in successful_results]
        
        # Get detailed service detection info
        detection_result = scanner.detect_service_with_confidence(ip, int(port))
        
        return jsonify({
            'target': f"{ip}:{port}",
            'service': service or detection_result.service,
            'detection': {
                'service': detection_result.service,
                'confidence': detection_result.confidence,
                'version': detection_result.version,
                'description': detection_result.description
            },
            'results': json_results,
            'summary': {
                'total_tests': len(results),
                'successful': len(successful_results),
                'failed': len(results) - len(successful_results),
                'vulnerable': len(successful_results) > 0
            }
        })
        
    except Exception as e:
        logger.error(f"Scan hatası: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Sağlık kontrol endpoint'i"""
    return jsonify({'status': 'healthy'})

@app.route('/services', methods=['GET'])
def supported_services():
    """Desteklenen servisleri listele"""
    return jsonify({
        'services': list(scanner.default_credentials.keys()),
        'total': len(scanner.default_credentials)
    })

if __name__ == '__main__':
    print("Default Credential Scanner başlatılıyor...")
    print("Endpoint'ler:")
    print("  POST /scan - Credential taraması")
    print("  GET  /health - Sağlık kontrolü") 
    print("  GET  /services - Desteklenen servisler")
    print("\nÖrnek kullanım:")
    print('curl -X POST http://localhost:5000/scan -H "Content-Type: application/json" -d \'{"ip": "192.168.1.100", "port": 22}\'')
    
    app.run(host='0.0.0.0', port=8081, debug=False)