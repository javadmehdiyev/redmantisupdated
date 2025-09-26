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
from typing import List, Dict, Any
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

class DefaultCredentialScanner:
    def __init__(self):
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

    def detect_service(self, ip: str, port: int) -> str:
        """Port numarasına göre servisi tespit et"""
        service_ports = {
            21: 'ftp',
            22: 'ssh',
            139: 'smb',
            445: 'smb',
            1433: 'mssql',
            1521: 'oracle',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            6379: 'redis',
            27017: 'mongodb'
        }
        
        # Önce port numarasına göre tahmin et
        detected = service_ports.get(port, None)
        if detected:
            return detected
            
        # Banner grabbing ile servisi tespit etmeye çalış
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                sock.send(b'\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').lower()
                sock.close()
                
                if 'ssh' in banner:
                    return 'ssh'
                elif 'ftp' in banner:
                    return 'ftp'
                elif 'mysql' in banner:
                    return 'mysql'
                elif 'postgresql' in banner:
                    return 'postgresql'
                elif 'microsoft' in banner:
                    return 'mssql'
                elif 'redis' in banner:
                    return 'redis'
                elif 'mongodb' in banner:
                    return 'mongodb'
        except:
            pass
            
        return 'unknown'

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
        
        return jsonify({
            'target': f"{ip}:{port}",
            'service': service or scanner.detect_service(ip, int(port)),
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