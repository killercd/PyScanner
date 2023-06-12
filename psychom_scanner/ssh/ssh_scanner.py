from ..threadscan.threadscan import ThreadScanner
import paramiko
from socket import *


class SSHServiceResult():
    """SSH scanner result
    
    :param ip: ip address
    :param port: ssh port
    :param banner: server banner
    :param success_login: login attack result
    :param user: user login
    :param password: password login
    """

    def __init__(self, 
                 ip, 
                port, 
                banner, 
                success_login, 
                user, 
                password):
        self.ip = ip
        self.port = port
        self.banner = banner
        self.success_login = success_login
        self.user = user
        self.password = password
    
    def __str__(self):
        if self.user:
            return "{}:{} ({}) - {}/{}".format(self.ip, str(self.port), self.banner, self.user, self.password)
        return "{}:{} ({})".format(self.ip, str(self.port), self.banner)


class SSHScanner():
    
    """SSH scanner module
    - Find ssh services
    - Try user/password combo against ssh service
    
    :param max_thread: specify the max number of threads
    :param timeout: specify the timeout of connection
    :param ssh_port: specify ssh port (default=22)

    """
    
    def __init__(self, max_thread, timeout, ssh_port=22):
        self.thread_scanner = ThreadScanner(max_thread, timeout, ssh_port, self._scan_ip)

        
        
    def _scan_ip(self, ip):
        """Try to connect to a specific ip address
        :param ip: ip address
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connSkt = None
        try:
            connSkt = socket(AF_INET, SOCK_STREAM)
            connSkt.settimeout(self.timeout)
            connSkt.connect((ip, self.thread_scanner.port))
        
        except:
            connSkt.close()
            try:
                del self.thread_list[ip]
            except:
                pass
            return
        finally:
            connSkt.close()
        
    