from ftplib import FTP
from socket import *
from ..threadscan.threadscan import ThreadScanner


class FtpServiceResult():
    """Ftp scanner result
    
    :param ip: ip address
    :param port: ftp port
    :param banner: server banner
    :param success_login: login attack result
    :param user: user login
    :param password: password login
    """
    def __init__(self, ip, 
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

class FtpScanner():
    """Ftp scanner module
    - Find ftp services
    - Try user/password combo against ftp service
    
    :param max_thread: specify the max number of threads
    :param timeout: specify the timeout of connection
    :param ftp_port: specify ftp port (default=21)

    """
    def __init__(self, max_thread, timeout, ftp_port=21):
        self.anonymous_usr = "anonymous"
        self.anonymous_pwd = "mailme@pass.com"
        self.thread_scanner = ThreadScanner(max_thread,timeout,ftp_port, self._scan_ip)

    def _scan_ip(self, ip):
        """Try to connect to a specific ip address
        :param ip: ip address
        """
        try:
            ftp = FTP()
            ftp.connect(ip, 
                        port=self.thread_scanner.port, 
                        timeout=self.thread_scanner.timeout)

            result = FtpServiceResult(ip,self.thread_scanner.port,ftp.getwelcome(),False,"","")

            try:
                ftp.login(self.anonymous_usr, self.anonymous_pwd)
                result.success_login=True
                result.user = self.anonymous_usr
                result.password = self.anonymous_pwd
                
            except Exception as ex:
                pass
            if not ip in self.thread_scanner.return_ips:
                self.thread_scanner.return_ips.append(result)

            
        except:
            ftp.close()
            if ip in self.thread_scanner.thread_list:
                del self.thread_scanner.thread_list[ip]
            return
        finally:
            ftp.close()
            
        del self.thread_scanner.thread_list[ip]
    
    def scan(self, start_ip, end_ip):
        return self.thread_scanner.scan(start_ip, end_ip)