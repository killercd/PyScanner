from ftplib import FTP
from ..tcp.IPScanner import IPUtils
import time
from threading import Thread
from socket import *



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
        self.forced_exit = False
        self.max_thread = max_thread
        self.thread_list = {}
        self.timeout = timeout
        self.ftp_port = ftp_port
        self.return_ips = []
        self.anonymous_usr = "anonymous"
        self.anonymous_pwd = "mailme@pass.com"

    def _scan_ip(self, ip):
        """Try to connect to a specific ip address
        :param ip: ip address
        """
        try:

            ftp = FTP()
            ftp.connect(ip, port=self.ftp_port, timeout=self.timeout)
            
            result = FtpServiceResult(ip,self.ftp_port,ftp.getwelcome(),False,"","")
            
            try:
                ftp.login(self.anonymous_usr, self.anonymous_pwd)
                result.success_login=True
                result.user = self.anonymous_usr
                result.password = self.anonymous_pwd
                
            except Exception as ex:
                pass
            if not ip in self.return_ips:
                self.return_ips.append(result)

            
        except:
            ftp.close()
            if ip in self.thread_list:
                del self.thread_list[ip]
            return
        finally:
            ftp.close()
            
        del self.thread_list[ip]
    
    def scan(self, start_ip, stop_ip):
        
        """Start ftp scanner
        :param start_ip: Start ip
        :param end_ip: End ip
        
        :return: returns a list of ip
        """
        
        while start_ip!=stop_ip:
            if self.forced_exit:
                return
            
            if len(self.thread_list)>=self.max_thread:
                pass
            else:
                ip = start_ip
                t = Thread(target=self._scan_ip, args=(ip,))
                t.start()
                self.thread_list[ip] = t
        
            start_ip = IPUtils._incIP(start_ip)
            while len(self.thread_list)>0:
                pass
        
        if ip in self.thread_list:
            del self.thread_list[ip]
        
        return self.return_ips