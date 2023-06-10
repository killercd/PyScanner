from threading import Thread
from ..tcp.IPScanner import IPUtils

class ThreadScanner():

    """Thread scanner module 
        
    :param max_thread: specify the max number of threads
    :param timeout: specify the timeout of connection
    :param scanip_f: scanner ip function handler

    """

    def __init__(self, max_thread, 
                 timeout, 
                 port,
                 scanip_f
                 ):
        self.forced_exit = False
        self.max_thread = max_thread
        self.thread_list = {}
        self.timeout = timeout
        self.port = port
        self.return_ips = []
        self.scanip_f = scanip_f

        
    def scan(self, start_ip, stop_ip):
        
        """Start multithreading ip scanner
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
                t = Thread(target=self.scanip_f, args=(ip,))
                t.start()
                self.thread_list[ip] = t
        
            start_ip = IPUtils._incIP(start_ip)
            while len(self.thread_list)>0:
                pass
        
        if ip in self.thread_list:
            del self.thread_list[ip]
        
        return self.return_ips