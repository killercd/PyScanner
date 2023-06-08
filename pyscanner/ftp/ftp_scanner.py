from ftplib import FTP

class FtpScanner():
    """Ftp scanner module
    - Find ftp services
    - Try user/password combo against ftp service
    
    
    """
    def __init__(self):
        pass
    
    def scan(self, start_ip, stop_ip):
        """Start ftp scanner
        :param start_ip: Start ip
        :param end_ip: End ip
        :return: returns a list of ip
        """

    def _incIP(self,ip):
        a,b,c,d = ip.split(".")

        a=int(a)
        b=int(b)
        c=int(c)
        d=int(d)

        if d<255:
            d=d+1
        elif c<255:
            c=c+1
            d=0
        elif b<255:
            b=b+1
            d=0
            c=0
        elif a<255:
            a=a+1
            d=0
            c=0
            b=0
        return "{}.{}.{}.{}".format(a,b,c,d)



