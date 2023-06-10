class IPUtils():
    
    @staticmethod
    def _incIP(ip):

            """Increment ip number
            :param ip: Ip to increment
            """

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