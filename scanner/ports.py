import socket

class PortScanner:
    def __init__(self):
        # Common ports to check (FTP, SSH, HTTP, HTTPS, MySQL)
        self.ports = [21, 22, 80, 443, 3306, 8080]

    def scan(self, ip):
        open_ports = []
        # Set a short timeout so the scan is fast
        socket.setdefaulttimeout(0.5)
        
        for port in self.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except:
                pass
        return open_ports