# Dependencies for host class
from socket import *
import multiprocessing


class Host:
    def __init__(self, dest, addr):
        self.ip = dest
        self.mac = addr
        self.ports = []

    # Scan the port of the number given
    def port_scanner(self, port_num):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(1)
        conn = s.connect_ex((self.ip, port_num))
        if (conn == 0):
            self.ports.append(port_num)
        s.close()

    # Sets up for multiprocessing
    def scan_ports(self, start, end, verb):
        if verb:
            print('Starting scan on host: ', self.ip)
        pool = multiprocessing.Pool()
        try:
            pool.map(self.port_scanner, range(start, end))
            if verb:
                for port in self.ports:
                    print(f"\tPost {port}: OPEN")
        except:
            print("Error occured!!!")
