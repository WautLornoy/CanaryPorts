# Copyright (c) 2025 Waut Lornoy
import socket, threading
from canaryports.firewall import Firewall

class Canary:
    def __init__(self, port: int, detection_only: bool):
        self.port = port
        self.detection_only = detection_only
        self.running = True

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._serve)
        self._thread.daemon = True
        self._thread.start()
    
    def _serve(self) -> None:
        while self.running:
            try:
                conn, addr = self._socket.accept()
                conn.close()

                #TODO: Log IP address
                if self.detection_only:
                    Firewall.block_ip(addr)

            except Exception as e:
                pass