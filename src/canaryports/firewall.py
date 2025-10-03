# Copyright (c) 2025 Waut Lornoy
import re, threading, json
from abc import ABC, abstractmethod
from canaryports.utils import validate_ipv4, validate_ipv6

class FirewallException(Exception):
    def __init__(self, message):
        super().__init__(message)

class Firewall(ABC):
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, log_path: str):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(Firewall, cls).__new__(cls)
                    cls._instance._initialize(log_path)
        return cls._instance

    def _initialize(self, log_path: str):
        self.log_path = log_path
        self._blocked_ips: list[str] = []
        self._thread_lock = threading.Lock()
        self.restore_blocked_ips()

    @abstractmethod
    def block_ipv4(self, ip_address: str) -> None:
        pass

    @abstractmethod
    def block_ipv6(self, ip_address: str) -> None:
        pass

    def block_ip(self, ip_address: str) -> None:
        if validate_ipv4(ip_address):
            self.block_ipv4(ip_address)
        elif validate_ipv6(ip_address):
            self.block_ipv6(ip_address)
        else:
            raise FirewallException(f"Invalid IP address")
        self.store_blocked_ips()

    @abstractmethod
    def unblock_ipv4(self, ip_address: str) -> None:
        pass

    @abstractmethod    
    def unblock_ipv6(self, ip_address: str) -> None:
        pass

    def unblock_ip(self, ip_address: str) -> None:
        if validate_ipv4(ip_address):
            self.unblock_ipv4(ip_address)
        elif validate_ipv6(ip_address):
            self.unblock_ipv6(ip_address)
        else:
            raise FirewallException("Invalid IP address")
        self.store_blocked_ips()

    def get_blocked_ips(self) -> list[str]:
        with self._thread_lock:
            return self._blocked_ips.copy()

    def clear_blocked_ips(self) -> None:
        with self._thread_lock:
            for ip in list(self._blocked_ips):
                self.unblock_ip(ip)
    
    def store_blocked_ips(self) -> None:
        with open(self.log_path, 'w') as f:
            json.dumps(self._blocked_ips, f)
    
    def restore_blocked_ips(self) -> None:
        with open(self.log_path, 'r') as f:
            self._blocked_ips = json.load(f)
