import subprocess
import re
from typing import Set, List, Optional, Dict
import logging
from dataclasses import dataclass
from datetime import datetime
import sys
import time
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# ASCII Intro Art
INTRO_ART = [
    "\033[32m ▄▄▄▄ ▓██   ██▓ ▄▄▄      \033[0m",
    "▓█████▄▒██  ██▒▒████▄    ",
    "▒██▒ ▄██▒██ ██░▒██  ▀█▄  ",
    "▒██░█▀  ░ ▐██▓░░██▄▄▄▄██ ",
    "░▓█  ▀█▓░ ██▒▓░ ▓█   ▓██▒",
    "░▒▓███▀▒ ██▒▒▒  ▒▒   ▓▒█░",
    "▒░▒   ░▓██ ░▒░   ▒   ▒▒ ░",
    " ░    ░▒ ▒ ░░    ░   ▒   ",
    " ░     ░ ░           ░  ░",
    "      ░░ ░               "
]

@dataclass
class PortScannerConfig:
    """Configuration class for port scanning parameters"""
    NORMAL_PORTS: Set[int] = frozenset([
        80,    # HTTP
        443,   # HTTPS
        22,    # SSH
        21,    # FTP
        25,    # SMTP
        110,   # POP3
        143,   # IMAP
        587,   # SMTP Submission
        3306,  # MySQL
        1433,  # MSSQL
        53,    # DNS
        123,   # NTP
        8080,  # HTTP Alternative
        3389   # RDP
    ])
    MIN_PORT: int = 1
    MAX_PORT: int = 65535
    PRIVILEGED_PORT_THRESHOLD: int = 1024

class PortScanner:
    """A professional port scanning utility class"""
    
    def __init__(self, config: PortScannerConfig = PortScannerConfig()):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.port_info = {}

    def _validate_port(self, port: int) -> bool:
        """Validate if a port number is within acceptable range"""
        return self.config.MIN_PORT <= port <= self.config.MAX_PORT

    def get_open_ports(self) -> Optional[Dict[int, str]]:
        """
        Retrieve currently open ports and their associated PIDs using netstat
        
        Returns:
            Dict mapping port numbers to PID or None if an error occurs
        """
        try:
            self.logger.info("Scanning for open ports...")
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            
            ports = {}
            port_pattern = re.compile(r'(?P<ip>[\d\.:]+):(?P<port>\d+).*?(?P<pid>\d+)$')
            
            for line in result.stdout.splitlines():
                match = port_pattern.search(line)
                if match:
                    try:
                        port = int(match.group("port"))
                        pid = match.group("pid")
                        if self._validate_port(port):
                            ports[port] = pid
                    except ValueError as ve:
                        self.logger.warning(f"Invalid port number encountered: {ve}")
                        continue
            
            self.logger.info(f"Found {len(ports)} open ports")
            return ports
            
        except subprocess.TimeoutExpired:
            self.logger.error("Port scanning timed out")
            return None
        except subprocess.CalledProcessError as cpe:
            self.logger.error(f"Subprocess error during port scanning: {cpe}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error during port scanning: {e}")
            return None

    def get_process_name(self, pid: str) -> str:
        """Get process name from PID using tasklist"""
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"],
                capture_output=True,
                text=True,
                check=True
            )
            # Parse CSV output
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:  # Skip header
                process_info = lines[1].split('","')
                return process_info[0].strip('"')  # Process name
            return "Unknown"
        except Exception:
            return "Unknown"

    def find_abnormal_ports(self, open_ports: Dict[int, str]) -> List[tuple]:
        """
        Identify abnormal ports and their applications
        
        Args:
            open_ports: Dict of port numbers to PIDs
            
        Returns:
            List of tuples (port, app_name)
        """
        if not open_ports:
            return []
            
        abnormal = []
        for port, pid in open_ports.items():
            if (port not in self.config.NORMAL_PORTS and 
                port > self.config.PRIVILEGED_PORT_THRESHOLD):
                app_name = self.get_process_name(pid)
                abnormal.append((port, app_name))
        
        self.logger.debug(f"Found {len(abnormal)} abnormal ports")
        return sorted(abnormal, key=lambda x: x[0])

    def scan_in_background(self) -> None:
        """Perform port scanning in background and store results"""
        open_ports = self.get_open_ports()
        if open_ports is not None:
            self.port_info = {"open_ports": open_ports, 
                            "abnormal_ports": self.find_abnormal_ports(open_ports)}

def main():
    """Main execution function"""
    # Display intro art
    for line in INTRO_ART:
        print(line)
    print("\nAdvanced Port Scanner initializing...")
    
    scanner = PortScanner()
    
    # Start background scanning
    scan_thread = threading.Thread(target=scanner.scan_in_background)
    scan_thread.start()
    
    # Wait 4 seconds
    time.sleep(4)
    
    # Wait for scanning to complete
    scan_thread.join()
    
    # Display results
    if not scanner.port_info:
        print("\n⚠️ Scanning failed!")
        scanner.logger.error("Failed to retrieve port information")
    else:
        open_ports = scanner.port_info["open_ports"]
        abnormal_ports = scanner.port_info["abnormal_ports"]
        
        print(f"\nTotal Open Ports: {len(open_ports)}")
        if abnormal_ports:
            print("\n⚠️ Abnormal Ports Detected:")
            for port, app in abnormal_ports:
                print(f"- Port {port}: Used by {app}")
        else:
            print("\n✅ No abnormal ports detected!")
    
    # Wait for Enter to exit
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()