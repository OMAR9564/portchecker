import subprocess
import re
from typing import Set, List, Optional
import logging
from dataclasses import dataclass
from datetime import datetime
import sys

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

    def _validate_port(self, port: int) -> bool:
        """Validate if a port number is within acceptable range"""
        return self.config.MIN_PORT <= port <= self.config.MAX_PORT

    def get_open_ports(self) -> Optional[Set[int]]:
        """
        Retrieve currently open ports using netstat command
        
        Returns:
            Set of open port numbers or None if an error occurs
        """
        try:
            self.logger.info("Scanning for open ports...")
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30  # 30-second timeout
            )
            
            ports = set()
            port_pattern = re.compile(r'(?P<ip>[\d\.:]+):(?P<port>\d+)')
            
            for line in result.stdout.splitlines():
                match = port_pattern.search(line)
                if match:
                    try:
                        port = int(match.group("port"))
                        if self._validate_port(port):
                            ports.add(port)
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

    def find_abnormal_ports(self, open_ports: Set[int]) -> List[int]:
        """
        Identify abnormal ports from the set of open ports
        
        Args:
            open_ports: Set of currently open ports
            
        Returns:
            List of ports considered abnormal
        """
        if not open_ports:
            return []
            
        abnormal = [
            port for port in open_ports 
            if port not in self.config.NORMAL_PORTS 
            and port > self.config.PRIVILEGED_PORT_THRESHOLD
        ]
        
        self.logger.debug(f"Found {len(abnormal)} abnormal ports")
        return sorted(abnormal)

    def generate_report(self, open_ports: Set[int], abnormal_ports: List[int]) -> str:
        """Generate a detailed report of the scan results"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = [
            f"Port Scan Report - {timestamp}",
            "=" * 50,
            f"Total Open Ports: {len(open_ports)}",
            f"Abnormal Ports Detected: {len(abnormal_ports)}",
            "-" * 50
        ]
        
        if abnormal_ports:
            report.append("Abnormal Ports:")
            for port in abnormal_ports:
                report.append(f"  - Port {port}: Potential security concern")
        else:
            report.append("No abnormal ports detected ✓")
            
        return "\n".join(report)

def main():
    """Main execution function"""
    # Display intro art
    for line in INTRO_ART:
        print(line)
    print("\nAdvanced Port Scanner initializing...\n")
    
    scanner = PortScanner()
    
    # Get open ports
    open_ports = scanner.get_open_ports()
    if open_ports is None:
        scanner.logger.error("Failed to retrieve open ports. Exiting.")
        sys.exit(1)
    
    # Analyze for abnormal ports
    abnormal_ports = scanner.find_abnormal_ports(open_ports)
    
    # Generate and display report
    report = scanner.generate_report(open_ports, abnormal_ports)
    print(report)
    
    # Exit with appropriate status code
    sys.exit(1 if abnormal_ports else 0)

if __name__ == "__main__":
    main()
