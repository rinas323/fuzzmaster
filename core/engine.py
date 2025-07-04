"""
FuzzMaster Scanning Engine
Core engine that wraps ffuf and manages the scanning process
"""

import subprocess
import json
import time
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from urllib.parse import urljoin, urlparse

from .config import FuzzConfig, ScanLevel

class ScanType(Enum):
    DIRECTORY = "directory"
    FILE = "file"
    PARAMETER = "parameter"
    SUBDOMAIN = "subdomain"
    EXTENSION = "extension"

@dataclass
class ScanResult:
    """Container for individual scan results"""
    url: str
    status_code: int
    response_size: int
    response_words: int
    response_lines: int
    redirect_location: str = ""
    response_time: float = 0.0
    content_type: str = ""
    scan_type: ScanType = ScanType.DIRECTORY
    
@dataclass
class ScanSession:
    """Container for complete scan session results"""
    target_url: str
    scan_level: ScanLevel
    start_time: float
    end_time: float = 0.0
    total_requests: int = 0
    results: List[ScanResult] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.results is None:
            self.results = []
        if self.errors is None:
            self.errors = []
    
    @property
    def duration(self) -> float:
        """Get scan duration in seconds"""
        end = self.end_time if self.end_time > 0 else time.time()
        return end - self.start_time

class FuzzEngine:
    """Main fuzzing engine that orchestrates all scanning activities"""
    
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.logger = self._setup_logger()
        self.ffuf_path = self._find_ffuf_binary()
        self.session = None
        self.current_scan_process = None
        self.stop_scan = False
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for the engine"""
        logger = logging.getLogger("FuzzMaster")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _find_ffuf_binary(self) -> str:
        """Find ffuf binary in system PATH"""
        try:
            result = subprocess.run(
                ["which", "ffuf"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            # Try common locations
            common_paths = [
                "/usr/local/bin/ffuf",
                "/usr/bin/ffuf",
                "/opt/ffuf/ffuf",
                "./ffuf"
            ]
            
            for path in common_paths:
                if Path(path).exists():
                    return path
            
            raise FileNotFoundError(
                "ffuf binary not found. Please install ffuf or ensure it's in your PATH"
            )
    
    def start_scan(self) -> ScanSession:
        """Start the complete scanning process"""
        self.logger.info(f"Starting FuzzMaster scan on {self.config.target_url}")
        self.logger.info(f"Scan Level: {self.config.scan_level.value}")
        
        self.session = ScanSession(
            target_url=self.config.target_url,
            scan_level=self.config.scan_level,
            start_time=time.time()
        )
        
        try:
            # Execute different scan types based on configuration
            if self.config.scan_level in [ScanLevel.LEVEL1, ScanLevel.LEVEL2]:
                self._run_basic_scans()
            elif self.config.scan_level == ScanLevel.LEVEL3:
                self._run_advanced_scans()
            else:  # LEVEL4
                self._run_expert_scans()
                
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.session.errors.append(str(e))
        finally:
            self.session.end_time = time.time()
            self.logger.info(f"Scan completed in {self.session.duration:.2f} seconds")
            
        return self.session
    
    def _run_basic_scans(self):
        """Execute basic directory and file discovery"""
        self.logger.info("Running basic directory discovery...")
        
        # Directory fuzzing
        dir_results = self._execute_ffuf_scan(
            scan_type=ScanType.DIRECTORY,
            wordlist="common.txt",
            url_pattern=f"{self.config.target_url}/FUZZ"
        )
        self.session.results.extend(dir_results)
        
        # File fuzzing with extensions
        if self.config.extensions:
            self.logger.info("Running file discovery...")
            file_results = self._execute_ffuf_scan(
                scan_type=ScanType.FILE,
                wordlist="files.txt",
                url_pattern=f"{self.config.target_url}/FUZZ",
                extensions=self.config.extensions
            )
            self.session.results.extend(file_results)
    
    def _run_advanced_scans(self):
        """Execute advanced scanning with recursive discovery"""
        # Start with basic scans
        self._run_basic_scans()
        
        # Recursive directory scanning
        if self.config.recursive:
            self.logger.info("Running recursive directory scanning...")
            self._run_recursive_scan()
        
        # Parameter fuzzing
        self.logger.info("Running parameter discovery...")
        param_results = self._execute_ffuf_scan(
            scan_type=ScanType.PARAMETER,
            wordlist="parameters.txt",
            url_pattern=f"{self.config.target_url}?FUZZ=test"
        )
        self.session.results.extend(param_results)
    
    def _run_expert_scans(self):
        """Execute expert-level comprehensive scanning"""
        # Run advanced scans first
        self._run_advanced_scans()
        
        # Subdomain enumeration
        parsed_url = urlparse(self.config.target_url)
        if parsed_url.hostname:
            self.logger.info("Running subdomain enumeration...")
            subdomain_results = self._execute_ffuf_scan(
                scan_type=ScanType.SUBDOMAIN,
                wordlist="subdomains.txt",
                url_pattern=f"https://FUZZ.{parsed_url.hostname}"
            )
            self.session.results.extend(subdomain_results)
        
        # Extension discovery
        self.logger.info("Running extension discovery...")
        ext_results = self._execute_ffuf_scan(
            scan_type=ScanType.EXTENSION,
            wordlist="common.txt",
            url_pattern=f"{self.config.target_url}/FUZZ.EXT",
            extensions=["php", "asp", "aspx", "jsp", "do", "action", "py", "rb", "pl", "cgi"]
        )
        self.session.results.extend(ext_results)
    
    def _run_recursive_scan(self):
        """Run recursive directory scanning on discovered directories"""
        directories = [
            result.url for result in self.session.results 
            if result.scan_type == ScanType.DIRECTORY and result.status_code in [200, 301, 302]
        ]
        
        depth = 1
        while directories and depth <= self.config.max_depth:
            self.logger.info(f"Recursive scan depth {depth} - {len(directories)} directories")
            new_directories = []
            
            for directory in directories:
                if self.stop_scan:
                    break
                    
                # Scan each directory
                recursive_results = self._execute_ffuf_scan(
                    scan_type=ScanType.DIRECTORY,
                    wordlist="common.txt",
                    url_pattern=f"{directory}/FUZZ"
                )
                
                self.session.results.extend(recursive_results)
                
                # Add new directories for next depth level
                new_directories.extend([
                    result.url for result in recursive_results 
                    if result.scan_type == ScanType.DIRECTORY and result.status_code in [200, 301, 302]
                ])
            
            directories = new_directories
            depth += 1
    
    def _execute_ffuf_scan(self, scan_type: ScanType, wordlist: str, url_pattern: str, extensions: List[str] = None) -> List[ScanResult]:
        """Execute a single ffuf scan with specified parameters"""
        if self.stop_scan:
            return []
        
        # Build ffuf command
        cmd = [
            self.ffuf_path,
            "-u", url_pattern,
            "-w", str(Path(__file__).parent.parent / "wordlists" / wordlist),
            "-t", str(self.config.threads),
            "-timeout", str(self.config.timeout),
            "-o", "-",  # Output to stdout
            "-of", "json",  # JSON output format
            "-c",  # Colorized output
            "-v"   # Verbose mode
        ]
        
        # Add status code filtering
        if self.config.status_codes:
            cmd.extend(["-mc", ",".join(map(str, self.config.status_codes))])
        
        # Add delay if specified
        if self.config.delay > 0:
            cmd.extend(["-p", str(self.config.delay)])
        
        # Add headers
        if self.config.headers:
            for key, value in self.config.headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        
        # Add User-Agent
        cmd.extend(["-H", f"User-Agent: {self.config.user_agent}"])
        
        # Add extensions for file scanning
        if extensions and scan_type in [ScanType.FILE, ScanType.EXTENSION]:
            cmd.extend(["-e", ",".join(extensions)])
        
        # Add recursion flag if needed
        if self.config.recursive and scan_type == ScanType.DIRECTORY:
            cmd.extend(["-recursion"])
        
        self.logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            # Execute ffuf command
            self.current_scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = self.current_scan_process.communicate()
            
            if self.current_scan_process.returncode != 0:
                error_msg = f"ffuf execution failed: {stderr}"
                self.logger.error(error_msg)
                self.session.errors.append(error_msg)
                return []
            
            # Parse JSON output
            results = []
            if stdout.strip():
                try:
                    ffuf_output = json.loads(stdout)
                    if "results" in ffuf_output:
                        for result in ffuf_output["results"]:
                            scan_result = ScanResult(
                                url=result.get("url", ""),
                                status_code=result.get("status", 0),
                                response_size=result.get("length", 0),
                                response_words=result.get("words", 0),
                                response_lines=result.get("lines", 0),
                                redirect_location=result.get("redirectlocation", ""),
                                response_time=result.get("duration", 0.0) / 1000000,  # Convert to seconds
                                scan_type=scan_type
                            )
                            results.append(scan_result)
                            
                        self.session.total_requests += len(results)
                        self.logger.info(f"Found {len(results)} results for {scan_type.value} scan")
                        
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse ffuf output: {e}")
                    self.session.errors.append(f"JSON parsing error: {e}")
            
            return results
            
        except Exception as e:
            error_msg = f"Error executing ffuf scan: {e}"
            self.logger.error(error_msg)
            self.session.errors.append(error_msg)
            return []
    
    def stop_current_scan(self):
        """Stop the current running scan"""
        self.stop_scan = True
        if self.current_scan_process:
            self.current_scan_process.terminate()
            self.logger.info("Scan stopped by user")
    
    def get_scan_progress(self) -> Dict[str, Any]:
        """Get current scan progress information"""
        if not self.session:
            return {"status": "not_started"}
        
        return {
            "status": "running" if self.session.end_time == 0 else "completed",
            "duration": self.session.duration,
            "total_requests": self.session.total_requests,
            "results_found": len(self.session.results),
            "errors": len(self.session.errors)
        }

# Example usage
if __name__ == "__main__":
    from .config import ConfigManager, ScanLevel
    
    # Create configuration
    config_manager = ConfigManager()
    config = config_manager.create_config(
        target_url="https://example.com",
        scan_level=ScanLevel.LEVEL2
    )
    
    # Initialize and start scan
    engine = FuzzEngine(config)
    session = engine.start_scan()
    
    print(f"Scan completed: {len(session.results)} results found")
    print(f"Duration: {session.duration:.2f} seconds")
    print(f"Total requests: {session.total_requests}")
