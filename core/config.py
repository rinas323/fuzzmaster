"""
FuzzMaster Configuration System
Handles all configuration management, profiles, and settings
"""

import yaml
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ScanLevel(Enum):
    LEVEL1 = "level1"  # Basic discovery
    LEVEL2 = "level2"  # Comprehensive scan
    LEVEL3 = "level3"  # Deep analysis
    LEVEL4 = "level4"  # Expert mode

@dataclass
class FuzzConfig:
    """Main configuration class for FuzzMaster"""
    target_url: str
    scan_level: ScanLevel = ScanLevel.LEVEL1
    threads: int = 50
    timeout: int = 10
    delay: float = 0.0
    follow_redirects: bool = True
    recursive: bool = False
    max_depth: int = 3
    status_codes: List[int] = None
    extensions: List[str] = None
    wordlists: List[str] = None
    output_format: str = "json"
    output_file: str = None
    stealth_mode: bool = False
    user_agent: str = None
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.status_codes is None:
            self.status_codes = [200, 301, 302, 307, 308, 403, 405]
        if self.extensions is None:
            self.extensions = ["php", "html", "txt", "js", "css", "json", "xml"]
        if self.headers is None:
            self.headers = {}
        if self.user_agent is None:
            self.user_agent = "FuzzMaster/1.0"

class ConfigManager:
    """Manages configuration loading, saving, and profile management"""
    
    def __init__(self, config_dir: str = None):
        self.config_dir = Path(config_dir) if config_dir else Path(__file__).parent.parent
        self.profiles_dir = self.config_dir / "profiles"
        self.wordlists_dir = self.config_dir / "wordlists"
        self.default_config_file = self.config_dir / "config.yaml"
        
        # Create directories if they don't exist
        self.profiles_dir.mkdir(exist_ok=True)
        self.wordlists_dir.mkdir(exist_ok=True)
        
        # Load default configuration
        self.default_config = self._load_default_config()
        
        # Initialize scan level profiles
        self._initialize_profiles()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration from file or create it"""
        default_config = {
            "general": {
                "threads": 50,
                "timeout": 10,
                "delay": 0.0,
                "follow_redirects": True,
                "user_agent": "FuzzMaster/1.0"
            },
            "filtering": {
                "status_codes": [200, 301, 302, 307, 308, 403, 405],
                "min_response_size": 0,
                "max_response_size": 0,
                "exclude_patterns": [],
                "content_filters": {
                    "enable_smart_filtering": True,
                    "similarity_threshold": 0.9,
                    "error_detection": True
                }
            },
            "wordlists": {
                "default_directory": ["common.txt", "directories.txt"],
                "default_files": ["files.txt", "common.txt"],
                "default_parameters": ["parameters.txt"],
                "default_subdomains": ["subdomains.txt"]
            },
            "output": {
                "format": "json",
                "include_errors": False,
                "include_filtered": False,
                "screenshot": False
            }
        }
        
        if self.default_config_file.exists():
            try:
                with open(self.default_config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    return {**default_config, **loaded_config}
            except Exception as e:
                print(f"Error loading config file: {e}")
                return default_config
        else:
            # Create default config file
            with open(self.default_config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            return default_config
    
    def _initialize_profiles(self):
        """Initialize scan level profiles"""
        profiles = {
            "level1": {
                "name": "Basic Discovery",
                "description": "Fast scan with common directories and files",
                "threads": 30,
                "timeout": 5,
                "delay": 0.1,
                "recursive": False,
                "max_depth": 1,
                "wordlists": ["common.txt"],
                "extensions": ["html", "php", "txt"],
                "status_codes": [200, 301, 302, 403],
                "filters": {
                    "enable_smart_filtering": True,
                    "similarity_threshold": 0.95
                }
            },
            "level2": {
                "name": "Comprehensive Scan",
                "description": "Thorough scan with extended wordlists",
                "threads": 50,
                "timeout": 10,
                "delay": 0.05,
                "recursive": True,
                "max_depth": 2,
                "wordlists": ["common.txt", "directories.txt", "files.txt"],
                "extensions": ["php", "html", "txt", "js", "css", "json", "xml", "asp", "aspx"],
                "status_codes": [200, 301, 302, 307, 308, 403, 405],
                "filters": {
                    "enable_smart_filtering": True,
                    "similarity_threshold": 0.9
                }
            },
            "level3": {
                "name": "Deep Analysis",
                "description": "Advanced scan with custom wordlists and analysis",
                "threads": 75,
                "timeout": 15,
                "delay": 0.02,
                "recursive": True,
                "max_depth": 3,
                "wordlists": ["common.txt", "directories.txt", "files.txt", "parameters.txt"],
                "extensions": ["php", "html", "txt", "js", "css", "json", "xml", "asp", "aspx", "jsp", "do", "action"],
                "status_codes": [200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500],
                "filters": {
                    "enable_smart_filtering": True,
                    "similarity_threshold": 0.85,
                    "content_analysis": True
                }
            },
            "level4": {
                "name": "Expert Mode",
                "description": "Maximum coverage with all techniques",
                "threads": 100,
                "timeout": 20,
                "delay": 0.01,
                "recursive": True,
                "max_depth": 5,
                "wordlists": ["common.txt", "directories.txt", "files.txt", "parameters.txt", "subdomains.txt"],
                "extensions": ["php", "html", "txt", "js", "css", "json", "xml", "asp", "aspx", "jsp", "do", "action", "py", "rb", "pl", "cgi"],
                "status_codes": [200, 201, 204, 301, 302, 304, 307, 308, 400, 401, 403, 405, 500, 501, 502, 503],
                "filters": {
                    "enable_smart_filtering": True,
                    "similarity_threshold": 0.8,
                    "content_analysis": True,
                    "ml_classification": True
                }
            }
        }
        
        for level, config in profiles.items():
            profile_file = self.profiles_dir / f"{level}.yaml"
            if not profile_file.exists():
                with open(profile_file, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False)
    
    def load_profile(self, level: ScanLevel) -> Dict[str, Any]:
        """Load a specific scan level profile"""
        profile_file = self.profiles_dir / f"{level.value}.yaml"
        if profile_file.exists():
            with open(profile_file, 'r') as f:
                return yaml.safe_load(f)
        else:
            raise FileNotFoundError(f"Profile {level.value} not found")
    
    def create_config(self, target_url: str, scan_level: ScanLevel, **kwargs) -> FuzzConfig:
        """Create a FuzzConfig instance with profile and custom settings"""
        profile = self.load_profile(scan_level)
        # List of valid FuzzConfig fields
        valid_fields = {
            'target_url', 'scan_level', 'threads', 'timeout', 'delay', 'follow_redirects',
            'recursive', 'max_depth', 'status_codes', 'extensions', 'wordlists',
            'output_format', 'output_file', 'stealth_mode', 'user_agent', 'headers'
        }
        config_dict = {
            "target_url": target_url,
            "scan_level": scan_level,
            **{k: v for k, v in profile.items() if k in valid_fields},
            **{k: v for k, v in kwargs.items() if k in valid_fields}
        }
        return FuzzConfig(**config_dict)
    
    def get_wordlist_path(self, wordlist_name: str) -> Path:
        """Get the full path to a wordlist file"""
        return self.wordlists_dir / wordlist_name
    
    def list_available_wordlists(self) -> List[str]:
        """List all available wordlist files"""
        return [f.name for f in self.wordlists_dir.glob("*.txt")]
    
    def save_config(self, config: FuzzConfig, filename: str = None):
        """Save configuration to file"""
        if filename is None:
            filename = f"config_{config.scan_level.value}.yaml"
        
        config_file = self.config_dir / filename
        config_dict = {
            "target_url": config.target_url,
            "scan_level": config.scan_level.value,
            "threads": config.threads,
            "timeout": config.timeout,
            "delay": config.delay,
            "follow_redirects": config.follow_redirects,
            "recursive": config.recursive,
            "max_depth": config.max_depth,
            "status_codes": config.status_codes,
            "extensions": config.extensions,
            "wordlists": config.wordlists,
            "output_format": config.output_format,
            "output_file": config.output_file,
            "stealth_mode": config.stealth_mode,
            "user_agent": config.user_agent,
            "headers": config.headers
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False)
        
        print(f"Configuration saved to {config_file}")

# Example usage
if __name__ == "__main__":
    # Initialize configuration manager
    config_manager = ConfigManager()
    
    # Create a Level 2 configuration
    config = config_manager.create_config(
        target_url="https://example.com",
        scan_level=ScanLevel.LEVEL2,
        threads=75,
        output_format="html"
    )
    
    print(f"Created configuration for {config.target_url}")
    print(f"Scan Level: {config.scan_level.value}")
    print(f"Threads: {config.threads}")
    print(f"Extensions: {config.extensions}")
