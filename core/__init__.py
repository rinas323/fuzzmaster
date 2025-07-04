"""
FuzzMaster - Advanced Web Fuzzing Automation Tool

A comprehensive web fuzzing framework with intelligent analysis,
automated filtering, and multi-level scanning capabilities.
"""

__version__ = "1.0.0"
__author__ = "FuzzMaster Team"
__email__ = "info@fuzzmaster.com"
__license__ = "MIT"

# Core imports
from .config import FuzzConfig, ConfigManager, ScanLevel
from .engine import FuzzEngine, ScanSession
from .analyzer import ResponseAnalyzer
from .filters import FilterManager, ResponseFilter
from ..utils.output_manager import OutputManager
from ..utils.progress_bar import ProgressBar

# Main CLI
from ..cli import FuzzMasterCLI

# Version info
VERSION_INFO = {
    'major': 1,
    'minor': 0,
    'patch': 0,
    'status': 'stable'
}

def get_version():
    """Get the current version string"""
    return __version__

def get_version_info():
    """Get detailed version information"""
    return VERSION_INFO.copy()

# Package metadata
__all__ = [
    # Core classes
    'FuzzConfig',
    'ConfigManager', 
    'ScanLevel',
    'FuzzEngine',
    'ScanSession',
    'ResponseAnalyzer',
    'AnalysisResult',
    'FilterManager',
    'ResponseFilter',
    'OutputManager',
    'ProgressBar',
    
    # CLI
    'FuzzMasterCLI',
    
    # Utility functions
    'get_version',
    'get_version_info',
    
    # Package info
    '__version__',
    '__author__',
    '__email__',
    '__license__',
]

# Initialize logging
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
