#!/usr/bin/env python3
"""
FuzzMaster - Advanced Web Fuzzing Automation Tool
Main entry point for the application
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Main entry point for FuzzMaster"""
    try:
        from fuzzmaster.cli import main as cli_main
        cli_main()
    except ImportError as e:
        print(f"[!] Import error: {e}")
        print("[!] Make sure all required dependencies are installed")
        print("[!] Run: pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Application interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
