#!/usr/bin/env python3
"""
FuzzMaster CLI Interface
Command-line interface for the FuzzMaster fuzzing automation tool
"""

import argparse
import sys
import json
import time
from pathlib import Path
from typing import List, Dict, Any
import signal

# FuzzMaster imports
from .core.config import ConfigManager, ScanLevel, FuzzConfig
from .core.engine import FuzzEngine, ScanSession
from .core.analyzer import ResponseAnalyzer
from .utils.output_manager import OutputManager
from .utils.progress_bar import ProgressBar

class FuzzMasterCLI:
    """Main CLI class for FuzzMaster"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.engine = None
        self.analyzer = None
        self.output_manager = OutputManager()
        self.interrupted = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        print("\n[!] Scan interrupted by user")
        self.interrupted = True
        if self.engine:
            self.engine.stop_current_scan()
        sys.exit(0)
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="FuzzMaster - Advanced Web Fuzzing Automation Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  fuzzmaster -u https://example.com -l 1
  fuzzmaster -u https://example.com -l 2 -t 100 -o results.json
  fuzzmaster -u https://example.com -l 3 --recursive -d 0.1
  fuzzmaster -u https://example.com -l 4 -w custom.txt -e php,asp,jsp
  fuzzmaster --list-wordlists
  fuzzmaster --show-profiles
            """
        )
        
        # Main arguments
        parser.add_argument(
            "-u", "--url",
            help="Target URL to fuzz",
            required=False
        )
        
        parser.add_argument(
            "-l", "--level",
            type=int,
            choices=[1, 2, 3, 4],
            default=1,
            help="Scan level (1=Basic, 2=Comprehensive, 3=Deep, 4=Expert)"
        )
        
        # Scan configuration
        parser.add_argument(
            "-t", "--threads",
            type=int,
            help="Number of threads (default: profile-based)"
        )
        
        parser.add_argument(
            "--timeout",
            type=int,
            help="Request timeout in seconds (default: profile-based)"
        )
        
        parser.add_argument(
            "-d", "--delay",
            type=float,
            help="Delay between requests in seconds (default: profile-based)"
        )
        
        parser.add_argument(
            "--recursive",
            action="store_true",
            help="Enable recursive directory scanning"
        )
        
        parser.add_argument(
            "--max-depth",
            type=int,
            help="Maximum recursion depth (default: 3)"
        )
        
        # Wordlists and extensions
        parser.add_argument(
            "-w", "--wordlist",
            action="append",
            help="Custom wordlist file(s) to use"
        )
        
        parser.add_argument(
            "-e", "--extensions",
            help="File extensions to fuzz (comma-separated)"
        )
        
        # Filtering options
        parser.add_argument(
            "-mc", "--match-codes",
            help="Match HTTP status codes (comma-separated)"
        )
        
        parser.add_argument(
            "-fc", "--filter-codes",
            help="Filter HTTP status codes (comma-separated)"
        )
        
        parser.add_argument(
            "--similarity-threshold",
            type=float,
            default=0.9,
            help="Similarity threshold for response clustering (0.0-1.0)"
        )
        
        # Headers and authentication
        parser.add_argument(
            "-H", "--header",
            action="append",
            help="Custom HTTP header (format: 'Name: Value')"
        )
        
        parser.add_argument(
            "--user-agent",
            help="Custom User-Agent string"
        )
        
        parser.add_argument(
            "--cookie",
            help="HTTP Cookie header"
        )
        
        # Output options
        parser.add_argument(
            "-o", "--output",
            help="Output file path"
        )
        
        parser.add_argument(
            "--output-format",
            choices=["json", "csv", "html", "txt"],
            default="json",
            help="Output format (default: json)"
        )
        
        parser.add_argument(
            "--include-errors",
            action="store_true",
            help="Include error responses in output"
        )
        
        parser.add_argument(
            "--no-analysis",
            action="store_true",
            help="Skip intelligent response analysis"
        )
        
        # Stealth options
        parser.add_argument(
            "--stealth",
            action="store_true",
            help="Enable stealth mode (slower but less detectable)"
        )
        
        parser.add_argument(
            "--random-agent",
            action="store_true",
            help="Use random User-Agent strings"
        )
        
        # Information commands
        parser.add_argument(
            "--list-wordlists",
            action="store_true",
            help="List available wordlists"
        )
        
        parser.add_argument(
            "--show-profiles",
            action="store_true",
            help="Show available scan profiles"
        )
        
        parser.add_argument(
            "--version",
            action="version",
            version="FuzzMaster 1.0.0"
        )
        
        # Debug options
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose output"
        )
        
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug output"
        )
        
        return parser
    
    def parse_headers(self, headers: List[str]) -> Dict[str, str]:
        """Parse header strings into dictionary"""
        header_dict = {}
        if headers:
            for header in headers:
                if ': ' in header:
                    key, value = header.split(': ', 1)
                    header_dict[key] = value
                else:
                    print(f"[!] Invalid header format: {header}")
        return header_dict
    
    def parse_extensions(self, extensions: str) -> List[str]:
        """Parse extension string into list"""
        if extensions:
            return [ext.strip() for ext in extensions.split(',')]
        return []
    
    def parse_status_codes(self, codes: str) -> List[int]:
        """Parse status code string into list"""
        if codes:
            try:
                return [int(code.strip()) for code in codes.split(',')]
            except ValueError:
                print(f"[!] Invalid status code format: {codes}")
                return []
        return []
    
    def list_wordlists(self):
        """List available wordlists"""
        print("\n[*] Available Wordlists:")
        print("=" * 50)
        
        wordlists = self.config_manager.list_available_wordlists()
        if wordlists:
            for wordlist in sorted(wordlists):
                path = self.config_manager.get_wordlist_path(wordlist)
                try:
                    with open(path, 'r') as f:
                        line_count = sum(1 for _ in f)
                    print(f"  {wordlist:<20} ({line_count:,} entries)")
                except Exception as e:
                    print(f"  {wordlist:<20} (Error: {e})")
        else:
            print("  No wordlists found")
        
        print()
    
    def show_profiles(self):
        """Show available scan profiles"""
        print("\n[*] Available Scan Profiles:")
        print("=" * 50)
        
        for level in ScanLevel:
            try:
                profile = self.config_manager.load_profile(level)
                print(f"\nLevel {level.value[-1]}: {profile.get('name', 'Unknown')}")
                print(f"  Description: {profile.get('description', 'No description')}")
                print(f"  Threads: {profile.get('threads', 'N/A')}")
                print(f"  Timeout: {profile.get('timeout', 'N/A')}s")
                print(f"  Recursive: {profile.get('recursive', False)}")
                print(f"  Max Depth: {profile.get('max_depth', 'N/A')}")
                print(f"  Wordlists: {', '.join(profile.get('wordlists', []))}")
                print(f"  Extensions: {', '.join(profile.get('extensions', []))}")
                
            except Exception as e:
                print(f"Level {level.value[-1]}: Error loading profile ({e})")
        
        print()
    
    def create_config(self, args) -> FuzzConfig:
        """Create configuration from command line arguments"""
        # Parse scan level
        scan_level = ScanLevel(f"level{args.level}")
        
        # Parse headers
        headers = self.parse_headers(args.header or [])
        
        # Add cookie header if specified
        if args.cookie:
            headers['Cookie'] = args.cookie
        
        # Parse extensions
        extensions = self.parse_extensions(args.extensions)
        
        # Parse status codes
        match_codes = self.parse_status_codes(args.match_codes)
        filter_codes = self.parse_status_codes(args.filter_codes)
        
        # Determine status codes to use
        status_codes = None
        if match_codes:
            status_codes = match_codes
        elif filter_codes:
            # Use default codes minus filtered codes
            default_codes = [200, 301, 302, 307, 308, 403, 405]
            status_codes = [code for code in default_codes if code not in filter_codes]
        
        # Create configuration
        config_kwargs = {
            'target_url': args.url,
            'scan_level': scan_level
        }
        
        # Add optional parameters
        if args.threads:
            config_kwargs['threads'] = args.threads
        if args.timeout:
            config_kwargs['timeout'] = args.timeout
        if args.delay is not None:
            config_kwargs['delay'] = args.delay
        if args.recursive:
            config_kwargs['recursive'] = True
        if args.max_depth:
            config_kwargs['max_depth'] = args.max_depth
        if status_codes:
            config_kwargs['status_codes'] = status_codes
        if extensions:
            config_kwargs['extensions'] = extensions
        if args.wordlist:
            config_kwargs['wordlists'] = args.wordlist
        if args.output_format:
            config_kwargs['output_format'] = args.output_format
        if args.output:
            config_kwargs['output_file'] = args.output
        if args.stealth:
            config_kwargs['stealth_mode'] = True
        if args.user_agent:
            config_kwargs['user_agent'] = args.user_agent
        if headers:
            config_kwargs['headers'] = headers
        
        return self.config_manager.create_config(**config_kwargs)
    
    def run_scan(self, config: FuzzConfig, args) -> ScanSession:
        """Run the fuzzing scan"""
        print(f"\n[*] FuzzMaster - Starting scan")
        print(f"[*] Target: {config.target_url}")
        print(f"[*] Scan Level: {config.scan_level.value}")
        print(f"[*] Threads: {config.threads}")
        print(f"[*] Timeout: {config.timeout}s")
        
        if config.delay:
            print(f"[*] Delay: {config.delay}s")
        if config.recursive:
            print(f"[*] Recursive: Yes (max depth: {config.max_depth})")
        if config.stealth_mode:
            print(f"[*] Stealth Mode: Enabled")
        
        print(f"[*] Extensions: {', '.join(config.extensions) if config.extensions else 'None'}")
        print(f"[*] Wordlists: {', '.join(config.wordlists) if config.wordlists else 'Default'}")
        print(f"[*] Status Codes: {', '.join(map(str, config.status_codes))}")
        print("-" * 60)
        
        # Initialize engine and analyzer
        self.engine = FuzzEngine(config)
        if not args.no_analysis:
            self.analyzer = ResponseAnalyzer(config)
            self.analyzer.similarity_threshold = args.similarity_threshold
        
        # Start the scan
        try:
            session = self.engine.start_scan()
            
            # Show progress
            progress = ProgressBar(session.total_requests)
            
            while not session.is_complete and not self.interrupted:
                time.sleep(0.1)
                progress.update(session.completed_requests)
                
                if args.verbose:
                    # Show recent results
                    recent_results = session.get_recent_results(5)
                    for result in recent_results:
                        print(f"[{result.status_code}] {result.url}")
            
            progress.finish()
            
            if not self.interrupted:
                print(f"\n[*] Scan completed!")
                print(f"[*] Total requests: {session.total_requests}")
                print(f"[*] Completed requests: {session.completed_requests}")
                print(f"[*] Found results: {len(session.results)}")
                
                # Analyze results if enabled
                if self.analyzer and session.results:
                    print(f"[*] Analyzing responses...")
                    analyzed_results = self.analyzer.analyze_responses(session.results)
                    session.analyzed_results = analyzed_results
                    print(f"[*] Unique response patterns: {len(analyzed_results.clusters)}")
                
                return session
            else:
                return session
                
        except Exception as e:
            print(f"[!] Error during scan: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            return None
    
    def save_results(self, session: ScanSession, args):
        """Save scan results to file"""
        if not args.output:
            return
        
        try:
            output_path = Path(args.output)
            
            print(f"[*] Saving results to: {output_path}")
            
            # Prepare results data
            results_data = {
                'scan_info': {
                    'target_url': session.config.target_url,
                    'scan_level': session.config.scan_level.value,
                    'timestamp': session.start_time.isoformat(),
                    'duration': session.duration,
                    'total_requests': session.total_requests,
                    'completed_requests': session.completed_requests,
                    'found_results': len(session.results)
                },
                'results': []
            }
            
            # Add results
            for result in session.results:
                result_data = {
                    'url': result.url,
                    'status_code': result.status_code,
                    'content_length': result.content_length,
                    'response_time': result.response_time,
                    'headers': dict(result.headers) if result.headers else {}
                }
                
                if args.include_errors or result.status_code < 400:
                    results_data['results'].append(result_data)
            
            # Add analysis results if available
            if hasattr(session, 'analyzed_results') and session.analyzed_results:
                results_data['analysis'] = {
                    'clusters': len(session.analyzed_results.clusters),
                    'patterns': session.analyzed_results.get_summary()
                }
            
            # Save in requested format
            if args.output_format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(results_data, f, indent=2)
            
            elif args.output_format == 'csv':
                import csv
                with open(output_path, 'w', newline='') as f:
                    if results_data['results']:
                        writer = csv.DictWriter(f, fieldnames=results_data['results'][0].keys())
                        writer.writeheader()
                        writer.writerows(results_data['results'])
            
            elif args.output_format == 'html':
                html_content = self.output_manager.generate_html_report(results_data)
                with open(output_path, 'w') as f:
                    f.write(html_content)
            
            elif args.output_format == 'txt':
                txt_content = self.output_manager.generate_text_report(results_data)
                with open(output_path, 'w') as f:
                    f.write(txt_content)
            
            print(f"[*] Results saved successfully")
            
        except Exception as e:
            print(f"[!] Error saving results: {e}")
    
    def print_summary(self, session: ScanSession, args):
        """Print scan summary"""
        if not session:
            return
        
        print(f"\n[*] Scan Summary")
        print("=" * 50)
        
        # Basic stats
        print(f"Target URL: {session.config.target_url}")
        print(f"Scan Level: {session.config.scan_level.value}")
        print(f"Duration: {session.duration:.2f}s")
        print(f"Total Requests: {session.total_requests}")
        print(f"Completed: {session.completed_requests}")
        if session.total_requests > 0:
            print(f"Success Rate: {(session.completed_requests/session.total_requests)*100:.1f}%")
        else:
            print("Success Rate: N/A (no requests made)")
        
        # Results by status code
        if session.results:
            status_counts = {}
            for result in session.results:
                status_counts[result.status_code] = status_counts.get(result.status_code, 0) + 1
            
            print(f"\nResults by Status Code:")
            for status_code, count in sorted(status_counts.items()):
                print(f"  {status_code}: {count}")
        
        # Interesting findings
        interesting_results = [r for r in session.results if r.status_code in [200, 301, 302, 403]]
        if interesting_results:
            print(f"\nInteresting Findings:")
            for result in interesting_results[:10]:  # Show top 10
                print(f"  [{result.status_code}] {result.url} ({result.content_length} bytes)")
            
            if len(interesting_results) > 10:
                print(f"  ... and {len(interesting_results) - 10} more")
        
        # Analysis summary
        if hasattr(session, 'analyzed_results') and session.analyzed_results:
            print(f"\nResponse Analysis:")
            print(f"  Unique patterns: {len(session.analyzed_results.clusters)}")
            print(f"  Potential false positives filtered: {session.analyzed_results.filtered_count}")
        
        print()
    
    def run(self):
        """Main CLI entry point"""
        parser = self.create_parser()
        args = parser.parse_args()
        
        # Handle information commands
        if args.list_wordlists:
            self.list_wordlists()
            return
        
        if args.show_profiles:
            self.show_profiles()
            return
        
        # Validate required arguments
        if not args.url:
            print("[!] Error: Target URL is required")
            print("Use --help for usage information")
            sys.exit(1)
        
        # Validate URL format
        if not args.url.startswith(('http://', 'https://')):
            print("[!] Error: URL must start with http:// or https://")
            sys.exit(1)
        
        try:
            # Create configuration
            config = self.create_config(args)
            
            # Run the scan
            session = self.run_scan(config, args)
            
            # Save results if requested
            if args.output and session:
                self.save_results(session, args)
            
            # Print summary
            self.print_summary(session, args)
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Fatal error: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)

def main():
    """Entry point for the CLI"""
    cli = FuzzMasterCLI()
    cli.run()

if __name__ == "__main__":
    main()
