"""
FuzzMaster Response Analyzer
Intelligent analysis and filtering of fuzzing results
"""

import requests
import hashlib
import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import difflib
import logging
from urllib.parse import urljoin, urlparse
import time

from .config import FuzzConfig
from .engine import ScanResult, ScanSession

@dataclass
class ResponseProfile:
    """Profile of a response for similarity analysis"""
    content_hash: str
    content_length: int
    word_count: int
    line_count: int
    title: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error_indicators: List[str] = field(default_factory=list)
    content_type: str = ""
    response_time: float = 0.0
    
@dataclass
class ContentCluster:
    """Group of similar responses"""
    cluster_id: str
    representative_url: str
    similar_urls: List[str] = field(default_factory=list)
    response_profile: ResponseProfile = None
    confidence: float = 0.0
    is_error_page: bool = False
    is_interesting: bool = False

class ResponseAnalyzer:
    """Intelligent response analyzer for filtering and categorizing results"""
    
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.logger = logging.getLogger("FuzzMaster.Analyzer")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.user_agent,
            **config.headers
        })
        
        # Analysis state
        self.response_profiles: Dict[str, ResponseProfile] = {}
        self.content_clusters: List[ContentCluster] = []
        self.error_patterns = self._load_error_patterns()
        self.interesting_patterns = self._load_interesting_patterns()
        
        # Similarity thresholds
        self.similarity_threshold = 0.9
        self.min_cluster_size = 3
        
    def _load_error_patterns(self) -> List[str]:
        """Load common error page patterns"""
        return [
            r"404.*not found",
            r"403.*forbidden",
            r"500.*internal server error",
            r"access denied",
            r"page not found",
            r"file not found",
            r"directory not found",
            r"unauthorized",
            r"permission denied",
            r"error.*occurred",
            r"something went wrong",
            r"default.*page",
            r"coming soon",
            r"under construction",
            r"maintenance mode"
        ]
    
    def _load_interesting_patterns(self) -> List[str]:
        """Load patterns that indicate interesting content"""
        return [
            r"admin",
            r"login",
            r"dashboard",
            r"config",
            r"backup",
            r"database",
            r"api",
            r"upload",
            r"download",
            r"password",
            r"secret",
            r"private",
            r"internal",
            r"debug",
            r"test",
            r"dev",
            r"staging",
            r"beta",
            r"\.git",
            r"\.svn",
            r"\.env",
            r"web\.config",
            r"\.htaccess",
            r"robots\.txt",
            r"sitemap\.xml"
        ]
    
    def analyze_session(self, session: ScanSession) -> ScanSession:
        """Analyze complete scan session and filter results"""
        self.logger.info(f"Analyzing {len(session.results)} scan results...")
        
        # Step 1: Fetch response content for analysis
        self._fetch_response_content(session.results)
        
        # Step 2: Create response profiles
        self._create_response_profiles(session.results)
        
        # Step 3: Cluster similar responses
        self._cluster_similar_responses()
        
        # Step 4: Identify error pages and false positives
        self._identify_error_pages()
        
        # Step 5: Score and rank interesting results
        filtered_results = self._filter_and_rank_results(session.results)
        
        # Update session with filtered results
        session.results = filtered_results
        
        self.logger.info(f"Analysis complete: {len(filtered_results)} results after filtering")
        return session
    
    def _fetch_response_content(self, results: List[ScanResult], max_workers: int = 10):
        """Fetch response content for analysis"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def fetch_content(result: ScanResult) -> Tuple[ScanResult, Optional[str], Optional[Dict]]:
            try:
                response = self.session.get(
                    result.url,
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects,
                    verify=False  # Skip SSL verification for testing
                )
                
                # Update result with response info
                result.status_code = response.status_code
                result.response_size = len(response.content)
                result.content_type = response.headers.get('Content-Type', '')
                
                return result, response.text, dict(response.headers)
                
            except Exception as e:
                self.logger.debug(f"Error fetching {result.url}: {e}")
                return result, None, None
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(fetch_content, result) for result in results]
            
            for future in as_completed(futures):
                result, content, headers = future.result()
                if content is not None:
                    # Store content for analysis
                    result.content = content
                    result.headers = headers
    
    def _create_response_profiles(self, results: List[ScanResult]):
        """Create response profiles for similarity analysis"""
        for result in results:
            if not hasattr(result, 'content') or result.content is None:
                continue
                
            # Create content hash
            content_hash = hashlib.md5(result.content.encode()).hexdigest()
            
            # Extract title
            title = ""
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', result.content, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
            
            # Count words and lines
            word_count = len(result.content.split())
            line_count = result.content.count('\n')
            
            # Check for error indicators
            error_indicators = []
            content_lower = result.content.lower()
            for pattern in self.error_patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    error_indicators.append(pattern)
            
            # Create profile
            profile = ResponseProfile(
                content_hash=content_hash,
                content_length=len(result.content),
                word_count=word_count,
                line_count=line_count,
                title=title,
                headers=getattr(result, 'headers', {}),
                error_indicators=error_indicators,
                content_type=result.content_type,
                response_time=result.response_time
            )
            
            self.response_profiles[result.url] = profile
    
    def _cluster_similar_responses(self):
        """Cluster similar responses together"""
        # Group by content hash first (exact matches)
        hash_groups = defaultdict(list)
        for url, profile in self.response_profiles.items():
            hash_groups[profile.content_hash].append(url)
        
        cluster_id = 0
        
        for content_hash, urls in hash_groups.items():
            if len(urls) >= self.min_cluster_size:
                # Create cluster for exact matches
                representative_url = urls[0]
                cluster = ContentCluster(
                    cluster_id=f"cluster_{cluster_id}",
                    representative_url=representative_url,
                    similar_urls=urls[1:],
                    response_profile=self.response_profiles[representative_url],
                    confidence=1.0  # Exact match
                )
                self.content_clusters.append(cluster)
                cluster_id += 1
        
        # Now check for similar content (fuzzy matching)
        processed_urls = set()
        for cluster in self.content_clusters:
            processed_urls.update([cluster.representative_url] + cluster.similar_urls)
        
        remaining_urls = [url for url in self.response_profiles.keys() if url not in processed_urls]
        
        # Fuzzy matching for remaining URLs
        for i, url1 in enumerate(remaining_urls):
            if url1 in processed_urls:
                continue
                
            similar_urls = [url1]
            profile1 = self.response_profiles[url1]
            
            for url2 in remaining_urls[i+1:]:
                if url2 in processed_urls:
                    continue
                    
                profile2 = self.response_profiles[url2]
                similarity = self._calculate_similarity(profile1, profile2)
                
                if similarity >= self.similarity_threshold:
                    similar_urls.append(url2)
                    processed_urls.add(url2)
            
            if len(similar_urls) >= self.min_cluster_size:
                cluster = ContentCluster(
                    cluster_id=f"cluster_{cluster_id}",
                    representative_url=url1,
                    similar_urls=similar_urls[1:],
                    response_profile=profile1,
                    confidence=self.similarity_threshold
                )
                self.content_clusters.append(cluster)
                processed_urls.add(url1)
                cluster_id += 1
    
    def _calculate_similarity(self, profile1: ResponseProfile, profile2: ResponseProfile) -> float:
        """Calculate similarity between two response profiles"""
        # Multiple similarity factors
        factors = []
        
        # Content length similarity
        if profile1.content_length > 0 and profile2.content_length > 0:
            length_ratio = min(profile1.content_length, profile2.content_length) / max(profile1.content_length, profile2.content_length)
            factors.append(length_ratio)
        
        # Word count similarity
        if profile1.word_count > 0 and profile2.word_count > 0:
            word_ratio = min(profile1.word_count, profile2.word_count) / max(profile1.word_count, profile2.word_count)
            factors.append(word_ratio)
        
        # Title similarity
        if profile1.title and profile2.title:
            title_similarity = difflib.SequenceMatcher(None, profile1.title.lower(), profile2.title.lower()).ratio()
            factors.append(title_similarity)
        
        # Content type similarity
        if profile1.content_type and profile2.content_type:
            content_type_match = 1.0 if profile1.content_type == profile2.content_type else 0.5
            factors.append(content_type_match)
        
        # Error indicators similarity
        if profile1.error_indicators and profile2.error_indicators:
            common_errors = set(profile1.error_indicators) & set(profile2.error_indicators)
            total_errors = set(profile1.error_indicators) | set(profile2.error_indicators)
            if total_errors:
                error_similarity = len(common_errors) / len(total_errors)
                factors.append(error_similarity)
        
        # Return average of all factors
        return sum(factors) / len(factors) if factors else 0.0
    
    def _identify_error_pages(self):
        """Identify clusters that represent error pages"""
        for cluster in self.content_clusters:
            profile = cluster.response_profile
            
            # Check for error indicators
            if profile.error_indicators:
                cluster.is_error_page = True
                continue
            
            # Check for common error status codes with generic content
            if cluster.representative_url.split('/')[-1] in ['404', '403', '500', 'error']:
                cluster.is_error_page = True
                continue
            
            # Check for very small or very large responses (often errors)
            if profile.content_length < 100 or profile.content_length > 100000:
                cluster.is_error_page = True
                continue
            
            # Check title for error indicators
            if profile.title:
                title_lower = profile.title.lower()
                if any(error in title_lower for error in ['error', 'not found', 'forbidden', 'denied']):
                    cluster.is_error_page = True
                    continue
    
    def _filter_and_rank_results(self, results: List[ScanResult]) -> List[ScanResult]:
        """Filter and rank results based on analysis"""
        filtered_results = []
        
        # Create URL to cluster mapping
        url_to_cluster = {}
        for cluster in self.content_clusters:
            url_to_cluster[cluster.representative_url] = cluster
            for url in cluster.similar_urls:
                url_to_cluster[url] = cluster
        
        for result in results:
            # Skip if part of an error page cluster
            if result.url in url_to_cluster:
                cluster = url_to_cluster[result.url]
                if cluster.is_error_page:
                    continue
                
                # Only keep representative URL from each cluster
                if result.url != cluster.representative_url:
                    continue
            
            # Calculate interest score
            interest_score = self._calculate_interest_score(result)
            result.interest_score = interest_score
            
            # Filter based on interest score
            if interest_score > 0.3:  # Threshold for interesting content
                filtered_results.append(result)
        
        # Sort by interest score (descending)
        filtered_results.sort(key=lambda x: getattr(x, 'interest_score', 0), reverse=True)
        
        return filtered_results
    
    def _calculate_interest_score(self, result: ScanResult) -> float:
        """Calculate interest score for a result"""
        score = 0.0
        
        # Base score from status code
        status_scores = {
            200: 0.8,
            301: 0.6,
            302: 0.6,
            403: 0.5,  # Often indicates protected content
            401: 0.7,  # Authentication required
            500: 0.3   # Might indicate vulnerable endpoint
        }
        score += status_scores.get(result.status_code, 0.1)
        
        # URL pattern analysis
        url_lower = result.url.lower()
        for pattern in self.interesting_patterns:
            if re.search(pattern, url_lower, re.IGNORECASE):
                score += 0.2
        
        # Content analysis (if available)
        if hasattr(result, 'content') and result.content:
            content_lower = result.content.lower()
            
            # Look for interesting keywords in content
            interesting_keywords = [
                'login', 'password', 'admin', 'config', 'database',
                'api', 'key', 'secret', 'token', 'upload', 'download'
            ]
            
            for keyword in interesting_keywords:
                if keyword in content_lower:
                    score += 0.1
        
        # Response size factor (very small or very large might be less interesting)
        if 100 < result.response_size < 50000:
            score += 0.1
        
        # Response time factor (very slow responses might indicate processing)
        if result.response_time > 2.0:
            score += 0.1
        
        return min(score, 1.0)  # Cap at 1.0
    
    def get_analysis_summary(self) -> Dict:
        """Get summary of analysis results"""
        total_clusters = len(self.content_clusters)
        error_clusters = sum(1 for cluster in self.content_clusters if cluster.is_error_page)
        interesting_clusters = sum(1 for cluster in self.content_clusters if cluster.is_interesting)
        
        return {
            'total_responses_analyzed': len(self.response_profiles),
            'total_clusters': total_clusters,
            'error_clusters': error_clusters,
            'interesting_clusters': interesting_clusters,
            'similarity_threshold': self.similarity_threshold,
            'clusters': [
                {
                    'id': cluster.cluster_id,
                    'representative_url': cluster.representative_url,
                    'similar_count': len(cluster.similar_urls),
                    'is_error_page': cluster.is_error_page,
                    'is_interesting': cluster.is_interesting,
                    'confidence': cluster.confidence
                }
                for cluster in self.content_clusters
            ]
        }

# Content-based filtering utilities
class ContentFilter:
    """Additional content-based filtering utilities"""
    
    @staticmethod
    def is_likely_error_page(content: str) -> bool:
        """Check if content is likely an error page"""
        if not content:
            return False
            
        content_lower = content.lower()
        
        # Common error page indicators
        error_indicators = [
            'error', 'not found', 'forbidden', 'access denied',
            'page not found', 'file not found', 'directory not found',
            'unauthorized', 'permission denied', 'internal server error',
            'bad request', 'service unavailable'
        ]
        
        # Check for multiple error indicators
        indicator_count = sum(1 for indicator in error_indicators if indicator in content_lower)
        
        return indicator_count >= 2
    
    @staticmethod
    def extract_technologies(content: str) -> List[str]:
        """Extract technologies from response content"""
        technologies = []
        
        # Common technology patterns
        patterns = {
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Drupal': r'drupal|sites/default',
            'Joomla': r'joomla|com_content',
            'PHP': r'\.php|<?php',
            'ASP.NET': r'\.aspx|__VIEWSTATE',
            'Java': r'\.jsp|\.do|jsessionid',
            'Python': r'\.py|django|flask',
            'Ruby': r'\.rb|rails',
            'Node.js': r'\.js|express',
            'Apache': r'apache|httpd',
            'Nginx': r'nginx',
            'IIS': r'iis|microsoft',
            'jQuery': r'jquery',
            'Bootstrap': r'bootstrap',
            'React': r'react',
            'Vue': r'vue\.js',
            'Angular': r'angular'
        }
        
        content_lower = content.lower()
        for tech, pattern in patterns.items():
            if re.search(pattern, content_lower, re.IGNORECASE):
                technologies.append(tech)
        
        return technologies

# Example usage
if __name__ == "__main__":
    from .config import ConfigManager, ScanLevel
    from .engine import FuzzEngine
    
    # Create configuration
    config_manager = ConfigManager()
    config = config_manager.create_config(
        target_url="https://example.com",
        scan_level=ScanLevel.LEVEL2
    )
    
    # Run scan
    engine = FuzzEngine(config)
    session = engine.start_scan()
    
    # Analyze results
    analyzer = ResponseAnalyzer(config)
    analyzed_session = analyzer.analyze_session(session)
    
    print(f"Analysis complete:")
    print(f"Original results: {len(session.results)}")
    print(f"Filtered results: {len(analyzed_session.results)}")
    
    # Print analysis summary
    summary = analyzer.get_analysis_summary()
    print(f"Total clusters: {summary['total_clusters']}")
    print(f"Error clusters: {summary['error_clusters']}")
    print(f"Interesting clusters: {summary['interesting_clusters']}")
