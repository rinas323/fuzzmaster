"""
FuzzMaster Response Filters
Advanced filtering system for fuzzing responses
"""

import re
import hashlib
from typing import List, Dict, Set, Optional, Callable, Any
from dataclasses import dataclass
from urllib.parse import urlparse
import difflib

@dataclass
class FilterRule:
    """Represents a single filter rule"""
    name: str
    description: str
    filter_func: Callable
    enabled: bool = True
    priority: int = 0  # Lower numbers = higher priority

class ResponseFilter:
    """Base class for response filters"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.enabled = True
    
    def should_filter(self, response) -> bool:
        """Return True if response should be filtered out"""
        raise NotImplementedError
    
    def get_reason(self) -> str:
        """Return reason for filtering"""
        return f"Filtered by {self.name}"

class StatusCodeFilter(ResponseFilter):
    """Filter responses by HTTP status codes"""
    
    def __init__(self, codes_to_filter: List[int] = None, codes_to_keep: List[int] = None):
        super().__init__("StatusCode", "Filter by HTTP status codes")
        self.codes_to_filter = set(codes_to_filter or [])
        self.codes_to_keep = set(codes_to_keep or [])
    
    def should_filter(self, response) -> bool:
        if self.codes_to_keep and response.status_code not in self.codes_to_keep:
            return True
        if self.codes_to_filter and response.status_code in self.codes_to_filter:
            return True
        return False

class ContentLengthFilter(ResponseFilter):
    """Filter responses by content length"""
    
    def __init__(self, min_length: int = 0, max_length: int = None, 
                 exact_lengths: List[int] = None):
        super().__init__("ContentLength", "Filter by response content length")
        self.min_length = min_length
        self.max_length = max_length
        self.exact_lengths = set(exact_lengths or [])
    
    def should_filter(self, response) -> bool:
        length = response.content_length or 0
        
        if self.exact_lengths and length in self.exact_lengths:
            return True
        
        if length < self.min_length:
            return True
        
        if self.max_length and length > self.max_length:
            return True
        
        return False

class WordCountFilter(ResponseFilter):
    """Filter responses by word count"""
    
    def __init__(self, min_words: int = 0, max_words: int = None,
                 exact_counts: List[int] = None):
        super().__init__("WordCount", "Filter by response word count")
        self.min_words = min_words
        self.max_words = max_words
        self.exact_counts = set(exact_counts or [])
    
    def should_filter(self, response) -> bool:
        if not hasattr(response, 'content') or not response.content:
            return False
        
        word_count = len(response.content.split())
        
        if self.exact_counts and word_count in self.exact_counts:
            return True
        
        if word_count < self.min_words:
            return True
        
        if self.max_words and word_count > self.max_words:
            return True
        
        return False

class RegexFilter(ResponseFilter):
    """Filter responses by regex patterns"""
    
    def __init__(self, patterns: List[str] = None, case_sensitive: bool = False,
                 filter_on_match: bool = True):
        super().__init__("Regex", "Filter by regex patterns")
        self.patterns = []
        self.case_sensitive = case_sensitive
        self.filter_on_match = filter_on_match
        
        if patterns:
            for pattern in patterns:
                flags = 0 if case_sensitive else re.IGNORECASE
                self.patterns.append(re.compile(pattern, flags))
    
    def should_filter(self, response) -> bool:
        if not hasattr(response, 'content') or not response.content:
            return False
        
        for pattern in self.patterns:
            if pattern.search(response.content):
                return self.filter_on_match
        
        return not self.filter_on_match

class SimilarityFilter(ResponseFilter):
    """Filter responses by similarity to baseline"""
    
    def __init__(self, baseline_response=None, threshold: float = 0.95):
        super().__init__("Similarity", "Filter by response similarity")
        self.baseline_response = baseline_response
        self.threshold = threshold
        self.baseline_hash = None
        
        if baseline_response:
            self.set_baseline(baseline_response)
    
    def set_baseline(self, response):
        """Set baseline response for comparison"""
        self.baseline_response = response
        if hasattr(response, 'content') and response.content:
            self.baseline_hash = hashlib.md5(response.content.encode()).hexdigest()
    
    def should_filter(self, response) -> bool:
        if not self.baseline_response or not hasattr(response, 'content'):
            return False
        
        if not response.content:
            return False
        
        # Quick hash comparison first
        current_hash = hashlib.md5(response.content.encode()).hexdigest()
        if current_hash == self.baseline_hash:
            return True
        
        # Detailed similarity comparison
        similarity = difflib.SequenceMatcher(
            None, 
            self.baseline_response.content, 
            response.content
        ).ratio()
        
        return similarity >= self.threshold

class ErrorPageFilter(ResponseFilter):
    """Filter common error pages"""
    
    def __init__(self):
        super().__init__("ErrorPage", "Filter common error pages")
        self.error_patterns = [
            r'404\s*(-\s*)?not\s*found',
            r'page\s*not\s*found',
            r'file\s*not\s*found',
            r'403\s*(-\s*)?forbidden',
            r'access\s*denied',
            r'unauthorized',
            r'500\s*(-\s*)?internal\s*server\s*error',
            r'server\s*error',
            r'bad\s*request',
            r'service\s*unavailable',
        ]
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.error_patterns
        ]
    
    def should_filter(self, response) -> bool:
        if not hasattr(response, 'content') or not response.content:
            return False
        
        content_lower = response.content.lower()
        
        for pattern in self.compiled_patterns:
            if pattern.search(content_lower):
                return True
        
        return False

class HeaderFilter(ResponseFilter):
    """Filter responses by headers"""
    
    def __init__(self, header_filters: Dict[str, str] = None):
        super().__init__("Header", "Filter by response headers")
        self.header_filters = header_filters or {}
    
    def should_filter(self, response) -> bool:
        if not hasattr(response, 'headers') or not response.headers:
            return False
        
        for header_name, expected_value in self.header_filters.items():
            actual_value = response.headers.get(header_name, "")
            if expected_value.lower() in actual_value.lower():
                return True
        
        return False

class ContentTypeFilter(ResponseFilter):
    """Filter responses by content type"""
    
    def __init__(self, allowed_types: List[str] = None, 
                 blocked_types: List[str] = None):
        super().__init__("ContentType", "Filter by content type")
        self.allowed_types = [t.lower() for t in (allowed_types or [])]
        self.blocked_types = [t.lower() for t in (blocked_types or [])]
    
    def should_filter(self, response) -> bool:
        if not hasattr(response, 'headers') or not response.headers:
            return False
        
        content_type = response.headers.get('content-type', '').lower()
        
        if self.blocked_types:
            for blocked_type in self.blocked_types:
                if blocked_type in content_type:
                    return True
        
        if self.allowed_types:
            for allowed_type in self.allowed_types:
                if allowed_type in content_type:
                    return False
            return True  # Not in allowed types
        
        return False

class FilterManager:
    """Manages multiple response filters"""
    
    def __init__(self):
        self.filters: List[ResponseFilter] = []
        self.stats = {
            'total_responses': 0,
            'filtered_responses': 0,
            'filter_reasons': {}
        }
    
    def add_filter(self, filter_obj: ResponseFilter):
        """Add a filter to the manager"""
        self.filters.append(filter_obj)
    
    def remove_filter(self, filter_name: str):
        """Remove a filter by name"""
        self.filters = [f for f in self.filters if f.name != filter_name]
    
    def enable_filter(self, filter_name: str):
        """Enable a filter by name"""
        for f in self.filters:
            if f.name == filter_name:
                f.enabled = True
                break
    
    def disable_filter(self, filter_name: str):
        """Disable a filter by name"""
        for f in self.filters:
            if f.name == filter_name:
                f.enabled = False
                break
    
    def should_filter_response(self, response) -> tuple[bool, str]:
        """Check if response should be filtered"""
        self.stats['total_responses'] += 1
        
        for filter_obj in self.filters:
            if not filter_obj.enabled:
                continue
            
            try:
                if filter_obj.should_filter(response):
                    reason = filter_obj.get_reason()
                    self.stats['filtered_responses'] += 1
                    self.stats['filter_reasons'][reason] = \
                        self.stats['filter_reasons'].get(reason, 0) + 1
                    return True, reason
            except Exception as e:
                print(f"[!] Error in filter {filter_obj.name}: {e}")
                continue
        
        return False, ""
    
    def filter_responses(self, responses: List) -> List:
        """Filter a list of responses"""
        filtered_responses = []
        
        for response in responses:
            should_filter, reason = self.should_filter_response(response)
            if not should_filter:
                filtered_responses.append(response)
        
        return filtered_responses
    
    def get_stats(self) -> Dict[str, Any]:
        """Get filtering statistics"""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset filtering statistics"""
        self.stats = {
            'total_responses': 0,
            'filtered_responses': 0,
            'filter_reasons': {}
        }
    
    def create_auto_filters(self, sample_responses: List, 
                          false_positive_threshold: float = 0.8) -> List[ResponseFilter]:
        """Automatically create filters based on sample responses"""
        auto_filters = []
        
        # Analyze response patterns
        status_codes = [r.status_code for r in sample_responses]
        content_lengths = [r.content_length or 0 for r in sample_responses]
        
        # Find common error status codes
        status_counts = {}
        for code in status_codes:
            status_counts[code] = status_counts.get(code, 0) + 1
        
        total_responses = len(sample_responses)
        for code, count in status_counts.items():
            if count / total_responses >= false_positive_threshold:
                if code >= 400:  # Error codes
                    auto_filters.append(StatusCodeFilter(codes_to_filter=[code]))
        
        # Find common content lengths (likely false positives)
        length_counts = {}
        for length in content_lengths:
            length_counts[length] = length_counts.get(length, 0) + 1
        
        for length, count in length_counts.items():
            if count / total_responses >= false_positive_threshold:
                auto_filters.append(ContentLengthFilter(exact_lengths=[length]))
        
        return auto_filters

class SmartFilterManager(FilterManager):
    """Advanced filter manager with machine learning capabilities"""
    
    def __init__(self):
        super().__init__()
        self.learning_enabled = True
        self.response_clusters = {}
        self.adaptive_thresholds = {}
    
    def learn_from_responses(self, responses: List, labels: List[str] = None):
        """Learn filtering patterns from labeled responses"""
        if not self.learning_enabled or not responses:
            return
        
        # Cluster similar responses
        clusters = self._cluster_responses(responses)
        
        # Analyze clusters for common patterns
        for cluster_id, cluster_responses in clusters.items():
            if len(cluster_responses) > 1:
                # Look for common patterns
                common_patterns = self._find_common_patterns(cluster_responses)
                
                # Create adaptive filters
                for pattern in common_patterns:
                    self._create_adaptive_filter(pattern, cluster_responses)
    
    def _cluster_responses(self, responses: List) -> Dict[str, List]:
        """Cluster responses by similarity"""
        clusters = {}
        
        for response in responses:
            # Simple clustering by content hash
            if hasattr(response, 'content') and response.content:
                content_hash = hashlib.md5(response.content.encode()).hexdigest()[:8]
                if content_hash not in clusters:
                    clusters[content_hash] = []
                clusters[content_hash].append(response)
        
        return clusters
    
    def _find_common_patterns(self, responses: List) -> List[Dict]:
        """Find common patterns in a group of responses"""
        patterns = []
        
        if not responses:
            return patterns
        
        # Common status codes
        status_codes = [r.status_code for r in responses]
        if len(set(status_codes)) == 1:
            patterns.append({
                'type': 'status_code',
                'value': status_codes[0],
                'confidence': 1.0
            })
        
        # Common content lengths
        lengths = [r.content_length or 0 for r in responses]
        if len(set(lengths)) == 1:
            patterns.append({
                'type': 'content_length',
                'value': lengths[0],
                'confidence': 1.0
            })
        
        return patterns
    
    def _create_adaptive_filter(self, pattern: Dict, responses: List):
        """Create an adaptive filter based on learned patterns"""
        if pattern['confidence'] < 0.7:
            return
        
        if pattern['type'] == 'status_code':
            filter_obj = StatusCodeFilter(codes_to_filter=[pattern['value']])
            self.add_filter(filter_obj)
        
        elif pattern['type'] == 'content_length':
            filter_obj = ContentLengthFilter(exact_lengths=[pattern['value']])
            self.add_filter(filter_obj)

# Predefined filter configurations
class FilterPresets:
    """Predefined filter configurations for common scenarios"""
    
    @staticmethod
    def get_basic_filters() -> List[ResponseFilter]:
        """Basic filter set for general fuzzing"""
        return [
            StatusCodeFilter(codes_to_filter=[404, 500, 502, 503]),
            ErrorPageFilter(),
            ContentLengthFilter(max_length=1024*1024)  # 1MB max
        ]
    
    @staticmethod
    def get_web_app_filters() -> List[ResponseFilter]:
        """Filters optimized for web application fuzzing"""
        return [
            StatusCodeFilter(codes_to_filter=[404, 500, 502, 503]),
            ErrorPageFilter(),
            ContentTypeFilter(blocked_types=['image/', 'video/', 'audio/']),
            ContentLengthFilter(min_length=10, max_length=5*1024*1024)  # 5MB max
        ]
    
    @staticmethod
    def get_api_filters() -> List[ResponseFilter]:
        """Filters optimized for API fuzzing"""
        return [
            StatusCodeFilter(codes_to_filter=[404, 500, 502, 503]),
            ContentTypeFilter(allowed_types=['application/json', 'application/xml', 'text/xml']),
            ContentLengthFilter(min_length=1)
        ]
    
    @staticmethod
    def get_stealth_filters() -> List[ResponseFilter]:
        """Filters for stealth fuzzing (more aggressive filtering)"""
        return [
            StatusCodeFilter(codes_to_filter=[404, 500, 502, 503, 403, 401]),
            ErrorPageFilter(),
            ContentLengthFilter(min_length=50),
            SimilarityFilter(threshold=0.9)
        ]
