#!/usr/bin/env python3
import os
import re
import subprocess
import requests
import json
import threading
import time
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
from collections import defaultdict
from datetime import datetime
import concurrent.futures
from bs4 import BeautifulSoup
import random
from flask import Flask, render_template, request, jsonify, session, send_file, redirect, url_for
from flask_socketio import SocketIO, emit
import uuid
import queue
import sqlite3
from functools import lru_cache
import re
import urllib3
import warnings

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)

socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

PATTERNS = {
    'js_interesting': [],
    'js_exclude': [],
    'api_regex': [],
    'secret_regex': [],
    'backend_tech': {},
    'backend_endpoints': {},
    'request_headers': [],
    'post_payloads': [],
    'endpoint_categories': {},
    'sensitive_params': {},
    'sensitive_extensions': [],
    'generic_endpoints': []
}


active_scans = {}
scan_results = {}

discovered_subdomains = {}

ENDPOINT_HARVESTING_ENABLED = False
HARVESTED_ENDPOINTS_FILE = "wordlists/endpoints_wordlist.txt"
HARVESTED_ENDPOINTS = set()

# =============================
# REGEX FIX
# =============================

def compile_safe_regex(pattern, flags=0):
    """
    Safely compile regex patterns that may contain inline flags
    """
    if not isinstance(pattern, str):
        # Return a pattern that matches nothing
        return re.compile(r'(?!)')
    
    try:
        # Check if pattern starts with inline flags like (?i), (?im), etc.
        if pattern.startswith('(?') and ')' in pattern:
            # Find the closing parenthesis of the flags section
            flag_end = pattern.find(')')
            if flag_end > 0:
                flag_section = pattern[2:flag_end]
                # Check if all characters are valid regex flags
                valid_flags = set('aiLmsux')
                if all(c in valid_flags for c in flag_section):
                    # This pattern already has inline flags, don't add more
                    return re.compile(pattern, flags=0)
        
        # Pattern doesn't have inline flags, use provided flags
        return re.compile(pattern, flags=flags)
    
    except (re.error, ValueError, TypeError) as e:
        # Log the error if needed
        # print(f"Regex compilation error for pattern '{pattern[:50]}...': {e}")
        
        # Try to compile without any flags as fallback
        try:
            return re.compile(pattern, flags=0)
        except:
            # Ultimate fallback: pattern that matches nothing
            return re.compile(r'(?!)')

# =============================
# ENDPOINT HARVESTING FUNCTIONS
# =============================

def load_harvested_endpoints():
    """Load previously harvested endpoints from file"""
    global HARVESTED_ENDPOINTS
    try:
        if os.path.exists(HARVESTED_ENDPOINTS_FILE):
            with open(HARVESTED_ENDPOINTS_FILE, 'r') as f:
                HARVESTED_ENDPOINTS = set(line.strip() for line in f if line.strip())
            return True
        else:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(HARVESTED_ENDPOINTS_FILE), exist_ok=True)
            with open(HARVESTED_ENDPOINTS_FILE, 'w') as f:
                f.write("")
            return True
    except Exception as e:
        print(f"Warning: Could not load harvested endpoints: {e}")
        return False

def save_harvested_endpoints():
    """Save harvested endpoints to file"""
    try:
        with open(HARVESTED_ENDPOINTS_FILE, 'w') as f:
            for endpoint in sorted(HARVESTED_ENDPOINTS):
                f.write(endpoint + "\n")
        return True
    except Exception as e:
        print(f"Error saving harvested endpoints: {e}")
        return False

def harvest_endpoints(endpoints, domain=None, scan_id=None):
    """Harvest unique endpoints for future use"""
    if not ENDPOINT_HARVESTING_ENABLED:
        return
    
    new_endpoints = 0
    for endpoint in endpoints:
        # Extract path from URL
        parsed = urlparse(endpoint)
        path = parsed.path
        
        # Skip if path is empty or too short
        if not path or len(path) < 2:
            continue
        
        # Skip common static files
        static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', 
                           '.svg', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3']
        if any(path.lower().endswith(ext) for ext in static_extensions):
            continue
        
        # Clean the path
        path = path.strip('/')
        
        # Add to harvested endpoints
        if path not in HARVESTED_ENDPOINTS:
            HARVESTED_ENDPOINTS.add(path)
            new_endpoints += 1
    
    # Save to file if we have new endpoints
    if new_endpoints > 0:
        save_harvested_endpoints()
        if scan_id:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📚 Added {new_endpoints} new endpoint patterns to learning database for future scans",
                'type': 'info'
            })
    
    return new_endpoints

def get_harvested_endpoints_count():
    """Get count of harvested endpoints"""
    return len(HARVESTED_ENDPOINTS)

def get_harvested_endpoints():
    """Get list of harvested endpoints"""
    return sorted(HARVESTED_ENDPOINTS)

# =============================
# WORDLIST LOADING FUNCTIONS
# =============================

def load_wordlists():
    """Load wordlists from files or create default patterns"""
    try:
        # Create default patterns if wordlists don't exist
        default_patterns()
        
        # Try to load from files if they exist
        wordlist_dir = "wordlists"
        if os.path.exists(wordlist_dir):
            # Load JS interesting patterns
            js_file = os.path.join(wordlist_dir, "js_interesting.txt")
            if os.path.exists(js_file):
                with open(js_file, 'r') as f:
                    PATTERNS['js_interesting'] = [line.strip() for line in f if line.strip()]
            
            # Load JS exclude patterns
            js_exclude_file = os.path.join(wordlist_dir, "js_exclude.txt")
            if os.path.exists(js_exclude_file):
                with open(js_exclude_file, 'r') as f:
                    PATTERNS['js_exclude'] = [line.strip() for line in f if line.strip()]
            
            # Load API regex patterns
            api_file = os.path.join(wordlist_dir, "api_regex.txt")
            if os.path.exists(api_file):
                with open(api_file, 'r') as f:
                    PATTERNS['api_regex'] = [line.strip() for line in f if line.strip()]
            
            # Load secret regex patterns
            secret_file = os.path.join(wordlist_dir, "secret_regex.txt")
            if os.path.exists(secret_file):
                with open(secret_file, 'r') as f:
                    PATTERNS['secret_regex'] = [line.strip() for line in f if line.strip()]
            
            # Load harvested endpoints if endpoint harvesting is enabled
            if ENDPOINT_HARVESTING_ENABLED:
                load_harvested_endpoints()
    
    except Exception as e:
        print(f"Warning: Could not load wordlists: {e}")
        # Use default patterns
        default_patterns()

def default_patterns():
    """Create default patterns if wordlists don't exist"""
    # Default JS interesting patterns
    PATTERNS['js_interesting'] = [
        'app', 'config', 'admin', 'api', 'auth', 'login', 'user', 'account',
        'profile', 'dashboard', 'main', 'core', 'bundle', 'vendor', 'common',
        'util', 'service', 'controller', 'model', 'view', 'script', 'base',
        'index', 'global', 'init', 'setup', 'debug', 'test', 'dev', 'staging',
        'prod', 'min'
    ]
    
    # Default JS exclude patterns
    PATTERNS['js_exclude'] = [
        'jquery', 'bootstrap', 'react', 'vue', 'angular', 'popper', 'fontawesome',
        'google', 'gstatic', 'cloudflare', 'cdnjs', 'unpkg', 'chartjs', 'moment',
        'lodash', 'underscore', 'axios', 'three', 'babylon', 'hammer', 'swiper',
        'slick', 'lightbox', 'magnific', 'fancybox', 'owl', 'isotope', 'waypoints',
        'parallax', 'scrollmagic', 'greensock', 'anime', 'velocity'
    ]
    
    # Default API regex patterns
    PATTERNS['api_regex'] = [
        r'/api/',
        r'/v[0-9]+/',
        r'/rest/',
        r'/graphql',
        r'/json/',
        r'/xml/',
        r'/soap/',
        r'/ws/',
        r'/wss/',
        r'/oauth/',
        r'/auth/',
        r'/token',
        r'/login',
        r'/register',
        r'/signup',
        r'/user',
        r'/admin',
        r'/dashboard',
        r'/config',
        r'/setting'
    ]
    
    # Default secret regex patterns
    PATTERNS['secret_regex'] = [
        r'(?i)api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'(?i)secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'(?i)token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'(?i)password["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.\!\@\#\$\%\^\&\*\(\)]{8,}["\']',
        r'(?i)auth["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'(?i)access["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'AKIA[0-9A-Z]{16}',
        r'sk_live_[0-9a-zA-Z]{24}',
        r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
        r'xox[pbard]\-[a-zA-Z0-9]{10,48}'
    ]

# =============================
# JAVASCRIPT ANALYSIS MODULE
# =============================

def is_interesting_js(url):
    """Check if a JS file is interesting"""
    url_lower = url.lower()
    
    # Check if it should be excluded
    for pattern in PATTERNS['js_exclude']:
        if pattern in url_lower:
            return False
    
    # Check if it's interesting
    for pattern in PATTERNS['js_interesting']:
        if pattern in url_lower:
            return True
    
    # Additional checks
    if 'app' in url_lower or 'config' in url_lower or 'api' in url_lower:
        return True
    
    return False
    
def parse_js_map(js_map_url, js_map_content, domain):
    """Parse .js.map files for additional URLs"""
    internal_urls = set()
    external_urls = set()
    api_urls = set()
    
    try:
        map_data = json.loads(js_map_content)
        
        # Extract from sources
        if 'sources' in map_data:
            for source in map_data['sources']:
                if source.startswith('http'):
                    if domain in source:
                        internal_urls.add(source)
                        
                        # Check if it's an API endpoint
                        if PATTERNS['api_regex']:
                            for api_pattern in PATTERNS['api_regex']:
                                try:
                                    compiled_pattern = compile_safe_regex(api_pattern, re.I)
                                    if compiled_pattern.search(source):
                                        api_urls.add(source)
                                        break
                                except Exception:
                                    continue
                    else:
                        external_urls.add(source)
        
        # Extract from mappings string
        if 'mappings' in map_data and isinstance(map_data['mappings'], str):
            url_pattern = r'https?://[^\s\"\'\;\)\]]+'
            for match in re.findall(url_pattern, map_data['mappings']):
                exclude_pattern = r"(jquery|bootstrap|react|vue|angular|min\.js|vendor|fontawesome|googleapis|cdnjs|cloudflare)"
                if re.search(exclude_pattern, match, re.I):
                    continue
                
                if domain in match:
                    internal_urls.add(match)
                    
                    # Check if it's an API endpoint
                    if PATTERNS['api_regex']:
                        for api_pattern in PATTERNS['api_regex']:
                            try:
                                compiled_pattern = compile_safe_regex(api_pattern, re.I)
                                if compiled_pattern.search(match):
                                    api_urls.add(match)
                                    break
                            except Exception:
                                continue
                else:
                    external_urls.add(match)
                    
    except json.JSONDecodeError:
        return set(), set(), set()
    
    return internal_urls, external_urls, api_urls

def extract_urls_from_js(js_url, js_content, domain, scan_id=None):
    """Extract URLs from JavaScript content"""
    base = normalize_base(js_url)
    internal_urls = set()
    external_urls = set()
    api_urls = set()
    secrets = []
    
    # Extract URLs from JavaScript
    url_pattern = r'https?://[^\s\"\'\;\)\]]+'
    for match in re.findall(url_pattern, js_content):
        # Skip common libraries
        exclude_pattern = r"(jquery|bootstrap|react|vue|angular|min\.js|vendor|fontawesome|googleapis|cdnjs|cloudflare)"
        if re.search(exclude_pattern, match, re.I):
            continue
        
        full_url = urljoin(base, match)
        full_url = full_url.rstrip(";,'\")]")
        
        if domain in full_url:
            internal_urls.add(full_url)
            
            # Check if it's an API endpoint
            if PATTERNS['api_regex']:
                for api_pattern in PATTERNS['api_regex']:
                    try:
                        compiled_pattern = compile_safe_regex(api_pattern, re.I)
                        if compiled_pattern.search(full_url):
                            api_urls.add(full_url)
                            break
                    except Exception:
                        continue
        else:
            external_urls.add(full_url)
    
    # Extract secrets using safe compilation
    if PATTERNS['secret_regex']:
        for secret_pattern in PATTERNS['secret_regex']:
            try:
                compiled_pattern = compile_safe_regex(secret_pattern, re.I)
                secret_matches = compiled_pattern.findall(js_content)
                for match in secret_matches:
                    secrets.append((match, js_url))
            except Exception as e:
                if scan_id:
                    socketio.emit('scan_log', {
                        'scan_id': scan_id,
                        'message': f"⚠️ Regex error in secret pattern: {str(e)[:100]}",
                        'type': 'warning'
                    })
                continue
    
    return internal_urls, external_urls, api_urls, secrets

def analyze_js_files(js_files, domain, scan_id=None):
    """Analyze JavaScript files for hidden endpoints and secrets"""
    results = {
        'internal_urls': set(),
        'external_urls': set(),
        'api_urls': set(),
        'secrets': [],
        'js_details': {},
        'endpoints_by_js': defaultdict(set),
        'api_by_js': defaultdict(set),
        'analysis_notes': [
            "🔍 JavaScript Analysis: This looks for patterns in JavaScript files, not actual vulnerabilities.",
            "📝 Found endpoints are based on text patterns - they may not be functional or accessible.",
            "⚠️ IMPORTANT: Secrets detected are from static code analysis only - they may be test values, placeholders, or red herrings.",
            "🔎 Manual verification is REQUIRED for any findings before taking action.",
            "ℹ️ Context: This tool reads JavaScript files but cannot execute them or understand their runtime behavior."
        ]
    }
    
    if not js_files:
        if scan_id:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "📋 No JavaScript files to analyze",
                'type': 'info'
            })
        return results
    
    if scan_id:
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"🔬 Analyzing {len(js_files)} JavaScript files for patterns and hidden endpoints...",
            'type': 'info'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "💡 Note: This is static analysis looking for text patterns, not dynamic execution.",
            'type': 'info'
        })
    
    processed = 0
    for js_url in sorted(js_files):
        processed += 1
        
        if scan_id and processed % 10 == 0:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📊 Processed {processed}/{len(js_files)} JS files",
                'type': 'info'
            })
        
        try:
            # Fetch JavaScript content
            response = requests.get(js_url, timeout=15, verify=False)
            if response.status_code != 200:
                continue
            
            content = response.text
            content_type = response.headers.get('content-type', '').lower()
            
            # Store basic info
            results['js_details'][js_url] = {
                'status': response.status_code,
                'content_length': len(content),
                'content_type': content_type
            }
            
            # Check if it's a source map
            if js_url.endswith('.js.map'):
                internal, external, api = parse_js_map(js_url, content, domain)
                results['internal_urls'].update(internal)
                results['external_urls'].update(external)
                results['api_urls'].update(api)
                
                # Track which JS file found which URLs
                for url in internal:
                    results['endpoints_by_js'][js_url].add(url)
                for url in api:
                    results['api_by_js'][js_url].add(url)
            
            else:
                # Regular JavaScript file - UPDATED HERE to pass scan_id
                internal, external, api, secrets = extract_urls_from_js(js_url, content, domain, scan_id)
                results['internal_urls'].update(internal)
                results['external_urls'].update(external)
                results['api_urls'].update(api)
                results['secrets'].extend(secrets)
                
                # Track which JS file found which URLs
                for url in internal:
                    results['endpoints_by_js'][js_url].add(url)
                for url in api:
                    results['api_by_js'][js_url].add(url)
        
        except Exception as e:
            if scan_id:
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"⚠️ Could not analyze {js_url}: {str(e)[:100]}",
                    'type': 'warning'
                })
            continue
    
    if scan_id:
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"✅ JS analysis complete. Found {len(results['internal_urls'])} internal URL patterns, {len(results['secrets'])} potential secret patterns",
            'type': 'success'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "📋 REMINDER: These are PATTERNS found in code, not confirmed secrets or vulnerabilities.",
            'type': 'warning'
        })
    
    # Convert sets to lists for JSON serialization
    results['internal_urls'] = list(results['internal_urls'])
    results['external_urls'] = list(results['external_urls'])
    results['api_urls'] = list(results['api_urls'])
    results['endpoints_by_js'] = {k: list(v) for k, v in results['endpoints_by_js'].items()}
    results['api_by_js'] = {k: list(v) for k, v in results['api_by_js'].items()}
    
    return results

# =============================
# IMPROVED ENDPOINT CLASSIFICATION MODULE
# =============================

def classify_endpoint(url):
    """Classify an endpoint and assign pattern match confidence"""
    url_lower = url.lower()
    
    classification = {
        'pattern_confidence': 0,
        'max_possible_score': 40,
        'matched_patterns': [],
        'matched_categories': [],
        'categories': [],  
        'sensitive_params': [],
        'has_sensitive_extension': False,
        'pattern_match_notes': [
            "🔍 PATTERN MATCH CONFIDENCE: Percentage of patterns matched from our database",
            "📊 WHAT THIS MEASURES: How many of our predefined patterns appear in this URL",
            "⚠️ WHAT THIS DOES NOT MEASURE: Security risk, exploitability, or actual vulnerability",
            "🎯 HOW TO USE: Higher confidence means more patterns matched - prioritize for investigation",
            "❌ IMPORTANT: Pattern match ≠ vulnerability. Confidence score ≠ security risk."
        ],
        'confidence_explanation': "",
        'priority': 'BASELINE',  
        'investigation_priority': {
            'level': 'BASELINE',
            'explanation': 'Few patterns matched - standard investigation priority',
            'recommended_action': 'Investigate when time permits'
        }
    }
    
    # Pattern categories with weights
    pattern_categories = {
        'ADMIN': {
            'patterns': ['admin', 'administrator', 'manage', 'panel', 'control', 'dashboard', 'console', 'backend'],
            'weight': 2
        },
        'AUTH': {
            'patterns': ['login', 'logout', 'signin', 'signout', 'register', 'signup', 'auth', 'authenticate'],
            'weight': 2
        },
        'API': {
            'patterns': ['/api/', '/rest/', '/json/', '/xml/', '/soap/', '/graphql/', '/v1/', '/v2/', '/v3/'],
            'weight': 3
        },
        'SENSITIVE': {
            'patterns': ['config', 'setting', 'setup', 'install', 'deploy', 'migrate', 'backup', 'restore', 'env'],
            'weight': 2
        },
        'DEBUG': {
            'patterns': ['debug', 'test', 'dev', 'staging', 'qa', 'uat', 'log', 'error', 'trace', 'status'],
            'weight': 1
        },
        'FILE': {
            'patterns': ['upload', 'file', 'download', 'export', 'import', 'attach', 'attachment', 'multipart'],
            'weight': 2
        },
        'USER_DATA': {
            'patterns': ['user', 'account', 'profile', 'member', 'customer', 'client'],
            'weight': 1
        }
    }
    
    # Check URL patterns
    for category_name, category_info in pattern_categories.items():
        for pattern in category_info['patterns']:
            if re.search(pattern, url_lower, re.I):
                classification['pattern_confidence'] += category_info['weight']
                if category_name not in classification['matched_categories']:
                    classification['matched_categories'].append(category_name)
                classification['matched_patterns'].append(f"{category_name}:{pattern}")
                break
    
    # Sync categories with matched_categories for backward compatibility
    classification['categories'] = classification['matched_categories'].copy()
    
    # Check query parameters
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    # Parameter sensitivity weights
    param_weights = {
        'HIGH': ['password', 'pass', 'passwd', 'pwd', 'secret', 'api_key', 'access_token', 'auth_token', 'key'],
        'MEDIUM': ['id', 'user', 'username', 'email', 'token', 'file', 'path', 'url', 'redirect'],
        'LOW': ['page', 'limit', 'offset', 'sort', 'order', 'filter', 'search', 'q', 'query']
    }
    
    for param in query_params.keys():
        param_lower = param.lower()
        
        for high_param in param_weights['HIGH']:
            if re.search(high_param, param_lower, re.I):
                classification['pattern_confidence'] += 3
                classification['sensitive_params'].append(f"High sensitivity:{param}")
                break
        
        for medium_param in param_weights['MEDIUM']:
            if re.search(medium_param, param_lower, re.I):
                classification['pattern_confidence'] += 2
                if f"Medium sensitivity:{param}" not in classification['sensitive_params']:
                    classification['sensitive_params'].append(f"Medium sensitivity:{param}")
                break
        
        for low_param in param_weights['LOW']:
            if re.search(low_param, param_lower, re.I):
                classification['pattern_confidence'] += 1
                if f"Low sensitivity:{param}" not in classification['sensitive_params']:
                    classification['sensitive_params'].append(f"Low sensitivity:{param}")
                break
    
    # Check for sensitive extensions
    sensitive_extensions = ['.bak', '.backup', '.old', '.tmp', '.temp', '.swp', '.sql', '.db', '.sqlite', '.env']
    path = parsed.path.lower()
    for ext in sensitive_extensions:
        if path.endswith(ext):
            classification['has_sensitive_extension'] = True
            classification['pattern_confidence'] += 5
            classification['matched_patterns'].append(f"SENSITIVE_EXTENSION:{ext}")
            break
    
    # Calculate confidence percentage (capped at 100)
    confidence_percentage = min(100, int((classification['pattern_confidence'] / classification['max_possible_score']) * 100))
    classification['confidence_percentage'] = confidence_percentage
    
    # Set investigation priority based on confidence
    if confidence_percentage >= 80:
        classification['priority'] = 'HIGH'
        classification['investigation_priority']['level'] = 'RECOMMENDED'
        classification['investigation_priority']['explanation'] = f'Strong pattern match ({confidence_percentage}%) - multiple patterns detected'
        classification['investigation_priority']['recommended_action'] = 'Prioritize for manual investigation'
    elif confidence_percentage >= 60:
        classification['priority'] = 'MEDIUM'
        classification['investigation_priority']['level'] = 'MODERATE'
        classification['investigation_priority']['explanation'] = f'Good pattern match ({confidence_percentage}%) - several patterns detected'
        classification['investigation_priority']['recommended_action'] = 'Consider for investigation'
    elif confidence_percentage >= 40:
        classification['priority'] = 'LOW'
        classification['investigation_priority']['level'] = 'LOW'
        classification['investigation_priority']['explanation'] = f'Moderate pattern match ({confidence_percentage}%) - some patterns detected'
        classification['investigation_priority']['recommended_action'] = 'Investigate if time permits'
    else:
        classification['priority'] = 'BASELINE'
        classification['investigation_priority']['level'] = 'BASELINE'
        classification['investigation_priority']['explanation'] = f'Minimal pattern match ({confidence_percentage}%) - few patterns detected'
        classification['investigation_priority']['recommended_action'] = 'Lowest priority'
    
    # Generate confidence explanation
    if classification['matched_categories']:
        categories_str = ', '.join(classification['matched_categories'][:3])
        classification['confidence_explanation'] = f"Matches {confidence_percentage}% of pattern criteria. Detected categories: {categories_str}"
    else:
        classification['confidence_explanation'] = f"Matches {confidence_percentage}% of pattern criteria. No specific categories detected."
    
    # Add statistical context
    classification['statistical_context'] = {
        'based_on': f"Analysis of {len(pattern_categories)} pattern categories and {sum(len(cat['patterns']) for cat in pattern_categories.values())} patterns",
        'false_positive_rate_note': 'Expected false positive rate: 30-50% for pattern-based detection',
        'verification_required': '100% of findings require manual verification',
        'confidence_calculation': f"Score {classification['pattern_confidence']}/{classification['max_possible_score']} = {confidence_percentage}% confidence"
    }
    
    return classification

def classify_endpoints(endpoints, domain):
    """Classify multiple endpoints with improved accuracy"""
    classified = []
    for endpoint in endpoints:
        classification = classify_endpoint(endpoint)
        classified.append({
            'url': endpoint,
            'classification': classification,
            'domain': domain,
            'investigation_context': {
                'confidence_level': classification['confidence_percentage'],
                'priority_reason': classification['investigation_priority']['explanation'],
                'verification_required': True,
                'false_positive_likelihood': 'Medium to High (pattern-based detection)',
                'next_steps': [
                    "1. Verify endpoint actually exists and is accessible",
                    "2. Check if patterns represent actual functionality",
                    "3. Consider context of the application",
                    "4. Manual testing required for security assessment"
                ]
            }
        })
    
    # Sort by confidence percentage (highest first)
    classified.sort(key=lambda x: x['classification']['confidence_percentage'], reverse=True)
    return classified

# =============================
# IMPROVED TESTING RECOMMENDATION MODULE
# =============================

class TestingRecommendation:
    def __init__(self):
        self.recommendations = {
            'SQL_INJECTION': {
                'description': 'Pattern suggests possible SQL interaction points',
                'test_cases': [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "'; DROP TABLE users--",
                    "1' AND SLEEP(5)--",
                    "1 UNION SELECT null,version()--"
                ],
                'pattern_confidence_weight': 25,
                'investigation_suggestion': 'Consider checking for SQLi if manual testing is planned',
                'tools': ['sqlmap', 'manual testing'],
                'patterns': [r'.*\.php.*', r'.*\.aspx.*', r'.*\.jsp.*', r'.*id=\d+.*', r'.*user=\d+.*', r'.*search=.*'],
                'limitations': [
                    'Pattern-based detection only',
                    'Cannot determine if input reaches database',
                    'Does not know database type or structure',
                    'High false positive rate expected'
                ],
                'confidence_interpretation': 'Pattern match likelihood, not vulnerability existence'
            },
            'XSS': {
                'description': 'Pattern suggests user input reflection points',
                'test_cases': [
                    '<script>console.log("test")</script>',
                    '" onmouseover="console.log("test")',
                    "'><svg/onload=console.log('test')>",
                    '"><img src=x onerror=console.log("test")>'
                ],
                'pattern_confidence_weight': 20,
                'investigation_suggestion': 'Consider checking for XSS if input reflection is suspected',
                'tools': ['manual testing with safe payloads'],
                'patterns': [
                    r'.*search.*', 
                    r'.*q=.*', 
                    r'.*name=.*', 
                    r'.*comment.*', 
                    r'.*message.*',
                    r'.*input.*',
                    r'.*text.*'
                ],
                'limitations': [
                    'Cannot determine output context',
                    'Does not know if input is sanitized',
                    'Cannot detect DOM-based XSS'
                ],
                'confidence_interpretation': 'Pattern match likelihood, not vulnerability existence'
            },
            'PATH_TRAVERSAL': {
                'description': 'Pattern suggests file path manipulation points',
                'test_cases': [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\win.ini',
                    '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
                ],
                'pattern_confidence_weight': 30,
                'investigation_suggestion': 'Consider checking for path traversal if file operations exist',
                'tools': ['manual testing'],
                'patterns': [r'.*file=.*', r'.*path=.*', r'.*include=.*', r'.*page=.*', r'.*doc=.*'],
                'limitations': [
                    'Cannot determine file system permissions',
                    'Does not know if path sanitization exists'
                ],
                'confidence_interpretation': 'Pattern match likelihood, not vulnerability existence'
            },
            'SSRF': {
                'description': 'Pattern suggests server-side request points',
                'test_cases': [
                    'http://169.254.169.254/latest/meta-data/',
                    'http://localhost:8080',
                    'file:///etc/passwd'
                ],
                'pattern_confidence_weight': 25,
                'investigation_suggestion': 'Consider checking for SSRF if URL fetching is suspected',
                'tools': ['manual testing'],
                'patterns': [r'.*url=.*', r'.*proxy=.*', r'.*webhook.*'],
                'limitations': [
                    'Cannot determine if requests are made',
                    'Does not know network restrictions'
                ],
                'confidence_interpretation': 'Pattern match likelihood, not vulnerability existence'
            }
        }
    
    def analyze_endpoint(self, url, classification, details=None):
        """Analyze endpoint and generate investigation suggestions"""
        suggestions = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        path = parsed.path.lower()
        
        # Only analyze endpoints with decent pattern match confidence
        if classification['confidence_percentage'] < 40:
            return suggestions
        
        # Check each pattern type
        for pattern_type, pattern_info in self.recommendations.items():
            match_score = 0
            
            # Check URL patterns
            for pattern in pattern_info['patterns']:
                if re.search(pattern, url, re.I):
                    match_score += pattern_info['pattern_confidence_weight'] * 0.6
                    break
            
            # Check query parameters
            param_keys = list(query_params.keys())
            for param in param_keys:
                param_lower = param.lower()
                for pattern in pattern_info['patterns']:
                    if re.search(pattern, f".*{param_lower}=.*", re.I):
                        match_score += pattern_info['pattern_confidence_weight'] * 0.4
                        break
            
            # Only add suggestion if there's a decent match
            if match_score > 15:
                confidence_percentage = min(95, match_score)
                
                suggestion = {
                    'pattern_type': pattern_type,
                    'description': pattern_info['description'],
                    'pattern_confidence': confidence_percentage,
                    'confidence_interpretation': pattern_info['confidence_interpretation'],
                    'investigation_suggestion': pattern_info['investigation_suggestion'],
                    'sample_test_cases': pattern_info['test_cases'][:2],
                    'tools': pattern_info['tools'],
                    'why_suggested': self._explain_suggestion(url, pattern_type, param_keys),
                    'limitations': pattern_info['limitations'],
                    'verification_required': '100% manual verification required',
                    'false_positive_note': 'High false positive rate expected for pattern-based suggestions'
                }
                suggestions.append(suggestion)
        
        # Sort by confidence (highest first)
        suggestions.sort(key=lambda x: x['pattern_confidence'], reverse=True)
        
        return suggestions[:3]  # Return top 3 suggestions
    
    def _explain_suggestion(self, url, pattern_type, param_keys=None):
        """Generate explanation for why this pattern was suggested"""
        if param_keys is None:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            param_keys = list(query_params.keys())[:3]
        
        param_str = ', '.join(param_keys[:3]) if param_keys else "no parameters"
        
        explanations = {
            'SQL_INJECTION': f"URL or parameters ({param_str}) match patterns commonly associated with database interactions",
            'XSS': f"URL or parameters ({param_str}) match patterns where user input is often reflected",
            'PATH_TRAVERSAL': f"URL or parameters ({param_str}) match patterns associated with file operations",
            'SSRF': f"URL or parameters ({param_str}) match patterns associated with server-side requests"
        }
        
        return explanations.get(pattern_type, f"Patterns in URL or parameters ({param_str}) match common investigation targets")

# =============================
# ENDPOINT VERIFICATION MODULE
# =============================

class EndpointVerifier:
    def __init__(self, max_workers=10, timeout=8):
        self.max_workers = max_workers
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.results_cache = {}
        self.verified_endpoints = []
        self.stats = {
            'total_tested': 0,
            'verified': 0,
            'false_positives': 0,
            'status_codes': defaultdict(int),
            'methods_used': defaultdict(int)
        }
        
        self.common_params = [
            'id', 'page', 'file', 'path', 'url', 'redirect', 'view', 'action',
            'debug', 'test', 'admin', 'login', 'token', 'key', 'secret',
            'user', 'username', 'email', 'password', 'search', 'q', 'query',
            'sort', 'order', 'limit', 'offset', 'format', 'callback', 'jsonp'
        ]
        
        self.common_values = [
            '1', 'test', 'admin', 'true', 'false', 'yes', 'no',
            'index', 'home', 'main', 'default', 'example'
        ]
        
        self.methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE']
        
        self.post_payloads = [
            {'test': 'test'},
            {'data': 'test'},
            {'action': 'test'},
            {'cmd': 'test'}
        ]
    
    def verify_endpoint(self, url, skip_cache=False):
        """Verify if an endpoint actually exists and is accessible"""
        if not skip_cache and url in self.results_cache:
            return self.results_cache[url]
        
        self.stats['total_tested'] += 1
        
        parsed = urlparse(url)
        
        static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', 
                            '.svg', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3']
        if any(parsed.path.lower().endswith(ext) for ext in static_extensions):
            result = {'verified': False, 'reason': 'static_file', 'url': url}
            self.results_cache[url] = result
            return result
        
       
        head_result = self.try_method('HEAD', url)
        if head_result and head_result['status'] != 404:
            self.stats['verified'] += 1
            self.stats['status_codes'][head_result['status']] += 1
            self.stats['methods_used']['HEAD'] += 1
            self.verified_endpoints.append(head_result)
            self.results_cache[url] = head_result
            return head_result
        
        
        get_result = self.try_method('GET', url)
        if get_result and get_result['status'] != 404:
            self.stats['verified'] += 1
            self.stats['status_codes'][get_result['status']] += 1
            self.stats['methods_used']['GET'] += 1
            self.verified_endpoints.append(get_result)
            self.results_cache[url] = get_result
            return get_result
        
        
        param_results = self.test_with_parameters(url)
        if param_results:
            for result in param_results:
                if result['status'] != 404:
                    self.stats['verified'] += 1
                    self.stats['status_codes'][result['status']] += 1
                    self.stats['methods_used'][result.get('method', 'GET')] += 1
                    self.verified_endpoints.append(result)
            
            if param_results:
                best_result = max(param_results, key=lambda x: x.get('confidence', 0))
                self.results_cache[url] = best_result
                return best_result
        
        # Try other methods for API-like endpoints
        if any(pattern in url.lower() for pattern in ['/api/', '/rest/', '/json/', '/xml/']):
            for method in ['POST', 'PUT', 'DELETE']:
                result = self.try_method(method, url)
                if result and result['status'] != 404:
                    self.stats['verified'] += 1
                    self.stats['status_codes'][result['status']] += 1
                    self.stats['methods_used'][method] += 1
                    self.verified_endpoints.append(result)
                    self.results_cache[url] = result
                    return result
        
        self.stats['false_positives'] += 1
        result = {
            'verified': False,
            'reason': '404_not_found',
            'url': url,
            'status': 404,
            'confidence': 0,
            'verification_note': 'Endpoint not accessible - may be hidden behind authentication or require specific conditions'
        }
        self.results_cache[url] = result
        return result
    
    def try_method(self, method, url, data=None):
        """Try a specific HTTP method"""
        try:
            if method == 'HEAD':
                response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            elif method == 'GET':
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            elif method == 'POST':
                response = self.session.post(url, data=data or {}, timeout=self.timeout, allow_redirects=True)
            elif method == 'PUT':
                response = self.session.put(url, data=data or {}, timeout=self.timeout, allow_redirects=True)
            elif method == 'DELETE':
                response = self.session.delete(url, timeout=self.timeout, allow_redirects=True)
            else:
                return None
            
            confidence = self.calculate_confidence(response, method)
            
            result = {
                'verified': response.status_code != 404,
                'url': url,
                'method': method,
                'status': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'redirect_count': len(response.history) if hasattr(response, 'history') else 0,
                'final_url': response.url,
                'confidence': confidence,
                'confidence_interpretation': 'Response pattern confidence, not security assessment',
                'is_error': 400 <= response.status_code < 600 and response.status_code != 404,
                'content_sample': response.text[:200] if response.text else '',
                'verification_notes': [
                    f"🔍 STATUS: {response.status_code} - {self._get_status_meaning(response.status_code)}",
                    "📊 CONFIDENCE: This measures response pattern matching, not security",
                    "⚠️ IMPORTANT: Accessible ≠ Secure. Manual security testing required.",
                    "🎯 USE FOR: Identifying endpoints to investigate further",
                    f"🔎 INTERPRETATION: Confidence {confidence}% based on response patterns"
                ]
            }
            
            if data and method in ['POST', 'PUT']:
                result['data'] = data
            
            return result
            
        except requests.RequestException as e:
            return {
                'verified': False,
                'url': url,
                'method': method,
                'error': str(e),
                'confidence': 0,
                'confidence_interpretation': 'Connection failure, not security assessment',
                'verification_notes': [
                    f"🔍 CONNECTION ERROR: {str(e)[:100]}",
                    "🎯 INTERPRETATION: Endpoint may be unreachable or blocking requests",
                    "⚠️ NOTE: Connection failure does not indicate security",
                    "📋 ACTION: Try different network conditions or timing"
                ]
            }
        except Exception as e:
            return {
                'verified': False,
                'url': url,
                'method': method,
                'error': str(e),
                'confidence': 0,
                'confidence_interpretation': 'Technical error, not security finding'
            }
    
    def _get_status_meaning(self, status_code):
        """Get human-readable meaning of status codes"""
        meanings = {
            200: 'OK - Endpoint accessible',
            201: 'Created - POST successful',
            204: 'No Content - DELETE successful',
            301: 'Moved Permanently',
            302: 'Found - Temporary redirect',
            304: 'Not Modified',
            400: 'Bad Request - Invalid input',
            401: 'Unauthorized - Authentication required',
            403: 'Forbidden - Access denied',
            404: 'Not Found',
            405: 'Method Not Allowed',
            500: 'Internal Server Error',
            502: 'Bad Gateway',
            503: 'Service Unavailable'
        }
        return meanings.get(status_code, f'HTTP {status_code}')
    
    def calculate_confidence(self, response, method):
        """Calculate confidence score for a response"""
        confidence = 0
        
        if 200 <= response.status_code < 300:
            confidence += 70
        elif 300 <= response.status_code < 400:
            confidence += 50
        elif response.status_code == 401 or response.status_code == 403:
            confidence += 60
        elif response.status_code == 500:
            confidence += 40
        elif response.status_code == 404:
            return 0
        
        if method in ['POST', 'PUT', 'DELETE']:
            confidence += 10
        
        content_type = response.headers.get('content-type', '').lower()
        if 'application/json' in content_type:
            confidence += 20
        if 'text/html' in content_type:
            confidence += 10
        
        content_length = len(response.content)
        if 100 < content_length < 10000:
            confidence += 10
        elif content_length == 0:
            confidence -= 10
        
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        framework_indicators = [
            ('laravel', 15), ('django', 15), ('spring', 15), ('express', 15),
            ('flask', 15), ('rails', 15), ('asp.net', 15), ('wordpress', 15),
            ('csrf', 10), ('token', 10), ('session', 10), ('auth', 10)
        ]
        
        for indicator, score in framework_indicators:
            if indicator in content or indicator in headers:
                confidence += score
        
        return min(100, confidence)
    
    def test_with_parameters(self, url):
        """Test URL with common parameters"""
        results = []
        parsed = urlparse(url)
        
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in self.common_params[:3]:
            for value in self.common_values[:2]:
                test_url = f"{clean_url}?{param}={quote(value)}"
                result = self.try_method('GET', test_url)
                if result:
                    results.append(result)
        
        return results
    
    def verify_batch(self, urls, callback=None):
        """Verify a batch of endpoints in parallel"""
        verified_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.verify_endpoint, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    verified_results.append(result)
                    
                    if callback:
                        callback(result)
                        
                except Exception as e:
                    error_result = {
                        'verified': False,
                        'url': url,
                        'error': str(e),
                        'confidence': 0,
                        'confidence_interpretation': 'Verification error, not security finding'
                    }
                    verified_results.append(error_result)
        
        return verified_results
    
    def get_verified_endpoints(self, min_confidence=30):
        """Get endpoints that passed verification with minimum confidence"""
        return [ep for ep in self.verified_endpoints 
                if ep.get('verified', False) and ep.get('confidence', 0) >= min_confidence]
    
    def get_false_positives(self):
        """Get endpoints that were classified as HIGH but are actually 404"""
        return [ep for ep in self.verified_endpoints if not ep.get('verified', False)]
    
    def generate_report(self, output_file):
        """Generate a detailed verification report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'verified_endpoints': self.get_verified_endpoints(30),
            'false_positives': self.get_false_positives(),
            'high_confidence': self.get_verified_endpoints(70),
            'report_notes': [
                "🔍 VERIFICATION REPORT: Endpoint accessibility check",
                "📊 STATISTICS: Show pattern matches, not security assessments",
                "⚠️ IMPORTANT: Accessible ≠ Secure. Manual testing required.",
                "🎯 SCORE INTERPRETATION: Confidence measures response patterns",
                "❌ FALSE POSITIVES: Occur when patterns match but endpoints don't exist",
                "🔎 NEXT STEP: Investigate verified endpoints manually",
                "📋 REMINDER: These are investigation starting points, not findings"
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return output_file

# =============================
# UTIL FUNCTIONS
# =============================

def run_with_timeout(cmd, timeout=300, outfile=None, check_tool=True, scan_id=None):
    """Run command with timeout and emit progress"""
    if scan_id:
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"🚀 Running: {cmd}",
            'type': 'info'
        })
    
    if outfile:
        os.makedirs(os.path.dirname(outfile) if os.path.dirname(outfile) else '.', exist_ok=True)
    
    def target():
        try:
            if outfile:
                with open(outfile, "w") as f:
                    result = subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.PIPE, text=True)
                    if result.returncode != 0 and check_tool:
                        if scan_id:
                            socketio.emit('scan_log', {
                                'scan_id': scan_id,
                                'message': f"⚠️ Command completed with warnings: {result.stderr.strip()[:200]}",
                                'type': 'warning'
                            })
            else:
                result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode != 0 and check_tool:
                    if scan_id:
                        socketio.emit('scan_log', {
                            'scan_id': scan_id,
                            'message': f"⚠️ Command completed with warnings: {result.stderr.strip()[:200]}",
                            'type': 'warning'
                        })
        except Exception as e:
            if scan_id:
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"❌ Error running command: {str(e)[:100]}",
                    'type': 'error'
                })
    
    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout)
    
    if thread.is_alive():
        if scan_id:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"⏱️ Command timed out after {timeout} seconds",
                'type': 'warning'
            })
        return False
    
    return True

def check_tool_installed(tool_name):
    """Check if a tool is installed and accessible"""
    try:
        subprocess.run(f"which {tool_name}", shell=True, check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def httpx_scan(input_file, output_file, show_progress=True, scan_id=None):
    """Scan URLs with httpx and save results"""
    if os.path.exists(input_file):
        if check_tool_installed("httpx"):
            if show_progress and scan_id:
                line_count = sum(1 for _ in open(input_file))
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"🌐 Scanning {line_count} URLs with httpx...",
                    'type': 'info'
                })
            run_with_timeout(
                f"httpx -l {input_file} -silent -sc -cl -wc -lc -title -td -location -no-color -timeout 10",
                timeout=600,
                outfile=output_file,
                scan_id=scan_id
            )
        else:
            if scan_id:
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"⚠️ httpx is not installed. Please install it: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                    'type': 'warning'
                })
    else:
        if scan_id:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"❌ Input file not found: {input_file}",
                'type': 'error'
            })

def normalize_base(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def parse_httpx_line(line):
    """Parse httpx output line - simpler version"""
    line = line.strip()
    if not line:
        return None
    
    # Try to extract URL (first part)
    parts = line.split()
    if not parts:
        return None
    
    url = parts[0]
    
    # Initialize with defaults
    result = {
        'url': url,
        'status': '',
        'content_length': '',
        'word_count': '',
        'line_count': '',
        'title': '',
        'tech_detect': '',
        'location': ''
    }
    
    # Extract status (look for [number])
    import re
    status_match = re.search(r'\[(\d+)\]', line)
    if status_match:
        result['status'] = status_match.group(1)
    
    # Extract other bracketed values
    bracket_matches = re.findall(r'\[([^\]]+)\]', line)
    if len(bracket_matches) >= 2:
        result['content_length'] = bracket_matches[1] if len(bracket_matches) > 1 else ''
    if len(bracket_matches) >= 3:
        result['word_count'] = bracket_matches[2] if len(bracket_matches) > 2 else ''
    if len(bracket_matches) >= 4:
        result['line_count'] = bracket_matches[3] if len(bracket_matches) > 3 else ''
    
    # Extract title (everything after URL and before any tech/location brackets)
    title_start = line.find(url) + len(url)
    title_end = line.find('[', title_start)
    if title_end == -1:
        title_end = len(line)
    
    title = line[title_start:title_end].strip()
    if title:
        result['title'] = title
    
    # Tech and location would be additional bracketed items
    if len(bracket_matches) >= 5:
        result['tech_detect'] = bracket_matches[4] if len(bracket_matches) > 4 else ''
    if len(bracket_matches) >= 6:
        result['location'] = bracket_matches[5] if len(bracket_matches) > 5 else ''
    
    return result

def get_crt_sh_subdomains(domain, scan_id=None):
    """Get subdomains from crt.sh API"""
    try:
        if scan_id:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📋 Querying crt.sh for {domain}...",
                'type': 'info'
            })
        
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                if 'name_value' in entry:
                    names = entry['name_value'].split('\n')
                    for name in names:
                        name = name.strip()
                        if name:
                            name = re.sub(r'^\*\.', '', name)
                            name = name.strip('.')
                            if name and domain in name:
                                subdomains.add(name)
                
                if 'common_name' in entry:
                    common_name = entry['common_name'].strip()
                    if common_name:
                        common_name = re.sub(r'^\*\.', '', common_name)
                        common_name = common_name.strip('.')
                        if common_name and domain in common_name:
                            subdomains.add(common_name)
            
            if scan_id:
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"✅ crt.sh found {len(subdomains)} unique subdomains",
                    'type': 'success'
                })
            return list(subdomains)
        else:
            if scan_id:
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"⚠️ crt.sh API returned status {response.status_code}",
                    'type': 'warning'
                })
            return []
            
    except Exception as e:
        if scan_id:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"❌ Error querying crt.sh: {str(e)[:100]}",
                'type': 'error'
            })
        return []

def scan_urls_with_details(urls_to_scan, scan_id=None):
    """Scan URLs and return detailed information"""
    if not urls_to_scan:
        return {}
    
    scan_file = f"tmp/url_scan_temp_{scan_id}.txt"
    with open(scan_file, "w") as f:
        f.write("\n".join(urls_to_scan))
    
    output_file = f"tmp/url_scan_results_{scan_id}.txt"
    httpx_scan(scan_file, output_file, show_progress=False, scan_id=scan_id)
    
    url_details = {}
    if os.path.exists(output_file):
        with open(output_file) as f:
            for line in f:
                parsed = parse_httpx_line(line)
                if parsed:
                    url_details[parsed['url']] = {
                        'status': parsed['status'],
                        'content_length': parsed['content_length'],
                        'word_count': parsed['word_count'],
                        'line_count': parsed['line_count'],
                        'title': parsed['title'],
                        'tech_detect': parsed['tech_detect'],
                        'location': parsed['location']
                    }
    
    if os.path.exists(scan_file):
        os.remove(scan_file)
    if os.path.exists(output_file):
        os.remove(output_file)
    
    return url_details

# =============================
# FLASK ROUTES
# =============================

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan/<scan_id>')
def scan_details(scan_id):
    """Show scan details page"""
    # Check if scan exists
    if scan_id not in scan_results and scan_id not in active_scans:
        return "Scan not found or has been deleted", 404
    
    return render_template('scan_details.html', scan_id=scan_id)

@app.route('/api/start_subdomain_discovery', methods=['POST'])
def start_subdomain_discovery():
    """Start subdomain discovery phase"""
    data = request.json
    domain = data.get('domain', '').strip()
    tools = data.get('tools', [])
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    scan_id = str(uuid.uuid4())
    
    # Initialize discovery in background
    socketio.start_background_task(target=discover_subdomains, 
                                  scan_id=scan_id, 
                                  domain=domain, 
                                  tools=tools)
    
    active_scans[scan_id] = {
        'status': 'discovering',
        'phase': 'subdomain_discovery',
        'progress': 0,
        'domain': domain,
        'start_time': datetime.now().isoformat(),
        'educational_notes': [
            "🔍 Subdomain discovery finds potential targets using public data",
            "📊 Results show what's publicly visible, not necessarily accessible",
            "⚠️ Many discovered subdomains may be inactive or restricted",
            "🎯 Use discovered patterns as investigation starting points"
        ]
    }
    
    return jsonify({'scan_id': scan_id, 'message': 'Subdomain discovery started'})

def discover_subdomains(scan_id, domain, tools):
    """Discover subdomains in background"""
    try:
        # Create temp directory
        clean_domain = re.sub(r'^https?://', '', domain)
        clean_domain = re.sub(r'^www\.', '', clean_domain)
        clean_domain = clean_domain.replace('/', '_').replace('.', '_')
        
        TMP = f"tmp_{clean_domain}"
        os.makedirs(TMP, exist_ok=True)
        
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"🔍 Starting subdomain discovery for: {domain}",
            'type': 'info'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "💡 This finds publicly visible subdomains using various sources",
            'type': 'info'
        })
        
        subs_files = []
        all_subs = set()
        
        tools_available = {
            "subfinder": check_tool_installed("subfinder"),
            "amass": check_tool_installed("amass"),
            "assetfinder": check_tool_installed("assetfinder"),
            "crt.sh": True
        }
        
        if "subfinder" in tools and tools_available["subfinder"]:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "🛠️ Running subfinder...",
                'type': 'info'
            })
            if run_with_timeout(f"subfinder -d {domain} -silent", timeout=120, 
                              outfile=f"{TMP}/subfinder.txt", scan_id=scan_id):
                if os.path.exists(f"{TMP}/subfinder.txt"):
                    with open(f"{TMP}/subfinder.txt", 'r') as f:
                        count = sum(1 for line in f if line.strip())
                    socketio.emit('scan_log', {
                        'scan_id': scan_id,
                        'message': f"✅ Subfinder found: {count} subdomain patterns",
                        'type': 'success'
                    })
                    subs_files.append(f"{TMP}/subfinder.txt")
        
        if "amass" in tools and tools_available["amass"]:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "🛠️ Running amass...",
                'type': 'info'
            })
            if run_with_timeout(f"amass enum -passive -d {domain}", timeout=180,
                              outfile=f"{TMP}/amass.txt", scan_id=scan_id):
                if os.path.exists(f"{TMP}/amass.txt"):
                    with open(f"{TMP}/amass.txt", 'r') as f:
                        count = sum(1 for line in f if line.strip())
                    socketio.emit('scan_log', {
                        'scan_id': scan_id,
                        'message': f"✅ Amass found: {count} subdomain patterns",
                        'type': 'success'
                    })
                    subs_files.append(f"{TMP}/amass.txt")
        
        if "assetfinder" in tools and tools_available["assetfinder"]:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "🛠️ Running assetfinder...",
                'type': 'info'
            })
            if run_with_timeout(f"assetfinder --subs-only {domain}", timeout=60,
                              outfile=f"{TMP}/assetfinder.txt", scan_id=scan_id):
                if os.path.exists(f"{TMP}/assetfinder.txt"):
                    with open(f"{TMP}/assetfinder.txt", 'r') as f:
                        count = sum(1 for line in f if line.strip())
                    socketio.emit('scan_log', {
                        'scan_id': scan_id,
                        'message': f"✅ Assetfinder found: {count} subdomain patterns",
                        'type': 'success'
                    })
                    subs_files.append(f"{TMP}/assetfinder.txt")
        
        if "crt.sh" in tools:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "📋 Querying crt.sh...",
                'type': 'info'
            })
            crt_subs = get_crt_sh_subdomains(domain, scan_id)
            if crt_subs:
                with open(f"{TMP}/crtsh.txt", "w") as f:
                    f.write("\n".join(crt_subs))
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"✅ crt.sh found: {len(crt_subs)} subdomain patterns",
                    'type': 'success'
                })
                subs_files.append(f"{TMP}/crtsh.txt")
                all_subs.update(crt_subs)
        
        # Merge results
        for file in subs_files:
            if os.path.exists(file):
                try:
                    with open(file, 'r') as f:
                        for line in f:
                            sub = line.strip()
                            if sub and domain in sub:
                                all_subs.add(sub)
                except Exception as e:
                    socketio.emit('scan_log', {
                        'scan_id': scan_id,
                        'message': f"⚠️ Error reading {file}: {str(e)[:100]}",
                        'type': 'warning'
                    })
        
        if all_subs:
            with open(f"{TMP}/subs.txt", "w") as f:
                f.write("\n".join(sorted(all_subs)))
            
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📊 Total unique subdomain patterns: {len(all_subs)}",
                'type': 'success'
            })
        else:
            # Add default subdomains if none found
            all_subs.add(domain)
            common_subs = [
                f"www.{domain}", f"mail.{domain}", f"webmail.{domain}",
                f"blog.{domain}", f"api.{domain}", f"dev.{domain}",
                f"test.{domain}", f"staging.{domain}", f"app.{domain}",
                f"admin.{domain}"
            ]
            all_subs.update(common_subs)
            
            with open(f"{TMP}/subs.txt", "w") as f:
                f.write("\n".join(sorted(all_subs)))
            
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📋 Using {len(all_subs)} common subdomain patterns for investigation",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "💡 Note: These are common patterns, not confirmed active subdomains",
                'type': 'info'
            })
        
        # Store discovered subdomains for selection
        discovered_subdomains[scan_id] = {
            'subdomains': list(all_subs),
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'educational_notes': [
                "🔍 These are discovered patterns, not confirmed active endpoints",
                "📊 Many subdomains may be inactive, internal, or restricted",
                "🎯 Use patterns to prioritize manual investigation",
                "⚠️ Pattern discovery ≠ vulnerability discovery"
            ]
        }
        
        # Update active scan status
        active_scans[scan_id]['status'] = 'discovery_complete'
        active_scans[scan_id]['progress'] = 100
        
        # Emit discovery complete
        socketio.emit('discovery_complete', {
            'scan_id': scan_id,
            'message': 'Subdomain discovery completed',
            'educational_note': 'Discovery finds public patterns - manual verification needed for actual access',
            'subdomains_count': len(all_subs),
            'domain': domain
        })
        
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"✅ Subdomain discovery complete. Found {len(all_subs)} patterns to investigate.",
            'type': 'success'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "🔍 Next: Select which patterns to investigate further",
            'type': 'info'
        })
        
    except Exception as e:
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"❌ Error during subdomain discovery: {str(e)[:100]}",
            'type': 'error'
        })
        
        socketio.emit('discovery_error', {
            'scan_id': scan_id,
            'message': f"Discovery failed: {str(e)[:100]}",
            'educational_note': 'Discovery tools rely on public data - failures are common and don\'t mean the target is secure'
        })
        
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'

@app.route('/api/get_discovered_subdomains/<scan_id>')
def get_discovered_subdomains(scan_id):
    """Get discovered subdomains for selection"""
    if scan_id in discovered_subdomains:
        return jsonify(discovered_subdomains[scan_id])
    else:
        return jsonify({'error': 'No discovered subdomains found'}), 404

@app.route('/api/start_selected_scan', methods=['POST'])
def start_selected_scan():
    """Start scan with selected subdomains"""
    data = request.json
    scan_id = data.get('scan_id', '')
    selected_subs = data.get('selected_subdomains', [])
    scan_mode = data.get('scan_mode', '1')
    verify_endpoints = data.get('verify_endpoints', 'no')
    js_analysis = data.get('js_analysis', 'yes')
    endpoint_harvesting = data.get('endpoint_harvesting', 'off')
    
    if not scan_id or scan_id not in discovered_subdomains:
        return jsonify({'error': 'Invalid scan ID or no discovered subdomains'}), 400
    
    if not selected_subs:
        return jsonify({'error': 'No subdomains selected'}), 400
    
    # Create a new scan ID for the actual scan
    new_scan_id = str(uuid.uuid4())
    
    # Get domain from discovery
    domain = discovered_subdomains[scan_id]['domain']
    
    # Start the actual scan with selected subdomains
    socketio.start_background_task(target=run_selected_scan, 
                                  scan_id=new_scan_id,
                                  discovery_scan_id=scan_id,
                                  domain=domain,
                                  selected_subs=selected_subs,
                                  scan_mode=scan_mode,
                                  verify_endpoints=verify_endpoints,
                                  js_analysis=js_analysis,
                                  endpoint_harvesting=endpoint_harvesting)
    
    active_scans[new_scan_id] = {
        'status': 'running',
        'phase': 'scanning',
        'progress': 0,
        'domain': domain,
        'start_time': datetime.now().isoformat(),
        'selected_subdomains_count': len(selected_subs),
        'educational_notes': [
            "🔍 Static reconnaissance in progress",
            "📊 This tool finds patterns and potential investigation targets",
            "⚠️ IMPORTANT: Findings are heuristic-based, not confirmed vulnerabilities",
            "🎯 PATTERN MATCH CONFIDENCE: Higher percentages mean more patterns matched",
            "❌ CONFIDENCE INTERPRETATION: Not exploitability, risk assessment, or vulnerability confirmation",
            "🔎 All findings require manual verification",
            "📋 REMINDER: Pattern matching ≠ vulnerability"
        ]
    }
    
    return jsonify({'scan_id': new_scan_id, 'message': 'Scan started with selected subdomains'})

def run_selected_scan(scan_id, discovery_scan_id, domain, selected_subs, scan_mode, verify_endpoints, js_analysis, endpoint_harvesting):
    """Run scan with selected subdomains"""
    try:
        # Set endpoint harvesting based on selection
        global ENDPOINT_HARVESTING_ENABLED
        ENDPOINT_HARVESTING_ENABLED = (endpoint_harvesting == 'on')
        
        if ENDPOINT_HARVESTING_ENABLED:
            load_harvested_endpoints()
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📚 Endpoint pattern learning enabled. Loaded {len(HARVESTED_ENDPOINTS)} patterns from previous scans.",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "💡 New endpoint patterns will be saved for future reconnaissance.",
                'type': 'info'
            })
        
        # Create temp directory
        clean_domain = re.sub(r'^https?://', '', domain)
        clean_domain = re.sub(r'^www\.', '', clean_domain)
        clean_domain = clean_domain.replace('/', '_').replace('.', '_')
        
        TMP = f"tmp_{clean_domain}_{scan_id}"
        os.makedirs(TMP, exist_ok=True)
        
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"🔍 Starting reconnaissance on {len(selected_subs)} selected subdomain patterns...",
            'type': 'info'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "💡 This is static reconnaissance - finding patterns and potential investigation targets",
            'type': 'info'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "⚠️ IMPORTANT: All findings require manual verification. This tool provides investigation starting points.",
            'type': 'warning'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "🎯 CONFIDENCE INTERPRETATION: Higher percentages indicate more patterns matched, NOT higher vulnerability likelihood",
            'type': 'info'
        })
        
        # Load wordlists (with error handling)
        try:
            load_wordlists()
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "📋 Loaded pattern databases for analysis",
                'type': 'success'
            })
        except Exception as e:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"⚠️ Using default patterns (custom pattern loading failed: {str(e)[:100]})",
                'type': 'warning'
            })
            # Set default patterns directly
            default_patterns()
        
        # Scan with httpx
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"🌐 Checking {len(selected_subs)} selected subdomain patterns with httpx...",
            'type': 'info'
        })
        
        urls_to_scan = set()
        for sub in selected_subs:
            urls_to_scan.add(f"http://{sub}")
            urls_to_scan.add(f"https://{sub}")
        
        with open(f"{TMP}/selected_urls.txt", "w") as f:
            f.write("\n".join(sorted(urls_to_scan)))
        
        httpx_scan(f"{TMP}/selected_urls.txt", f"{TMP}/selected_urls_status.txt", scan_id=scan_id)
        
        # Parse httpx results
        all_subdomains_data = []
        if os.path.exists(f"{TMP}/selected_urls_status.txt"):
            with open(f"{TMP}/selected_urls_status.txt") as f:
                for line in f:
                    parsed = parse_httpx_line(line)
                    if parsed:
                        all_subdomains_data.append(parsed)
        
        live_urls = []
        for data in all_subdomains_data:
            try:
                status = int(data['status'])
                if 200 <= status < 400:
                    live_urls.append(data['url'])
            except:
                pass
        
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"📊 Found {len(live_urls)} accessible URLs from selected patterns",
            'type': 'success'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "💡 Accessible URLs are starting points for investigation, not confirmed vulnerabilities",
            'type': 'info'
        })
        
        # Use all URLs as targets
        targets = [data['url'] for data in all_subdomains_data]
        
        # Initialize results
        urls = set()
        js_files = set()
        interesting_js_files = set()
        
        # Run katana if there are targets
        if targets and scan_mode in ["1", "3"]:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"🕷️ Running katana on {len(targets)} targets to find linked content...",
                'type': 'info'
            })
            
            katana_flags = "-silent -depth 5"
            if scan_mode in ("2", "3"):
                katana_flags += " -jc"
            
            if check_tool_installed("katana"):
                # Create katana targets file
                with open(f"{TMP}/katana_targets.txt", "w") as f:
                    f.write("\n".join(targets))
                    
                run_with_timeout(
                    f"katana -list {TMP}/katana_targets.txt {katana_flags}",
                    timeout=600,
                    outfile=f"{TMP}/katana.txt",
                    scan_id=scan_id
                )
            else:
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': "⚠️ katana is not installed - skipping content discovery",
                    'type': 'warning'
                })
            
            # Parse katana results
            if os.path.exists(f"{TMP}/katana.txt"):
                with open(f"{TMP}/katana.txt") as f:
                    for l in f:
                        l = l.strip()
                        if l.endswith(".js") or l.endswith(".js.map"):
                            js_files.add(l)
                        elif l.startswith("http"):
                            urls.add(l)
                
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"📊 Katana found: {len(urls)} URL patterns and {len(js_files)} JS file patterns",
                    'type': 'success'
                })
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': "💡 These are discovered patterns - many may be non-functional or require authentication",
                    'type': 'info'
                })
        
        # Filter interesting JS files
        for js_file in js_files:
            if is_interesting_js(js_file):
                interesting_js_files.add(js_file)
                # Also add corresponding source map if it exists
                if js_file.endswith('.js') and not js_file.endswith('.js.map'):
                    js_map_file = js_file + '.map'
                    interesting_js_files.add(js_map_file)
        
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"🔍 Found {len(interesting_js_files)} interesting JS file patterns for analysis",
            'type': 'info'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "💡 'Interesting' means the filename matches common patterns for application code",
            'type': 'info'
        })
        
        # ============================================
        # JavaScript Analysis Module
        # ============================================
        js_analysis_results = {}
        if js_analysis == 'yes' and interesting_js_files:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"🔬 Starting static JavaScript analysis on {len(interesting_js_files)} file patterns...",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "⚠️ IMPORTANT: This is static code analysis looking for text patterns only",
                'type': 'warning'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "💡 The tool reads JavaScript files but cannot execute them or understand runtime behavior",
                'type': 'info'
            })
            
            js_analysis_results = analyze_js_files(list(interesting_js_files), domain, scan_id)
            
            # Add discovered endpoints from JS to main URL list
            urls.update(js_analysis_results.get('internal_urls', []))
            
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📊 JS analysis found {len(js_analysis_results.get('internal_urls', []))} internal URL patterns and {len(js_analysis_results.get('secrets', []))} potential secret patterns",
                'type': 'success'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "⚠️ REMINDER: These are PATTERNS found in code, not confirmed secrets or vulnerabilities",
                'type': 'warning'
            })
        
        # ============================================
        # Endpoint Verification
        # ============================================
        verification_results = {}
        if verify_endpoints in ['yes', 'sample']:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "🔍 Starting endpoint accessibility verification...",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "💡 This checks if endpoints respond to HTTP requests - it does NOT test functionality or security",
                'type': 'info'
            })
            
            verifier = EndpointVerifier(max_workers=10, timeout=10)
            
            endpoints_to_verify = list(urls)
            if verify_endpoints == 'sample':
                endpoints_to_verify = endpoints_to_verify[:50]
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': "📋 Checking sample of 50 endpoints for accessibility",
                    'type': 'info'
                })
            
            verification_results = verifier.verify_batch(endpoints_to_verify)
            
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📊 Verified {len([r for r in verification_results if r.get('verified', False)])} endpoints as accessible",
                'type': 'success'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "💡 Accessible endpoints are investigation starting points, not security findings",
                'type': 'info'
            })
        
        # ============================================
        # IMPROVED Endpoint Classification
        # ============================================
        classified_endpoints = []
        if urls:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "📊 Classifying discovered endpoint patterns by pattern match confidence...",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "⚠️ IMPORTANT: Classification is based on URL patterns only, not security testing",
                'type': 'warning'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "🎯 PATTERN MATCH CONFIDENCE: Higher percentage means more patterns matched from our database",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "📋 CONFIDENCE CONTEXT: Percentages measure pattern matching, not exploitability or risk",
                'type': 'info'
            })
            
            classified_endpoints = classify_endpoints(list(urls), domain)
            
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': f"📊 Classified {len(classified_endpoints)} endpoint patterns by pattern match confidence",
                'type': 'success'
            })
        
        # ============================================
        # Endpoint Harvesting
        # ============================================
        harvested_count = 0
        if ENDPOINT_HARVESTING_ENABLED and urls:
            harvested_count = harvest_endpoints(urls, domain, scan_id)
            if harvested_count > 0:
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': f"📚 Learned {harvested_count} new endpoint patterns. Total patterns in database: {len(HARVESTED_ENDPOINTS)}",
                    'type': 'success'
                })
                socketio.emit('scan_log', {
                    'scan_id': scan_id,
                    'message': "💡 Pattern learning improves future reconnaissance by remembering common endpoint structures",
                    'type': 'info'
                })
        
        # ============================================
        # IMPROVED Testing Recommendations
        # ============================================
        investigation_suggestions = []
        if classified_endpoints:
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "💡 Generating investigation suggestions...",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "⚠️ IMPORTANT: These are SUGGESTIONS for manual investigation, not confirmed vulnerabilities",
                'type': 'warning'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "🔍 The tool cannot test actual authentication, authorization, or business logic",
                'type': 'info'
            })
            socketio.emit('scan_log', {
                'scan_id': scan_id,
                'message': "🎯 PATTERN CONFIDENCE: Measures pattern matching likelihood, not exploitability",
                'type': 'info'
            })
            
            tester = TestingRecommendation()
            # Only analyze endpoints with decent pattern match confidence
            high_confidence_endpoints = [ep for ep in classified_endpoints 
                                      if ep['classification']['confidence_percentage'] >= 40]
            
            for endpoint in high_confidence_endpoints[:15]:
                suggestions = tester.analyze_endpoint(
                    endpoint['url'], 
                    endpoint['classification']
                )
                if suggestions:
                    endpoint['investigation_suggestions'] = suggestions
                    investigation_suggestions.append(endpoint)
        
        # Generate report data with improved classification
        report = {
            'scan_id': scan_id,
            'domain': domain,
            'selected_subdomains': selected_subs,
            'live_urls': live_urls,
            'katana_urls': list(urls),
            'js_files': list(js_files),
            'interesting_js_files': list(interesting_js_files),
            'js_analysis': js_analysis_results,
            'verification': verification_results,
            'classified_endpoints': classified_endpoints,
            'investigation_suggestions': investigation_suggestions,
            'endpoint_harvesting': {
                'enabled': ENDPOINT_HARVESTING_ENABLED,
                'harvested_count': harvested_count,
                'total_harvested': len(HARVESTED_ENDPOINTS)
            },
            'status': 'completed',
            'scan_summary': {
                'selected_subdomains_count': len(selected_subs),
                'live_urls_count': len(live_urls),
                'endpoints_count': len(urls),
                'js_files_count': len(js_files),
                'interesting_js_count': len(interesting_js_files),
                'classified_endpoints_count': len(classified_endpoints),
                'high_confidence_patterns': len([ep for ep in classified_endpoints 
                                              if ep['classification']['confidence_percentage'] >= 80]),
                'secrets_found': len(js_analysis_results.get('secrets', [])),
                'api_endpoints_found': len(js_analysis_results.get('api_urls', [])),
                'harvested_endpoints': harvested_count
            },
            'scan_details': {
                'scan_mode': scan_mode,
                'verify_endpoints': verify_endpoints,
                'js_analysis': js_analysis,
                'endpoint_harvesting': endpoint_harvesting
            },
            'timestamp': datetime.now().isoformat(),
            'pattern_match_interpretation': {
                'what_percentages_measure': [
                    "Percentage of predefined patterns matched",
                    "Pattern recognition confidence",
                    "Similarity to known endpoint structures"
                ],
                'what_percentages_do_not_measure': [
                    "Security risk or exploitability",
                    "Attack success likelihood",
                    "Actual vulnerability existence",
                    "Impact severity"
                ],
                'how_to_use_percentages': [
                    "Prioritize manual investigation - higher percentages first",
                    "Use as pattern matching confidence indicators",
                    "Combine with other investigation factors",
                    "Remember: Percentage ≠ Vulnerability"
                ],
                'expected_false_positive_rates': [
                    "30-50% false positive rate for pattern-based detection",
                    "All findings require manual verification",
                    "Context matters - patterns alone are not conclusive"
                ]
            },
            'educational_notes': [
                "🔍 RECONNAISSANCE REPORT: Static Pattern Analysis",
                "📊 This report shows PATTERN MATCH CONFIDENCE and investigation suggestions",
                "⚠️ IMPORTANT DISCLAIMER: These are NOT confirmed vulnerabilities",
                "🎯 PATTERN MATCH CONFIDENCE: Higher percentages indicate more patterns matched",
                "❌ WHAT CONFIDENCE MEASURES: Pattern recognition, NOT security risk",
                "🔎 ALL FINDINGS REQUIRE 100% MANUAL VERIFICATION",
                "ℹ️ TOOL LIMITATIONS:",
                "   • Cannot test authentication or authorization",
                "   • Does not understand business logic",
                "   • Sees patterns but cannot interact with applications",
                "   • Cannot determine actual security controls",
                "📋 CONFIDENCE INTERPRETATION GUIDE:",
                "   • 80-100%: Strong pattern match - prioritize investigation",
                "   • 60-79%: Good pattern match - consider for investigation",
                "   • 40-59%: Moderate pattern match - investigate if time permits",
                "   • 20-39%: Weak pattern match - low priority",
                "   • 0-19%: Minimal pattern match - baseline investigation",
                "🎯 NEXT STEPS FOR MANUAL INVESTIGATION:",
                "   1. ⚠️ GET PROPER AUTHORIZATION before testing",
                "   2. 🔍 Start with strong pattern matches",
                "   3. 🛡️ Test with appropriate tools and methodologies",
                "   4. 📝 Document all findings and testing procedures",
                "   5. 🔄 Remember: Pattern matching ≠ vulnerability",
                "   6. 🎓 Use findings as learning opportunities"
            ]
        }
        
        # Store results in memory
        scan_results[scan_id] = report
        
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "✅ Reconnaissance completed successfully!",
            'type': 'success'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "📋 Report generated with pattern match confidence analysis",
            'type': 'info'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "⚠️ REMEMBER: This is static pattern analysis. Manual verification required for all findings.",
            'type': 'warning'
        })
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': "🎯 USE CONFIDENCE PERCENTAGES TO: Prioritize investigation order, NOT to assess security",
            'type': 'info'
        })
        
        # Emit completion with report data
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'message': 'Reconnaissance completed successfully',
            'educational_note': 'This report shows pattern match confidence. Manual verification required.',
            'results': report
        })
        
        # Update active_scans
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['progress'] = 100
            active_scans[scan_id]['results'] = report
        
    except Exception as e:
        socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': f"❌ Error during reconnaissance: {str(e)[:100]}",
            'type': 'error'
        })
        
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'message': f"Reconnaissance failed: {str(e)[:100]}",
            'educational_note': 'Tool failures do not indicate target security. Manual investigation is still required.'
        })
        
        # Mark as failed
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'

@app.route('/api/scan_status/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status without loading full results"""
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    elif scan_id in scan_results:
        return jsonify({
            'status': 'completed',
            'scan_id': scan_id,
            'domain': scan_results[scan_id].get('domain', ''),
            'completion_time': scan_results[scan_id].get('timestamp', ''),
            'educational_note': 'This was static pattern reconnaissance. Percentages indicate pattern match confidence, not vulnerability likelihood.'
        })
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scan_results/<scan_id>')
def get_scan_results(scan_id):
    """Get scan results - FIXED VERSION"""
    if scan_id in scan_results:
        try:
            # Return the results directly from memory
            return jsonify(scan_results[scan_id])
        except Exception as e:
            app.logger.error(f"Error loading scan results from memory: {e}")
            return jsonify({
                'error': 'Could not load results',
                'details': str(e),
                'scan_id': scan_id,
                'educational_note': 'Tool limitations: Static analysis provides investigation starting points only'
            }), 500
    elif scan_id in active_scans:
        # Scan is still running
        return jsonify({
            'status': 'running',
            'scan_id': scan_id,
            'domain': active_scans[scan_id].get('domain', ''),
            'message': 'Reconnaissance is still in progress',
            'educational_note': 'This is static pattern analysis. Percentages will indicate pattern match confidence, not security risk.'
        })
    else:
        return jsonify({
            'error': 'Scan not found',
            'scan_id': scan_id,
            'educational_note': 'Reconnaissance tools find patterns, not vulnerabilities. Manual testing is always required.'
        }), 404

@app.route('/api/check_tools')
def check_tools():
    """Check which tools are installed"""
    tools = {
        'subfinder': check_tool_installed('subfinder'),
        'amass': check_tool_installed('amass'),
        'assetfinder': check_tool_installed('assetfinder'),
        'katana': check_tool_installed('katana'),
        'httpx': check_tool_installed('httpx'),
        'educational_note': 'These tools help with reconnaissance by finding patterns and accessible endpoints'
    }
    return jsonify(tools)

@app.route('/api/stop_scan/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan"""
    if scan_id in active_scans:
        # Mark as stopped
        active_scans[scan_id]['status'] = 'stopped'
        return jsonify({
            'message': 'Reconnaissance stopped',
            'educational_note': 'Partial results may still provide investigation starting points'
        })
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scan_exists/<scan_id>')
def scan_exists(scan_id):
    """Check if a scan exists"""
    exists = scan_id in active_scans or scan_id in scan_results
    return jsonify({'exists': exists})

# =============================
# EXPORT ROUTES
# =============================

@app.route('/api/export/<scan_id>/<export_type>')
def export_scan_data(scan_id, export_type):
    """Export scan data in different formats"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = scan_results[scan_id]
    
    if export_type == 'json':
        # Return as JSON download
        response = jsonify(scan_data)
        response.headers['Content-Disposition'] = f'attachment; filename=recon_patterns_{scan_id}.json'
        response.headers['Content-Type'] = 'application/json'
        return response
    
    elif export_type == 'txt':
        # Create a text summary
        text_content = create_text_summary(scan_data, scan_id)
        response = app.response_class(
            response=text_content,
            status=200,
            mimetype='text/plain'
        )
        response.headers['Content-Disposition'] = f'attachment; filename=recon_investigation_guide_{scan_id}.txt'
        return response
    
    elif export_type == 'csv':
        # Create CSV export
        csv_content = create_csv_export(scan_data)
        response = app.response_class(
            response=csv_content,
            status=200,
            mimetype='text/csv'
        )
        response.headers['Content-Disposition'] = f'attachment; filename=recon_patterns_{scan_id}.csv'
        return response
    
    else:
        return jsonify({'error': 'Invalid export type'}), 400

def create_text_summary(scan_data, scan_id):
    """Create a text summary of the scan"""
    text = f"""
==========================================
WEB RECONNAISSANCE FRAMEWORK - PATTERN ANALYSIS REPORT
==========================================
⚠️  IMPORTANT DISCLAIMER: This is STATIC PATTERN ANALYSIS
⚠️  Findings are pattern match confidence indicators, NOT vulnerability confirmations
⚠️  ALL findings require 100% MANUAL VERIFICATION
⚠️  PERCENTAGES MEASURE PATTERN MATCHING, NOT SECURITY RISK

Scan ID: {scan_id}
Domain: {scan_data.get('domain', 'N/A')}
Timestamp: {scan_data.get('timestamp', 'N/A')}
Status: {scan_data.get('status', 'N/A')}

🔍 PATTERN MATCH CONFIDENCE INTERPRETATION:
------------------------------------------
• CONFIDENCE PERCENTAGES: Higher percentages indicate more patterns matched from our database
• WHAT THIS MEASURES: Pattern recognition accuracy, similarity to known structures
• WHAT THIS DOES NOT MEASURE: Security risk, exploitability, actual vulnerability existence
• HOW TO USE PERCENTAGES: Prioritize manual investigation - higher percentages first
• EXPECTED FALSE POSITIVE RATE: 30-50% for pattern-based detection
• VERIFICATION REQUIREMENT: 100% manual verification required for all findings

📊 RECONNAISSANCE SUMMARY (Pattern Analysis):
---------------------------------------------
Selected Subdomain Patterns: {scan_data.get('selected_subdomains_count', 0)}
Accessible URLs Found: {scan_data.get('live_urls_count', 0)}
Endpoint Patterns Discovered: {scan_data.get('endpoints_count', 0)}
JS File Patterns Found: {scan_data.get('js_files_count', 0)}
Interesting JS File Patterns: {scan_data.get('interesting_js_count', 0)}
Classified Endpoint Patterns: {scan_data.get('classified_endpoints_count', 0)}
Strong Pattern Matches: {scan_data.get('high_confidence_patterns', 0)}
Potential Secret Patterns: {scan_data.get('secrets_found', 0)}
API Endpoint Patterns: {scan_data.get('api_endpoints_found', 0)}
New Patterns Learned: {scan_data.get('endpoint_harvesting', {}).get('harvested_count', 0)}

🔍 RECONNAISSANCE DETAILS:
-------------------------
Scan Mode: {scan_data.get('scan_details', {}).get('scan_mode', 'N/A')}
Endpoint Accessibility Check: {scan_data.get('scan_details', {}).get('verify_endpoints', 'N/A')}
JS Pattern Analysis: {scan_data.get('scan_details', {}).get('js_analysis', 'N/A')}
Pattern Learning: {scan_data.get('scan_details', {}).get('endpoint_harvesting', 'N/A')}

📋 SELECTED SUBDOMAIN PATTERNS:
-------------------------------
"""
    
    for i, subdomain in enumerate(scan_data.get('selected_subdomains', []), 1):
        text += f"{i}. {subdomain}\n"
    
    text += f"\n🔗 ACCESSIBLE URLs ({len(scan_data.get('live_urls', []))}):\n"
    text += "-" * 70 + "\n"
    text += "💡 These URLs responded to HTTP requests. They are investigation starting points.\n"
    for i, url in enumerate(scan_data.get('live_urls', []), 1):
        text += f"{i}. {url}\n"
    
    # Classified Endpoints with Confidence Percentages
    if 'classified_endpoints' in scan_data and scan_data['classified_endpoints']:
        text += f"\n🎯 CLASSIFIED ENDPOINT PATTERNS (by Pattern Match Confidence):\n"
        text += "-" * 70 + "\n"
        text += "⚠️ IMPORTANT: Classification is based on URL patterns only, not security testing\n"
        text += "🎯 PATTERN MATCH CONFIDENCE: Higher percentage means more patterns matched\n"
        text += "📋 CONFIDENCE INTERPRETATION: Percentages measure pattern matching, not exploitability\n\n"
        
        # Group by confidence ranges
        strong_matches = [ep for ep in scan_data['classified_endpoints'] 
                          if ep['classification']['confidence_percentage'] >= 80]
        good_matches = [ep for ep in scan_data['classified_endpoints'] 
                             if 60 <= ep['classification']['confidence_percentage'] < 80]
        
        if strong_matches:
            text += f"🔴 STRONG PATTERN MATCHES ({len(strong_matches)} endpoints):\n"
            text += "💡 These match multiple patterns from our database - prioritize investigation\n"
            for i, ep in enumerate(strong_matches[:10], 1):
                text += f"  {i}. {ep['url']}\n"
                text += f"     🔍 Pattern Match Confidence: {ep['classification']['confidence_percentage']}%\n"
                
                # Use categories (backward compatible field)
                categories = ep['classification'].get('categories', [])
                if not categories:
                    categories = ep['classification'].get('matched_categories', [])
                categories_str = ', '.join(categories[:3]) if categories else 'None'
                
                text += f"     📊 Categories: {categories_str}\n"
                text += f"     🎯 Investigation Priority: {ep['classification'].get('priority', 'BASELINE')}\n"
        
        if good_matches:
            text += f"\n🟡 GOOD PATTERN MATCHES ({len(good_matches)} endpoints):\n"
            text += "💡 These match several patterns - consider for investigation\n"
            for i, ep in enumerate(good_matches[:5], 1):
                text += f"  {i}. {ep['url']}\n"
                text += f"     🔍 Pattern Match Confidence: {ep['classification']['confidence_percentage']}%\n"
    
    # Investigation Suggestions
    if 'investigation_suggestions' in scan_data and scan_data['investigation_suggestions']:
        text += f"\n💡 INVESTIGATION SUGGESTIONS:\n"
        text += "-" * 70 + "\n"
        text += "⚠️ IMPORTANT: These are SUGGESTIONS for manual investigation, not confirmed vulnerabilities\n"
        text += "🔍 The tool cannot test actual authentication, authorization, or business logic\n"
        text += "🎯 PATTERN CONFIDENCE: Measures pattern matching likelihood, not exploitability\n\n"
        
        for i, suggestion in enumerate(scan_data['investigation_suggestions'][:5], 1):
            text += f"\n{i}. {suggestion['url']}\n"
            text += f"   🔍 Pattern Match Confidence: {suggestion['classification']['confidence_percentage']}%\n"
            
            # Use categories (backward compatible field)
            categories = suggestion['classification'].get('categories', [])
            if not categories:
                categories = suggestion['classification'].get('matched_categories', [])
            categories_str = ', '.join(categories[:3]) if categories else 'None'
            
            text += f"   📊 Categories: {categories_str}\n"
            text += f"   🎯 Investigation Priority: {suggestion['classification'].get('priority', 'BASELINE')}\n"
            
            if 'investigation_suggestions' in suggestion:
                for pattern_suggestion in suggestion['investigation_suggestions'][:2]:
                    text += f"\n   🎯 {pattern_suggestion['pattern_type']}\n"
                    text += f"      📋 Pattern Confidence: {pattern_suggestion['pattern_confidence']}%\n"
                    text += f"      💡 Suggestion: {pattern_suggestion['investigation_suggestion']}\n"
                    text += f"      📝 Why suggested: {pattern_suggestion['why_suggested']}\n"
                    
                    text += f"      ⚠️ TOOL LIMITATIONS:\n"
                    for limitation in pattern_suggestion['limitations']:
                        text += f"         • {limitation}\n"
    
    text += "\n" + "=" * 70 + "\n"
    text += "🎯 NEXT STEPS FOR MANUAL INVESTIGATION:\n"
    text += "=" * 70 + "\n"
    text += "1. ⚠️  GET PROPER AUTHORIZATION before testing\n"
    text += "2. 🔍  Start with strong pattern matches\n"
    text += "3. 📊  Use confidence percentages to prioritize investigation order\n"
    text += "4. 🛡️  Test with appropriate tools and methodologies\n"
    text += "5. 📝  Document all findings and testing procedures\n"
    text += "6. 🔄  Remember: Pattern matching ≠ vulnerability\n"
    text += "7. 🎓  Use findings as learning opportunities\n"
    text += "\n" + "=" * 70 + "\n"
    text += "📋 CONFIDENCE PERCENTAGE INTERPRETATION REMINDER:\n"
    text += "=" * 70 + "\n"
    text += "• 80-100%: Strong pattern match - prioritize investigation\n"
    text += "• 60-79%: Good pattern match - consider for investigation\n"
    text += "• 40-59%: Moderate pattern match - investigate if time permits\n"
    text += "• 20-39%: Weak pattern match - low priority\n"
    text += "• 0-19%: Minimal pattern match - baseline investigation\n"
    text += "\n" + "=" * 70 + "\n"
    text += "END OF PATTERN ANALYSIS REPORT\n"
    text += "=" * 70 + "\n"
    text += "\n⚠️  REMEMBER: This is a reconnaissance tool for finding investigation\n"
    text += "    starting points. It does NOT perform security testing.\n"
    text += "    Always verify findings manually with proper authorization.\n"
    text += "\n🎯  USE PERCENTAGES TO: Prioritize investigation order\n"
    text += "❌  NOT TO: Assess security risk or exploitability\n"
    
    return text

def create_csv_export(scan_data):
    """Create CSV export of scan data"""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header with disclaimer
    writer.writerow(['WEB RECONNAISSANCE - PATTERN ANALYSIS REPORT'])
    writer.writerow(['Disclaimer: Static pattern analysis only - 100% manual verification required'])
    writer.writerow(['Domain', scan_data.get('domain', 'N/A'), 'Timestamp', scan_data.get('timestamp', 'N/A')])
    writer.writerow(['Confidence Interpretation: Pattern match percentages, NOT vulnerability scores'])
    writer.writerow([])
    
    # Write summary with educational notes
    writer.writerow(['SUMMARY - PATTERN ANALYSIS'])
    writer.writerow(['Category', 'Count', 'Interpretation'])
    writer.writerow(['Selected Subdomain Patterns', scan_data.get('selected_subdomains_count', 0), 'Potential investigation targets'])
    writer.writerow(['Accessible URLs', scan_data.get('live_urls_count', 0), 'URLs that responded to HTTP requests'])
    writer.writerow(['Endpoint Patterns', scan_data.get('endpoints_count', 0), 'Discovered URL patterns'])
    writer.writerow(['Strong Pattern Matches', scan_data.get('high_confidence_patterns', 0), 'Patterns matching ≥80% of criteria'])
    writer.writerow(['Potential Secret Patterns', scan_data.get('secrets_found', 0), 'Text patterns that look like secrets - VERIFY MANUALLY'])
    writer.writerow(['API Endpoint Patterns', scan_data.get('api_endpoints_found', 0), 'URL patterns matching API conventions'])
    if 'endpoint_harvesting' in scan_data:
        writer.writerow(['New Patterns Learned', scan_data['endpoint_harvesting']['harvested_count'], 'Patterns saved for future reconnaissance'])
    writer.writerow([])
    writer.writerow(['IMPORTANT NOTES:'])
    writer.writerow(['• This is static pattern analysis, not security testing'])
    writer.writerow(['• Higher percentages mean "more patterns matched", not "exploitable"'])
    writer.writerow(['• All findings require 100% manual verification'])
    writer.writerow(['• Expected false positive rate: 30-50% for pattern-based detection'])
    writer.writerow(['• Percentages measure pattern matching, not exploitability'])
    writer.writerow([])
    
    # Write classified endpoints with confidence percentages
    if 'classified_endpoints' in scan_data and scan_data['classified_endpoints']:
        writer.writerow(['CLASSIFIED ENDPOINT PATTERNS (Top 100 by Pattern Match Confidence)'])
        writer.writerow(['Rank', 'Pattern', 'Confidence %', 'Categories', 'Investigation Priority'])
        
        for i, ep in enumerate(scan_data['classified_endpoints'][:100], 1):
            # Use categories (backward compatible field)
            categories = ep['classification'].get('categories', [])
            if not categories:
                categories = ep['classification'].get('matched_categories', [])
            categories_str = ', '.join(categories[:2]) if categories else 'None'
            
            writer.writerow([
                i,
                ep['url'],
                f"{ep['classification']['confidence_percentage']}%",
                categories_str,
                ep['classification'].get('priority', 'BASELINE')
            ])
        writer.writerow([])
    
    return output.getvalue()

@app.route('/api/export_category/<scan_id>/<category>')
def export_category(scan_id, category):
    """Export specific category data"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = scan_results[scan_id]
    
    if category == 'subdomains':
        data = scan_data.get('selected_subdomains', [])
        filename = f'subdomain_patterns_{scan_id}.txt'
        content = 'Subdomain Patterns for Investigation\n====================\n'
        content += 'These are potential targets found through reconnaissance.\n'
        content += 'Manual verification required for all patterns.\n\n'
        content += '\n'.join(data)
        mimetype = 'text/plain'
    
    elif category == 'live_urls':
        data = scan_data.get('live_urls', [])
        filename = f'accessible_urls_{scan_id}.txt'
        content = 'Accessible URLs for Investigation\n====================\n'
        content += 'These URLs responded to HTTP requests.\n'
        content += 'They are starting points for manual testing.\n\n'
        content += '\n'.join(data)
        mimetype = 'text/plain'
    
    elif category == 'classified_endpoints':
        data = scan_data.get('classified_endpoints', [])
        filename = f'pattern_confidence_analysis_{scan_id}.csv'
        
        # Create CSV with confidence percentages
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['URL', 'Pattern Match Confidence %', 'Categories', 'Investigation Priority', 'Suggestion'])
        
        for ep in data:
            url = ep.get('url', 'N/A')
            confidence = 'N/A'
            
            if 'classification' in ep and 'confidence_percentage' in ep['classification']:
                confidence = f"{ep['classification']['confidence_percentage']}%"
            elif 'classification' in ep and 'pattern_confidence' in ep['classification']:
                confidence = f"{ep['classification']['pattern_confidence']}%"
            
            # Use categories (backward compatible field)
            categories = ep['classification'].get('categories', [])
            if not categories:
                categories = ep['classification'].get('matched_categories', [])
            categories_str = 'None'
            if categories:
                categories_str = ', '.join(categories[:3])
            
            priority = ep['classification'].get('priority', 'BASELINE')
            
            suggestion = 'Investigate when time permits'
            if 'classification' in ep and 'investigation_priority' in ep['classification']:
                priority_data = ep['classification']['investigation_priority']
                if isinstance(priority_data, dict) and 'recommended_action' in priority_data:
                    suggestion = priority_data['recommended_action']
                elif isinstance(priority_data, dict) and 'explanation' in priority_data:
                    suggestion = priority_data['explanation']
            elif 'classification' in ep and 'suggestion' in ep['classification']:
                suggestion = ep['classification']['suggestion']
            
            writer.writerow([
                url,
                confidence,
                categories_str,
                priority,
                suggestion
            ])
        
        content = output.getvalue()
        mimetype = 'text/csv'
    
    else:
        return jsonify({'error': 'Invalid category'}), 400
    
    response = app.response_class(
        response=content,
        status=200,
        mimetype=mimetype
    )
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

# =============================
# CLEANUP FUNCTION
# =============================

def cleanup_old_files():
    """Clean up old temporary files"""
    import shutil
    import time
    
    current_time = time.time()
    max_age_hours = 24
    
    # Clean up old tmp directories
    for item in os.listdir('.'):
        if item.startswith('tmp_') and os.path.isdir(item):
            try:
                dir_mtime = os.path.getmtime(item)
                if current_time - dir_mtime > max_age_hours * 3600:
                    shutil.rmtree(item)
                    print(f"Cleaned up old directory: {item}")
            except Exception as e:
                print(f"Error cleaning up {item}: {e}")
    
    # Clean up individual tmp files
    tmp_dir = 'tmp'
    if os.path.exists(tmp_dir):
        for item in os.listdir(tmp_dir):
            item_path = os.path.join(tmp_dir, item)
            try:
                if os.path.isfile(item_path):
                    file_mtime = os.path.getmtime(item_path)
                    if current_time - file_mtime > max_age_hours * 3600:
                        os.remove(item_path)
                        print(f"Cleaned up old file: {item_path}")
            except Exception as e:
                print(f"Error cleaning up {item_path}: {e}")

# =============================
# MAIN ENTRY POINT
# =============================

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                     MERAGLIM				   ║
    ║			          WEB RECONNAISSANCE FRAMEWORK                     ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    
    🔍 By: Cod3pont1f | Version: 2.0
    
    ⚠️  IMPORTANT EDUCATIONAL NOTES:
    ════════════════════════════════════════════════════════════════════════
    1. This tool performs STATIC PATTERN ANALYSIS for reconnaissance
    2. It finds investigation starting points, NOT vulnerabilities
    3. Higher confidence percentages mean "more patterns matched", MAY NOT "exploitable"
    4. ALL findings require 100% MANUAL VERIFICATION
    5. Expected false positive rate: 30-50% for pattern-based detection
    
    🚀 FEATURES SUMMARY:
    ════════════════════════════════════════════════════════════════════════
    1. Professional pattern analysis with confidence scoring
    2. JavaScript file pattern analysis
    3. Source map (.js.map) parsing
    4. Potential secret pattern detection
    5. Endpoint pattern classification with professional confidence levels
    6. Investigation suggestions based on pattern matching
    7. Pattern learning for future reconnaissance
    8. Comprehensive professional results export
    
    🚀 Starting server on http://localhost:5000
    """)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
