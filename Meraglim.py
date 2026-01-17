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

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize SocketIO WITHOUT Eventlet (uses Flask's threading)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Global patterns dictionary to be loaded from wordlists
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

# Store active scans
active_scans = {}
scan_results = {}
# Store discovered subdomains for selection
discovered_subdomains = {}

# Dashboard settings
DASHBOARD_ENABLED = True
DASHBOARD_SAVE_TO_DB = False  # Default to not save to DB unless user enables
DASHBOARD_DB_FILE = "dashboard_data.db"

# Endpoint Harvesting settings
ENDPOINT_HARVESTING_ENABLED = False
HARVESTED_ENDPOINTS_FILE = "wordlists/endpoints_wordlist.txt"
HARVESTED_ENDPOINTS = set()

# =============================
# DASHBOARD DATABASE FUNCTIONS
# =============================

def init_dashboard_db():
    """Initialize dashboard SQLite database"""
    if not DASHBOARD_SAVE_TO_DB:
        return
    
    try:
        conn = sqlite3.connect(DASHBOARD_DB_FILE)
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                domain TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                selected_subdomains_count INTEGER,
                live_urls_count INTEGER,
                endpoints_count INTEGER,
                js_files_count INTEGER,
                interesting_js_count INTEGER,
                classified_endpoints_count INTEGER,
                high_confidence_patterns INTEGER,
                secrets_found INTEGER,
                api_endpoints_found INTEGER,
                harvested_endpoints INTEGER,
                scan_data_json TEXT
            )
        ''')
        
        # Create classification_stats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS classification_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                confidence_range TEXT,
                count INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        ''')
        
        # Create endpoint_categories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS endpoint_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                category TEXT,
                count INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        ''')
        
        # Create top_endpoints table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS top_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                endpoint_url TEXT,
                confidence_percentage INTEGER,
                categories TEXT,
                priority TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        ''')
        
        # Create dashboard_settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dashboard_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_name TEXT UNIQUE,
                setting_value TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error initializing dashboard database: {e}")
        return False

def save_scan_to_dashboard(scan_id, scan_data):
    """Save scan results to dashboard database"""
    if not DASHBOARD_SAVE_TO_DB:
        return
    
    try:
        conn = sqlite3.connect(DASHBOARD_DB_FILE)
        cursor = conn.cursor()
        
        # Insert scan summary
        summary = scan_data.get('scan_summary', {})
        cursor.execute('''
            INSERT OR REPLACE INTO scans (
                scan_id, domain, start_time, end_time, status,
                selected_subdomains_count, live_urls_count, endpoints_count,
                js_files_count, interesting_js_count, classified_endpoints_count,
                high_confidence_patterns, secrets_found, api_endpoints_found,
                harvested_endpoints, scan_data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            scan_data.get('domain', ''),
            scan_data.get('start_time', datetime.now().isoformat()),
            scan_data.get('timestamp', datetime.now().isoformat()),
            scan_data.get('status', 'completed'),
            summary.get('selected_subdomains_count', 0),
            summary.get('live_urls_count', 0),
            summary.get('endpoints_count', 0),
            summary.get('js_files_count', 0),
            summary.get('interesting_js_count', 0),
            summary.get('classified_endpoints_count', 0),
            summary.get('high_confidence_patterns', 0),
            summary.get('secrets_found', 0),
            summary.get('api_endpoints_found', 0),
            summary.get('harvested_endpoints', 0),
            json.dumps(scan_data)
        ))
        
        # Save classification statistics
        classified_endpoints = scan_data.get('classified_endpoints', [])
        if classified_endpoints:
            confidence_ranges = {
                'Strong Match (80-100%)': 0,
                'Good Match (60-79%)': 0,
                'Moderate Match (40-59%)': 0,
                'Weak Match (20-39%)': 0,
                'Minimal Match (0-19%)': 0
            }
            
            for ep in classified_endpoints:
                confidence = ep['classification'].get('confidence_percentage', 0)
                if confidence >= 80:
                    confidence_ranges['Strong Match (80-100%)'] += 1
                elif confidence >= 60:
                    confidence_ranges['Good Match (60-79%)'] += 1
                elif confidence >= 40:
                    confidence_ranges['Moderate Match (40-59%)'] += 1
                elif confidence >= 20:
                    confidence_ranges['Weak Match (20-39%)'] += 1
                else:
                    confidence_ranges['Minimal Match (0-19%)'] += 1
            
            for range_name, count in confidence_ranges.items():
                cursor.execute('''
                    INSERT INTO classification_stats (scan_id, confidence_range, count)
                    VALUES (?, ?, ?)
                ''', (scan_id, range_name, count))
        
        # Save endpoint categories
        category_counts = defaultdict(int)
        for ep in classified_endpoints:
            # Use categories (backward compatible field)
            categories = ep['classification'].get('categories', [])
            if not categories:
                categories = ep['classification'].get('matched_categories', [])
            
            for category in categories:
                category_counts[category] += 1
        
        for category, count in category_counts.items():
            cursor.execute('''
                INSERT INTO endpoint_categories (scan_id, category, count)
                VALUES (?, ?, ?)
            ''', (scan_id, category, count))
        
        # Save top 10 endpoints by confidence
        top_endpoints = sorted(classified_endpoints, 
                             key=lambda x: x['classification'].get('confidence_percentage', 0), 
                             reverse=True)[:10]
        
        for ep in top_endpoints:
            # Use categories (backward compatible field)
            categories = ep['classification'].get('categories', [])
            if not categories:
                categories = ep['classification'].get('matched_categories', [])
            categories_str = ', '.join(categories[:3]) if categories else ''
            
            cursor.execute('''
                INSERT INTO top_endpoints (scan_id, endpoint_url, confidence_percentage, categories, priority)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                scan_id,
                ep['url'],
                ep['classification'].get('confidence_percentage', 0),
                categories_str,
                ep['classification'].get('priority', 'BASELINE')
            ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving scan to dashboard database: {e}")
        return False

def get_dashboard_settings():
    """Get dashboard settings from database"""
    settings = {
        'save_to_db': DASHBOARD_SAVE_TO_DB,
        'dashboard_enabled': DASHBOARD_ENABLED
    }
    
    if DASHBOARD_SAVE_TO_DB:
        try:
            conn = sqlite3.connect(DASHBOARD_DB_FILE)
            cursor = conn.cursor()
            cursor.execute('SELECT setting_name, setting_value FROM dashboard_settings')
            rows = cursor.fetchall()
            for row in rows:
                settings[row[0]] = row[1]
            conn.close()
        except:
            pass
    
    return settings

def save_dashboard_setting(setting_name, setting_value):
    """Save dashboard setting to database"""
    if not DASHBOARD_SAVE_TO_DB:
        return False
    
    try:
        conn = sqlite3.connect(DASHBOARD_DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO dashboard_settings (setting_name, setting_value)
            VALUES (?, ?)
        ''', (setting_name, setting_value))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving dashboard setting: {e}")
        return False

def get_dashboard_stats():
    """Get overall dashboard statistics"""
    stats = {
        'total_scans': 0,
        'total_domains': set(),
        'total_endpoints': 0,
        'total_secrets_found': 0,
        'total_api_endpoints': 0,
        'recent_scans': [],
        'confidence_distribution': {
            'strong': 0,
            'good': 0,
            'moderate': 0,
            'weak': 0,
            'minimal': 0
        },
        'top_categories': [],
        'scan_timeline': []
    }
    
    if not DASHBOARD_SAVE_TO_DB:
        # Use in-memory data if DB not enabled
        stats['total_scans'] = len(scan_results)
        stats['total_domains'] = len(set(scan_data.get('domain', '') for scan_data in scan_results.values()))
        
        for scan_data in scan_results.values():
            summary = scan_data.get('scan_summary', {})
            stats['total_endpoints'] += summary.get('endpoints_count', 0)
            stats['total_secrets_found'] += summary.get('secrets_found', 0)
            stats['total_api_endpoints'] += summary.get('api_endpoints_found', 0)
            
            # Add to recent scans
            stats['recent_scans'].append({
                'scan_id': list(scan_results.keys())[list(scan_results.values()).index(scan_data)],
                'domain': scan_data.get('domain', ''),
                'timestamp': scan_data.get('timestamp', ''),
                'endpoints_count': summary.get('endpoints_count', 0),
                'high_confidence_patterns': summary.get('high_confidence_patterns', 0)
            })
        
        # Sort recent scans by timestamp
        stats['recent_scans'].sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        stats['recent_scans'] = stats['recent_scans'][:10]
        
        return stats
    
    try:
        conn = sqlite3.connect(DASHBOARD_DB_FILE)
        cursor = conn.cursor()
        
        # Get total scans
        cursor.execute('SELECT COUNT(*) FROM scans')
        stats['total_scans'] = cursor.fetchone()[0]
        
        # Get unique domains
        cursor.execute('SELECT COUNT(DISTINCT domain) FROM scans')
        stats['total_domains'] = cursor.fetchone()[0]
        
        # Get aggregated statistics
        cursor.execute('''
            SELECT 
                SUM(endpoints_count),
                SUM(secrets_found),
                SUM(api_endpoints_found)
            FROM scans
        ''')
        row = cursor.fetchone()
        if row:
            stats['total_endpoints'] = row[0] or 0
            stats['total_secrets_found'] = row[1] or 0
            stats['total_api_endpoints'] = row[2] or 0
        
        # Get recent scans
        cursor.execute('''
            SELECT scan_id, domain, end_time, endpoints_count, high_confidence_patterns
            FROM scans 
            ORDER BY end_time DESC 
            LIMIT 10
        ''')
        for row in cursor.fetchall():
            stats['recent_scans'].append({
                'scan_id': row[0],
                'domain': row[1],
                'timestamp': row[2],
                'endpoints_count': row[3],
                'high_confidence_patterns': row[4]
            })
        
        # Get confidence distribution
        cursor.execute('''
            SELECT confidence_range, SUM(count)
            FROM classification_stats
            GROUP BY confidence_range
        ''')
        for row in cursor.fetchall():
            range_name = row[0]
            count = row[1]
            if 'Strong' in range_name:
                stats['confidence_distribution']['strong'] += count
            elif 'Good' in range_name:
                stats['confidence_distribution']['good'] += count
            elif 'Moderate' in range_name:
                stats['confidence_distribution']['moderate'] += count
            elif 'Weak' in range_name:
                stats['confidence_distribution']['weak'] += count
            elif 'Minimal' in range_name:
                stats['confidence_distribution']['minimal'] += count
        
        # Get top categories
        cursor.execute('''
            SELECT category, SUM(count)
            FROM endpoint_categories
            GROUP BY category
            ORDER BY SUM(count) DESC
            LIMIT 10
        ''')
        for row in cursor.fetchall():
            stats['top_categories'].append({
                'category': row[0],
                'count': row[1]
            })
        
        # Get scan timeline (last 30 days)
        cursor.execute('''
            SELECT DATE(end_time), COUNT(*)
            FROM scans
            WHERE end_time >= DATE('now', '-30 days')
            GROUP BY DATE(end_time)
            ORDER BY DATE(end_time)
        ''')
        for row in cursor.fetchall():
            stats['scan_timeline'].append({
                'date': row[0],
                'count': row[1]
            })
        
        conn.close()
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
    
    return stats

def get_scan_dashboard_data(scan_id):
    """Get specific scan data for dashboard visualization"""
    if scan_id not in scan_results:
        return None
    
    scan_data = scan_results[scan_id]
    summary = scan_data.get('scan_summary', {})
    classified_endpoints = scan_data.get('classified_endpoints', [])
    
    # Calculate confidence distribution
    confidence_distribution = {
        'Strong Match (80-100%)': 0,
        'Good Match (60-79%)': 0,
        'Moderate Match (40-59%)': 0,
        'Weak Match (20-39%)': 0,
        'Minimal Match (0-19%)': 0
    }
    
    for ep in classified_endpoints:
        confidence = ep['classification'].get('confidence_percentage', 0)
        if confidence >= 80:
            confidence_distribution['Strong Match (80-100%)'] += 1
        elif confidence >= 60:
            confidence_distribution['Good Match (60-79%)'] += 1
        elif confidence >= 40:
            confidence_distribution['Moderate Match (40-59%)'] += 1
        elif confidence >= 20:
            confidence_distribution['Weak Match (20-39%)'] += 1
        else:
            confidence_distribution['Minimal Match (0-19%)'] += 1
    
    # Get endpoint categories
    category_counts = defaultdict(int)
    for ep in classified_endpoints:
        # Use categories (backward compatible field)
        categories = ep['classification'].get('categories', [])
        if not categories:
            categories = ep['classification'].get('matched_categories', [])
        
        for category in categories:
            category_counts[category] += 1
    
    # Sort categories by count
    sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Get top endpoints by confidence
    top_endpoints = sorted(classified_endpoints, 
                         key=lambda x: x['classification'].get('confidence_percentage', 0), 
                         reverse=True)[:10]
    
    # Prepare data for charts
    chart_data = {
        'confidence_distribution': {
            'labels': list(confidence_distribution.keys()),
            'data': list(confidence_distribution.values()),
            'colors': ['#10B981', '#3B82F6', '#F59E0B', '#EF4444', '#6B7280']
        },
        'endpoint_categories': {
            'labels': [cat[0] for cat in sorted_categories[:10]],
            'data': [cat[1] for cat in sorted_categories[:10]],
            'colors': ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6',
                      '#EC4899', '#14B8A6', '#F97316', '#84CC16', '#06B6D4']
        },
        'scan_summary': {
            'labels': ['Live URLs', 'Endpoints', 'JS Files', 'Strong Matches'],
            'data': [
                summary.get('live_urls_count', 0),
                summary.get('endpoints_count', 0),
                summary.get('js_files_count', 0),
                summary.get('high_confidence_patterns', 0)
            ],
            'colors': ['#3B82F6', '#10B981', '#F59E0B', '#EF4444']
        }
    }
    
    # Get verification stats if available
    verification_stats = {
        'verified': 0,
        'false_positives': 0,
        'errors': 0
    }
    
    if 'verification' in scan_data and isinstance(scan_data['verification'], list):
        for result in scan_data['verification']:
            if result.get('verified', False):
                verification_stats['verified'] += 1
            elif 'error' in result:
                verification_stats['errors'] += 1
            else:
                verification_stats['false_positives'] += 1
    
    dashboard_data = {
        'scan_id': scan_id,
        'domain': scan_data.get('domain', ''),
        'timestamp': scan_data.get('timestamp', ''),
        'summary': summary,
        'confidence_distribution': confidence_distribution,
        'category_counts': dict(sorted_categories[:10]),
        'top_endpoints': [
            {
                'url': ep['url'],
                'confidence': ep['classification'].get('confidence_percentage', 0),
                'categories': ep['classification'].get('categories', ep['classification'].get('matched_categories', [])),
                'priority': ep['classification'].get('priority', 'BASELINE')
            }
            for ep in top_endpoints
        ],
        'chart_data': chart_data,
        'verification_stats': verification_stats,
        'scan_details': scan_data.get('scan_details', {}),
        'educational_notes': scan_data.get('educational_notes', [])
    }
    
    return dashboard_data

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

def extract_urls_from_js(js_url, js_content, domain):
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
                api_pattern = re.compile('|'.join(PATTERNS['api_regex']), re.I)
                if api_pattern.search(full_url):
                    api_urls.add(full_url)
        else:
            external_urls.add(full_url)
    
    # Extract secrets
    if PATTERNS['secret_regex']:
        secret_pattern = re.compile('|'.join(PATTERNS['secret_regex']), re.I)
        secret_matches = secret_pattern.findall(js_content)
        for match in secret_matches:
            secrets.append((match, js_url))
    
    return internal_urls, external_urls, api_urls, secrets

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
                            api_pattern = re.compile('|'.join(PATTERNS['api_regex']), re.I)
                            if api_pattern.search(source):
                                api_urls.add(source)
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
                        api_pattern = re.compile('|'.join(PATTERNS['api_regex']), re.I)
                        if api_pattern.search(match):
                            api_urls.add(match)
                else:
                    external_urls.add(match)
                    
    except json.JSONDecodeError:
        return set(), set(), set()
    
    return internal_urls, external_urls, api_urls

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
                # Regular JavaScript file
                internal, external, api, secrets = extract_urls_from_js(js_url, content, domain)
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
        'categories': [],  # ADDED: Alias for matched_categories for backward compatibility
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
        'priority': 'BASELINE',  # For backward compatibility
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
        
        # Try HEAD first
        head_result = self.try_method('HEAD', url)
        if head_result and head_result['status'] != 404:
            self.stats['verified'] += 1
            self.stats['status_codes'][head_result['status']] += 1
            self.stats['methods_used']['HEAD'] += 1
            self.verified_endpoints.append(head_result)
            self.results_cache[url] = head_result
            return head_result
        
        # Try GET
        get_result = self.try_method('GET', url)
        if get_result and get_result['status'] != 404:
            self.stats['verified'] += 1
            self.stats['status_codes'][get_result['status']] += 1
            self.stats['methods_used']['GET'] += 1
            self.verified_endpoints.append(get_result)
            self.results_cache[url] = get_result
            return get_result
        
        # Try with parameters
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

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    if not DASHBOARD_ENABLED:
        return redirect(url_for('index'))
    
    # Get dashboard statistics
    stats = get_dashboard_stats()
    
    # Get recent scans
    recent_scans = []
    for scan_id in list(scan_results.keys())[-10:]:
        scan_data = scan_results[scan_id]
        recent_scans.append({
            'scan_id': scan_id,
            'domain': scan_data.get('domain', 'Unknown'),
            'timestamp': scan_data.get('timestamp', ''),
            'endpoints_count': scan_data.get('scan_summary', {}).get('endpoints_count', 0),
            'high_confidence_patterns': scan_data.get('scan_summary', {}).get('high_confidence_patterns', 0)
        })
    
    # Sort by timestamp
    recent_scans.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Get settings
    settings = get_dashboard_settings()
    
    return render_template('dashboard.html', 
                          stats=stats, 
                          recent_scans=recent_scans[:5],
                          settings=settings,
                          dashboard_enabled=DASHBOARD_ENABLED)

@app.route('/dashboard/scan/<scan_id>')
def scan_dashboard(scan_id):
    """Scan-specific dashboard"""
    if not DASHBOARD_ENABLED:
        return redirect(url_for('index'))
    
    if scan_id not in scan_results:
        return render_template('dashboard_scan.html', 
                             error="Scan not found",
                             scan_id=scan_id)
    
    # Get scan data for dashboard
    dashboard_data = get_scan_dashboard_data(scan_id)
    
    if not dashboard_data:
        return render_template('dashboard_scan.html', 
                             error="Could not load scan data",
                             scan_id=scan_id)
    
    return render_template('dashboard_scan.html', 
                         dashboard_data=dashboard_data,
                         scan_id=scan_id)

@app.route('/api/dashboard/stats')
def api_dashboard_stats():
    """Get dashboard statistics API"""
    if not DASHBOARD_ENABLED:
        return jsonify({'error': 'Dashboard not enabled'}), 403
    
    stats = get_dashboard_stats()
    return jsonify(stats)

@app.route('/api/dashboard/scan/<scan_id>')
def api_scan_dashboard_data(scan_id):
    """Get scan dashboard data API"""
    if not DASHBOARD_ENABLED:
        return jsonify({'error': 'Dashboard not enabled'}), 403
    
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    dashboard_data = get_scan_dashboard_data(scan_id)
    if not dashboard_data:
        return jsonify({'error': 'Could not load dashboard data'}), 500
    
    return jsonify(dashboard_data)

@app.route('/api/dashboard/settings', methods=['GET'])
def get_dashboard_settings_api():
    """Get dashboard settings"""
    settings = get_dashboard_settings()
    return jsonify(settings)

@app.route('/api/dashboard/settings', methods=['POST'])
def update_dashboard_settings():
    """Update dashboard settings"""
    global DASHBOARD_SAVE_TO_DB
    
    data = request.json
    save_to_db = data.get('save_to_db', False)
    
    DASHBOARD_SAVE_TO_DB = save_to_db
    
    # Initialize database if saving is enabled
    if save_to_db:
        init_dashboard_db()
        save_dashboard_setting('save_to_db', 'true')
        save_dashboard_setting('last_updated', datetime.now().isoformat())
    else:
        save_dashboard_setting('save_to_db', 'false')
    
    return jsonify({
        'message': 'Dashboard settings updated',
        'save_to_db': DASHBOARD_SAVE_TO_DB,
        'educational_note': 'Data saving helps track reconnaissance patterns over time for learning purposes'
    })

@app.route('/api/dashboard/clear_data', methods=['POST'])
def clear_dashboard_data():
    """Clear all dashboard data"""
    if DASHBOARD_SAVE_TO_DB:
        try:
            conn = sqlite3.connect(DASHBOARD_DB_FILE)
            cursor = conn.cursor()
            
            # Clear all tables
            cursor.execute('DELETE FROM scans')
            cursor.execute('DELETE FROM classification_stats')
            cursor.execute('DELETE FROM endpoint_categories')
            cursor.execute('DELETE FROM top_endpoints')
            cursor.execute('DELETE FROM dashboard_settings')
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': 'Dashboard data cleared successfully',
                'educational_note': 'Cleared learning database. This does not affect current scan results in memory.'
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({
            'message': 'Data saving is disabled - no data to clear',
            'educational_note': 'Enable data saving in settings to store reconnaissance patterns'
        })

@app.route('/api/endpoint_harvesting_status', methods=['GET'])
def get_endpoint_harvesting_status():
    """Get current endpoint harvesting status"""
    global ENDPOINT_HARVESTING_ENABLED, HARVESTED_ENDPOINTS
    return jsonify({
        'enabled': ENDPOINT_HARVESTING_ENABLED,
        'count': len(HARVESTED_ENDPOINTS),
        'file': HARVESTED_ENDPOINTS_FILE,
        'educational_note': 'Endpoint harvesting collects URL patterns for future scans - these are patterns, not confirmed vulnerabilities'
    })

@app.route('/api/toggle_endpoint_harvesting', methods=['POST'])
def toggle_endpoint_harvesting():
    """Toggle endpoint harvesting on/off"""
    global ENDPOINT_HARVESTING_ENABLED
    data = request.json
    enabled = data.get('enabled', False)
    
    ENDPOINT_HARVESTING_ENABLED = enabled
    
    if enabled:
        load_harvested_endpoints()
        return jsonify({
            'message': f'🔍 Endpoint pattern learning enabled - discovered endpoints will be saved as patterns for future reconnaissance.',
            'educational_note': 'This feature helps the tool learn common endpoint patterns over time. It does NOT mean these endpoints are vulnerable.',
            'enabled': True,
            'count': len(HARVESTED_ENDPOINTS)
        })
    else:
        return jsonify({
            'message': '📋 Endpoint pattern learning disabled.',
            'educational_note': 'Pattern learning helps improve future reconnaissance accuracy by remembering common endpoint structures.',
            'enabled': False,
            'count': len(HARVESTED_ENDPOINTS)
        })

@app.route('/api/get_harvested_endpoints')
def get_harvested_endpoints_route():
    """Get list of harvested endpoints"""
    return jsonify({
        'endpoints': get_harvested_endpoints(),
        'count': get_harvested_endpoints_count(),
        'educational_note': 'These are URL patterns learned from previous scans. Use them as starting points for manual investigation, not as vulnerability lists.'
    })

@app.route('/api/clear_harvested_endpoints', methods=['POST'])
def clear_harvested_endpoints():
    """Clear all harvested endpoints"""
    global HARVESTED_ENDPOINTS
    count = len(HARVESTED_ENDPOINTS)
    HARVESTED_ENDPOINTS.clear()
    save_harvested_endpoints()
    return jsonify({
        'message': f'🧹 Cleared {count} learned endpoint patterns.',
        'educational_note': 'Pattern learning helps reconnaissance tools improve over time. Consider keeping patterns unless starting fresh.',
        'count': 0
    })

@app.route('/api/export_harvested_endpoints')
def export_harvested_endpoints():
    """Export harvested endpoints as text file"""
    try:
        endpoints = get_harvested_endpoints()
        content = "\n".join(endpoints)
        
        response = app.response_class(
            response=content,
            status=200,
            mimetype='text/plain'
        )
        response.headers['Content-Disposition'] = f'attachment; filename=learned_endpoint_patterns_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        
        # Save to dashboard database if enabled
        if DASHBOARD_SAVE_TO_DB:
            save_scan_to_dashboard(scan_id, report)
        
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
# HTML TEMPLATES
# =============================

# Create templates directory if it doesn't exist
os.makedirs('templates', exist_ok=True)

# Create dashboard.html template
dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Dashboard - Web Recon Framework</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2563eb;
            --secondary-color: #3b82f6;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --dark-color: #1f2937;
            --light-color: #f9fafb;
            --gray-color: #6b7280;
            --border-color: #e5e7eb;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #f8fafc;
            color: #334155;
            line-height: 1.6;
        }
        
        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header-title {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .header-icon {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            width: 48px;
            height: 48px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        
        .header h1 {
            font-size: 24px;
            font-weight: 700;
            color: var(--dark-color);
        }
        
        .header-subtitle {
            color: var(--gray-color);
            font-size: 14px;
            margin-top: 4px;
        }
        
        .nav-buttons {
            display: flex;
            gap: 12px;
        }
        
        .btn {
            padding: 10px 18px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: none;
        }
        
        .btn-primary {
            background: var(--primary-color);
            color: white;
        }
        
        .btn-secondary {
            background: white;
            color: var(--dark-color);
            border: 1px solid var(--border-color);
        }
        
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .btn-primary:hover {
            background: var(--secondary-color);
        }
        
        .btn-secondary:hover {
            background: #f8fafc;
        }
        
        .dashboard-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
            transition: transform 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .card-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--dark-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-icon {
            color: var(--primary-color);
            font-size: 18px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #f8fafc;
            border-radius: 10px;
            padding: 16px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        
        .stat-number {
            font-size: 28px;
            font-weight: 700;
            color: var(--dark-color);
            margin-bottom: 4px;
        }
        
        .stat-label {
            font-size: 13px;
            color: var(--gray-color);
            font-weight: 500;
        }
        
        .chart-container {
            height: 280px;
            margin: 20px 0;
            position: relative;
        }
        
        .recent-scans {
            margin-top: 20px;
        }
        
        .scan-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px;
            background: #f8fafc;
            border-radius: 8px;
            margin-bottom: 8px;
            border: 1px solid var(--border-color);
            transition: all 0.2s;
        }
        
        .scan-item:hover {
            background: #f1f5f9;
            border-color: var(--primary-color);
        }
        
        .scan-info h4 {
            color: var(--dark-color);
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 4px;
        }
        
        .scan-info p {
            color: var(--gray-color);
            font-size: 12px;
        }
        
        .scan-stats {
            display: flex;
            gap: 8px;
        }
        
        .stat-badge {
            background: white;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: var(--dark-color);
            border: 1px solid var(--border-color);
        }
        
        .stat-badge.strong {
            background: #d1fae5;
            color: #065f46;
            border-color: #a7f3d0;
        }
        
        .settings-panel {
            margin-top: 24px;
        }
        
        .setting-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            background: #f8fafc;
            border-radius: 10px;
            margin-bottom: 12px;
            border: 1px solid var(--border-color);
        }
        
        .switch {
            position: relative;
            display: inline-block;
            width: 52px;
            height: 28px;
        }
        
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #cbd5e1;
            transition: .4s;
            border-radius: 28px;
        }
        
        .slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        
        input:checked + .slider {
            background-color: var(--primary-color);
        }
        
        input:checked + .slider:before {
            transform: translateX(24px);
        }
        
        .info-card {
            background: linear-gradient(135deg, #f0f9ff, #e0f2fe);
            border-left: 4px solid var(--primary-color);
            padding: 16px;
            border-radius: 8px;
            margin-top: 20px;
        }
        
        .info-card strong {
            color: var(--primary-color);
            font-size: 14px;
        }
        
        .info-card p {
            color: var(--gray-color);
            font-size: 13px;
            margin-top: 4px;
        }
        
        .footer {
            text-align: center;
            color: var(--gray-color);
            padding: 20px;
            font-size: 13px;
            border-top: 1px solid var(--border-color);
            margin-top: 24px;
        }
        
        .footer strong {
            color: var(--dark-color);
        }
        
        @media (max-width: 768px) {
            .dashboard-content {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                gap: 16px;
                text-align: center;
            }
            
            .nav-buttons {
                width: 100%;
                justify-content: center;
                flex-wrap: wrap;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        /* Tooltip styles */
        .tooltip {
            position: relative;
            display: inline-block;
        }
        
        .tooltip .tooltip-text {
            visibility: hidden;
            width: 200px;
            background-color: var(--dark-color);
            color: white;
            text-align: center;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 12px;
            font-weight: normal;
        }
        
        .tooltip:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }
        
        /* Loading animation */
        .loading {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px;
            color: var(--gray-color);
        }
        
        .loading-spinner {
            border: 3px solid #f3f4f6;
            border-top: 3px solid var(--primary-color);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin-bottom: 16px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <div class="header-title">
                <div class="header-icon">
                    <i class="fas fa-chart-line"></i>
                </div>
                <div>
                    <h1>Reconnaissance Dashboard</h1>
                    <div class="header-subtitle">Pattern Analysis & Investigation Overview</div>
                </div>
            </div>
            <div class="nav-buttons">
                <a href="/" class="btn btn-secondary">
                    <i class="fas fa-home"></i> Home
                </a>
                <a href="/dashboard" class="btn btn-primary">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
            </div>
        </div>
        
        <div class="dashboard-content">
            <!-- Overall Statistics -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-chart-bar card-icon"></i>
                        Overall Statistics
                    </h2>
                    <span class="tooltip">
                        <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                        <span class="tooltip-text">These statistics represent pattern matches from reconnaissance scans, not vulnerability counts</span>
                    </span>
                </div>
                <div class="stats-grid" id="overallStats">
                    <!-- Will be populated by JavaScript -->
                </div>
                <div class="info-card">
                    <strong><i class="fas fa-lightbulb"></i> Note:</strong>
                    <p>Higher numbers indicate more patterns discovered. This helps prioritize manual investigation but does not measure security risk.</p>
                </div>
            </div>
            
            <!-- Pattern Match Confidence -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-bullseye card-icon"></i>
                        Pattern Match Confidence
                    </h2>
                    <span class="tooltip">
                        <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                        <span class="tooltip-text">Confidence percentages show pattern matching accuracy, not exploitability</span>
                    </span>
                </div>
                <div class="chart-container">
                    <canvas id="confidenceChart"></canvas>
                </div>
                <div class="info-card">
                    <strong><i class="fas fa-chart-pie"></i> Interpretation:</strong>
                    <p>Higher confidence means more patterns matched from database. Use to prioritize investigation order.</p>
                </div>
            </div>
            
            <!-- Recent Scans -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-history card-icon"></i>
                        Recent Scans
                    </h2>
                    <span class="stat-badge">{{ recent_scans|length }} scans</span>
                </div>
                <div class="recent-scans" id="recentScans">
                    {% for scan in recent_scans %}
                    <a href="/dashboard/scan/{{ scan.scan_id }}" style="text-decoration: none;">
                        <div class="scan-item">
                            <div class="scan-info">
                                <h4>{{ scan.domain }}</h4>
                                <p>{{ scan.timestamp }}</p>
                            </div>
                            <div class="scan-stats">
                                <span class="stat-badge">{{ scan.endpoints_count }} patterns</span>
                                <span class="stat-badge strong">{{ scan.high_confidence_patterns }} strong</span>
                            </div>
                        </div>
                    </a>
                    {% endfor %}
                </div>
                {% if not recent_scans %}
                <div class="loading">
                    <i class="fas fa-search" style="font-size: 32px; color: var(--gray-color); margin-bottom: 16px;"></i>
                    <p>No scans yet. Start your first reconnaissance scan.</p>
                </div>
                {% endif %}
            </div>
            
            <!-- Top Categories -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-tags card-icon"></i>
                        Top Pattern Categories
                    </h2>
                    <span class="tooltip">
                        <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                        <span class="tooltip-text">Categories represent pattern types, not vulnerability types</span>
                    </span>
                </div>
                <div class="chart-container">
                    <canvas id="categoriesChart"></canvas>
                </div>
                <div class="info-card">
                    <strong><i class="fas fa-filter"></i> Usage:</strong>
                    <p>Common pattern categories help understand application structure for manual investigation.</p>
                </div>
            </div>
            
            <!-- Dashboard Settings -->
            <div class="card settings-panel">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-cog card-icon"></i>
                        Dashboard Settings
                    </h2>
                </div>
                <div class="setting-item">
                    <div>
                        <h4 style="font-size: 14px; font-weight: 600; color: var(--dark-color);">Save Data to Database</h4>
                        <p style="color: var(--gray-color); font-size: 13px;">Store pattern analysis results for historical review</p>
                    </div>
                    <label class="switch">
                        <input type="checkbox" id="saveToDbToggle" {% if settings.save_to_db == 'true' %}checked{% endif %}>
                        <span class="slider"></span>
                    </label>
                </div>
                <div class="setting-item">
                    <div>
                        <h4 style="font-size: 14px; font-weight: 600; color: var(--dark-color);">Clear All Data</h4>
                        <p style="color: var(--gray-color); font-size: 13px;">Remove all stored reconnaissance patterns</p>
                    </div>
                    <button class="btn btn-secondary" id="clearDataBtn" style="font-size: 13px;">
                        <i class="fas fa-trash-alt"></i> Clear Data
                    </button>
                </div>
                <div class="info-card">
                    <strong><i class="fas fa-graduation-cap"></i> Learning Purpose:</strong>
                    <p>Data saving helps track reconnaissance patterns over time for educational analysis of web application structures.</p>
                </div>
            </div>
            
            <!-- Educational Information -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">
                        <i class="fas fa-info-circle card-icon"></i>
                        Important Information
                    </h2>
                </div>
                <div style="padding: 8px 0;">
                    <div style="margin-bottom: 16px;">
                        <strong style="color: var(--dark-color); font-size: 14px; display: block; margin-bottom: 4px;">
                            <i class="fas fa-exclamation-triangle" style="color: var(--warning-color);"></i> Tool Purpose
                        </strong>
                        <p style="color: var(--gray-color); font-size: 13px; line-height: 1.5;">
                            This tool performs static pattern analysis for reconnaissance. It finds investigation starting points, not vulnerabilities.
                        </p>
                    </div>
                    <div style="margin-bottom: 16px;">
                        <strong style="color: var(--dark-color); font-size: 14px; display: block; margin-bottom: 4px;">
                            <i class="fas fa-shield-alt" style="color: var(--primary-color);"></i> Confidence Interpretation
                        </strong>
                        <p style="color: var(--gray-color); font-size: 13px; line-height: 1.5;">
                            Higher percentages indicate more patterns matched from our database. They do NOT measure exploitability or security risk.
                        </p>
                    </div>
                    <div>
                        <strong style="color: var(--dark-color); font-size: 14px; display: block; margin-bottom: 4px;">
                            <i class="fas fa-user-check" style="color: var(--success-color);"></i> Verification Required
                        </strong>
                        <p style="color: var(--gray-color); font-size: 13px; line-height: 1.5;">
                            100% manual verification required for all findings. Pattern matching ≠ vulnerability confirmation.
                        </p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Web Reconnaissance Framework - Educational Edition</strong></p>
            <p>Pattern analysis for investigation prioritization | Manual verification always required</p>
            <p style="margin-top: 8px; font-size: 12px; color: var(--gray-color);">
                <i class="fas fa-exclamation-circle"></i> Use responsibly with proper authorization
            </p>
        </div>
    </div>

    <script>
        // Initialize dashboard data
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboardData();
            setupEventListeners();
            updateOverallStatsPlaceholder();
        });
        
        function updateOverallStatsPlaceholder() {
            const statsContainer = document.getElementById('overallStats');
            statsContainer.innerHTML = `
                <div class="loading">
                    <div class="loading-spinner"></div>
                    <p style="font-size: 12px; margin-top: 8px;">Loading statistics...</p>
                </div>
            `;
        }
        
        async function loadDashboardData() {
            try {
                const response = await fetch('/api/dashboard/stats');
                if (!response.ok) throw new Error('Failed to load dashboard data');
                
                const data = await response.json();
                
                // Update overall statistics
                updateOverallStats(data);
                
                // Create confidence distribution chart
                createConfidenceChart(data.confidence_distribution);
                
                // Create categories chart if available
                if (data.top_categories && data.top_categories.length > 0) {
                    createCategoriesChart(data.top_categories);
                }
                
            } catch (error) {
                console.error('Error loading dashboard data:', error);
                document.getElementById('overallStats').innerHTML = `
                    <div style="text-align: center; padding: 20px; color: var(--danger-color);">
                        <i class="fas fa-exclamation-triangle" style="font-size: 24px; margin-bottom: 12px;"></i>
                        <p style="font-size: 14px;">Failed to load dashboard data</p>
                        <button onclick="loadDashboardData()" class="btn btn-secondary" style="margin-top: 12px; font-size: 13px;">
                            <i class="fas fa-redo"></i> Retry
                        </button>
                    </div>
                `;
            }
        }
        
        function updateOverallStats(data) {
            const statsContainer = document.getElementById('overallStats');
            
            const stats = [
                { 
                    label: 'Total Scans', 
                    value: data.total_scans || 0, 
                    icon: 'fas fa-search',
                    color: 'var(--primary-color)',
                    tooltip: 'Number of reconnaissance scans performed'
                },
                { 
                    label: 'Unique Domains', 
                    value: data.total_domains || 0, 
                    icon: 'fas fa-globe',
                    color: 'var(--success-color)',
                    tooltip: 'Number of unique domains analyzed'
                },
                { 
                    label: 'Patterns Found', 
                    value: data.total_endpoints || 0, 
                    icon: 'fas fa-sitemap',
                    color: 'var(--warning-color)',
                    tooltip: 'Total endpoint patterns discovered'
                },
                { 
                    label: 'Strong Matches', 
                    value: data.confidence_distribution?.strong || 0, 
                    icon: 'fas fa-bullseye',
                    color: 'var(--danger-color)',
                    tooltip: 'Patterns with strong match confidence (80-100%)'
                },
                { 
                    label: 'API Patterns', 
                    value: data.total_api_endpoints || 0, 
                    icon: 'fas fa-plug',
                    color: 'var(--primary-color)',
                    tooltip: 'API endpoint patterns discovered'
                },
                { 
                    label: 'Secret Patterns', 
                    value: data.total_secrets_found || 0, 
                    icon: 'fas fa-key',
                    color: 'var(--gray-color)',
                    tooltip: 'Potential secret patterns found (require verification)'
                }
            ];
            
            statsContainer.innerHTML = stats.map(stat => `
                <div class="stat-card tooltip">
                    <div style="font-size: 20px; color: ${stat.color}; margin-bottom: 8px;">
                        <i class="${stat.icon}"></i>
                    </div>
                    <div class="stat-number">${stat.value}</div>
                    <div class="stat-label">${stat.label}</div>
                    <span class="tooltip-text">${stat.tooltip}</span>
                </div>
            `).join('');
        }
        
        function createConfidenceChart(distribution) {
            const ctx = document.getElementById('confidenceChart').getContext('2d');
            
            const labels = ['Strong Match', 'Good Match', 'Moderate Match', 'Weak Match', 'Minimal Match'];
            const data = [
                distribution.strong || 0,
                distribution.good || 0,
                distribution.moderate || 0,
                distribution.weak || 0,
                distribution.minimal || 0
            ];
            
            const colors = ['#10B981', '#3B82F6', '#F59E0B', '#EF4444', '#6B7280'];
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors,
                        borderColor: 'white',
                        borderWidth: 2,
                        hoverOffset: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 20,
                                font: {
                                    size: 11
                                },
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                                    return `${label}: ${value} patterns (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
        
        function createCategoriesChart(categories) {
            const ctx = document.getElementById('categoriesChart').getContext('2d');
            
            const labels = categories.map(cat => cat.category);
            const data = categories.map(cat => cat.count);
            
            // Generate colors
            const colors = [
                '#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6',
                '#EC4899', '#14B8A6', '#F97316', '#84CC16', '#06B6D4'
            ];
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Pattern Count',
                        data: data,
                        backgroundColor: colors.slice(0, categories.length),
                        borderColor: 'white',
                        borderWidth: 1,
                        borderRadius: 4,
                        borderSkipped: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                drawBorder: false
                            },
                            ticks: {
                                font: {
                                    size: 11
                                }
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                font: {
                                    size: 10
                                },
                                maxRotation: 45
                            }
                        }
                    }
                }
            });
        }
        
        function setupEventListeners() {
            // Save to DB toggle
            const saveToggle = document.getElementById('saveToDbToggle');
            saveToggle.addEventListener('change', async function() {
                const saveToDb = this.checked;
                
                try {
                    const response = await fetch('/api/dashboard/settings', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ save_to_db: saveToDb })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        showNotification(result.message, 'success');
                        if (saveToDb) {
                            setTimeout(() => location.reload(), 1500);
                        }
                    } else {
                        showNotification('Error updating settings: ' + result.error, 'error');
                        this.checked = !saveToDb; // Revert toggle
                    }
                } catch (error) {
                    console.error('Error updating settings:', error);
                    showNotification('Error updating settings. Please check console for details.', 'error');
                    this.checked = !saveToDb; // Revert toggle
                }
            });
            
            // Clear data button
            const clearBtn = document.getElementById('clearDataBtn');
            clearBtn.addEventListener('click', async function() {
                if (confirm('⚠️ Are you sure you want to clear all dashboard data?\n\nThis action cannot be undone.')) {
                    try {
                        const response = await fetch('/api/dashboard/clear_data', {
                            method: 'POST'
                        });
                        
                        const result = await response.json();
                        
                        if (response.ok) {
                            showNotification(result.message, 'success');
                            setTimeout(() => location.reload(), 1500);
                        } else {
                            showNotification('Error clearing data: ' + result.error, 'error');
                        }
                    } catch (error) {
                        console.error('Error clearing data:', error);
                        showNotification('Error clearing data. Please check console for details.', 'error');
                    }
                }
            });
        }
        
        function showNotification(message, type = 'info') {
            // Create notification element
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 12px 16px;
                border-radius: 8px;
                color: white;
                font-weight: 500;
                z-index: 1000;
                max-width: 300px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                animation: slideIn 0.3s ease;
            `;
            
            if (type === 'success') {
                notification.style.backgroundColor = '#10B981';
            } else if (type === 'error') {
                notification.style.backgroundColor = '#EF4444';
            } else {
                notification.style.backgroundColor = '#3B82F6';
            }
            
            notification.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    <span>${message}</span>
                </div>
            `;
            
            document.body.appendChild(notification);
            
            // Remove notification after 5 seconds
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }, 5000);
        }
        
        // Add CSS animations
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>
"""

# Create dashboard_scan.html template
dashboard_scan_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Dashboard - {{ scan_id }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2563eb;
            --secondary-color: #3b82f6;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --dark-color: #1f2937;
            --light-color: #f9fafb;
            --gray-color: #6b7280;
            --border-color: #e5e7eb;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #f8fafc;
            color: #334155;
            line-height: 1.6;
        }
        
        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header-title {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .header-icon {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            width: 48px;
            height: 48px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        
        .header h1 {
            font-size: 22px;
            font-weight: 700;
            color: var(--dark-color);
        }
        
        .header-subtitle {
            color: var(--gray-color);
            font-size: 13px;
            margin-top: 4px;
        }
        
        .nav-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            border: none;
        }
        
        .btn-primary {
            background: var(--primary-color);
            color: white;
        }
        
        .btn-secondary {
            background: white;
            color: var(--dark-color);
            border: 1px solid var(--border-color);
        }
        
        .btn-success {
            background: var(--success-color);
            color: white;
        }
        
        .btn-warning {
            background: var(--warning-color);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .btn-primary:hover {
            background: var(--secondary-color);
        }
        
        .btn-secondary:hover {
            background: #f8fafc;
        }
        
        .dashboard-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
            transition: transform 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .card-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--dark-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-icon {
            color: var(--primary-color);
            font-size: 18px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #f8fafc;
            border-radius: 10px;
            padding: 16px;
            border: 1px solid var(--border-color);
            text-align: center;
        }
        
        .stat-number {
            font-size: 24px;
            font-weight: 700;
            color: var(--dark-color);
            margin-bottom: 4px;
        }
        
        .stat-label {
            font-size: 12px;
            color: var(--gray-color);
            font-weight: 500;
        }
        
        .chart-container {
            height: 240px;
            margin: 20px 0;
            position: relative;
        }
        
        .top-patterns {
            margin-top: 20px;
        }
        
        .pattern-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: #f8fafc;
            border-radius: 8px;
            margin-bottom: 8px;
            border: 1px solid var(--border-color);
            transition: all 0.2s;
        }
        
        .pattern-item:hover {
            background: #f1f5f9;
            border-color: var(--primary-color);
        }
        
        .pattern-url {
            flex: 1;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 11px;
            color: var(--dark-color);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .pattern-confidence {
            background: white;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            color: var(--dark-color);
            border: 1px solid var(--border-color);
            margin-left: 10px;
            min-width: 50px;
            text-align: center;
        }
        
        .confidence-strong {
            background: #d1fae5;
            color: #065f46;
            border-color: #a7f3d0;
        }
        
        .confidence-good {
            background: #dbeafe;
            color: #1e40af;
            border-color: #bfdbfe;
        }
        
        .confidence-moderate {
            background: #fef3c7;
            color: #92400e;
            border-color: #fde68a;
        }
        
        .info-card {
            background: linear-gradient(135deg, #f0f9ff, #e0f2fe);
            border-left: 4px solid var(--primary-color);
            padding: 16px;
            border-radius: 8px;
            margin-top: 20px;
        }
        
        .info-card strong {
            color: var(--primary-color);
            font-size: 14px;
        }
        
        .info-card p {
            color: var(--gray-color);
            font-size: 13px;
            margin-top: 4px;
        }
        
        .error-message {
            background: #fee2e2;
            color: #991b1b;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin: 20px 0;
            border-left: 4px solid var(--danger-color);
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: var(--gray-color);
        }
        
        .loading-spinner {
            border: 3px solid #f3f4f6;
            border-top: 3px solid var(--primary-color);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .footer {
            text-align: center;
            color: var(--gray-color);
            padding: 20px;
            font-size: 13px;
            border-top: 1px solid var(--border-color);
            margin-top: 24px;
        }
        
        .footer strong {
            color: var(--dark-color);
        }
        
        @media (max-width: 768px) {
            .dashboard-content {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                gap: 16px;
                text-align: center;
            }
            
            .nav-buttons {
                width: 100%;
                justify-content: center;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        /* Tooltip styles */
        .tooltip {
            position: relative;
            display: inline-block;
        }
        
        .tooltip .tooltip-text {
            visibility: hidden;
            width: 200px;
            background-color: var(--dark-color);
            color: white;
            text-align: center;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 12px;
            font-weight: normal;
        }
        
        .tooltip:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <div class="header-title">
                <div class="header-icon">
                    <i class="fas fa-chart-pie"></i>
                </div>
                <div>
                    <h1 id="scanDomain">Scan Analysis Dashboard</h1>
                    <div class="header-subtitle">Scan ID: {{ scan_id }}</div>
                </div>
            </div>
            <div class="nav-buttons">
                <a href="/dashboard" class="btn btn-secondary">
                    <i class="fas fa-arrow-left"></i> Back
                </a>
                <a href="/scan/{{ scan_id }}" class="btn btn-primary">
                    <i class="fas fa-file-alt"></i> Full Report
                </a>
                <a href="/api/export/{{ scan_id }}/json" class="btn btn-success" target="_blank">
                    <i class="fas fa-download"></i> JSON
                </a>
                <a href="/api/export/{{ scan_id }}/csv" class="btn btn-warning" target="_blank">
                    <i class="fas fa-file-csv"></i> CSV
                </a>
            </div>
        </div>
        
        {% if error %}
        <div class="error-message">
            <h3 style="margin-bottom: 8px;"><i class="fas fa-exclamation-triangle"></i> Error</h3>
            <p style="margin-bottom: 16px;">{{ error }}</p>
            <a href="/dashboard" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i> Back to Dashboard
            </a>
        </div>
        {% else %}
        <div id="loading" class="loading">
            <div class="loading-spinner"></div>
            <p>Loading scan analysis data...</p>
        </div>
        
        <div id="dashboardContent" style="display: none;">
            <div class="dashboard-content">
                <!-- Scan Summary -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-chart-bar card-icon"></i>
                            Scan Summary
                        </h2>
                        <span class="tooltip">
                            <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                            <span class="tooltip-text">Pattern analysis summary - not vulnerability assessment</span>
                        </span>
                    </div>
                    <div class="stats-grid" id="scanStats">
                        <!-- Will be populated by JavaScript -->
                    </div>
                    <div class="info-card">
                        <strong><i class="fas fa-lightbulb"></i> Note:</strong>
                        <p>These numbers represent pattern matches discovered through reconnaissance. Manual verification is required for all findings.</p>
                    </div>
                </div>
                
                <!-- Pattern Match Confidence -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-bullseye card-icon"></i>
                            Pattern Match Confidence
                        </h2>
                        <span class="tooltip">
                            <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                            <span class="tooltip-text">Confidence percentages show pattern matching, not security risk</span>
                        </span>
                    </div>
                    <div class="chart-container">
                        <canvas id="confidenceChart"></canvas>
                    </div>
                    <div class="info-card">
                        <strong><i class="fas fa-chart-pie"></i> Interpretation:</strong>
                        <p>Higher confidence means more patterns matched. Use to prioritize investigation order, not assess exploitability.</p>
                    </div>
                </div>
                
                <!-- Top Patterns -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-fire card-icon"></i>
                            Top Patterns by Confidence
                        </h2>
                        <span class="tooltip">
                            <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                            <span class="tooltip-text">Patterns with highest match confidence - prioritize for investigation</span>
                        </span>
                    </div>
                    <div class="top-patterns" id="topPatterns">
                        <!-- Will be populated by JavaScript -->
                    </div>
                    <div class="info-card">
                        <strong><i class="fas fa-sort-amount-down"></i> Priority:</strong>
                        <p>Patterns are sorted by match confidence. Higher percentages indicate more patterns matched from database.</p>
                    </div>
                </div>
                
                <!-- Pattern Categories -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-tags card-icon"></i>
                            Pattern Categories
                        </h2>
                        <span class="tooltip">
                            <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                            <span class="tooltip-text">Pattern type distribution for analysis</span>
                        </span>
                    </div>
                    <div class="chart-container">
                        <canvas id="categoriesChart"></canvas>
                    </div>
                </div>
                
                <!-- Verification Status -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-check-circle card-icon"></i>
                            Endpoint Verification
                        </h2>
                        <span class="tooltip">
                            <i class="fas fa-info-circle" style="color: var(--gray-color);"></i>
                            <span class="tooltip-text">HTTP response verification - not security validation</span>
                        </span>
                    </div>
                    <div class="chart-container">
                        <canvas id="verificationChart"></canvas>
                    </div>
                    <div class="info-card">
                        <strong><i class="fas fa-shield-alt"></i> Verification Note:</strong>
                        <p>Verification checks HTTP accessibility only. Accessible ≠ Vulnerable. Manual security testing required.</p>
                    </div>
                </div>
                
                <!-- Scan Configuration -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-cogs card-icon"></i>
                            Scan Configuration
                        </h2>
                    </div>
                    <div class="stats-grid" id="scanDetails">
                        <!-- Will be populated by JavaScript -->
                    </div>
                    <div class="info-card">
                        <strong><i class="fas fa-tools"></i> Configuration:</strong>
                        <p>Scan settings used for this reconnaissance. These affect pattern discovery and analysis results.</p>
                    </div>
                </div>
                
                <!-- Educational Information -->
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-info-circle card-icon"></i>
                            Analysis Information
                        </h2>
                    </div>
                    <div style="padding: 8px 0;">
                        <div style="margin-bottom: 16px;">
                            <strong style="color: var(--dark-color); font-size: 14px; display: block; margin-bottom: 4px;">
                                <i class="fas fa-exclamation-triangle" style="color: var(--warning-color);"></i> False Positive Rate
                            </strong>
                            <p style="color: var(--gray-color); font-size: 13px; line-height: 1.5;">
                                Expected 30-50% false positive rate for pattern-based detection. All findings require manual verification.
                            </p>
                        </div>
                        <div style="margin-bottom: 16px;">
                            <strong style="color: var(--dark-color); font-size: 14px; display: block; margin-bottom: 4px;">
                                <i class="fas fa-chart-line" style="color: var(--primary-color);"></i> Confidence Interpretation
                            </strong>
                            <p style="color: var(--gray-color); font-size: 13px; line-height: 1.5;">
                                <strong>80-100%:</strong> Strong pattern match - prioritize investigation<br>
                                <strong>60-79%:</strong> Good pattern match - consider for investigation<br>
                                <strong>40-59%:</strong> Moderate pattern match - investigate if time permits<br>
                                <strong>20-39%:</strong> Weak pattern match - low priority<br>
                                <strong>0-19%:</strong> Minimal pattern match - baseline
                            </p>
                        </div>
                        <div>
                            <strong style="color: var(--dark-color); font-size: 14px; display: block; margin-bottom: 4px;">
                                <i class="fas fa-user-check" style="color: var(--success-color);"></i> Next Steps
                            </strong>
                            <p style="color: var(--gray-color); font-size: 13px; line-height: 1.5;">
                                1. Get proper authorization before testing<br>
                                2. Start with strong pattern matches<br>
                                3. Use percentages to prioritize investigation order<br>
                                4. Remember: Pattern matching ≠ vulnerability
                            </p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p><strong>Pattern Analysis Dashboard</strong> | Scan ID: {{ scan_id }}</p>
                <p>Static reconnaissance results for investigation prioritization | Manual verification required</p>
                <p style="margin-top: 8px; font-size: 12px; color: var(--gray-color);">
                    <i class="fas fa-exclamation-circle"></i> This tool finds investigation starting points, not vulnerabilities
                </p>
            </div>
        </div>
        {% endif %}
    </div>

    {% if not error %}
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            loadScanDashboardData();
        });
        
        async function loadScanDashboardData() {
            try {
                const response = await fetch('/api/dashboard/scan/{{ scan_id }}');
                
                if (!response.ok) {
                    throw new Error('Failed to load scan data');
                }
                
                const data = await response.json();
                
                // Hide loading, show content
                document.getElementById('loading').style.display = 'none';
                document.getElementById('dashboardContent').style.display = 'block';
                
                // Update dashboard content
                updateDashboard(data);
                
            } catch (error) {
                console.error('Error loading scan dashboard:', error);
                document.getElementById('loading').innerHTML = `
                    <div class="error-message">
                        <h3 style="margin-bottom: 8px;"><i class="fas fa-exclamation-triangle"></i> Error Loading Data</h3>
                        <p style="margin-bottom: 16px;">${error.message}</p>
                        <button onclick="loadScanDashboardData()" class="btn btn-secondary">
                            <i class="fas fa-redo"></i> Retry
                        </button>
                    </div>
                `;
            }
        }
        
        function updateDashboard(data) {
            // Update header
            document.getElementById('scanDomain').textContent = data.domain || 'Scan Analysis';
            
            // Update scan summary stats
            updateScanStats(data.summary);
            
            // Update scan details
            updateScanDetails(data.scan_details);
            
            // Create charts
            createConfidenceChart(data.chart_data.confidence_distribution);
            createCategoriesChart(data.chart_data.endpoint_categories);
            createVerificationChart(data.verification_stats);
            
            // Update top patterns
            updateTopPatterns(data.top_endpoints);
        }
        
        function updateScanStats(summary) {
            const statsContainer = document.getElementById('scanStats');
            
            const stats = [
                { 
                    label: 'Live URLs', 
                    value: summary.live_urls_count || 0, 
                    icon: 'fas fa-globe',
                    color: 'var(--primary-color)',
                    tooltip: 'URLs responding to HTTP requests'
                },
                { 
                    label: 'Patterns Found', 
                    value: summary.endpoints_count || 0, 
                    icon: 'fas fa-sitemap',
                    color: 'var(--warning-color)',
                    tooltip: 'Total endpoint patterns discovered'
                },
                { 
                    label: 'JS Files', 
                    value: summary.js_files_count || 0, 
                    icon: 'fas fa-file-code',
                    color: 'var(--primary-color)',
                    tooltip: 'JavaScript files analyzed'
                },
                { 
                    label: 'Strong Matches', 
                    value: summary.high_confidence_patterns || 0, 
                    icon: 'fas fa-bullseye',
                    color: 'var(--success-color)',
                    tooltip: 'Patterns with strong match confidence (80-100%)'
                },
                { 
                    label: 'API Patterns', 
                    value: summary.api_endpoints_found || 0, 
                    icon: 'fas fa-plug',
                    color: 'var(--secondary-color)',
                    tooltip: 'API endpoint patterns discovered'
                },
                { 
                    label: 'Secret Patterns', 
                    value: summary.secrets_found || 0, 
                    icon: 'fas fa-key',
                    color: 'var(--gray-color)',
                    tooltip: 'Potential secret patterns (require verification)'
                },
                { 
                    label: 'Classified', 
                    value: summary.classified_endpoints_count || 0, 
                    icon: 'fas fa-tags',
                    color: 'var(--primary-color)',
                    tooltip: 'Patterns analyzed and categorized'
                },
                { 
                    label: 'Patterns Learned', 
                    value: summary.harvested_endpoints || 0, 
                    icon: 'fas fa-brain',
                    color: 'var(--success-color)',
                    tooltip: 'New patterns added to learning database'
                }
            ];
            
            statsContainer.innerHTML = stats.map(stat => `
                <div class="stat-card tooltip">
                    <div style="font-size: 18px; color: ${stat.color}; margin-bottom: 8px;">
                        <i class="${stat.icon}"></i>
                    </div>
                    <div class="stat-number">${stat.value}</div>
                    <div class="stat-label">${stat.label}</div>
                    <span class="tooltip-text">${stat.tooltip}</span>
                </div>
            `).join('');
        }
        
        function updateScanDetails(details) {
            const detailsContainer = document.getElementById('scanDetails');
            
            if (!details) return;
            
            const scanDetails = [
                { 
                    label: 'Scan Mode', 
                    value: getScanModeLabel(details.scan_mode), 
                    icon: 'fas fa-cog',
                    color: 'var(--primary-color)'
                },
                { 
                    label: 'JS Analysis', 
                    value: details.js_analysis === 'yes' ? 'Enabled' : 'Disabled', 
                    icon: 'fas fa-file-code',
                    color: details.js_analysis === 'yes' ? 'var(--success-color)' : 'var(--gray-color)'
                },
                { 
                    label: 'Endpoint Check', 
                    value: getVerificationLabel(details.verify_endpoints), 
                    icon: 'fas fa-check-circle',
                    color: details.verify_endpoints !== 'no' ? 'var(--success-color)' : 'var(--gray-color)'
                },
                { 
                    label: 'Pattern Learning', 
                    value: details.endpoint_harvesting === 'on' ? 'Enabled' : 'Disabled', 
                    icon: 'fas fa-brain',
                    color: details.endpoint_harvesting === 'on' ? 'var(--success-color)' : 'var(--gray-color)'
                }
            ];
            
            detailsContainer.innerHTML = scanDetails.map(detail => `
                <div class="stat-card">
                    <div style="font-size: 16px; color: ${detail.color}; margin-bottom: 8px;">
                        <i class="${detail.icon}"></i>
                    </div>
                    <div class="stat-number">${detail.value}</div>
                    <div class="stat-label">${detail.label}</div>
                </div>
            `).join('');
        }
        
        function getScanModeLabel(mode) {
            const modes = {
                '1': 'Basic',
                '2': 'JS Only',
                '3': 'Full'
            };
            return modes[mode] || 'Unknown';
        }
        
        function getVerificationLabel(verify) {
            const labels = {
                'yes': 'Full',
                'sample': 'Sample',
                'no': 'Disabled'
            };
            return labels[verify] || 'Unknown';
        }
        
        function createConfidenceChart(chartData) {
            const ctx = document.getElementById('confidenceChart').getContext('2d');
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: chartData.labels,
                    datasets: [{
                        data: chartData.data,
                        backgroundColor: chartData.colors,
                        borderColor: 'white',
                        borderWidth: 2,
                        hoverOffset: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 15,
                                font: {
                                    size: 10
                                },
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                                    return `${label}: ${value} patterns (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
        
        function createCategoriesChart(chartData) {
            const ctx = document.getElementById('categoriesChart').getContext('2d');
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: chartData.labels,
                    datasets: [{
                        label: 'Pattern Count',
                        data: chartData.data,
                        backgroundColor: chartData.colors,
                        borderColor: 'white',
                        borderWidth: 1,
                        borderRadius: 4,
                        borderSkipped: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                drawBorder: false
                            },
                            ticks: {
                                font: {
                                    size: 10
                                }
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                font: {
                                    size: 9
                                },
                                maxRotation: 45
                            }
                        }
                    }
                }
            });
        }
        
        function createVerificationChart(stats) {
            const ctx = document.getElementById('verificationChart').getContext('2d');
            
            const labels = ['Verified', 'False Positives', 'Errors'];
            const data = [
                stats.verified || 0,
                stats.false_positives || 0,
                stats.errors || 0
            ];
            
            const colors = ['#10B981', '#F59E0B', '#EF4444'];
            
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors,
                        borderColor: 'white',
                        borderWidth: 2,
                        hoverOffset: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 15,
                                font: {
                                    size: 11
                                }
                            }
                        }
                    }
                }
            });
        }
        
        function updateTopPatterns(patterns) {
            const container = document.getElementById('topPatterns');
            
            if (!patterns || patterns.length === 0) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 20px; color: var(--gray-color);">
                        <i class="fas fa-search" style="font-size: 24px; margin-bottom: 12px;"></i>
                        <p>No pattern matches found</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = patterns.map(pattern => {
                const confidenceClass = getConfidenceClass(pattern.confidence);
                const truncatedUrl = pattern.url.length > 60 ? pattern.url.substring(0, 57) + '...' : pattern.url;
                const categories = pattern.categories && pattern.categories.length > 0 
                    ? pattern.categories.join(', ') 
                    : 'No categories';
                
                return `
                    <div class="pattern-item tooltip">
                        <div style="flex: 1;">
                            <div class="pattern-url" title="${pattern.url}">${truncatedUrl}</div>
                            <div style="font-size: 10px; color: var(--gray-color); margin-top: 4px;">
                                <i class="fas fa-tag"></i> ${categories}
                            </div>
                        </div>
                        <div class="pattern-confidence ${confidenceClass}">${pattern.confidence}%</div>
                        <span class="tooltip-text">
                            <strong>Confidence:</strong> ${pattern.confidence}%<br>
                            <strong>Categories:</strong> ${categories}<br>
                            <strong>Priority:</strong> ${pattern.priority}<br>
                            <strong>URL:</strong> ${pattern.url}
                        </span>
                    </div>
                `;
            }).join('');
        }
        
        function getConfidenceClass(confidence) {
            if (confidence >= 80) return 'confidence-strong';
            if (confidence >= 60) return 'confidence-good';
            if (confidence >= 40) return 'confidence-moderate';
            return '';
        }
    </script>
    {% endif %}
</body>
</html>
"""

# Write templates to files
with open('templates/dashboard.html', 'w') as f:
    f.write(dashboard_html)

with open('templates/dashboard_scan.html', 'w') as f:
    f.write(dashboard_scan_html)

# =============================
# MAIN ENTRY POINT
# =============================

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                    WEB RECONNAISSANCE FRAMEWORK                             ║
    ║                     - EDUCATIONAL EDITION -                                 ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    
    📊 DASHBOARD STATUS: ENABLED | DATA SAVING: """ + ("ENABLED" if DASHBOARD_SAVE_TO_DB else "DISABLED") + """
    🔍 By: Cod3pont1f | Version: 2.0 | Professional Edition
    
    ⚠️  IMPORTANT EDUCATIONAL NOTES:
    ════════════════════════════════════════════════════════════════════════
    1. This tool performs STATIC PATTERN ANALYSIS for reconnaissance
    2. It finds investigation starting points, NOT vulnerabilities
    3. Higher confidence percentages mean "more patterns matched", NOT "exploitable"
    4. ALL findings require 100% MANUAL VERIFICATION
    5. Expected false positive rate: 30-50% for pattern-based detection
    
    🎯 TOOL PURPOSE:
    ════════════════════════════════════════════════════════════════════════
    • Learn about web application structure patterns
    • Find potential investigation targets
    • Understand pattern matching in web apps
    • Practice manual verification skills
    
    📊 DASHBOARD FEATURES:
    ════════════════════════════════════════════════════════════════════════
    • Professional statistics visualization
    • Pattern match confidence analysis
    • Top pattern categories overview
    • Recent scans with investigation priorities
    • Scan-specific analysis dashboards
    • Educational information throughout
    
    ⚙️  CONFIDENCE INTERPRETATION:
    ════════════════════════════════════════════════════════════════════════
    • 80-100%: Strong pattern match - prioritize investigation
    • 60-79%: Good pattern match - consider for investigation
    • 40-59%: Moderate pattern match - investigate if time permits
    • 20-39%: Weak pattern match - low priority
    • 0-19%: Minimal pattern match - baseline investigation
    
    ⚠️  ETHICAL USE REQUIREMENTS:
    ════════════════════════════════════════════════════════════════════════
    • Only scan systems you own or have explicit permission to test
    • Respect rate limits and terms of service
    • Use findings for educational purposes only
    • Report discovered issues responsibly
    
    🚀 FEATURES SUMMARY:
    ════════════════════════════════════════════════════════════════════════
    1. Professional pattern analysis with confidence scoring
    2. JavaScript file pattern analysis
    3. Source map (.js.map) parsing
    4. Potential secret pattern detection
    5. Endpoint pattern classification with professional confidence levels
    6. Investigation suggestions based on pattern matching
    7. Pattern learning for future reconnaissance
    8. Comprehensive professional dashboard with visualizations
    
    📊 Access Dashboard: http://localhost:5000/dashboard
    🚀 Starting server on http://localhost:5000
    """)

    # Initialize dashboard database if saving is enabled
    if DASHBOARD_SAVE_TO_DB:
        init_dashboard_db()
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
