#!/usr/bin/env python3
"""
Advanced Website Technology Detection Tool
Comprehensive detection with multiple detection methods
"""

import requests
import json
import re
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse, urljoin
from datetime import datetime
import csv
from typing import Dict, List, Set, Optional, Tuple, Any
import argparse
import sys
from bs4 import BeautifulSoup
import warnings
import random
warnings.filterwarnings('ignore')

class AdvancedTechDetector:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }
        
        # Comprehensive technology signatures database
        self.tech_signatures = self.load_tech_signatures()
        
        # Extended patterns database
        self.extended_patterns = self.load_extended_patterns()
        
    def display_banner(self):
        """Display ASCII art banner with hacker face"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║    ████████╗███████╗ ██████╗██╗  ██╗     ██████╗ ███████╗████████╗      ║
║    ╚══██╔══╝██╔════╝██╔════╝██║  ██║    ██╔════╝ ██╔════╝╚══██╔══╝      ║
║       ██║   █████╗  ██║     ███████║    ██║  ███╗█████╗     ██║         ║
║       ██║   ██╔══╝  ██║     ██╔══██║    ██║   ██║██╔══╝     ██║         ║
║       ██║   ███████╗╚██████╗██║  ██║    ╚██████╔╝███████╗   ██║         ║
║       ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝     ╚═════╝ ╚══════╝   ╚═╝         ║
║                                                                          ║
║                  WEBSITE TECHNOLOGY DETECTOR                            ║
║                 Advanced OSINT Reconnaissance Tool                      ║
║                                                                          ║
║                     (⌐■_■) ATAF_PNG Security Research                   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
        """
        print("\033[92m" + banner + "\033[0m")
        print("\033[96m" + "="*78 + "\033[0m")
        print("\033[93m🔥 Advanced Technology Detection with Multiple Analysis Methods 🔥\033[0m")
        print("\033[96m" + "="*78 + "\033[0m\n")
    
    def load_tech_signatures(self) -> Dict:
        """Load comprehensive technology detection signatures"""
        return {
            # Analytics
            'Google Analytics': {'patterns': ['google-analytics', 'gtag\\.js', 'analytics\\.js', '_ga', '_gat', '_gid'], 'type': 'analytics'},
            'Google Analytics 4': {'patterns': ['gtag\\.js', 'ga4', 'google.*analytics.*4'], 'type': 'analytics'},
            'Hotjar': {'patterns': ['hotjar', '_hj'], 'type': 'analytics'},
            
            # Authentication Services with detailed types
            'Auth0 (Enterprise SSO)': {'patterns': ['auth0', 'auth0\\.com', '\\.auth0\\.com'], 'type': 'authentication', 'auth_type': 'Enterprise SSO'},
            'Firebase Authentication (Google)': {'patterns': ['firebase-auth', 'firebaseapp\\.com'], 'type': 'authentication', 'auth_type': 'Cloud Authentication'},
            'Okta (Enterprise Identity)': {'patterns': ['okta', 'okta\\.com', 'oktapreview\\.com'], 'type': 'authentication', 'auth_type': 'Enterprise Identity'},
            'OneLogin (SSO Platform)': {'patterns': ['onelogin', 'onelogin\\.com'], 'type': 'authentication', 'auth_type': 'SSO Platform'},
            'Ping Identity (IAM)': {'patterns': ['pingidentity'], 'type': 'authentication', 'auth_type': 'Identity & Access Management'},
            'Keycloak (Open Source IAM)': {'patterns': ['keycloak'], 'type': 'authentication', 'auth_type': 'Open Source IAM'},
            'Amazon Cognito (AWS Auth)': {'patterns': ['cognito', 'amazoncognito\\.com'], 'type': 'authentication', 'auth_type': 'AWS Authentication'},
            'Azure AD (Microsoft SSO)': {'patterns': ['azure.*ad', 'microsoftonline\\.com'], 'type': 'authentication', 'auth_type': 'Microsoft SSO'},
            'Google Sign-In (OAuth 2.0)': {'patterns': ['google.*signin', 'accounts\\.google\\.com'], 'type': 'authentication', 'auth_type': 'OAuth 2.0'},
            'Facebook Login (OAuth)': {'patterns': ['facebook.*login', 'fb-login'], 'type': 'authentication', 'auth_type': 'OAuth'},
            'OAuth 2.0 Protocol': {'patterns': ['oauth2', 'oauth/authorize', 'oauth/token'], 'type': 'authentication', 'auth_type': 'OAuth 2.0 Protocol'},
            'OAuth 1.0 Protocol': {'patterns': ['oauth', 'oauth/request_token'], 'type': 'authentication', 'auth_type': 'OAuth 1.0 Protocol'},
            'Passport.js (Node.js Middleware)': {'patterns': ['passport', 'passport\\.js'], 'type': 'authentication', 'auth_type': 'Node.js Authentication Middleware'},
            'JWT (JSON Web Tokens)': {'patterns': ['jwt', 'jsonwebtoken', 'Bearer eyJ'], 'type': 'authentication', 'auth_type': 'Token-Based Authentication'},
            'OpenID Connect': {'patterns': ['openid', '\\.well-known/openid-configuration'], 'type': 'authentication', 'auth_type': 'OpenID Connect'},
            'SAML 2.0': {'patterns': ['saml', 'saml2', 'saml/SSO'], 'type': 'authentication', 'auth_type': 'SAML 2.0'},
            'Apple Sign-In (OAuth)': {'patterns': ['appleid\\.apple\\.com', 'apple.*sign'], 'type': 'authentication', 'auth_type': 'OAuth'},
            'GitHub OAuth': {'patterns': ['github.*oauth', 'github.*login'], 'type': 'authentication', 'auth_type': 'OAuth'},
            'Basic Authentication': {'patterns': ['basic.*auth', 'authorization: basic'], 'type': 'authentication', 'auth_type': 'Basic HTTP Authentication'},
            'LDAP Authentication': {'patterns': ['ldap', 'ldap://', 'ldaps://'], 'type': 'authentication', 'auth_type': 'LDAP Directory'},
            'Session Cookies': {'patterns': ['sessionid', 'session', 'PHPSESSID'], 'type': 'authentication', 'auth_type': 'Session-Based'},
            'Magic Links': {'patterns': ['magic.*link', 'passwordless'], 'type': 'authentication', 'auth_type': 'Passwordless'},
            '2FA/MFA': {'patterns': ['2fa', 'mfa', 'two-factor', 'multi-factor'], 'type': 'authentication', 'auth_type': 'Multi-Factor Authentication'},
            
            # Cloud Computing Services
            'Amazon Web Services': {'patterns': ['aws', 'amazonaws', 'x-amz-'], 'type': 'cloud'},
            'Vercel': {'patterns': ['vercel', 'x-vercel'], 'type': 'hosting'},
            'Netlify': {'patterns': ['netlify', '_netlify'], 'type': 'hosting'},
            'Heroku': {'patterns': ['heroku', 'herokuapp'], 'type': 'platform'},
            
            # Content Management System
            'WordPress': {'patterns': ['wordpress', 'wp-', 'wp_content', 'wp_includes'], 'type': 'cms'},
            'Drupal': {'patterns': ['drupal', 'drupal\\.'], 'type': 'cms'},
            'Joomla': {'patterns': ['joomla', 'joomla_'], 'type': 'cms'},
            'Shopify': {'patterns': ['shopify', 'shopify\\.com', '_shopify'], 'type': 'ecommerce'},
            'Magento': {'patterns': ['magento', 'magento_'], 'type': 'ecommerce'},
            'WooCommerce': {'patterns': ['woocommerce', 'wc_'], 'type': 'ecommerce'},
            
            # Programming Framework
            'React': {'patterns': ['react', 'react-dom', 'react\\.js'], 'type': 'frontend'},
            'Next.js': {'patterns': ['next', 'next\\.js', '_next'], 'type': 'frontend'},
            'Vue.js': {'patterns': ['vue', 'vue\\.js', 'vue-'], 'type': 'frontend'},
            'Angular': {'patterns': ['angular', 'ng-'], 'type': 'frontend'},
            'Node.js': {'patterns': ['node\\.js', 'express'], 'type': 'backend'},
            'Express.js': {'patterns': ['express'], 'type': 'backend'},
            'Django': {'patterns': ['django', 'csrftoken'], 'type': 'backend'},
            'Flask': {'patterns': ['flask'], 'type': 'backend'},
            'Ruby on Rails': {'patterns': ['rails', 'ruby.*on.*rails'], 'type': 'backend'},
            'Laravel': {'patterns': ['laravel'], 'type': 'backend'},
            'ASP.NET': {'patterns': ['asp\\.net'], 'type': 'backend'},
            
            # Programming Language
            'JavaScript': {'patterns': ['javascript', 'js/', '\\.js'], 'type': 'language'},
            'Python': {'patterns': ['python', '\\.py'], 'type': 'language'},
            'Java': {'patterns': ['java', 'jsp', 'servlet'], 'type': 'language'},
            'PHP': {'patterns': ['php', '\\.php'], 'type': 'language'},
            'Ruby': {'patterns': ['ruby', '\\.rb'], 'type': 'language'},
            
            # Security
            'Cloudflare': {'patterns': ['cloudflare', 'cf-', '__cfduid'], 'type': 'security'},
            'reCAPTCHA v3': {'patterns': ['recaptcha/api.js?render=', 'grecaptcha.execute'], 'type': 'security', 'auth_type': 'Bot Protection'},
            'reCAPTCHA v2': {'patterns': ['recaptcha/api.js', 'g-recaptcha'], 'type': 'security', 'auth_type': 'Bot Protection'},
            'hCaptcha': {'patterns': ['hcaptcha'], 'type': 'security', 'auth_type': 'Bot Protection'},
            
            # Social Media Integration
            'Facebook SDK': {'patterns': ['facebook.*sdk', 'connect\\.facebook\\.net'], 'type': 'social'},
            'Facebook Pixel': {'patterns': ['facebook.*pixel', 'fbq\\(', 'fb\\.q'], 'type': 'social'},
            'Twitter Widgets': {'patterns': ['platform\\.twitter\\.com', 'twitter-widgets'], 'type': 'social'},
            'Twitter Cards': {'patterns': ['twitter:card', 'twitter:site'], 'type': 'social'},
            'LinkedIn Insight Tag': {'patterns': ['linkedin.*insight', '_linkedin'], 'type': 'social'},
            'Pinterest Tag': {'patterns': ['pinterest.*tag', 'pinimg'], 'type': 'social'},
            'Instagram Embed': {'patterns': ['instagram.*embed', 'instagr\\.am'], 'type': 'social'},
            'TikTok Pixel': {'patterns': ['tiktok.*pixel'], 'type': 'social'},
            'AddThis': {'patterns': ['addthis', 'addthis\\.com'], 'type': 'social'},
            'ShareThis': {'patterns': ['sharethis'], 'type': 'social'},
            'Disqus': {'patterns': ['disqus', 'disqus\\.com'], 'type': 'social'},
            
            # Social Login
            'Facebook Login SDK': {'patterns': ['facebook.*login.*sdk'], 'type': 'authentication', 'auth_type': 'Social Login (OAuth)'},
            'Google Sign-In SDK': {'patterns': ['google.*sign.*in.*sdk'], 'type': 'authentication', 'auth_type': 'Social Login (OAuth)'},
            'Apple Sign-In SDK': {'patterns': ['apple.*sign.*in.*sdk'], 'type': 'authentication', 'auth_type': 'Social Login (OAuth)'},
            
            # Additional
            'Bootstrap': {'patterns': ['bootstrap', 'bs-'], 'type': 'css'},
            'Tailwind CSS': {'patterns': ['tailwind', 'tw-'], 'type': 'css'},
            'jQuery': {'patterns': ['jquery'], 'type': 'js'},
            'Font Awesome': {'patterns': ['font.*awesome', 'fa-'], 'type': 'icons'},
            'Google Fonts': {'patterns': ['fonts\\.googleapis'], 'type': 'fonts'},
        }
    
    def load_extended_patterns(self):
        """Load extended patterns for more comprehensive detection"""
        return {
            'generator_meta': {
                'WordPress': ['wordpress', 'wp'],
                'Drupal': ['drupal'],
                'Joomla': ['joomla'],
                'Magento': ['magento'],
                'Shopify': ['shopify'],
            },
            'powered_by': {
                'PHP': ['php'],
                'ASP.NET': ['asp.net'],
                'Node.js': ['express', 'node.js'],
                'Python': ['python', 'django', 'flask'],
                'Ruby': ['ruby', 'rails'],
            },
            'js_frameworks': {
                'React': ['React', 'createElement', 'useState', 'useEffect'],
                'Vue.js': ['Vue', 'new Vue', 'v-'],
                'Angular': ['angular', 'ng-'],
                'jQuery': ['jQuery', '$('],
                'Next.js': ['__NEXT_DATA__', 'next/router'],
            },
            'css_frameworks': {
                'Bootstrap': ['bootstrap', 'container', 'row', 'col-'],
                'Tailwind CSS': ['tailwind', 'bg-', 'text-', 'p-', 'm-'],
            },
            'social_media': {
                'Facebook': ['facebook\\.com', 'fb\\.com', 'fbcdn', 'fbsbx'],
                'Twitter': ['twitter\\.com', 'twimg\\.com', 't\\.co'],
                'LinkedIn': ['linkedin\\.com', 'licdn\\.com'],
                'Instagram': ['instagram\\.com', 'instagr\\.am', 'cdninstagram'],
                'Pinterest': ['pinterest\\.com', 'pinimg\\.com'],
                'YouTube': ['youtube\\.com', 'youtu\\.be', 'ytimg\\.com'],
                'TikTok': ['tiktok\\.com'],
            },
            'authentication': {
                'OAuth 2.0': ['oauth2', 'oauth/authorize', 'oauth/token', 'code=', 'access_token='],
                'OAuth 1.0': ['oauth', 'oauth/request_token', 'oauth_signature='],
                'JWT': ['eyJ', 'Bearer eyJ', 'jwt=', 'token_type=Bearer'],
                'SAML': ['SAMLRequest', 'SAMLResponse', 'saml/SSO'],
                'OpenID': ['openid', 'oidc'],
                'LDAP': ['ldap://', 'ldaps://'],
                'Session': ['sessionid=', 'PHPSESSID=', 'JSESSIONID='],
                'Basic Auth': ['authorization: basic', 'www-authenticate: basic'],
            }
        }
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def fetch_url(self, url: str) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Fetch URL content with multiple attempts"""
        attempts = [
            {'url': url, 'verify': False},
            {'url': url.replace('https://', 'http://'), 'verify': False},
            {'url': f"{url}/robots.txt", 'verify': False},
            {'url': f"{url}/login", 'verify': False},
            {'url': f"{url}/auth/login", 'verify': False},
        ]
        
        for attempt in attempts:
            try:
                response = requests.get(
                    attempt['url'], 
                    headers=self.headers, 
                    timeout=10, 
                    verify=attempt['verify'],
                    allow_redirects=True
                )
                if response.status_code < 400:
                    return response, None
            except:
                continue
        
        return None, "Failed to fetch URL after multiple attempts"
    
    def analyze_headers(self, response: requests.Response) -> List[Dict]:
        """Analyze HTTP headers for technologies"""
        detected = []
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Server header analysis
        if 'server' in headers:
            server = headers['server']
            if 'apache' in server:
                detected.append({'name': 'Apache', 'type': 'server', 'details': 'Web Server'})
            if 'nginx' in server:
                detected.append({'name': 'Nginx', 'type': 'server', 'details': 'Web Server'})
            if 'iis' in server or 'microsoft-iis' in server:
                detected.append({'name': 'Microsoft IIS', 'type': 'server', 'details': 'Web Server'})
            if 'cloudflare' in server:
                detected.append({'name': 'Cloudflare', 'type': 'security', 'details': 'CDN & Security'})
        
        # X-Powered-By header
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            if 'php' in powered_by:
                detected.append({'name': 'PHP', 'type': 'backend', 'details': 'Backend Language'})
            if 'asp.net' in powered_by:
                detected.append({'name': 'ASP.NET', 'type': 'backend', 'details': 'Backend Framework'})
            if 'express' in powered_by:
                detected.append({'name': 'Node.js (Express)', 'type': 'backend', 'details': 'Backend Runtime'})
            if 'django' in powered_by:
                detected.append({'name': 'Django', 'type': 'backend', 'details': 'Python Framework'})
        
        # Authentication headers
        if 'www-authenticate' in headers:
            auth_header = headers['www-authenticate']
            if 'basic' in auth_header:
                detected.append({'name': 'Basic Authentication', 'type': 'authentication', 'details': 'HTTP Basic Auth'})
            if 'bearer' in auth_header:
                detected.append({'name': 'Bearer Token', 'type': 'authentication', 'details': 'Token-Based Auth'})
        
        # Check for JWT tokens in headers
        for header_name, header_value in response.headers.items():
            if 'authorization' in header_name.lower() and 'bearer' in header_value.lower():
                if 'eyJ' in header_value:  # JWT token pattern
                    detected.append({'name': 'JWT Authentication', 'type': 'authentication', 'details': 'JSON Web Token'})
        
        # Other headers
        for header, value in headers.items():
            if 'vercel' in header or 'vercel' in value:
                detected.append({'name': 'Vercel', 'type': 'hosting', 'details': 'Hosting Platform'})
            if 'netlify' in header or 'netlify' in value:
                detected.append({'name': 'Netlify', 'type': 'hosting', 'details': 'Hosting Platform'})
            if 'heroku' in header or 'heroku' in value:
                detected.append({'name': 'Heroku', 'type': 'hosting', 'details': 'Platform as a Service'})
            if 'aws' in header or 'amazon' in value:
                detected.append({'name': 'Amazon Web Services', 'type': 'cloud', 'details': 'Cloud Platform'})
            if 'azure' in header:
                detected.append({'name': 'Azure', 'type': 'cloud', 'details': 'Microsoft Cloud'})
        
        return detected
    
    def analyze_html_content(self, html: str) -> List[Dict]:
        """Analyze HTML content for technologies"""
        detected = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Meta generator tags
        for meta in soup.find_all('meta', attrs={'name': 'generator'}):
            content = meta.get('content', '').lower()
            for tech, patterns in self.extended_patterns['generator_meta'].items():
                if any(pattern in content for pattern in patterns):
                    detected.append({'name': tech, 'type': 'cms', 'details': 'Content Management System'})
        
        # Script tags analysis
        for script in soup.find_all('script'):
            src = script.get('src', '').lower()
            content = script.string or ''
            
            # Source URL analysis
            for tech, data in self.tech_signatures.items():
                patterns = data['patterns']
                if any(re.search(pattern, src, re.IGNORECASE) for pattern in patterns):
                    tech_type = data.get('type', 'other')
                    auth_type = data.get('auth_type', '')
                    details = auth_type if auth_type else data.get('details', tech_type)
                    detected.append({'name': tech, 'type': tech_type, 'details': details})
            
            # Inline script analysis for authentication
            if content:
                content_lower = content.lower()
                
                # Check for authentication patterns
                for auth_name, patterns in self.extended_patterns['authentication'].items():
                    if any(pattern.lower() in content_lower for pattern in patterns):
                        detected.append({'name': auth_name, 'type': 'authentication', 'details': 'Authentication Protocol'})
                
                # Check for social media
                for social, patterns in self.extended_patterns['social_media'].items():
                    if any(pattern.lower() in content_lower for pattern in patterns):
                        detected.append({'name': social, 'type': 'social', 'details': 'Social Media Platform'})
                
                # Check for JS frameworks
                for tech, patterns in self.extended_patterns['js_frameworks'].items():
                    if any(pattern.lower() in content_lower for pattern in patterns):
                        detected.append({'name': tech, 'type': 'frontend', 'details': 'JavaScript Framework'})
        
        # Link tags (CSS)
        for link in soup.find_all('link', attrs={'rel': 'stylesheet'}):
            href = link.get('href', '').lower()
            for tech, patterns in self.extended_patterns['css_frameworks'].items():
                if any(pattern.lower() in href for pattern in patterns):
                    detected.append({'name': tech, 'type': 'css', 'details': 'CSS Framework'})
        
        # Meta tags for social media
        for meta in soup.find_all('meta'):
            prop = meta.get('property', '').lower()
            content = meta.get('content', '').lower()
            
            # Open Graph (Facebook)
            if 'og:' in prop:
                detected.append({'name': 'Facebook Open Graph', 'type': 'social', 'details': 'Social Meta Tags'})
            
            # Twitter Cards
            if 'twitter:' in prop:
                detected.append({'name': 'Twitter Cards', 'type': 'social', 'details': 'Social Meta Tags'})
        
        # Form analysis for authentication
        for form in soup.find_all('form'):
            action = form.get('action', '').lower()
            method = form.get('method', '').lower()
            form_html = str(form).lower()
            
            # Check for login forms
            if any(keyword in action or keyword in form_html for keyword in ['login', 'signin', 'auth', 'oauth']):
                detected.append({'name': 'Login Form', 'type': 'authentication', 'details': 'Form-Based Authentication'})
            
            # Check for OAuth flows
            if 'oauth' in action or 'oauth' in form_html:
                detected.append({'name': 'OAuth Flow', 'type': 'authentication', 'details': 'OAuth Authentication'})
            
            # Check for SAML
            if 'saml' in action or 'saml' in form_html:
                detected.append({'name': 'SAML Authentication', 'type': 'authentication', 'details': 'SAML SSO'})
        
        # Check for social media iframes/embeds
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '').lower()
            if 'facebook' in src:
                detected.append({'name': 'Facebook SDK', 'type': 'social', 'details': 'Social Media Integration'})
            if 'twitter' in src:
                detected.append({'name': 'Twitter Widgets', 'type': 'social', 'details': 'Social Media Widgets'})
            if 'youtube' in src or 'youtu.be' in src:
                detected.append({'name': 'YouTube', 'type': 'social', 'details': 'Video Embed'})
            if 'instagram' in src:
                detected.append({'name': 'Instagram Embed', 'type': 'social', 'details': 'Social Media Embed'})
        
        # Check for authentication-related divs/classes
        for element in soup.find_all(class_=True):
            classes = ' '.join(element.get('class', [])).lower()
            if any(auth_term in classes for auth_term in ['login', 'signin', 'auth', 'oauth', 'sso', '2fa', 'mfa']):
                detected.append({'name': 'Authentication UI', 'type': 'authentication', 'details': 'Authentication Interface'})
        
        # Remove duplicates while preserving details
        unique_detected = []
        seen = set()
        for item in detected:
            key = (item['name'], item['type'])
            if key not in seen:
                seen.add(key)
                unique_detected.append(item)
        
        return unique_detected
    
    def check_common_paths(self, url: str) -> List[Dict]:
        """Check common paths for technology fingerprints"""
        detected = []
        common_paths = {
            '/wp-admin/': {'name': 'WordPress', 'type': 'cms', 'details': 'Admin Dashboard'},
            '/wp-login.php': {'name': 'WordPress', 'type': 'cms', 'details': 'Login Page'},
            '/administrator/': {'name': 'Joomla', 'type': 'cms', 'details': 'Admin Dashboard'},
            '/user/login': {'name': 'Drupal', 'type': 'cms', 'details': 'Login Page'},
            '/admin/': {'name': 'Generic Admin', 'type': 'admin', 'details': 'Admin Interface'},
            '/robots.txt': {'name': 'Robots File', 'type': 'seo', 'details': 'Search Engine File'},
            # Authentication paths
            '/auth/': {'name': 'Auth Endpoint', 'type': 'authentication', 'details': 'Authentication API'},
            '/login': {'name': 'Login Page', 'type': 'authentication', 'details': 'Authentication Interface'},
            '/signin': {'name': 'Sign In Page', 'type': 'authentication', 'details': 'Authentication Interface'},
            '/oauth/': {'name': 'OAuth Endpoint', 'type': 'authentication', 'details': 'OAuth API'},
            '/oauth2/': {'name': 'OAuth 2.0 Endpoint', 'type': 'authentication', 'details': 'OAuth 2.0 API'},
            '/api/auth/': {'name': 'Auth API', 'type': 'authentication', 'details': 'Authentication API'},
            '/saml/': {'name': 'SAML Endpoint', 'type': 'authentication', 'details': 'SAML SSO'},
            '/.well-known/openid-configuration': {'name': 'OpenID Connect', 'type': 'authentication', 'details': 'OpenID Configuration'},
        }
        
        for path, tech_info in common_paths.items():
            try:
                test_url = url.rstrip('/') + path
                response = requests.get(test_url, headers=self.headers, timeout=3, verify=False)
                if response.status_code < 400:
                    detected.append(tech_info)
                    
                    # Additional analysis for authentication endpoints
                    if 'auth' in path or 'login' in path or 'oauth' in path:
                        content = response.text.lower()
                        
                        # Check for specific authentication technologies
                        if 'oauth' in path and ('token' in content or 'authorization' in content):
                            detected.append({'name': 'OAuth Provider', 'type': 'authentication', 'details': 'OAuth Authorization Server'})
                        
                        if 'saml' in path:
                            detected.append({'name': 'SAML Identity Provider', 'type': 'authentication', 'details': 'SAML SSO Provider'})
                        
                        # Check response headers for auth info
                        headers = response.headers
                        if 'www-authenticate' in str(headers).lower():
                            detected.append({'name': 'HTTP Authentication', 'type': 'authentication', 'details': 'HTTP Auth Challenge'})
                        
            except:
                continue
        
        return detected
    
    def detect_technologies(self, url: str) -> Dict:
        """Main technology detection function"""
        print(f"\n\033[92m[+] Analyzing:\033[0m \033[96m{url}\033[0m")
        print("\033[90m" + "="*70 + "\033[0m")
        
        # Normalize URL
        url = self.normalize_url(url)
        
        # Initialize results structure
        results = {
            'cms': [],
            'ecommerce': [],
            'frontend': [],
            'backend': [],
            'language': [],
            'cloud': [],
            'hosting': [],
            'analytics': [],
            'security': [],
            'authentication': [],  # Will store dicts with name and type
            'social': [],
            'other': []
        }
        
        # Map tech types to result categories
        type_to_category = {
            'cms': 'cms',
            'ecommerce': 'ecommerce',
            'frontend': 'frontend',
            'backend': 'backend',
            'language': 'language',
            'cloud': 'cloud',
            'hosting': 'hosting',
            'analytics': 'analytics',
            'security': 'security',
            'authentication': 'authentication',
            'social': 'social',
            'server': 'other',
            'admin': 'other',
            'seo': 'other',
            'css': 'other',
            'js': 'other',
            'icons': 'other',
            'fonts': 'other',
        }
        
        try:
            # Step 1: Fetch the main page
            print("\033[93m[+] Fetching website...\033[0m")
            response, error = self.fetch_url(url)
            
            if not response:
                print(f"\033[91m  ✗ {error}\033[0m")
                return results
            
            print(f"\033[92m  ✓ HTTP Status: {response.status_code}\033[0m")
            
            # Step 2: Analyze headers
            print("\033[93m[+] Analyzing HTTP headers...\033[0m")
            header_techs = self.analyze_headers(response)
            for tech_info in header_techs:
                category = type_to_category.get(tech_info['type'], 'other')
                if tech_info not in results[category]:
                    results[category].append(tech_info)
            
            print(f"\033[92m  ✓ Found {len(header_techs)} technologies in headers\033[0m")
            
            # Step 3: Analyze HTML content
            print("\033[93m[+] Analyzing HTML content...\033[0m")
            html_techs = self.analyze_html_content(response.text)
            
            # Categorize HTML technologies
            for tech_info in html_techs:
                category = type_to_category.get(tech_info['type'], 'other')
                
                # Special handling for authentication to ensure details are shown
                if category == 'authentication' and 'details' in tech_info:
                    # Format authentication entry to show type
                    formatted_entry = {
                        'name': tech_info['name'],
                        'type': tech_info['details']  # Use details as the type display
                    }
                    if formatted_entry not in results[category]:
                        results[category].append(formatted_entry)
                elif tech_info not in results[category]:
                    results[category].append(tech_info)
            
            print(f"\033[92m  ✓ Found {len(html_techs)} technologies in HTML\033[0m")
            
            # Step 4: Check common paths
            print("\033[93m[+] Checking common paths...\033[0m")
            path_techs = self.check_common_paths(url)
            for tech_info in path_techs:
                category = type_to_category.get(tech_info['type'], 'other')
                
                # Special formatting for authentication
                if category == 'authentication':
                    formatted_entry = {
                        'name': tech_info['name'],
                        'type': tech_info['details']
                    }
                    if formatted_entry not in results[category]:
                        results[category].append(formatted_entry)
                elif tech_info not in results[category]:
                    results[category].append(tech_info)
            
            print(f"\033[92m  ✓ Checked common paths\033[0m")
            
            # Display results
            print("\n\033[92m[+] DETECTION RESULTS:\033[0m")
            print("\033[96m" + "="*70 + "\033[0m")
            
            for category, techs in results.items():
                if techs:
                    print(f"\n\033[93m{category.upper()}:\033[0m")
                    for tech in techs:
                        if isinstance(tech, dict):
                            if 'type' in tech and tech['type']:
                                print(f"  \033[92m✓\033[0m {tech['name']} (\033[94m{tech['type']}\033[0m)")
                            else:
                                print(f"  \033[92m✓\033[0m {tech['name']}")
                        else:
                            print(f"  \033[92m✓\033[0m {tech}")
            
            # Summary
            print("\n\033[96m" + "="*70 + "\033[0m")
            total_techs = sum(len(techs) for techs in results.values())
            
            # Count authentication types
            auth_techs = results.get('authentication', [])
            if auth_techs:
                print(f"\n\033[92m[+] Authentication Methods Found:\033[0m")
                for auth in auth_techs:
                    if isinstance(auth, dict) and 'type' in auth:
                        print(f"  • {auth['name']}: \033[94m{auth['type']}\033[0m")
                    else:
                        print(f"  • {auth}")
            
            print(f"\n\033[92m[+] Total technologies detected: {total_techs}\033[0m")
            
        except Exception as e:
            print(f"\033[91m  ✗ Error during analysis: {e}\033[0m")
        
        return results

def main():
    """Main function to run the tool"""
    parser = argparse.ArgumentParser(description='Advanced Website Technology Detector')
    parser.add_argument('url', nargs='?', help='URL to analyze')
    parser.add_argument('-f', '--file', help='File containing list of URLs')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    
    args = parser.parse_args()
    
    detector = AdvancedTechDetector()
    detector.display_banner()
    
    urls_to_analyze = []
    
    # Collect URLs to analyze
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls_to_analyze = [line.strip() for line in f if line.strip()]
            print(f"\033[92m[+] Loaded {len(urls_to_analyze)} URLs from file\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error reading file: {e}\033[0m")
            return
    elif args.url:
        urls_to_analyze = [args.url]
    else:
        # Interactive mode
        print("\033[93m[!] No URL provided. Enter URL to analyze:\033[0m")
        url_input = input("\033[96mEnter URL: \033[0m").strip()
        if url_input:
            urls_to_analyze = [url_input]
        else:
            print("\033[91m[!] No URL provided. Exiting.\033[0m")
            return
    
    # Analyze URLs
    all_results = {}
    
    for url in urls_to_analyze:
        print("\n" + "="*78)
        results = detector.detect_technologies(url)
        all_results[url] = results
    
    # Save results if output file specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2)
            print(f"\n\033[92m[+] Results saved to {args.output}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error saving results: {e}\033[0m")
    
    print("\n\033[92m[+] Analysis complete!\033[0m")

if __name__ == "__main__":
    main()
