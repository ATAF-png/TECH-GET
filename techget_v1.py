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
            
            # Authentication Services
            'Auth0': {'patterns': ['auth0', 'auth0\\.com', '\\.auth0\\.com'], 'type': 'authentication'},
            'Firebase Authentication': {'patterns': ['firebase-auth', 'firebaseapp\\.com'], 'type': 'authentication'},
            'Okta': {'patterns': ['okta', 'okta\\.com', 'oktapreview\\.com'], 'type': 'authentication'},
            'OneLogin': {'patterns': ['onelogin', 'onelogin\\.com'], 'type': 'authentication'},
            'Ping Identity': {'patterns': ['pingidentity'], 'type': 'authentication'},
            'Keycloak': {'patterns': ['keycloak'], 'type': 'authentication'},
            'Cognito': {'patterns': ['cognito', 'amazoncognito\\.com'], 'type': 'authentication'},
            'Azure AD': {'patterns': ['azure.*ad', 'microsoftonline\\.com'], 'type': 'authentication'},
            'Google Sign-In': {'patterns': ['google.*signin', 'accounts\\.google\\.com'], 'type': 'authentication'},
            'Facebook Login': {'patterns': ['facebook.*login', 'fb-login'], 'type': 'authentication'},
            'OAuth': {'patterns': ['oauth', 'oauth2'], 'type': 'authentication'},
            'Passport.js': {'patterns': ['passport', 'passport\\.js'], 'type': 'authentication'},
            'JWT': {'patterns': ['jwt', 'jsonwebtoken'], 'type': 'authentication'},
            
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
            'reCAPTCHA': {'patterns': ['recaptcha', 'g-recaptcha'], 'type': 'security'},
            'hCaptcha': {'patterns': ['hcaptcha'], 'type': 'security'},
            
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
            'Facebook Login SDK': {'patterns': ['facebook.*login.*sdk'], 'type': 'authentication'},
            'Google Sign-In SDK': {'patterns': ['google.*sign.*in.*sdk'], 'type': 'authentication'},
            'Apple Sign-In': {'patterns': ['appleid\\.apple\\.com', 'apple.*sign'], 'type': 'authentication'},
            
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
                'Auth0': ['auth0', 'auth0\\.com'],
                'Firebase Auth': ['firebaseapp\\.com'],
                'OAuth': ['oauth', 'oauth2'],
                'JWT': ['jwt', 'Bearer '],
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
    
    def analyze_headers(self, response: requests.Response) -> List[str]:
        """Analyze HTTP headers for technologies"""
        detected = []
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Server header analysis
        if 'server' in headers:
            server = headers['server']
            if 'apache' in server:
                detected.append('Apache')
            if 'nginx' in server:
                detected.append('Nginx')
            if 'iis' in server or 'microsoft-iis' in server:
                detected.append('Microsoft-IIS')
            if 'cloudflare' in server:
                detected.append('Cloudflare')
        
        # X-Powered-By header
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            if 'php' in powered_by:
                detected.append('PHP')
            if 'asp.net' in powered_by:
                detected.append('ASP.NET')
            if 'express' in powered_by:
                detected.append('Node.js')
            if 'django' in powered_by:
                detected.append('Django')
        
        # Other headers
        for header, value in headers.items():
            if 'vercel' in header or 'vercel' in value:
                detected.append('Vercel')
            if 'netlify' in header or 'netlify' in value:
                detected.append('Netlify')
            if 'heroku' in header or 'heroku' in value:
                detected.append('Heroku')
            if 'aws' in header or 'amazon' in value:
                detected.append('Amazon Web Services')
            if 'azure' in header:
                detected.append('Azure')
        
        return list(set(detected))
    
    def analyze_html_content(self, html: str) -> List[str]:
        """Analyze HTML content for technologies"""
        detected = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Meta generator tags
        for meta in soup.find_all('meta', attrs={'name': 'generator'}):
            content = meta.get('content', '').lower()
            for tech, patterns in self.extended_patterns['generator_meta'].items():
                if any(pattern in content for pattern in patterns):
                    detected.append(tech)
        
        # Script tags analysis
        for script in soup.find_all('script'):
            src = script.get('src', '').lower()
            content = script.string or ''
            
            # Source URL analysis
            for tech, data in self.tech_signatures.items():
                patterns = data['patterns']
                if any(re.search(pattern, src, re.IGNORECASE) for pattern in patterns):
                    detected.append(tech)
            
            # Inline script analysis
            if content:
                content_lower = content.lower()
                # Check for social media scripts
                for tech, patterns in self.extended_patterns['social_media'].items():
                    if any(pattern.lower() in content_lower for pattern in patterns):
                        if tech not in detected:
                            detected.append(tech)
                
                # Check for authentication
                for tech, patterns in self.extended_patterns['authentication'].items():
                    if any(pattern.lower() in content_lower for pattern in patterns):
                        if tech not in detected:
                            detected.append(tech)
                
                # Check for JS frameworks
                for tech, patterns in self.extended_patterns['js_frameworks'].items():
                    if any(pattern.lower() in content_lower for pattern in patterns):
                        if tech not in detected:
                            detected.append(tech)
        
        # Link tags (CSS)
        for link in soup.find_all('link', attrs={'rel': 'stylesheet'}):
            href = link.get('href', '').lower()
            for tech, patterns in self.extended_patterns['css_frameworks'].items():
                if any(pattern.lower() in href for pattern in patterns):
                    if tech not in detected:
                        detected.append(tech)
        
        # Meta tags for social media
        for meta in soup.find_all('meta'):
            prop = meta.get('property', '').lower()
            content = meta.get('content', '').lower()
            
            # Open Graph (Facebook)
            if 'og:' in prop:
                if 'facebook' not in detected:
                    detected.append('Facebook Open Graph')
            
            # Twitter Cards
            if 'twitter:' in prop:
                if 'Twitter Cards' not in detected:
                    detected.append('Twitter Cards')
        
        # HTML attributes and classes
        for element in soup.find_all(attrs=True):
            # Class analysis
            classes = element.get('class', [])
            if classes:
                class_str = ' '.join(classes).lower()
                for tech, patterns in self.extended_patterns['css_frameworks'].items():
                    if any(pattern.lower() in class_str for pattern in patterns):
                        if tech not in detected:
                            detected.append(tech)
            
            # Attribute analysis
            for attr_name, attr_value in element.attrs.items():
                if isinstance(attr_value, str):
                    attr_str = f"{attr_name}={attr_value}".lower()
                    for tech, data in self.tech_signatures.items():
                        patterns = data['patterns']
                        if any(re.search(pattern, attr_str, re.IGNORECASE) for pattern in patterns):
                            if tech not in detected:
                                detected.append(tech)
        
        # Comments analysis
        comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        for comment in comments:
            comment_text = comment.strip().lower()
            for tech, data in self.tech_signatures.items():
                patterns = data['patterns']
                if any(re.search(pattern, comment_text, re.IGNORECASE) for pattern in patterns):
                    if tech not in detected:
                        detected.append(tech)
        
        # Check for social media iframes/embeds
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '').lower()
            if 'facebook' in src:
                if 'Facebook SDK' not in detected:
                    detected.append('Facebook SDK')
            if 'twitter' in src:
                if 'Twitter Widgets' not in detected:
                    detected.append('Twitter Widgets')
            if 'youtube' in src or 'youtu.be' in src:
                if 'YouTube' not in detected:
                    detected.append('YouTube')
            if 'instagram' in src:
                if 'Instagram Embed' not in detected:
                    detected.append('Instagram Embed')
        
        return list(set(detected))
    
    def check_common_paths(self, url: str) -> List[str]:
        """Check common paths for technology fingerprints"""
        detected = []
        common_paths = {
            '/wp-admin/': 'WordPress',
            '/wp-login.php': 'WordPress',
            '/administrator/': 'Joomla',
            '/user/login': 'Drupal',
            '/admin/': 'Generic Admin',
            '/robots.txt': 'Robots File',
            # Authentication paths
            '/auth/': 'Authentication',
            '/login': 'Authentication',
            '/signin': 'Authentication',
            '/oauth/': 'OAuth',
            '/oauth2/': 'OAuth2',
            '/api/auth/': 'API Authentication',
        }
        
        for path, tech in common_paths.items():
            try:
                test_url = url.rstrip('/') + path
                response = requests.get(test_url, headers=self.headers, timeout=3, verify=False)
                if response.status_code < 400:
                    detected.append(tech)
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
            'authentication': [],
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
            for tech in header_techs:
                # Categorize header technologies
                server_techs = ['Apache', 'Nginx', 'Microsoft-IIS']
                backend_techs = ['PHP', 'ASP.NET', 'Node.js', 'Django', 'Express.js']
                hosting_techs = ['Vercel', 'Netlify', 'Heroku', 'Cloudflare']
                cloud_techs = ['Amazon Web Services', 'Azure', 'Google Cloud']
                
                if tech in server_techs:
                    if tech not in results['other']:
                        results['other'].append(tech)
                elif tech in backend_techs:
                    if tech not in results['backend']:
                        results['backend'].append(tech)
                elif tech in hosting_techs:
                    if tech not in results['hosting']:
                        results['hosting'].append(tech)
                elif tech in cloud_techs:
                    if tech not in results['cloud']:
                        results['cloud'].append(tech)
                else:
                    if tech not in results['other']:
                        results['other'].append(tech)
            
            print(f"\033[92m  ✓ Found {len(header_techs)} technologies in headers\033[0m")
            
            # Step 3: Analyze HTML content
            print("\033[93m[+] Analyzing HTML content...\033[0m")
            html_techs = self.analyze_html_content(response.text)
            
            # Categorize HTML technologies
            for tech in html_techs:
                if tech in self.tech_signatures:
                    tech_type = self.tech_signatures[tech]['type']
                    category = type_to_category.get(tech_type, 'other')
                    if tech not in results[category]:
                        results[category].append(tech)
                else:
                    # Check for social media platforms detected
                    if any(social in tech.lower() for social in ['facebook', 'twitter', 'linkedin', 'instagram', 'pinterest', 'youtube', 'tiktok']):
                        if tech not in results['social']:
                            results['social'].append(tech)
                    elif tech not in results['other']:
                        results['other'].append(tech)
            
            print(f"\033[92m  ✓ Found {len(html_techs)} technologies in HTML\033[0m")
            
            # Step 4: Check common paths
            print("\033[93m[+] Checking common paths...\033[0m")
            path_techs = self.check_common_paths(url)
            for tech in path_techs:
                if tech == 'WordPress':
                    if 'WordPress' not in results['cms']:
                        results['cms'].append('WordPress')
                elif tech == 'Joomla':
                    if 'Joomla' not in results['cms']:
                        results['cms'].append('Joomla')
                elif tech == 'Drupal':
                    if 'Drupal' not in results['cms']:
                        results['cms'].append('Drupal')
                elif tech in ['Authentication', 'OAuth', 'OAuth2', 'API Authentication']:
                    if 'Authentication System' not in results['authentication']:
                        results['authentication'].append('Authentication System')
            
            print(f"\033[92m  ✓ Checked common paths\033[0m")
            
            # Display results
            print("\n\033[92m[+] DETECTION RESULTS:\033[0m")
            print("\033[96m" + "="*70 + "\033[0m")
            
            for category, techs in results.items():
                if techs:
                    print(f"\n\033[93m{category.upper()}:\033[0m")
                    for tech in sorted(techs):
                        print(f"  \033[92m✓\033[0m {tech}")
            
            # Summary
            print("\n\033[96m" + "="*70 + "\033[0m")
            total_techs = sum(len(techs) for techs in results.values())
            print(f"\033[92m[+] Total technologies detected: {total_techs}\033[0m")
            
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
