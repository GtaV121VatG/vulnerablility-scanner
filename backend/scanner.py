import requests
from urllib.parse import urljoin, urlparse
import ssl
import socket
from datetime import datetime
from bs4 import BeautifulSoup
import os

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Scanner) VulnScan/1.0'
        })
        
        self.security_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        
        self.dangerous_paths = [
            '/.env', '/.git', '/.git/config', '/admin', '/backup',
            '/config', '/.DS_Store', '/phpinfo.php', '/phpmyadmin',
            '/.htaccess', '/wp-admin', '/db_backup', '/database.sql',
            '/config.php', '/wp-config.php', '/.svn', '/test'
        ]
        
        self.logs_dir = 'logs'
        if not os.path.exists(self.logs_dir):
            os.makedirs(self.logs_dir)
    
    def log_scan(self, url, results):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_file = os.path.join(self.logs_dir, 'scans.log')
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n[{timestamp}] Scan Report\n")
            f.write(f"Target: {url}\n")
            f.write(f"Pages Scanned: {len(results.get('pages_scanned', []))}\n")
            f.write(f"{'-'*80}\n")
            
            for finding in results.get('findings', []):
                f.write(f"[{finding['severity'].upper()}] {finding['title']}\n")
                f.write(f"Description: {finding['description']}\n")
                if finding.get('cve'):
                    f.write(f"Reference: {finding['cve']}\n")
                f.write(f"\n")
            
            f.write(f"{'='*80}\n")
    
    def scan(self, url, crawl_depth=3):
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'pages_scanned': []
        }
        
        try:
            https_findings = self._check_https(url)
            results['findings'].extend(https_findings)
            
            main_page = self._scan_page(url)
            results['findings'].extend(main_page['findings'])
            results['pages_scanned'].append(url)
            
            header_findings = self._check_security_headers(url)
            results['findings'].extend(header_findings)
            
            dir_findings = self._check_exposed_directories(url)
            results['findings'].extend(dir_findings)
            
            cookie_findings = self._check_cookies(url)
            results['findings'].extend(cookie_findings)
            
            if crawl_depth > 0:
                crawled_pages = self._crawl_pages(url, main_page.get('links', []), crawl_depth)
                for page_url in crawled_pages[:5]:
                    if page_url not in results['pages_scanned']:
                        page_results = self._scan_page(page_url)
                        results['findings'].extend(page_results['findings'])
                        results['pages_scanned'].append(page_url)
            
            for finding in results['findings']:
                severity = finding.get('severity', 'info')
                results['stats'][severity] = results['stats'].get(severity, 0) + 1
            
            self.log_scan(url, results)
                
        except Exception as e:
            results['findings'].append({
                'severity': 'critical',
                'title': 'Scan Error',
                'description': f'Error scanning {url}: {str(e)}',
                'cve': None
            })
        
        return results
    
    def _check_https(self, url):
        findings = []
        parsed = urlparse(url)
        
        if parsed.scheme == 'http':
            findings.append({
                'severity': 'critical',
                'title': 'Unencrypted Connection',
                'description': 'Website uses HTTP instead of HTTPS. All data transmitted is unencrypted and vulnerable to interception.',
                'cve': 'CWE-319',
                'cve_url': 'https://cwe.mitre.org/data/definitions/319.html'
            })
        else:
            findings.append({
                'severity': 'info',
                'title': 'Encrypted Connection',
                'description': 'Website uses HTTPS for secure encrypted communication.',
                'cve': None
            })
            
            try:
                hostname = parsed.netloc.split(':')[0]
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        findings.append({
                            'severity': 'info',
                            'title': 'Valid SSL Certificate',
                            'description': f'SSL certificate is valid. Issued to: {cert.get("subject", [[("commonName", "Unknown")]])[0][0][1]}',
                            'cve': None
                        })
            except Exception:
                findings.append({
                    'severity': 'high',
                    'title': 'SSL Certificate Issue',
                    'description': 'Problem with SSL certificate verification',
                    'cve': 'CWE-295',
                    'cve_url': 'https://cwe.mitre.org/data/definitions/295.html'
                })
        
        return findings
    
    def _scan_page(self, url):
        result = {'findings': [], 'links': []}
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            if 'Server' in response.headers:
                result['findings'].append({
                    'severity': 'low',
                    'title': 'Server Information Disclosure',
                    'description': f'Server header reveals: {response.headers["Server"]}',
                    'cve': 'CWE-200',
                    'cve_url': 'https://cwe.mitre.org/data/definitions/200.html'
                })
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        result['links'].append(full_url)
                
                scripts = soup.find_all('script')
                inline_scripts = [s for s in scripts if not s.get('src')]
                if len(inline_scripts) > 5:
                    result['findings'].append({
                        'severity': 'low',
                        'title': 'Excessive Inline JavaScript',
                        'description': f'Found {len(inline_scripts)} inline scripts',
                        'cve': None
                    })
                
                if urlparse(url).scheme == 'http':
                    forms = soup.find_all('form')
                    if forms:
                        result['findings'].append({
                            'severity': 'high',
                            'title': 'Forms on Unencrypted Page',
                            'description': f'Found {len(forms)} form(s) on HTTP page',
                            'cve': 'CWE-319',
                            'cve_url': 'https://cwe.mitre.org/data/definitions/319.html'
                        })
                
        except Exception:
            pass
        
        return result
    
    def _check_security_headers(self, url):
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            missing_headers = []
            present_headers = []
            
            for header in self.security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
                else:
                    present_headers.append(header)
            
            if missing_headers:
                findings.append({
                    'severity': 'medium',
                    'title': 'Missing Security Headers',
                    'description': f'Missing headers: {", ".join(missing_headers)}',
                    'cve': 'CWE-693',
                    'cve_url': 'https://cwe.mitre.org/data/definitions/693.html'
                })
            
            if present_headers:
                findings.append({
                    'severity': 'info',
                    'title': 'Security Headers Present',
                    'description': f'Found: {", ".join(present_headers)}',
                    'cve': None
                })
                
        except Exception:
            pass
        
        return findings
    
    def _check_exposed_directories(self, url):
        findings = []
        exposed = []
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.dangerous_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 403]:
                    exposed.append(path)
                    
            except:
                pass
        
        if exposed:
            findings.append({
                'severity': 'critical',
                'title': 'Exposed Sensitive Directories',
                'description': f'Found: {", ".join(exposed)}',
                'cve': 'CWE-548',
                'cve_url': 'https://cwe.mitre.org/data/definitions/548.html'
            })
        else:
            findings.append({
                'severity': 'info',
                'title': 'No Exposed Directories Found',
                'description': 'Common sensitive directories are not publicly accessible',
                'cve': None
            })
        
        return findings
    
    def _check_cookies(self, url):
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            cookies = response.cookies
            
            if not cookies:
                return findings
            
            issues = []
            
            for cookie in cookies:
                if not cookie.secure:
                    issues.append(f'{cookie.name}: Missing Secure flag')
                
            if issues:
                findings.append({
                    'severity': 'medium',
                    'title': 'Cookie Security Issues',
                    'description': f'{", ".join(issues)}',
                    'cve': 'CWE-614',
                    'cve_url': 'https://cwe.mitre.org/data/definitions/614.html'
                })
            else:
                findings.append({
                    'severity': 'info',
                    'title': 'Secure Cookie Configuration',
                    'description': 'Cookies properly configured',
                    'cve': None
                })
                
        except Exception:
            pass
        
        return findings
    
    def _crawl_pages(self, base_url, links, max_depth):
        unique_links = list(set(links))
        parsed_base = urlparse(base_url)
        
        same_domain_links = [
            link for link in unique_links 
            if urlparse(link).netloc == parsed_base.netloc
        ]
        
        return same_domain_links[:max_depth]
