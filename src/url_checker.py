"""
URL Checker Module for ScamShield
Analyzes URLs for potential phishing and malicious indicators
"""

import re
import tldextract
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class URLChecker:
    """URL security analyzer"""
    
    # Known URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
        'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'short.link'
    ]
    
    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = [
        'verify', 'account', 'secure', 'update', 'confirm', 'login',
        'banking', 'password', 'suspend', 'limited', 'unusual',
        'click', 'urgent', 'alert', 'winner', 'prize', 'reward',
        'free', 'claim', 'refund', 'tax', 'gov', 'paypal', 'amazon'
    ]
    
    # Common legitimate domains (whitelist)
    TRUSTED_DOMAINS = [
        'google.com', 'facebook.com', 'amazon.com', 'apple.com',
        'microsoft.com', 'linkedin.com', 'twitter.com', 'instagram.com',
        'youtube.com', 'wikipedia.org', 'github.com'
    ]
    
    def __init__(self):
        """Initialize URL checker"""
        self.risk_factors = []
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for security risks
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing risk analysis
        """
        self.risk_factors = []
        risk_score = 0
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Check for IP address instead of domain
        if self._is_ip_address(parsed.netloc):
            risk_score += 30
            self.risk_factors.append("Uses IP address instead of domain name")
        
        # Check if HTTPS
        if parsed.scheme != 'https':
            risk_score += 15
            self.risk_factors.append("Not using secure HTTPS protocol")
        
        # Check for URL shortener
        domain = f"{extracted.domain}.{extracted.suffix}"
        if self._is_url_shortener(domain):
            risk_score += 25
            self.risk_factors.append("Uses URL shortening service (hides destination)")
        
        # Check for trusted domain
        if self._is_trusted_domain(domain):
            risk_score = max(0, risk_score - 30)
            self.risk_factors.append("Domain is on trusted list")
        
        # Check for suspicious keywords
        suspicious_found = self._check_suspicious_keywords(url.lower())
        if suspicious_found:
            risk_score += len(suspicious_found) * 10
            self.risk_factors.append(f"Contains suspicious keywords: {', '.join(suspicious_found)}")
        
        # Check domain length
        if len(parsed.netloc) > 40:
            risk_score += 15
            self.risk_factors.append("Unusually long domain name")
        
        # Check for excessive subdomains
        subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
        if len(subdomains) > 2:
            risk_score += 20
            self.risk_factors.append(f"Multiple subdomains detected ({len(subdomains)})")
        
        # Check for @ symbol in URL (can hide real domain)
        if '@' in url:
            risk_score += 35
            self.risk_factors.append("Contains @ symbol (potential domain masking)")
        
        # Check for excessive hyphens
        if parsed.netloc.count('-') > 2:
            risk_score += 15
            self.risk_factors.append("Excessive hyphens in domain")
        
        # Check for digits in domain
        if re.search(r'\d', extracted.domain):
            risk_score += 10
            self.risk_factors.append("Contains numbers in domain name")
        
        # Check URL path length
        if len(parsed.path) > 100:
            risk_score += 10
            self.risk_factors.append("Unusually long URL path")
        
        # Check for query parameters (common in phishing)
        query_params = parse_qs(parsed.query)
        if len(query_params) > 5:
            risk_score += 15
            self.risk_factors.append(f"Many query parameters ({len(query_params)})")
        
        # Check for port number
        if parsed.port and parsed.port not in [80, 443]:
            risk_score += 20
            self.risk_factors.append(f"Uses non-standard port: {parsed.port}")
        
        # Check TLD (top-level domain)
        risky_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(extracted.suffix.endswith(tld.strip('.')) for tld in risky_tlds):
            risk_score += 25
            self.risk_factors.append(f"Uses risky top-level domain (.{extracted.suffix})")
        
        # Cap risk score at 100
        risk_score = min(100, risk_score)
        
        return {
            'url': url,
            'domain': domain,
            'subdomain': extracted.subdomain,
            'tld': extracted.suffix,
            'is_https': parsed.scheme == 'https',
            'is_shortened': self._is_url_shortener(domain),
            'is_trusted': self._is_trusted_domain(domain),
            'risk_score': risk_score,
            'risk_factors': self.risk_factors,
            'is_suspicious': risk_score >= 50
        }
    
    def analyze_multiple_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple URLs
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            List of analysis results
        """
        results = []
        for url in urls:
            try:
                result = self.analyze_url(url)
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing URL {url}: {str(e)}")
                results.append({
                    'url': url,
                    'error': str(e),
                    'risk_score': 50,
                    'is_suspicious': True
                })
        
        return results
    
    def _is_ip_address(self, netloc: str) -> bool:
        """Check if netloc is an IP address"""
        # Remove port if present
        host = netloc.split(':')[0]
        
        # Check for IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, host):
            return True
        
        # Check for IPv6
        if ':' in host and '[' in host:
            return True
        
        return False
    
    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a URL shortener"""
        return domain in self.URL_SHORTENERS
    
    def _is_trusted_domain(self, domain: str) -> bool:
        """Check if domain is trusted"""
        return domain in self.TRUSTED_DOMAINS
    
    def _check_suspicious_keywords(self, url: str) -> List[str]:
        """Check for suspicious keywords in URL"""
        found = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url:
                found.append(keyword)
        return found
    
    def get_safety_recommendation(self, risk_score: float) -> str:
        """
        Get safety recommendation based on risk score
        
        Args:
            risk_score: Calculated risk score
            
        Returns:
            Safety recommendation string
        """
        if risk_score >= 75:
            return "DANGER: Do not click this link. High probability of phishing or malware."
        elif risk_score >= 50:
            return "WARNING: This link shows multiple suspicious indicators. Avoid clicking unless you trust the source."
        elif risk_score >= 25:
            return "CAUTION: Some risk factors detected. Verify the source before clicking."
        else:
            return "This link appears relatively safe, but always exercise caution with unfamiliar URLs."


# Example usage and testing
if __name__ == "__main__":
    checker = URLChecker()
    
    # Test URLs
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login",
        "http://secure-banking-verify.tk/account",
        "https://bit.ly/abc123",
        "http://amaz0n-security-alert.com/verify-account?id=12345"
    ]
    
    print("URL Security Analysis Test\n" + "="*50)
    for url in test_urls:
        result = checker.analyze_url(url)
        print(f"\nURL: {result['url']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Suspicious: {result['is_suspicious']}")
        print(f"Risk Factors: {', '.join(result['risk_factors']) if result['risk_factors'] else 'None'}")
