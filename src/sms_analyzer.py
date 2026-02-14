"""
SMS/MMS Analyzer Module for ScamShield
Detects phishing and scam patterns in SMS/MMS messages
"""

import re
import joblib
import numpy as np
from typing import Dict, List, Any, Optional
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.url_checker import URLChecker
from src.utils import extract_urls

logger = logging.getLogger(__name__)


class SMSAnalyzer:
    """SMS/MMS message analyzer for scam detection"""
    
    # Scam indicator keywords
    SCAM_KEYWORDS = [
        # Urgency indicators
        'urgent', 'immediately', 'act now', 'limited time', 'expires',
        'hurry', 'don\'t delay', 'last chance', 'final notice',
        
        # Financial/Account related
        'verify account', 'confirm identity', 'update payment', 'suspended',
        'unusual activity', 'unauthorized', 'blocked', 'locked',
        'refund', 'rebate', 'claim', 'prize', 'winner', 'congratulations',
        
        # Threats
        'legal action', 'arrest', 'warrant', 'law enforcement', 'suspend',
        'terminate', 'cancel', 'penalties',
        
        # Requests for information
        'click here', 'click link', 'confirm', 'verify', 'validate',
        'social security', 'ssn', 'password', 'pin', 'credit card',
        
        # Too good to be true
        'free', 'gift card', 'cash prize', 'selected', 'chosen',
        'thousands', 'million', 'inheritance',
        
        # Impersonation
        'bank', 'paypal', 'amazon', 'irs', 'tax', 'government',
        'federal', 'social security', 'medicare'
    ]
    
    # Legitimate message patterns (negative indicators)
    LEGITIMATE_KEYWORDS = [
        'unsubscribe', 'opt-out', 'terms and conditions', 'privacy policy'
    ]
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize SMS analyzer
        
        Args:
            model_path: Path to trained model (if available)
        """
        self.url_checker = URLChecker()
        self.model = None
        
        if model_path:
            try:
                self.model = joblib.load(model_path)
                logger.info(f"Loaded SMS model from {model_path}")
            except Exception as e:
                logger.warning(f"Could not load model: {e}. Using rule-based analysis.")
    
    def analyze_message(self, message_text: str, sender: str = "Unknown") -> Dict[str, Any]:
        """
        Analyze SMS/MMS message for scam indicators
        
        Args:
            message_text: The message text to analyze
            sender: Sender phone number or ID
            
        Returns:
            Analysis result dictionary
        """
        # Extract features
        features = self._extract_features(message_text, sender)
        
        # Check for URLs
        urls = extract_urls(message_text)
        url_analysis = []
        url_risk_scores = []
        
        if urls:
            features['has_urls'] = 1
            features['url_count'] = len(urls)
            
            # Analyze each URL
            for url in urls:
                url_result = self.url_checker.analyze_url(url)
                url_analysis.append(url_result)
                url_risk_scores.append(url_result['risk_score'])
            
            # Average URL risk
            features['avg_url_risk'] = np.mean(url_risk_scores) if url_risk_scores else 0
        else:
            features['has_urls'] = 0
            features['url_count'] = 0
            features['avg_url_risk'] = 0
        
        # Calculate risk score
        if self.model:
            # Use ML model prediction
            risk_probability = self._predict_with_model(features)
            risk_score = risk_probability * 100
        else:
            # Use rule-based scoring
            risk_score = self._calculate_rule_based_score(features, message_text)
        
        # Determine if message is scam
        is_scam = risk_score >= 50
        
        # Get risk level
        risk_level = self._get_risk_level(risk_score)
        
        # Generate explanation
        explanation = self._generate_explanation(features, url_analysis)
        
        # Get recommendations
        recommendations = self._get_recommendations(risk_level, features)
        
        return {
            'sender': sender,
            'message_text': message_text,
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'is_scam': is_scam,
            'features': features,
            'urls': urls,
            'url_analysis': url_analysis,
            'explanation': explanation,
            'recommendations': recommendations,
            'has_url': len(urls) > 0
        }
    
    def _extract_features(self, message_text: str, sender: str) -> Dict[str, Any]:
        """Extract features from message for analysis"""
        text_lower = message_text.lower()
        
        features = {
            # Message length features
            'length': len(message_text),
            'word_count': len(message_text.split()),
            
            # Character features
            'exclamation_count': message_text.count('!'),
            'question_count': message_text.count('?'),
            'uppercase_ratio': sum(1 for c in message_text if c.isupper()) / len(message_text) if message_text else 0,
            'digit_count': sum(1 for c in message_text if c.isdigit()),
            
            # Sender features
            'sender_is_numeric': sender.replace('+', '').replace('-', '').isdigit(),
            'sender_is_shortcode': len(sender.replace('+', '').replace('-', '')) <= 6,
            
            # Keyword features
            'scam_keyword_count': sum(1 for keyword in self.SCAM_KEYWORDS if keyword in text_lower),
            'legitimate_keyword_count': sum(1 for keyword in self.LEGITIMATE_KEYWORDS if keyword in text_lower),
            
            # Specific indicators
            'has_urgency': any(word in text_lower for word in ['urgent', 'immediately', 'now', 'hurry']),
            'requests_action': any(word in text_lower for word in ['click', 'call', 'reply', 'confirm', 'verify']),
            'mentions_money': any(word in text_lower for word in ['$', 'money', 'cash', 'prize', 'refund', 'payment']),
            'mentions_account': any(word in text_lower for word in ['account', 'bank', 'card', 'password']),
            'has_threat': any(word in text_lower for word in ['suspend', 'locked', 'blocked', 'arrest', 'legal']),
        }
        
        return features
    
    def _calculate_rule_based_score(self, features: Dict[str, Any], message_text: str) -> float:
        """Calculate risk score using rule-based approach"""
        score = 0
        
        # URL risk (weighted heavily)
        if features['has_urls']:
            score += features['avg_url_risk'] * 0.4
        
        # Scam keywords
        score += min(features['scam_keyword_count'] * 10, 30)
        
        # Urgency indicators
        if features['has_urgency']:
            score += 15
        
        # Action requests
        if features['requests_action']:
            score += 10
        
        # Money mentions
        if features['mentions_money']:
            score += 15
        
        # Account mentions
        if features['mentions_account']:
            score += 12
        
        # Threats
        if features['has_threat']:
            score += 20
        
        # Excessive punctuation
        if features['exclamation_count'] > 2:
            score += 10
        
        # High uppercase ratio
        if features['uppercase_ratio'] > 0.3:
            score += 10
        
        # Sender is shortcode (often used by scammers)
        if features['sender_is_shortcode'] and not features['legitimate_keyword_count']:
            score += 10
        
        # Reduce score for legitimate indicators
        if features['legitimate_keyword_count'] > 0:
            score -= 20
        
        return min(100, max(0, score))
    
    def _predict_with_model(self, features: Dict[str, Any]) -> float:
        """Use ML model to predict scam probability"""
        try:
            # Convert features to array in correct order
            feature_array = np.array([[
                features['length'],
                features['word_count'],
                features['exclamation_count'],
                features['question_count'],
                features['uppercase_ratio'],
                features['digit_count'],
                features['scam_keyword_count'],
                features['has_urls'],
                features['url_count'],
                features['has_urgency'],
                features['requests_action'],
                features['mentions_money'],
                features['mentions_account'],
                features['has_threat']
            ]])
            
            # Get prediction probability
            if hasattr(self.model, 'predict_proba'):
                prob = self.model.predict_proba(feature_array)[0][1]
            else:
                prob = self.model.predict(feature_array)[0]
            
            return float(prob)
        except Exception as e:
            logger.error(f"Model prediction error: {e}")
            return self._calculate_rule_based_score(features, "") / 100
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to level"""
        if risk_score >= 75:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_explanation(self, features: Dict[str, Any], url_analysis: List[Dict]) -> List[str]:
        """Generate explanation for the risk assessment"""
        explanations = []
        
        if features['scam_keyword_count'] > 3:
            explanations.append(f"Contains {features['scam_keyword_count']} common scam keywords")
        
        if features['has_urgency']:
            explanations.append("Uses urgent language to pressure immediate action")
        
        if features['has_threat']:
            explanations.append("Contains threatening language")
        
        if features['mentions_money'] or features['mentions_account']:
            explanations.append("Mentions financial or account information")
        
        if features['has_urls']:
            suspicious_urls = [u for u in url_analysis if u.get('is_suspicious', False)]
            if suspicious_urls:
                explanations.append(f"Contains {len(suspicious_urls)} suspicious URL(s)")
        
        if features['uppercase_ratio'] > 0.3:
            explanations.append("Excessive use of capital letters")
        
        if features['exclamation_count'] > 2:
            explanations.append("Excessive use of exclamation marks")
        
        if features['sender_is_shortcode']:
            explanations.append("Sent from a short code (common in scams)")
        
        if not explanations:
            explanations.append("No significant risk indicators detected")
        
        return explanations
    
    def _get_recommendations(self, risk_level: str, features: Dict[str, Any]) -> List[str]:
        """Get safety recommendations based on risk level"""
        recommendations = []
        
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.append("Do NOT click any links in this message")
            recommendations.append("Do NOT reply or provide any personal information")
            recommendations.append("Delete this message immediately")
            recommendations.append("Block the sender")
            
            if features['mentions_account']:
                recommendations.append("Contact your bank/service provider directly using official contact info")
        
        elif risk_level == "MEDIUM":
            recommendations.append("Exercise caution with this message")
            recommendations.append("Verify the sender through official channels")
            recommendations.append("Do not click links unless you can verify the source")
        
        else:
            recommendations.append("Message appears relatively safe")
            recommendations.append("Still verify sender if requesting sensitive information")
        
        recommendations.append("Never share passwords, PINs, or security codes via SMS")
        
        return recommendations


# Example usage
if __name__ == "__main__":
    analyzer = SMSAnalyzer()
    
    # Test messages
    test_messages = [
        ("Your bank account has been locked! Click here immediately to verify: http://bit.ly/bank123", "12345"),
        ("Hi, your package will be delivered tomorrow. Track: https://fedex.com/track/abc", "FedEx"),
        ("URGENT: You have won $10,000! Claim now at winner-prize.tk/claim?id=999", "88888")
    ]
    
    print("SMS Security Analysis Test\n" + "="*50)
    for message, sender in test_messages:
        result = analyzer.analyze_message(message, sender)
        print(f"\nSender: {sender}")
        print(f"Message: {message[:60]}...")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Explanation: {', '.join(result['explanation'][:2])}")
