"""
Call Pattern Analyzer Module for ScamShield
Detects scam calls based on call metadata patterns
"""

import joblib
import numpy as np
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class CallAnalyzer:
    """Call pattern analyzer for scam detection"""
    
    # Country codes commonly used in scam calls
    RISKY_COUNTRY_CODES = [
        '+375',  # Belarus
        '+371',  # Latvia
        '+254',  # Kenya
        '+234',  # Nigeria
        '+233',  # Ghana
        '+880',  # Bangladesh
        '+92',   # Pakistan
        '+62',   # Indonesia
        '+84',   # Vietnam
    ]
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize call analyzer
        
        Args:
            model_path: Path to trained model (if available)
        """
        self.model = None
        
        if model_path:
            try:
                self.model = joblib.load(model_path)
                logger.info(f"Loaded call model from {model_path}")
            except Exception as e:
                logger.warning(f"Could not load model: {e}. Using rule-based analysis.")
    
    def analyze_call(self, 
                     phone_number: str,
                     duration: int,
                     call_frequency: int = 1,
                     is_unknown: bool = True,
                     time_of_day: str = "business_hours") -> Dict[str, Any]:
        """
        Analyze call for scam indicators
        
        Args:
            phone_number: The calling phone number
            duration: Call duration in seconds
            call_frequency: Number of calls from this number in past 24h
            is_unknown: Whether number is in contacts
            time_of_day: Time category (business_hours, evening, night, early_morning)
            
        Returns:
            Analysis result dictionary
        """
        # Extract features
        features = self._extract_features(
            phone_number, duration, call_frequency, is_unknown, time_of_day
        )
        
        # Calculate risk score
        if self.model:
            risk_probability = self._predict_with_model(features)
            risk_score = risk_probability * 100
        else:
            risk_score = self._calculate_rule_based_score(features)
        
        # Determine if call is scam
        is_scam = risk_score >= 50
        
        # Get risk level
        risk_level = self._get_risk_level(risk_score)
        
        # Generate explanation
        explanation = self._generate_explanation(features)
        
        # Get recommendations
        recommendations = self._get_recommendations(risk_level, features)
        
        return {
            'phone_number': phone_number,
            'duration': duration,
            'call_frequency': call_frequency,
            'is_unknown': is_unknown,
            'is_international': features['is_international'],
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'is_scam': is_scam,
            'features': features,
            'explanation': explanation,
            'recommendations': recommendations
        }
    
    def _extract_features(self, phone_number: str, duration: int, 
                         call_frequency: int, is_unknown: bool, 
                         time_of_day: str) -> Dict[str, Any]:
        """Extract features from call data"""
        
        # Clean phone number
        clean_number = phone_number.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        
        # Check if international
        is_international = clean_number.startswith('+') or (len(clean_number) > 10 and clean_number.startswith('00'))
        
        # Check if from risky country
        is_risky_country = any(clean_number.startswith(code) for code in self.RISKY_COUNTRY_CODES)
        
        # Extract country code if international
        country_code = None
        if is_international:
            if clean_number.startswith('+'):
                country_code = clean_number[1:4]
            elif clean_number.startswith('00'):
                country_code = clean_number[2:5]
        
        # Pattern analysis
        has_repeated_digits = self._check_repeated_digits(clean_number)
        has_sequential_digits = self._check_sequential_digits(clean_number)
        
        # Time risk
        time_risk_map = {
            'early_morning': 3,  # 12am-6am (high risk)
            'business_hours': 1,  # 9am-5pm (low risk)
            'evening': 2,        # 5pm-9pm (medium risk)
            'night': 3           # 9pm-12am (high risk)
        }
        time_risk = time_risk_map.get(time_of_day, 2)
        
        features = {
            # Call metadata
            'duration': duration,
            'call_frequency': call_frequency,
            'is_unknown': 1 if is_unknown else 0,
            'is_international': 1 if is_international else 0,
            'is_risky_country': 1 if is_risky_country else 0,
            
            # Duration patterns
            'very_short_call': 1 if duration < 10 else 0,  # < 10 seconds
            'short_call': 1 if 10 <= duration < 30 else 0,  # 10-30 seconds
            'normal_call': 1 if 30 <= duration < 300 else 0,  # 30s-5min
            'long_call': 1 if duration >= 300 else 0,  # > 5 minutes
            
            # Frequency patterns
            'single_call': 1 if call_frequency == 1 else 0,
            'repeated_calls': 1 if call_frequency > 1 else 0,
            'excessive_calls': 1 if call_frequency > 5 else 0,
            
            # Number patterns
            'has_repeated_digits': 1 if has_repeated_digits else 0,
            'has_sequential_digits': 1 if has_sequential_digits else 0,
            'number_length': len(clean_number),
            
            # Time factor
            'time_risk': time_risk,
            'suspicious_time': 1 if time_risk >= 3 else 0,
            
            # Combined risk factors
            'unknown_and_international': 1 if (is_unknown and is_international) else 0,
            'short_and_repeated': 1 if (duration < 30 and call_frequency > 1) else 0,
        }
        
        return features
    
    def _calculate_rule_based_score(self, features: Dict[str, Any]) -> float:
        """Calculate risk score using rule-based approach"""
        score = 0
        
        # Base score for unknown numbers
        if features['is_unknown']:
            score += 20
        
        # International calls from unknown numbers
        if features['unknown_and_international']:
            score += 25
        
        # Risky country codes
        if features['is_risky_country']:
            score += 30
        
        # Very short calls (robocalls, screening)
        if features['very_short_call']:
            score += 15
        
        # Excessive call frequency (harassment pattern)
        if features['excessive_calls']:
            score += 25
        elif features['repeated_calls']:
            score += 10
        
        # Suspicious number patterns
        if features['has_repeated_digits']:
            score += 10
        
        if features['has_sequential_digits']:
            score += 10
        
        # Suspicious timing
        if features['suspicious_time']:
            score += 15
        
        # Combined risk factors
        if features['short_and_repeated']:
            score += 20
        
        # Reduce score for normal patterns
        if features['normal_call'] and not features['is_unknown']:
            score -= 15
        
        if features['long_call']:
            score -= 10  # Scammers usually keep calls short
        
        return min(100, max(0, score))
    
    def _predict_with_model(self, features: Dict[str, Any]) -> float:
        """Use ML model to predict scam probability"""
        try:
            # Convert features to array
            feature_array = np.array([[
                features['duration'],
                features['call_frequency'],
                features['is_unknown'],
                features['is_international'],
                features['is_risky_country'],
                features['very_short_call'],
                features['repeated_calls'],
                features['excessive_calls'],
                features['has_repeated_digits'],
                features['has_sequential_digits'],
                features['time_risk'],
                features['unknown_and_international'],
                features['short_and_repeated']
            ]])
            
            # Get prediction
            if hasattr(self.model, 'predict_proba'):
                prob = self.model.predict_proba(feature_array)[0][1]
            else:
                prob = self.model.predict(feature_array)[0]
            
            return float(prob)
        except Exception as e:
            logger.error(f"Model prediction error: {e}")
            return self._calculate_rule_based_score(features) / 100
    
    def _check_repeated_digits(self, number: str) -> bool:
        """Check if number has many repeated digits"""
        clean = number.replace('+', '')
        for digit in '0123456789':
            if clean.count(digit) >= 4:
                return True
        return False
    
    def _check_sequential_digits(self, number: str) -> bool:
        """Check if number has sequential digit patterns"""
        clean = number.replace('+', '')
        sequences = ['0123', '1234', '2345', '3456', '4567', '5678', '6789',
                    '3210', '4321', '5432', '6543', '7654', '8765', '9876']
        return any(seq in clean for seq in sequences)
    
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
    
    def _generate_explanation(self, features: Dict[str, Any]) -> List[str]:
        """Generate explanation for the risk assessment"""
        explanations = []
        
        if features['is_unknown']:
            explanations.append("Number is not in your contacts")
        
        if features['is_international']:
            explanations.append("International call")
        
        if features['is_risky_country']:
            explanations.append("Call originates from high-risk country")
        
        if features['very_short_call']:
            explanations.append("Very short call duration (possible robocall)")
        
        if features['excessive_calls']:
            explanations.append(f"Excessive call frequency ({features['call_frequency']} calls)")
        elif features['repeated_calls']:
            explanations.append(f"Multiple calls from this number ({features['call_frequency']} calls)")
        
        if features['has_repeated_digits']:
            explanations.append("Number contains repeated digit patterns")
        
        if features['has_sequential_digits']:
            explanations.append("Number contains sequential digits")
        
        if features['suspicious_time']:
            explanations.append("Call at unusual time (late night/early morning)")
        
        if not explanations:
            explanations.append("No significant risk indicators detected")
        
        return explanations
    
    def _get_recommendations(self, risk_level: str, features: Dict[str, Any]) -> List[str]:
        """Get safety recommendations based on risk level"""
        recommendations = []
        
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.append("Do NOT answer calls from this number")
            recommendations.append("Block this number immediately")
            recommendations.append("Do NOT call back")
            recommendations.append("Report to your phone carrier or FTC")
            
            if features['is_international']:
                recommendations.append("Enable international call blocking on your device")
        
        elif risk_level == "MEDIUM":
            recommendations.append("Exercise caution when answering")
            recommendations.append("Do not provide personal information")
            recommendations.append("Ask for caller credentials and verify independently")
            recommendations.append("Consider blocking if they call repeatedly")
        
        else:
            recommendations.append("Call appears relatively safe")
            recommendations.append("Still verify identity if they request sensitive information")
        
        recommendations.append("Never share passwords, PINs, or account numbers over the phone")
        recommendations.append("Legitimate organizations will not pressure you for immediate action")
        
        return recommendations


# Example usage
if __name__ == "__main__":
    analyzer = CallAnalyzer()
    
    # Test calls
    test_calls = [
        ("+234-555-1234", 8, 3, True, "night"),           # International, short, repeated
        ("555-123-4567", 120, 1, False, "business_hours"), # Known number, normal call
        ("888-888-8888", 15, 7, True, "early_morning"),   # Repeated digits, excessive
    ]
    
    print("Call Security Analysis Test\n" + "="*50)
    for number, duration, frequency, unknown, time in test_calls:
        result = analyzer.analyze_call(number, duration, frequency, unknown, time)
        print(f"\nNumber: {number}")
        print(f"Duration: {duration}s, Frequency: {frequency}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Explanation: {', '.join(result['explanation'][:2])}")
