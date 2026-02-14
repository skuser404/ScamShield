"""
Risk Engine Module for ScamShield
Provides unified risk assessment and awareness alerts
"""

from typing import Dict, Any, List
from src.utils import get_risk_level, get_risk_color, get_safety_tips
import logging

logger = logging.getLogger(__name__)


class RiskEngine:
    """Unified risk assessment and awareness engine"""
    
    def __init__(self):
        """Initialize risk engine"""
        self.risk_thresholds = {
            'CRITICAL': 75,
            'HIGH': 50,
            'MEDIUM': 25,
            'LOW': 0
        }
    
    def assess_overall_risk(self, call_result: Dict[str, Any] = None,
                           sms_result: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Assess overall risk from multiple sources
        
        Args:
            call_result: Call analysis result
            sms_result: SMS analysis result
            
        Returns:
            Unified risk assessment
        """
        risk_scores = []
        risk_sources = []
        all_explanations = []
        all_recommendations = []
        
        if call_result:
            risk_scores.append(call_result['risk_score'])
            risk_sources.append('call')
            all_explanations.extend([f"Call: {exp}" for exp in call_result['explanation']])
            all_recommendations.extend(call_result['recommendations'])
        
        if sms_result:
            risk_scores.append(sms_result['risk_score'])
            risk_sources.append('sms')
            all_explanations.extend([f"SMS: {exp}" for exp in sms_result['explanation']])
            all_recommendations.extend(sms_result['recommendations'])
        
        if not risk_scores:
            return {
                'overall_risk_score': 0,
                'risk_level': 'LOW',
                'risk_sources': [],
                'explanation': [],
                'recommendations': []
            }
        
        # Calculate weighted average (SMS gets slightly higher weight due to URL analysis)
        if len(risk_scores) == 2:
            overall_score = (risk_scores[0] * 0.45 + risk_scores[1] * 0.55)
        else:
            overall_score = sum(risk_scores) / len(risk_scores)
        
        risk_level = get_risk_level(overall_score)
        
        # Remove duplicate recommendations
        unique_recommendations = list(dict.fromkeys(all_recommendations))
        
        return {
            'overall_risk_score': round(overall_score, 2),
            'risk_level': risk_level,
            'risk_color': get_risk_color(risk_level),
            'risk_sources': risk_sources,
            'explanation': all_explanations,
            'recommendations': unique_recommendations[:8],  # Top 8 recommendations
            'call_analysis': call_result,
            'sms_analysis': sms_result
        }
    
    def generate_awareness_alert(self, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate user awareness alert with educational content
        
        Args:
            risk_assessment: Risk assessment result
            
        Returns:
            Awareness alert dictionary
        """
        risk_level = risk_assessment['risk_level']
        risk_score = risk_assessment['overall_risk_score']
        
        # Generate alert message
        alert_messages = {
            'CRITICAL': {
                'title': '🚨 CRITICAL THREAT DETECTED',
                'message': 'This communication shows strong indicators of a scam. DO NOT ENGAGE.',
                'icon': '⛔',
                'action': 'BLOCK AND REPORT'
            },
            'HIGH': {
                'title': '⚠️ HIGH RISK WARNING',
                'message': 'Multiple scam indicators detected. Exercise extreme caution.',
                'icon': '🛑',
                'action': 'DO NOT RESPOND'
            },
            'MEDIUM': {
                'title': '⚡ MEDIUM RISK ALERT',
                'message': 'Some suspicious patterns detected. Verify before taking action.',
                'icon': '⚠️',
                'action': 'VERIFY SOURCE'
            },
            'LOW': {
                'title': '✅ LOW RISK',
                'message': 'No significant threats detected, but remain vigilant.',
                'icon': '🛡️',
                'action': 'PROCEED WITH CAUTION'
            }
        }
        
        alert = alert_messages.get(risk_level, alert_messages['MEDIUM'])
        
        # Generate educational content
        education = self._generate_educational_content(risk_assessment)
        
        # Get relevant safety tips
        if 'sms' in risk_assessment['risk_sources']:
            safety_tips = get_safety_tips('sms')
        elif 'call' in risk_assessment['risk_sources']:
            safety_tips = get_safety_tips('call')
        else:
            safety_tips = get_safety_tips('general')
        
        return {
            'alert_level': risk_level,
            'title': alert['title'],
            'message': alert['message'],
            'icon': alert['icon'],
            'recommended_action': alert['action'],
            'risk_score': risk_score,
            'risk_percentage': f"{risk_score}%",
            'explanation': risk_assessment['explanation'],
            'recommendations': risk_assessment['recommendations'],
            'educational_content': education,
            'safety_tips': safety_tips[:5],  # Top 5 tips
            'visual_indicators': self._get_visual_indicators(risk_level)
        }
    
    def _generate_educational_content(self, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate educational content about detected threats"""
        risk_sources = risk_assessment['risk_sources']
        
        content = {
            'what_we_found': [],
            'why_its_risky': [],
            'how_scams_work': []
        }
        
        # What we found
        if 'call' in risk_sources:
            call_data = risk_assessment.get('call_analysis', {})
            if call_data.get('is_international'):
                content['what_we_found'].append("International call from unknown number")
            if call_data.get('features', {}).get('very_short_call'):
                content['what_we_found'].append("Suspiciously short call duration")
            if call_data.get('features', {}).get('excessive_calls'):
                content['what_we_found'].append("Multiple calls from same number")
        
        if 'sms' in risk_sources:
            sms_data = risk_assessment.get('sms_analysis', {})
            if sms_data.get('has_url'):
                content['what_we_found'].append("Message contains URLs")
            if sms_data.get('features', {}).get('has_urgency'):
                content['what_we_found'].append("Urgent language designed to pressure action")
            if sms_data.get('features', {}).get('has_threat'):
                content['what_we_found'].append("Threatening language to create fear")
        
        # Why it's risky
        content['why_its_risky'] = [
            "Scammers use psychological tricks to bypass critical thinking",
            "Clicking malicious links can install malware or steal credentials",
            "Sharing personal info can lead to identity theft",
            "Financial losses can occur through fraudulent transactions"
        ]
        
        # How scams work
        content['how_scams_work'] = [
            "1. CREATE URGENCY: Scammers use time pressure to prevent verification",
            "2. IMPERSONATE AUTHORITY: Pretend to be banks, government, or companies",
            "3. REQUEST INFORMATION: Ask for passwords, PINs, or account details",
            "4. MANIPULATE EMOTIONS: Use fear, greed, or excitement to cloud judgment",
            "5. HIDE TRACKS: Use spoofed numbers, shortened URLs, or disposable accounts"
        ]
        
        return content
    
    def _get_visual_indicators(self, risk_level: str) -> Dict[str, str]:
        """Get visual indicators for UI display"""
        indicators = {
            'CRITICAL': {
                'color': '#dc3545',
                'background': '#f8d7da',
                'border': '#f5c6cb',
                'text_color': '#721c24',
                'progress_bar': 'danger'
            },
            'HIGH': {
                'color': '#fd7e14',
                'background': '#ffe5d0',
                'border': '#ffd3b8',
                'text_color': '#8b4513',
                'progress_bar': 'warning'
            },
            'MEDIUM': {
                'color': '#ffc107',
                'background': '#fff3cd',
                'border': '#ffeaa7',
                'text_color': '#856404',
                'progress_bar': 'warning'
            },
            'LOW': {
                'color': '#28a745',
                'background': '#d4edda',
                'border': '#c3e6cb',
                'text_color': '#155724',
                'progress_bar': 'success'
            }
        }
        
        return indicators.get(risk_level, indicators['MEDIUM'])
    
    def generate_risk_report(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive risk report from multiple analyses
        
        Args:
            analyses: List of analysis results
            
        Returns:
            Risk report dictionary
        """
        if not analyses:
            return {
                'total_analyses': 0,
                'scam_count': 0,
                'safe_count': 0,
                'risk_distribution': {},
                'average_risk_score': 0
            }
        
        total = len(analyses)
        scam_count = sum(1 for a in analyses if a.get('is_scam', False))
        safe_count = total - scam_count
        
        risk_distribution = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        total_risk_score = 0
        
        for analysis in analyses:
            risk_level = analysis.get('risk_level', 'LOW')
            if risk_level in risk_distribution:
                risk_distribution[risk_level] += 1
            total_risk_score += analysis.get('risk_score', 0)
        
        average_risk_score = total_risk_score / total if total > 0 else 0
        
        return {
            'total_analyses': total,
            'scam_count': scam_count,
            'safe_count': safe_count,
            'scam_percentage': (scam_count / total * 100) if total > 0 else 0,
            'risk_distribution': risk_distribution,
            'average_risk_score': round(average_risk_score, 2),
            'most_common_risk': max(risk_distribution, key=risk_distribution.get)
        }
    
    def get_risk_trend(self, historical_data: List[Dict[str, Any]], days: int = 7) -> Dict[str, Any]:
        """
        Analyze risk trends over time
        
        Args:
            historical_data: Historical analysis data
            days: Number of days to analyze
            
        Returns:
            Trend analysis
        """
        # This would analyze trends in the data
        # For now, return basic structure
        return {
            'trend': 'stable',  # or 'increasing', 'decreasing'
            'daily_averages': [],
            'peak_risk_day': None,
            'total_threats_blocked': len([d for d in historical_data if d.get('is_scam', False)])
        }


# Example usage
if __name__ == "__main__":
    engine = RiskEngine()
    
    # Simulate analysis results
    call_result = {
        'risk_score': 75,
        'risk_level': 'CRITICAL',
        'explanation': ['International call from unknown number', 'Very short duration'],
        'recommendations': ['Do not answer', 'Block number']
    }
    
    sms_result = {
        'risk_score': 85,
        'risk_level': 'CRITICAL',
        'explanation': ['Contains suspicious URL', 'Uses urgent language'],
        'recommendations': ['Do not click links', 'Delete message']
    }
    
    # Assess overall risk
    assessment = engine.assess_overall_risk(call_result, sms_result)
    print(f"Overall Risk Score: {assessment['overall_risk_score']}")
    print(f"Risk Level: {assessment['risk_level']}")
    
    # Generate awareness alert
    alert = engine.generate_awareness_alert(assessment)
    print(f"\n{alert['title']}")
    print(alert['message'])
