"""
Utility functions for ScamShield
Provides common helper functions for the scam detection system
"""

import re
import logging
from datetime import datetime
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text using regex
    
    Args:
        text: Input text that may contain URLs
        
    Returns:
        List of extracted URLs
    """
    # Regex pattern to match URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    
    # Also check for URLs without http/https
    domain_pattern = r'(?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?'
    potential_urls = re.findall(domain_pattern, text)
    
    for url in potential_urls:
        if url not in urls and not any(url in u for u in urls):
            urls.append(url if url.startswith('http') else f'http://{url}')
    
    return urls


def calculate_risk_score(predictions: Dict[str, float], weights: Dict[str, float] = None) -> float:
    """
    Calculate overall risk score from multiple prediction sources
    
    Args:
        predictions: Dictionary of prediction probabilities
        weights: Optional weights for each prediction source
        
    Returns:
        Risk score between 0 and 100
    """
    if weights is None:
        weights = {key: 1.0 for key in predictions.keys()}
    
    total_weight = sum(weights.values())
    weighted_score = sum(predictions[key] * weights.get(key, 1.0) for key in predictions.keys())
    
    risk_score = (weighted_score / total_weight) * 100
    return min(100, max(0, risk_score))


def get_risk_level(risk_score: float) -> str:
    """
    Convert numeric risk score to categorical risk level
    
    Args:
        risk_score: Numeric risk score (0-100)
        
    Returns:
        Risk level string
    """
    if risk_score >= 75:
        return "CRITICAL"
    elif risk_score >= 50:
        return "HIGH"
    elif risk_score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


def get_risk_color(risk_level: str) -> str:
    """
    Get color code for risk level
    
    Args:
        risk_level: Risk level string
        
    Returns:
        Hex color code
    """
    colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745"
    }
    return colors.get(risk_level, "#6c757d")


def format_phone_number(phone: str) -> str:
    """
    Format phone number for display
    
    Args:
        phone: Raw phone number string
        
    Returns:
        Formatted phone number
    """
    # Remove non-digit characters
    digits = re.sub(r'\D', '', phone)
    
    if len(digits) == 10:
        return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    elif len(digits) == 11:
        return f"+{digits[0]} ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
    else:
        return phone


def validate_input(data: Dict[str, Any], required_fields: List[str]) -> tuple:
    """
    Validate input data for required fields
    
    Args:
        data: Input data dictionary
        required_fields: List of required field names
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    missing_fields = [field for field in required_fields if field not in data or data[field] is None]
    
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    return True, None


def sanitize_text(text: str) -> str:
    """
    Sanitize text input to prevent injection attacks
    
    Args:
        text: Input text
        
    Returns:
        Sanitized text
    """
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>\'\";&|`$]', '', text)
    return sanitized.strip()


def get_timestamp() -> str:
    """
    Get current timestamp in ISO format
    
    Returns:
        Timestamp string
    """
    return datetime.now().isoformat()


def log_analysis(analysis_type: str, result: Dict[str, Any]) -> None:
    """
    Log analysis result
    
    Args:
        analysis_type: Type of analysis (call/sms)
        result: Analysis result dictionary
    """
    logger.info(f"{analysis_type.upper()} Analysis - Risk: {result.get('risk_level', 'UNKNOWN')}, "
                f"Score: {result.get('risk_score', 0):.2f}")


# Scam awareness tips
SCAM_TIPS = {
    "general": [
        "Never share personal information over the phone unless you initiated the call",
        "Be suspicious of urgent requests for money or information",
        "Verify caller identity through official channels",
        "Don't click on links from unknown sources",
        "Enable two-factor authentication on all accounts"
    ],
    "call": [
        "Legitimate organizations won't ask for passwords over the phone",
        "Government agencies don't demand immediate payment by gift cards or wire transfer",
        "If a caller claims to be from a company, hang up and call the official number",
        "Be wary of robocalls claiming you've won a prize"
    ],
    "sms": [
        "Don't click on shortened URLs from unknown numbers",
        "Banks will never ask you to verify account details via SMS link",
        "Check the sender's number - legitimate companies use consistent numbers",
        "Look for spelling errors and grammatical mistakes in messages"
    ]
}


def get_safety_tips(category: str = "general") -> List[str]:
    """
    Get safety tips for scam prevention
    
    Args:
        category: Category of tips (general/call/sms)
        
    Returns:
        List of safety tips
    """
    return SCAM_TIPS.get(category, SCAM_TIPS["general"])
