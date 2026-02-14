"""
Flask Web Application for ScamShield
AI-Powered Scam Call Detection and Prevention System
"""

from flask import Flask, render_template, request, jsonify, session
import os
import sys
from datetime import datetime
import logging

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.call_analyzer import CallAnalyzer
from src.sms_analyzer import SMSAnalyzer
from src.risk_engine import RiskEngine
from src.database import Database
from src.utils import format_phone_number, get_risk_color, sanitize_text

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'scamshield_secret_key_2024'  # Change in production

# Initialize components
call_analyzer = CallAnalyzer(model_path='models/call_model.pkl')
sms_analyzer = SMSAnalyzer(model_path='models/sms_model.pkl')
risk_engine = RiskEngine()
db = Database('scamshield.db')

# App configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size


@app.route('/')
def index():
    """Home page"""
    try:
        # Get recent statistics
        stats = db.get_statistics(days=30)
        risk_dist = db.get_risk_distribution()
        
        # Calculate summary stats
        total_analyzed = sum(s.get('total', 0) for s in stats.values())
        total_scams = sum(s.get('scams', 0) for s in stats.values())
        
        return render_template('index.html',
                             total_analyzed=total_analyzed,
                             total_scams=total_scams,
                             stats=stats,
                             risk_distribution=risk_dist)
    except Exception as e:
        logger.error(f"Error in index: {e}")
        return render_template('index.html',
                             total_analyzed=0,
                             total_scams=0,
                             stats={},
                             risk_distribution={})


@app.route('/analyze_call')
def analyze_call_page():
    """Call analysis page"""
    return render_template('analyze_call.html')


@app.route('/analyze_sms')
def analyze_sms_page():
    """SMS analysis page"""
    return render_template('analyze_sms.html')


@app.route('/api/analyze_call', methods=['POST'])
def api_analyze_call():
    """API endpoint for call analysis"""
    try:
        data = request.get_json()
        
        # Validate input
        phone_number = data.get('phone_number', '').strip()
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400
        
        # Sanitize input
        phone_number = sanitize_text(phone_number)
        
        # Extract parameters
        duration = int(data.get('duration', 30))
        call_frequency = int(data.get('call_frequency', 1))
        is_unknown = data.get('is_unknown', True)
        time_of_day = data.get('time_of_day', 'business_hours')
        
        # Analyze call
        result = call_analyzer.analyze_call(
            phone_number=phone_number,
            duration=duration,
            call_frequency=call_frequency,
            is_unknown=is_unknown,
            time_of_day=time_of_day
        )
        
        # Save to database
        db.save_call_analysis(result)
        
        # Generate awareness alert
        assessment = risk_engine.assess_overall_risk(call_result=result)
        alert = risk_engine.generate_awareness_alert(assessment)
        
        # Format response
        response = {
            'success': True,
            'analysis': result,
            'alert': alert,
            'formatted_number': format_phone_number(phone_number)
        }
        
        return jsonify(response)
        
    except ValueError as e:
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Error analyzing call: {e}")
        return jsonify({'error': 'An error occurred during analysis'}), 500


@app.route('/api/analyze_sms', methods=['POST'])
def api_analyze_sms():
    """API endpoint for SMS analysis"""
    try:
        data = request.get_json()
        
        # Validate input
        message_text = data.get('message_text', '').strip()
        if not message_text:
            return jsonify({'error': 'Message text is required'}), 400
        
        if len(message_text) > 5000:
            return jsonify({'error': 'Message text too long (max 5000 characters)'}), 400
        
        # Sanitize input
        message_text = sanitize_text(message_text)
        sender = sanitize_text(data.get('sender', 'Unknown'))
        
        # Analyze SMS
        result = sms_analyzer.analyze_message(
            message_text=message_text,
            sender=sender
        )
        
        # Save to database
        db.save_sms_analysis(result)
        
        # Generate awareness alert
        assessment = risk_engine.assess_overall_risk(sms_result=result)
        alert = risk_engine.generate_awareness_alert(assessment)
        
        # Format response
        response = {
            'success': True,
            'analysis': result,
            'alert': alert
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing SMS: {e}")
        return jsonify({'error': 'An error occurred during analysis'}), 500


@app.route('/report')
def report_page():
    """Risk report page"""
    try:
        # Get recent analyses
        recent_calls = db.get_recent_analyses('call', limit=10)
        recent_sms = db.get_recent_analyses('sms', limit=10)
        
        # Get statistics
        stats = db.get_statistics(days=30)
        risk_dist = db.get_risk_distribution()
        
        return render_template('result.html',
                             recent_calls=recent_calls,
                             recent_sms=recent_sms,
                             stats=stats,
                             risk_distribution=risk_dist)
    except Exception as e:
        logger.error(f"Error in report: {e}")
        return render_template('result.html',
                             recent_calls=[],
                             recent_sms=[],
                             stats={},
                             risk_distribution={})


@app.route('/api/statistics')
def api_statistics():
    """API endpoint for statistics"""
    try:
        days = int(request.args.get('days', 30))
        stats = db.get_statistics(days=days)
        risk_dist = db.get_risk_distribution()
        
        return jsonify({
            'success': True,
            'stats': stats,
            'risk_distribution': risk_dist
        })
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': 'Could not retrieve statistics'}), 500


@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('index.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


# Custom template filters
@app.template_filter('format_datetime')
def format_datetime(value):
    """Format datetime for display"""
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return value
    return value


@app.template_filter('format_percentage')
def format_percentage(value):
    """Format percentage for display"""
    try:
        return f"{float(value):.1f}%"
    except:
        return "0.0%"


if __name__ == '__main__':
    # Ensure database is initialized
    db.init_database()
    
    # Print startup message
    print("\n" + "="*60)
    print("🛡️  ScamShield - AI-Powered Scam Detection System")
    print("="*60)
    print(f"Starting server...")
    print(f"Dashboard will be available at: http://localhost:5000")
    print(f"Press CTRL+C to stop the server")
    print("="*60 + "\n")
    
    # Run app
    app.run(host='0.0.0.0', port=5000, debug=True)
