# System Architecture

## Overview

ScamShield is built on a modular, three-tier architecture consisting of:
1. **Presentation Layer** - Web interface (HTML/CSS/JavaScript)
2. **Application Layer** - Flask backend with ML models
3. **Data Layer** - SQLite database

This document provides detailed technical specifications of each component.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER                       │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              Web Browser (Client)                      │  │
│  │                                                         │  │
│  │  [Home Page]  [Call Analysis]  [SMS Analysis]  [Reports│  │
│  │                                                         │  │
│  │  • HTML5 Templates                                     │  │
│  │  • CSS3 Styling                                        │  │
│  │  • Vanilla JavaScript (Fetch API)                     │  │
│  │  • Responsive Design                                   │  │
│  └─────────────────────┬──────────────────────────────────┘  │
└────────────────────────┼─────────────────────────────────────┘
                         │ HTTP/HTTPS
                         │ REST API (JSON)
┌────────────────────────▼─────────────────────────────────────┐
│                     APPLICATION LAYER                         │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Flask Web Framework                      │ │
│  │                                                          │ │
│  │  app.py: Main application                              │ │
│  │  • Route handlers                                      │ │
│  │  • Request validation                                  │ │
│  │  • Response formatting                                 │ │
│  │  • Error handling                                      │ │
│  └───────┬──────────────────────┬──────────────────────────┘ │
│          │                      │                            │
│  ┌───────▼──────────┐  ┌────────▼────────┐                 │
│  │ Call Analyzer    │  │  SMS Analyzer   │                 │
│  │                  │  │                 │                 │
│  │ • Feature        │  │ • Text analysis │                 │
│  │   extraction     │  │ • Keyword       │                 │
│  │ • Pattern        │  │   matching      │                 │
│  │   detection      │  │ • URL extraction│                 │
│  │ • ML prediction  │  │ • ML prediction │                 │
│  └───────┬──────────┘  └────────┬────────┘                 │
│          │                      │                            │
│          │              ┌───────▼────────┐                  │
│          │              │  URL Checker   │                  │
│          │              │                │                  │
│          │              │ • Domain parse │                  │
│          │              │ • TLD check    │                  │
│          │              │ • Risk score   │                  │
│          │              └───────┬────────┘                  │
│          │                      │                            │
│  ┌───────▼──────────────────────▼────────┐                 │
│  │         Machine Learning Models        │                 │
│  │                                         │                 │
│  │  call_model.pkl    sms_model.pkl      │                 │
│  │  (Random Forest)   (Logistic Reg)     │                 │
│  │  95KB              1KB                 │                 │
│  └───────┬─────────────────────────────────┘                 │
│          │                                                    │
│  ┌───────▼─────────────────────────────────┐                │
│  │          Risk Engine                     │                │
│  │                                           │                │
│  │  • Score calculation                     │                │
│  │  • Risk level determination              │                │
│  │  • Alert generation                      │                │
│  │  • Recommendation creation               │                │
│  └───────┬───────────────────────────────────┘                │
│          │                                                    │
│  ┌───────▼───────────────────────────────────┐              │
│  │          Database Module                   │              │
│  │                                             │              │
│  │  • Analysis storage                        │              │
│  │  • Statistics calculation                  │              │
│  │  • History retrieval                       │              │
│  └───────┬─────────────────────────────────────┘              │
└──────────┼────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────┐
│                         DATA LAYER                           │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               SQLite Database                        │   │
│  │              (scamshield.db)                         │   │
│  │                                                       │   │
│  │  Tables:                                             │   │
│  │  • call_analysis (call records)                     │   │
│  │  • sms_analysis (SMS records)                       │   │
│  │  • risk_statistics (aggregated stats)              │   │
│  │                                                       │   │
│  │  Features:                                           │   │
│  │  • Local storage (no cloud)                         │   │
│  │  • Zero-config setup                                │   │
│  │  • Efficient querying                               │   │
│  │  • Transaction support                              │   │
│  └────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

## Component Specifications

### 1. Presentation Layer

#### 1.1 Web Interface
**Technology**: HTML5, CSS3, Vanilla JavaScript
**Purpose**: User interaction and visualization

**Pages**:
- `index.html` - Homepage with dashboard
- `analyze_call.html` - Call analysis interface
- `analyze_sms.html` - SMS analysis interface
- `result.html` - Analysis reports

**Features**:
- Responsive design (mobile-friendly)
- Progressive enhancement
- Accessible (WCAG 2.1 guidelines)
- No external dependencies

**Communication**:
- REST API calls via Fetch API
- JSON request/response format
- AJAX for async operations
- Error handling and loading states

### 2. Application Layer

#### 2.1 Flask Web Framework
**File**: `src/app.py`
**Version**: 3.0.0
**Purpose**: HTTP server and request routing

**Key Routes**:
```python
GET  /                   # Homepage
GET  /analyze_call       # Call analysis page
GET  /analyze_sms        # SMS analysis page
GET  /report             # Reports page
POST /api/analyze_call   # Call analysis API
POST /api/analyze_sms    # SMS analysis API
GET  /api/statistics     # Statistics API
```

**Configuration**:
```python
app.config = {
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB
    'SECRET_KEY': 'scamshield_secret_key',
    'DEBUG': True  # Disable in production
}
```

**Security Features**:
- Input sanitization
- CSRF protection (via Flask forms if extended)
- XSS prevention (Jinja2 autoescaping)
- SQL injection prevention (parameterized queries)

#### 2.2 Call Analyzer
**File**: `src/call_analyzer.py`
**Dependencies**: numpy, joblib
**Purpose**: Analyze call patterns for scam indicators

**Class**: `CallAnalyzer`

**Methods**:
```python
def __init__(model_path=None)
    # Initialize analyzer with optional ML model

def analyze_call(phone_number, duration, call_frequency, 
                 is_unknown, time_of_day) -> dict
    # Analyze call and return risk assessment

def _extract_features(...)
    # Extract 13 features from call data

def _calculate_rule_based_score(features) -> float
    # Calculate risk score using rules

def _predict_with_model(features) -> float
    # Use ML model for prediction
```

**Features Extracted**:
1. Duration-based (4 features)
2. Frequency-based (3 features)
3. Number patterns (2 features)
4. Timing-based (1 feature)
5. International indicators (2 features)
6. Combined risk factors (2 features)

**Output**:
```python
{
    'phone_number': str,
    'risk_score': float (0-100),
    'risk_level': str (LOW/MEDIUM/HIGH/CRITICAL),
    'is_scam': bool,
    'features': dict,
    'explanation': list[str],
    'recommendations': list[str]
}
```

#### 2.3 SMS Analyzer
**File**: `src/sms_analyzer.py`
**Dependencies**: numpy, joblib, re
**Purpose**: Analyze SMS content for phishing/scam

**Class**: `SMSAnalyzer`

**Methods**:
```python
def __init__(model_path=None)
    # Initialize analyzer

def analyze_message(message_text, sender) -> dict
    # Analyze SMS and return assessment

def _extract_features(message_text, sender)
    # Extract 14 features from message

def _calculate_rule_based_score(features, text) -> float
    # Calculate risk using rules

def _predict_with_model(features) -> float
    # Use ML model
```

**Features Extracted**:
1. Text characteristics (7 features)
2. Content patterns (7 features)
3. URL presence and risk (2 features)

**Scam Keyword Categories**:
- Urgency indicators (8 keywords)
- Financial terms (10 keywords)
- Threats (7 keywords)
- Request terms (10 keywords)
- Too-good-to-be-true (7 keywords)
- Impersonation (7 keywords)

#### 2.4 URL Checker
**File**: `src/url_checker.py`
**Dependencies**: tldextract, urllib
**Purpose**: Verify URL security

**Class**: `URLChecker`

**Methods**:
```python
def analyze_url(url) -> dict
    # Comprehensive URL analysis

def analyze_multiple_urls(urls) -> list[dict]
    # Batch URL analysis

def get_safety_recommendation(risk_score) -> str
    # Get human-readable recommendation
```

**Analysis Checks** (14 total):
1. IP address detection
2. HTTPS verification
3. URL shortener detection
4. Domain reputation
5. TLD risk assessment
6. Suspicious keywords
7. Domain length
8. Subdomain count
9. Special character detection
10. Hyphen analysis
11. Digit presence
12. URL path length
13. Query parameter count
14. Port number check

**Risk Scoring**:
```python
risk_score = sum([
    ip_address ? 30 : 0,
    not_https ? 15 : 0,
    url_shortener ? 25 : 0,
    suspicious_keywords ? 10 * count : 0,
    risky_tld ? 25 : 0,
    # ... more checks
])
```

#### 2.5 Machine Learning Models

##### Call Model
**Type**: RandomForestClassifier
**File**: `models/call_model.pkl`
**Size**: ~95KB
**Training**: 79 samples, 20 test samples

**Hyperparameters**:
```python
RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=42
)
```

**Performance**:
- Accuracy: 100% (on test set)
- AUC-ROC: 1.0
- Precision: 1.0
- Recall: 1.0

**Top Features by Importance**:
1. Duration (30%)
2. Is unknown (19%)
3. Short and repeated (14%)
4. Call frequency (13%)
5. Time risk (11%)

##### SMS Model
**Type**: LogisticRegression (after comparison)
**File**: `models/sms_model.pkl`
**Size**: ~1KB
**Training**: 72 samples, 18 test samples

**Hyperparameters**:
```python
LogisticRegression(
    max_iter=1000,
    class_weight='balanced',
    random_state=42
)
```

**Performance**:
- Accuracy: 100% (on test set)
- AUC-ROC: 1.0
- Precision: 1.0
- Recall: 1.0

**Top Features by Coefficient**:
1. Requests action (1.28)
2. Scam keyword count (1.10)
3. URL count (0.62)
4. Mentions account (0.58)
5. Exclamation count (0.55)

#### 2.6 Risk Engine
**File**: `src/risk_engine.py`
**Purpose**: Unified risk assessment

**Class**: `RiskEngine`

**Methods**:
```python
def assess_overall_risk(call_result, sms_result) -> dict
    # Combine multiple analysis sources

def generate_awareness_alert(risk_assessment) -> dict
    # Create user-friendly alert

def generate_risk_report(analyses) -> dict
    # Create statistical report

def get_risk_trend(historical_data, days) -> dict
    # Analyze trends over time
```

**Risk Calculation**:
```python
# For combined analysis
overall_score = (
    call_score * 0.45 +
    sms_score * 0.55    # SMS weighted slightly higher
)

# Risk levels
CRITICAL: >= 75
HIGH:     >= 50
MEDIUM:   >= 25
LOW:      < 25
```

#### 2.7 Database Module
**File**: `src/database.py`
**Technology**: SQLite3
**Purpose**: Data persistence

**Class**: `Database`

**Database Schema**:
```sql
-- Call analysis records
CREATE TABLE call_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT,
    duration INTEGER,
    call_frequency INTEGER,
    is_unknown INTEGER,
    is_international INTEGER,
    risk_score REAL,
    risk_level TEXT,
    is_scam INTEGER,
    timestamp TEXT,
    features TEXT  -- JSON
);

-- SMS analysis records
CREATE TABLE sms_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    message_text TEXT,
    has_url INTEGER,
    urls TEXT,  -- JSON array
    risk_score REAL,
    risk_level TEXT,
    is_scam INTEGER,
    timestamp TEXT,
    features TEXT  -- JSON
);

-- Aggregated statistics
CREATE TABLE risk_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_type TEXT,
    total_analyzed INTEGER,
    scam_detected INTEGER,
    date TEXT
);
```

**Methods**:
```python
def save_call_analysis(data) -> int
def save_sms_analysis(data) -> int
def get_recent_analyses(type, limit) -> list
def get_statistics(days) -> dict
def get_risk_distribution() -> dict
def update_statistics(type, is_scam)
def clear_old_records(days)
```

#### 2.8 Utility Module
**File**: `src/utils.py`
**Purpose**: Common helper functions

**Key Functions**:
```python
def extract_urls(text) -> list[str]
    # Extract URLs using regex

def calculate_risk_score(predictions, weights) -> float
    # Weighted risk calculation

def get_risk_level(score) -> str
    # Convert score to level

def get_risk_color(level) -> str
    # Get UI color code

def format_phone_number(phone) -> str
    # Format for display

def validate_input(data, required_fields) -> tuple
    # Input validation

def sanitize_text(text) -> str
    # Prevent injection attacks

def get_safety_tips(category) -> list[str]
    # Get relevant safety tips
```

### 3. Data Layer

#### 3.1 SQLite Database
**File**: `scamshield.db`
**Location**: Project root directory
**Size**: Variable (grows with usage)

**Characteristics**:
- Zero-configuration
- Serverless
- Self-contained
- Cross-platform
- ACID compliant

**Backup Strategy**:
- Periodic file backups
- Export to CSV for portability
- No cloud sync (privacy-first)

## Data Flow

### Call Analysis Data Flow
```
1. User Input (frontend)
   ↓
2. POST /api/analyze_call (Flask)
   ↓
3. Input validation & sanitization
   ↓
4. CallAnalyzer.analyze_call()
   ↓
5. Feature extraction
   ↓
6. ML model prediction
   ↓
7. Risk score calculation
   ↓
8. RiskEngine.assess_overall_risk()
   ↓
9. RiskEngine.generate_awareness_alert()
   ↓
10. Database.save_call_analysis()
   ↓
11. JSON response to frontend
   ↓
12. Display results to user
```

### SMS Analysis Data Flow
```
1. User Input (frontend)
   ↓
2. POST /api/analyze_sms (Flask)
   ↓
3. Input validation & sanitization
   ↓
4. SMSAnalyzer.analyze_message()
   ↓
5. Text feature extraction
   ↓
6. URL extraction
   ↓
7. For each URL: URLChecker.analyze_url()
   ↓
8. ML model prediction
   ↓
9. Combined risk score
   ↓
10. RiskEngine processing
   ↓
11. Database.save_sms_analysis()
   ↓
12. JSON response to frontend
   ↓
13. Display results with URL details
```

## Technology Stack

### Backend
- **Python**: 3.8+
- **Flask**: 3.0.0 (web framework)
- **scikit-learn**: 1.3.2 (ML)
- **pandas**: 2.1.3 (data manipulation)
- **numpy**: 1.26.2 (numerical computing)
- **joblib**: 1.3.2 (model persistence)
- **tldextract**: 5.1.1 (URL parsing)

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Modern styling, flexbox, grid
- **JavaScript (ES6+)**: Fetch API, async/await
- **No frameworks**: Vanilla JS for simplicity

### Database
- **SQLite3**: 3.x (bundled with Python)

### Development Tools
- **Git**: Version control
- **pip**: Package management
- **venv**: Virtual environments

## Deployment Architecture

### Local Development
```
User's Machine
  ├─ Python 3.8+ installed
  ├─ Virtual environment (venv)
  ├─ Dependencies (pip install)
  ├─ Flask development server
  │  └─ http://localhost:5000
  └─ SQLite database (local file)
```

### Production Deployment (Recommended)
```
Server (Linux)
  ├─ Python 3.8+
  ├─ Virtual environment
  ├─ WSGI Server (Gunicorn/uWSGI)
  ├─ Reverse Proxy (Nginx)
  ├─ SSL/TLS (Let's Encrypt)
  ├─ Firewall (UFW)
  └─ Process Manager (systemd)
```

**Example Production Stack**:
```
Internet
  ↓
Nginx (443)
  ↓ reverse proxy
Gunicorn (8000)
  ↓
Flask App
  ↓
SQLite DB
```

## Security Architecture

### Defense in Depth

#### Layer 1: Input Validation
- Type checking
- Range validation
- Format verification
- Required field checks

#### Layer 2: Input Sanitization
- Remove dangerous characters
- Escape HTML/SQL special chars
- Normalize encoding

#### Layer 3: Framework Security
- Flask's built-in protections
- Jinja2 autoescaping
- Werkzeug security utilities

#### Layer 4: Database Security
- Parameterized queries
- No dynamic SQL
- Least privilege access

#### Layer 5: Application Logic
- Risk-based detection
- Multiple validation layers
- Error handling

## Performance Characteristics

### Response Times (Average)
- Call analysis: 150ms
- SMS analysis: 200ms (with URLs: 300ms)
- Dashboard load: 100ms
- Database queries: 50ms

### Scalability
- **Concurrent Users**: 10-50 (Flask dev server)
- **With Gunicorn**: 100-500
- **Database**: SQLite handles millions of records
- **Memory Usage**: ~50MB base + 10MB per analysis

### Bottlenecks
1. ML model prediction (CPU-bound)
2. Multiple URL analysis (network I/O)
3. Database writes (disk I/O)

### Optimization Strategies
1. Model caching
2. Connection pooling
3. Async URL checking
4. Database indexing

## Monitoring and Logging

### Logging Levels
```python
DEBUG: Detailed diagnostic info
INFO: General informational messages
WARNING: Warning messages
ERROR: Error messages
CRITICAL: Critical issues
```

### Log Locations
- Application logs: `logs/scamshield.log`
- Error logs: `logs/error.log`
- Access logs: Flask/Gunicorn logs

### Metrics Tracked
- Total analyses performed
- Scams detected
- Average risk scores
- Response times
- Error rates

---

**Architecture Version**: 1.0
**Last Updated**: 2024
**Review Cycle**: Quarterly
