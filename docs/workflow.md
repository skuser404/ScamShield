# System Workflow

## Overview

This document describes the complete workflow of the ScamShield system, from user input to final result display.

## Workflow Diagrams

### 1. Call Analysis Workflow

```
START
  │
  ├─> User enters call details on web interface
  │   ├─ Phone number
  │   ├─ Call duration
  │   ├─ Call frequency
  │   ├─ Known/unknown status
  │   └─ Time of day
  │
  ├─> Frontend validates input
  │   ├─ Required fields present?
  │   ├─ Valid formats?
  │   └─ Reasonable values?
  │
  ├─> Send POST request to /api/analyze_call
  │
  ├─> Flask backend receives request
  │   └─ Sanitize inputs (prevent injection)
  │
  ├─> Call Analyzer processes data
  │   ├─ Extract features
  │   │   ├─ Is international?
  │   │   ├─ From risky country?
  │   │   ├─ Duration category
  │   │   ├─ Frequency pattern
  │   │   ├─ Number patterns (repeated/sequential digits)
  │   │   └─ Time risk score
  │   │
  │   ├─ Machine Learning Prediction
  │   │   ├─ Load trained Random Forest model
  │   │   ├─ Convert features to array
  │   │   ├─ Predict scam probability
  │   │   └─ Get risk score (0-100)
  │   │
  │   └─ Rule-based adjustments
  │       └─ Fine-tune based on specific patterns
  │
  ├─> Risk Engine evaluates results
  │   ├─ Calculate final risk score
  │   ├─ Determine risk level (LOW/MEDIUM/HIGH/CRITICAL)
  │   ├─ Generate explanation
  │   └─ Create recommendations
  │
  ├─> Generate Awareness Alert
  │   ├─ Alert title and message
  │   ├─ Educational content
  │   ├─ Safety tips
  │   └─ Visual indicators
  │
  ├─> Save to database
  │   ├─ Store call analysis record
  │   └─ Update statistics
  │
  ├─> Return JSON response to frontend
  │
  ├─> Frontend displays results
  │   ├─ Risk score visualization
  │   ├─ Color-coded alert box
  │   ├─ Risk factors list
  │   ├─ Recommendations
  │   └─ Educational content
  │
END
```

### 2. SMS Analysis Workflow

```
START
  │
  ├─> User enters SMS details
  │   ├─ Sender information
  │   └─ Message text
  │
  ├─> Frontend validates input
  │
  ├─> Send POST request to /api/analyze_sms
  │
  ├─> Flask backend receives request
  │   └─ Sanitize inputs
  │
  ├─> SMS Analyzer processes message
  │   │
  │   ├─> Extract text features
  │   │   ├─ Length and word count
  │   │   ├─ Punctuation analysis
  │   │   ├─ Uppercase ratio
  │   │   ├─ Digit count
  │   │   ├─ Keyword matching
  │   │   └─ Pattern detection
  │   │
  │   ├─> Extract and analyze URLs
  │   │   │
  │   │   ├─ Use regex to find URLs
  │   │   │
  │   │   └─> For each URL found:
  │   │       │
  │   │       ├─> URL Checker analyzes
  │   │       │   ├─ Parse URL components
  │   │       │   ├─ Check for IP address
  │   │       │   ├─ Verify HTTPS
  │   │       │   ├─ Detect URL shorteners
  │   │       │   ├─ Check TLD reputation
  │   │       │   ├─ Analyze domain length
  │   │       │   ├─ Count subdomains
  │   │       │   ├─ Look for suspicious chars
  │   │       │   └─ Calculate URL risk score
  │   │       │
  │   │       └─ Store URL analysis result
  │   │
  │   ├─> Machine Learning Prediction
  │   │   ├─ Load trained SMS model
  │   │   ├─ Convert features to array
  │   │   ├─ Predict scam probability
  │   │   └─ Incorporate URL risk scores
  │   │
  │   └─> Calculate overall risk
  │       ├─ Weight ML prediction (60%)
  │       ├─ Weight URL risk (40%)
  │       └─ Apply rule-based adjustments
  │
  ├─> Risk Engine evaluates results
  │   ├─ Determine risk level
  │   ├─ Generate detailed explanation
  │   │   ├─ Text-based indicators
  │   │   └─ URL-specific warnings
  │   └─ Create actionable recommendations
  │
  ├─> Generate Awareness Alert
  │
  ├─> Save to database
  │   ├─ Store SMS analysis record
  │   └─ Update statistics
  │
  ├─> Return JSON response
  │
  ├─> Frontend displays results
  │   ├─ Risk score and level
  │   ├─ Message preview
  │   ├─ URL analysis cards (if URLs present)
  │   ├─ Risk factors
  │   ├─ Recommendations
  │   └─ Educational tips
  │
END
```

### 3. Dashboard/Reports Workflow

```
START
  │
  ├─> User navigates to Reports page
  │
  ├─> Frontend requests /report
  │
  ├─> Flask backend queries database
  │   │
  │   ├─> Get recent analyses
  │   │   ├─ Last 10 call analyses
  │   │   └─ Last 10 SMS analyses
  │   │
  │   ├─> Get statistics
  │   │   ├─ Total analyzed (30 days)
  │   │   ├─ Scams detected
  │   │   ├─ Safe communications
  │   │   └─ Detection rate
  │   │
  │   └─> Get risk distribution
  │       ├─ Count CRITICAL threats
  │       ├─ Count HIGH threats
  │       ├─ Count MEDIUM threats
  │       └─ Count LOW threats
  │
  ├─> Render results in template
  │   │
  │   ├─> Statistics cards
  │   │   ├─ Total analyzed
  │   │   ├─ Threats detected
  │   │   ├─ Safe count
  │   │   └─ Detection rate %
  │   │
  │   ├─> Risk distribution chart
  │   │   └─ Visual breakdown by risk level
  │   │
  │   ├─> Recent call analyses table
  │   │   ├─ Timestamp
  │   │   ├─ Phone number
  │   │   ├─ Duration
  │   │   ├─ Risk score
  │   │   └─ Risk level badge
  │   │
  │   └─> Recent SMS analyses table
  │       ├─ Timestamp
  │       ├─ Sender
  │       ├─ Message preview
  │       ├─ Risk score
  │       └─ Risk level badge
  │
  ├─> Display page to user
  │
END
```

## Detailed Component Interactions

### Feature Extraction Process

#### Call Features
```python
# Extracted automatically from input
features = {
    'duration': <seconds>,
    'call_frequency': <count>,
    'is_unknown': <0 or 1>,
    'is_international': <detected from number>,
    'is_risky_country': <checked against list>,
    'very_short_call': <duration < 10>,
    'repeated_calls': <frequency > 1>,
    'excessive_calls': <frequency > 5>,
    'has_repeated_digits': <pattern detection>,
    'has_sequential_digits': <pattern detection>,
    'time_risk': <1-3 based on time_of_day>,
    'unknown_and_international': <combined>,
    'short_and_repeated': <combined>
}
```

#### SMS Features
```python
features = {
    'length': <character count>,
    'word_count': <word count>,
    'exclamation_count': <count of '!'>,
    'question_count': <count of '?'>,
    'uppercase_ratio': <uppercase / total>,
    'digit_count': <digit count>,
    'scam_keyword_count': <matched keywords>,
    'has_urls': <URL present?>,
    'url_count': <number of URLs>,
    'has_urgency': <urgency words present?>,
    'requests_action': <action words present?>,
    'mentions_money': <money words present?>,
    'mentions_account': <account words present?>,
    'has_threat': <threat words present?>,
    'avg_url_risk': <average URL risk if present>
}
```

### Machine Learning Prediction Process

```python
# 1. Load trained model
model = joblib.load('models/call_model.pkl')

# 2. Prepare feature array
feature_array = np.array([[
    features['duration'],
    features['call_frequency'],
    # ... all features in correct order
]])

# 3. Get prediction
if hasattr(model, 'predict_proba'):
    # Get probability of scam class
    probability = model.predict_proba(feature_array)[0][1]
else:
    # Get binary prediction
    probability = model.predict(feature_array)[0]

# 4. Convert to risk score
risk_score = probability * 100  # 0-100 scale
```

### Risk Level Determination

```python
def get_risk_level(risk_score):
    if risk_score >= 75:
        return "CRITICAL"
    elif risk_score >= 50:
        return "HIGH"
    elif risk_score >= 25:
        return "MEDIUM"
    else:
        return "LOW"
```

### Database Storage Process

```python
# 1. Prepare data dictionary
analysis_data = {
    'phone_number': cleaned_number,
    'duration': duration,
    'call_frequency': frequency,
    'is_unknown': is_unknown,
    'is_international': is_international,
    'risk_score': final_risk_score,
    'risk_level': risk_level,
    'is_scam': 1 if risk_score >= 50 else 0,
    'timestamp': datetime.now().isoformat(),
    'features': json.dumps(features)
}

# 2. Insert into database
db.save_call_analysis(analysis_data)

# 3. Update statistics
db.update_statistics('call', is_scam)
```

## Error Handling Workflow

```
Error Occurs
  │
  ├─> Catch exception
  │
  ├─> Log error details
  │   ├─ Error type
  │   ├─ Stack trace
  │   └─ User input (sanitized)
  │
  ├─> Determine error category
  │   ├─ Validation error (400)
  │   ├─ Server error (500)
  │   └─ Not found (404)
  │
  ├─> Create user-friendly message
  │   └─ Don't expose technical details
  │
  ├─> Return JSON error response
  │
  └─> Frontend displays error
      └─ Show retry options if applicable
```

## Security Measures Throughout Workflow

### 1. Input Validation
- Required field checking
- Type validation
- Range validation
- Format validation

### 2. Input Sanitization
```python
def sanitize_text(text):
    # Remove dangerous characters
    sanitized = re.sub(r'[<>\'\";&|`$]', '', text)
    return sanitized.strip()
```

### 3. SQL Injection Prevention
- Use parameterized queries
- Never concatenate user input into SQL

### 4. XSS Prevention
- Escape user input in HTML
- Use Jinja2 autoescaping
- Sanitize before display

### 5. Rate Limiting
- Limit API requests per IP
- Prevent abuse

## Performance Optimizations

### 1. Model Loading
- Load models once at startup
- Keep in memory for fast access

### 2. Database Queries
- Use indexes on timestamp
- Limit result sets
- Connection pooling

### 3. Caching
- Cache static analysis results
- Cache blacklist checks

### 4. Async Processing
- Non-blocking I/O for URL checks
- Background database writes

## User Experience Flow

```
User Journey:
  │
  ├─> Lands on homepage
  │   └─ Sees statistics and features
  │
  ├─> Chooses analysis type
  │   ├─ Call Analysis
  │   └─ SMS Analysis
  │
  ├─> Fills in form
  │   └─ Can use example data
  │
  ├─> Submits for analysis
  │   └─ Sees loading indicator
  │
  ├─> Views results
  │   ├─ Risk score (visual)
  │   ├─ Detailed explanation
  │   ├─ Actionable recommendations
  │   └─ Educational content
  │
  ├─> Takes action
  │   ├─ Block number
  │   ├─ Delete message
  │   └─ Report to authorities
  │
  └─> Learns and repeats
      └─ Builds scam awareness
```

## Monitoring and Logging

### Events Logged
1. Analysis requests (count, type)
2. Risk scores generated
3. Model predictions
4. Database operations
5. Errors and exceptions
6. System performance metrics

### Log Format
```
2024-01-15 14:32:45 - INFO - Call analysis started
2024-01-15 14:32:45 - INFO - Features extracted: 13 features
2024-01-15 14:32:45 - INFO - ML prediction: 0.92 (CRITICAL)
2024-01-15 14:32:45 - INFO - Risk score: 92/100
2024-01-15 14:32:45 - INFO - Saved to database: record_id=123
2024-01-15 14:32:45 - INFO - Call analysis completed in 0.15s
```

---

This workflow ensures:
- ✅ Reliable scam detection
- ✅ Clear user communication
- ✅ Secure data handling
- ✅ Educational value
- ✅ Privacy protection
- ✅ Actionable insights
