# Dataset Description

## Overview

ScamShield uses two primary datasets for training machine learning models:
1. **Call Dataset** (`call_dataset.csv`) - 100 call records
2. **SMS Dataset** (`sms_dataset.csv`) - 100 SMS message records

Both datasets are **simulated but realistic**, based on actual scam patterns documented by the FTC, FBI IC3, and cybersecurity research.

## Call Dataset

### File: `data/call_dataset.csv`

### Structure
- **Total Records**: 100
- **Scam Records**: 50 (50%)
- **Legitimate Records**: 50 (50%)
- **Features**: 21 columns

### Column Descriptions

| Column Name | Type | Description | Example Values |
|-------------|------|-------------|----------------|
| phone_number | String | Calling number with country code | +234-555-1234, 555-123-4567 |
| duration | Integer | Call duration in seconds | 5, 120, 300 |
| call_frequency | Integer | Number of calls from this number in 24h | 1, 3, 7 |
| is_unknown | Binary | 1 if not in contacts, 0 if known | 0, 1 |
| is_international | Binary | 1 if international call | 0, 1 |
| is_risky_country | Binary | 1 if from high-risk country | 0, 1 |
| very_short_call | Binary | 1 if duration < 10 seconds | 0, 1 |
| short_call | Binary | 1 if duration 10-30 seconds | 0, 1 |
| normal_call | Binary | 1 if duration 30-300 seconds | 0, 1 |
| long_call | Binary | 1 if duration > 300 seconds | 0, 1 |
| single_call | Binary | 1 if only called once | 0, 1 |
| repeated_calls | Binary | 1 if called 2+ times | 0, 1 |
| excessive_calls | Binary | 1 if called 5+ times | 0, 1 |
| has_repeated_digits | Binary | 1 if number has repeated digits | 0, 1 |
| has_sequential_digits | Binary | 1 if number has sequential digits | 0, 1 |
| number_length | Integer | Length of phone number | 10, 13 |
| time_risk | Integer | Risk score based on time (1-3) | 1, 2, 3 |
| suspicious_time | Binary | 1 if called at odd hours | 0, 1 |
| unknown_and_international | Binary | Combined risk factor | 0, 1 |
| short_and_repeated | Binary | Combined risk factor | 0, 1 |
| is_scam | Binary | **TARGET**: 1 if scam, 0 if legitimate | 0, 1 |

### High-Risk Country Codes
Based on FTC and IC3 reports, the following country codes are flagged as high-risk:
- +375 (Belarus)
- +371 (Latvia)
- +254 (Kenya)
- +234 (Nigeria)
- +233 (Ghana)
- +880 (Bangladesh)
- +92 (Pakistan)
- +62 (Indonesia)
- +84 (Vietnam)

### Scam Call Patterns
**Typical scam call characteristics**:
- Very short duration (< 10 seconds) - robocall screening
- International from risky countries
- Multiple calls in short period
- Calls at unusual times (late night/early morning)
- Repeated or sequential digit patterns
- Unknown to recipient

**Typical legitimate call characteristics**:
- Normal duration (30-300 seconds)
- Domestic or known international
- Single call or infrequent
- During business hours
- From known contacts

### Example Records

#### Scam Example
```csv
+234-555-1234,5,3,1,1,1,1,0,0,0,0,1,0,0,0,13,3,1,1,1,1
```
- Nigerian number (+234)
- 5 seconds duration (very short)
- Called 3 times
- Unknown number
- International call
- Risky country
- Suspicious time
- **Label: SCAM**

#### Legitimate Example
```csv
555-123-4567,120,1,0,0,0,0,0,1,0,1,0,0,0,0,10,1,0,0,0,0
```
- Domestic number
- 120 seconds (2 minutes) - normal duration
- Single call
- Known number (in contacts)
- Business hours
- **Label: LEGITIMATE**

## SMS Dataset

### File: `data/sms_dataset.csv`

### Structure
- **Total Records**: 100
- **Scam Records**: 50 (50%)
- **Legitimate Records**: 50 (50%)
- **Features**: 16 columns

### Column Descriptions

| Column Name | Type | Description | Example Values |
|-------------|------|-------------|----------------|
| message_text | String | Complete SMS message content | "URGENT: Your account..." |
| sender | String | Sender phone number or ID | "12345", "FedEx", "+1-555-1234" |
| length | Integer | Character count of message | 91, 104 |
| word_count | Integer | Number of words in message | 13, 15 |
| exclamation_count | Integer | Number of exclamation marks | 0, 1, 2 |
| question_count | Integer | Number of question marks | 0, 1 |
| uppercase_ratio | Float | Ratio of uppercase letters | 0.02, 0.35 |
| digit_count | Integer | Number of digits in message | 5, 10 |
| scam_keyword_count | Integer | Count of known scam keywords | 0, 3, 5 |
| has_urls | Binary | 1 if message contains URLs | 0, 1 |
| url_count | Integer | Number of URLs in message | 0, 1, 2 |
| has_urgency | Binary | 1 if urgent language present | 0, 1 |
| requests_action | Binary | 1 if requests action (click, call) | 0, 1 |
| mentions_money | Binary | 1 if mentions money/prizes | 0, 1 |
| mentions_account | Binary | 1 if mentions accounts/banks | 0, 1 |
| has_threat | Binary | 1 if contains threats | 0, 1 |
| is_scam | Binary | **TARGET**: 1 if scam, 0 if legitimate | 0, 1 |

### Scam Keywords Library
The dataset uses 50+ scam keywords across categories:

**Urgency Indicators**:
- urgent, immediately, act now, limited time, expires, hurry, last chance

**Financial Terms**:
- verify account, confirm identity, update payment, suspended, refund, prize, winner

**Threats**:
- legal action, arrest, warrant, suspend, terminate, penalties

**Request Terms**:
- click here, confirm, verify, validate, social security, password, credit card

**Too-Good-To-Be-True**:
- free, gift card, cash prize, selected, chosen, inheritance

**Impersonation**:
- bank, paypal, amazon, IRS, tax, government, federal

### Example Records

#### Scam SMS Example
```csv
"URGENT: Your bank account has been suspended! Click here to verify: http://bit.ly/bank123",12345,91,13,1,0,0.11,5,4,1,1,1,1,1,1,1,1
```
- Contains urgent language
- Mentions bank account
- Has URL (shortened)
- Requests action
- Multiple scam keywords
- **Label: SCAM**

#### Legitimate SMS Example
```csv
"Hi, your package will be delivered tomorrow between 2-5pm. Track: https://fedex.com/track/abc123",FedEx,104,14,0,0,0.02,5,0,1,1,0,0,0,0,0,0
```
- Professional sender ID
- Informational content
- Legitimate URL (fedex.com)
- No pressure or threats
- **Label: LEGITIMATE**

## Data Collection Methodology

### Sources
1. **FTC Scam Alerts** - Real reported scam patterns
2. **IC3 Reports** - FBI Internet Crime database
3. **Academic Research** - Papers on phishing detection
4. **Public Datasets** - SMS Spam Collection UCI
5. **Cybersecurity Blogs** - Latest scam tactics

### Simulation Process
1. **Pattern Extraction**: Identified common scam characteristics
2. **Feature Engineering**: Created relevant ML features
3. **Balanced Dataset**: Equal scam/legitimate samples
4. **Realistic Values**: Based on actual scam statistics
5. **Privacy Protection**: No real phone numbers or messages

### Data Quality
- **Completeness**: No missing values
- **Consistency**: Standardized formats
- **Representativeness**: Covers major scam types
- **Balance**: 50/50 scam/legitimate distribution
- **Diversity**: Various scam tactics represented

## Model Training Split

### Cross-Validation Strategy
```
Training Set: 80% (80 records)
Test Set: 20% (20 records)
Stratified split to maintain class balance
```

### Performance Metrics
Models evaluated using:
- Accuracy
- Precision
- Recall
- F1-Score
- AUC-ROC
- Confusion Matrix

## Dataset Limitations

### Known Limitations
1. **Simulated Data**: Not from real-world production
2. **Limited Size**: 100 records per dataset
3. **Language**: English only
4. **Time Period**: Based on 2023-2024 scam patterns
5. **Geographic Bias**: Focused on US-based scams

### Mitigation Strategies
1. Use ensemble models to improve generalization
2. Regular retraining with new patterns
3. Rule-based fallback for edge cases
4. User feedback loop for model improvement
5. Clear communication of limitations to users

## Ethical Considerations

### Data Ethics
- ✅ No personal information used
- ✅ Simulated data only
- ✅ Public scam patterns
- ✅ Privacy-preserving
- ✅ Transparent methodology

### Bias Considerations
- Monitored for demographic bias
- Tested across various scam types
- Balanced representation
- Regular fairness audits

## Future Dataset Enhancements

### Planned Improvements
1. **Expand to 1000+ records** per dataset
2. **Multi-language support** (Spanish, Chinese, Hindi)
3. **Voice call transcripts** (with consent)
4. **Image-based scams** (QR codes, fake screenshots)
5. **Real-world validation** with anonymized data
6. **Temporal evolution** tracking new scam tactics

### Community Contributions
- Accepting anonymized scam reports
- Federated learning for privacy-preserving updates
- Collaboration with carriers and security firms
- Research partnerships with universities

## References

1. Federal Trade Commission (FTC) - Consumer Sentinel Network
2. FBI Internet Crime Complaint Center (IC3) - Annual Reports
3. Truecaller - Global Spam & Scam Report 2023
4. SMS Spam Collection Dataset - UCI Machine Learning Repository
5. PhishTank - Phishing URL Database

---

*Dataset Version: 1.0*
*Last Updated: 2024*
*License: MIT (for research and educational use)*
