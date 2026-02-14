# Threat Model

## Overview

This document outlines the threat landscape that ScamShield is designed to defend against, along with the attack vectors, threat actors, and defensive mechanisms implemented.

## Threat Landscape

### Primary Threats

#### 1. Scam Phone Calls
**Description**: Fraudulent phone calls designed to deceive victims into providing sensitive information or money.

**Attack Vectors**:
- Caller ID spoofing (appearing as legitimate organizations)
- Robocalls with pre-recorded messages
- Live scammers using social engineering
- Vishing (voice phishing) attacks
- One-ring scams to trigger callbacks

**Common Tactics**:
- Impersonating IRS, Social Security Administration, or banks
- Creating urgency and fear (arrest warrants, account suspension)
- Requesting immediate payment via gift cards or wire transfers
- Asking for personal information (SSN, account numbers, passwords)
- Using threatening language to pressure victims

#### 2. Phishing SMS/MMS (Smishing)
**Description**: Malicious text messages containing phishing links or scam content.

**Attack Vectors**:
- Shortened URLs hiding malicious destinations
- Typosquatting domains (amaz0n.com instead of amazon.com)
- Credential harvesting through fake login pages
- Malware distribution via malicious APK files
- QR codes linking to phishing sites

**Common Tactics**:
- Package delivery notifications with tracking links
- Bank security alerts requiring "verification"
- Prize/lottery winning notifications
- COVID-19 vaccine or stimulus check scams
- Romance scams building emotional connections

#### 3. URL-Based Attacks
**Description**: Malicious URLs embedded in messages to compromise devices or steal information.

**Attack Vectors**:
- Phishing websites mimicking legitimate services
- Drive-by downloads of malware
- Man-in-the-middle attacks on HTTP sites
- Session hijacking through XSS vulnerabilities
- Credential stuffing attacks

**Indicators**:
- IP addresses instead of domain names
- Suspicious TLDs (.tk, .ml, .ga, .cf)
- URL shorteners hiding destinations
- Excessive subdomains or hyphens
- Misspelled brand names

## Threat Actors

### 1. Individual Scammers
- **Motivation**: Financial gain
- **Sophistication**: Low to medium
- **Scale**: Small (dozens of victims)
- **Tactics**: Generic scripts, basic social engineering

### 2. Organized Crime Groups
- **Motivation**: Large-scale financial fraud
- **Sophistication**: Medium to high
- **Scale**: Large (thousands of victims)
- **Tactics**: Advanced social engineering, call centers, data breaches

### 3. State-Sponsored Actors
- **Motivation**: Intelligence gathering, destabilization
- **Sophistication**: Very high
- **Scale**: Targeted (specific individuals or groups)
- **Tactics**: Advanced persistent threats, zero-day exploits

### 4. Script Kiddies
- **Motivation**: Experimentation, reputation
- **Sophistication**: Low
- **Scale**: Small and unfocused
- **Tactics**: Pre-made tools, automated attacks

## Attack Scenarios

### Scenario 1: IRS Tax Scam
```
1. Victim receives call from spoofed IRS number
2. Robocall claims unpaid taxes and impending arrest
3. Directs victim to call back at scammer's number
4. Scammer demands immediate payment via gift cards
5. Threatens legal action if not paid within hours
```

**ScamShield Defense**:
- ✅ Detects international origin (many IRS scams from abroad)
- ✅ Flags short call duration (robocall pattern)
- ✅ Identifies threatening language
- ✅ Warns that IRS never calls demanding gift cards

### Scenario 2: Bank Account Phishing
```
1. Victim receives SMS: "Your account suspended"
2. Message contains shortened URL (bit.ly/bank123)
3. Link leads to fake bank login page
4. Victim enters credentials
5. Attacker gains account access
```

**ScamShield Defense**:
- ✅ Detects URL shortener
- ✅ Identifies urgent language
- ✅ Flags account-related keywords
- ✅ Warns about non-HTTPS phishing site
- ✅ Educates that banks don't send such links

### Scenario 3: Prize Scam SMS
```
1. SMS: "You won $10,000! Claim now!"
2. Link to fake lottery site
3. Asks for personal information to "verify"
4. Requests "processing fee" to release prize
5. Steals information and payment
```

**ScamShield Defense**:
- ✅ Detects "too good to be true" language
- ✅ Identifies money-related keywords
- ✅ Flags suspicious domain
- ✅ Warns about advance fee scams

### Scenario 4: One-Ring Scam
```
1. Victim receives call from international number
2. Rings once and hangs up (< 5 seconds)
3. Victim calls back out of curiosity
4. Connected to premium-rate number
5. Charged exorbitant per-minute fees
```

**ScamShield Defense**:
- ✅ Detects very short call duration
- ✅ Flags international from risky country
- ✅ Warns not to call back unknown numbers

## Attack Patterns Detected

### Call Patterns
| Pattern | Indicator | Risk Weight |
|---------|-----------|-------------|
| Very short duration (<10s) | Robocall screening | High |
| International + Unknown | Often scam origin | High |
| Excessive frequency (5+/day) | Harassment pattern | High |
| Risky country codes | Known scam sources | High |
| Repeated/sequential digits | Fake numbers | Medium |
| Late night calls | Suspicious timing | Medium |

### SMS Patterns
| Pattern | Indicator | Risk Weight |
|---------|-----------|-------------|
| Urgent language | Pressure tactic | High |
| URL shorteners | Hiding destination | High |
| Account mentions + URL | Phishing attempt | Critical |
| Money/prize mentions | Financial scam | High |
| Threats | Coercion tactic | High |
| Multiple exclamations | Emotional manipulation | Medium |
| All caps | Attention grabbing | Low |

### URL Patterns
| Pattern | Indicator | Risk Weight |
|---------|-----------|-------------|
| IP address | No legitimate domain | Critical |
| Risky TLD | Often used in scams | High |
| No HTTPS | Insecure connection | High |
| URL shortener | Hiding true destination | High |
| Excessive subdomains | Obfuscation | Medium |
| Numbers in domain | Typosquatting | Medium |

## Defense Mechanisms

### 1. Machine Learning Detection
**Purpose**: Identify scam patterns through trained models

**Implementation**:
- Random Forest for call pattern analysis
- Logistic Regression for SMS content analysis
- Trained on 100+ scam examples
- Achieves 85%+ accuracy

**Limitations**:
- May not detect novel scam tactics
- Requires retraining for evolving threats
- Can produce false positives/negatives

### 2. Rule-Based Analysis
**Purpose**: Catch known scam indicators

**Implementation**:
- Blacklist of risky country codes
- Database of scam keywords
- URL pattern matching
- Suspicious timing detection

**Limitations**:
- Can be circumvented by sophisticated attackers
- Requires manual updates for new patterns

### 3. URL Security Verification
**Purpose**: Analyze embedded links for threats

**Implementation**:
- Domain parsing and analysis
- TLD reputation checking
- HTTPS verification
- Pattern-based risk scoring

**Limitations**:
- Cannot detect compromised legitimate sites
- No real-time URL testing (no clicking)

### 4. User Education
**Purpose**: Empower users to recognize scams

**Implementation**:
- Contextual explanations of threats
- Safety recommendations
- Scam awareness tips
- Educational content about tactics

**Limitations**:
- Relies on user reading and understanding
- Cannot prevent all social engineering

## Out of Scope Threats

### What ScamShield Does NOT Protect Against

#### 1. Advanced Persistent Threats (APTs)
- State-sponsored zero-day exploits
- Targeted surveillance
- Hardware-level compromises

#### 2. Man-in-the-Middle Attacks
- Network traffic interception
- SSL/TLS stripping
- DNS poisoning

#### 3. Malware Already Installed
- Keyloggers capturing input
- Spyware monitoring communications
- Ransomware encrypting files

#### 4. Physical Security Threats
- SIM swapping attacks
- Device theft
- Shoulder surfing

#### 5. Insider Threats
- Trusted contacts being compromised
- Family/friend impersonation
- Workplace social engineering

#### 6. Novel/Zero-Day Scams
- Brand new scam tactics
- AI-generated voice cloning
- Deepfake video calls

## Security Assumptions

### Assumptions Made
1. **Honest User**: User provides accurate information
2. **Secure Environment**: User's device is not compromised
3. **Network Security**: Basic network security in place
4. **Data Integrity**: Training data represents real threats
5. **Model Validity**: ML models generalize to new data

### Trust Boundaries
- User trusts ScamShield with call/message metadata
- ScamShield trusts user-provided information is accurate
- No trust in external URLs (all analyzed as potentially malicious)
- No trust in unknown senders

## Risk Assessment

### Residual Risks After Using ScamShield

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| False negative (missed scam) | Medium | High | User education, multiple detection layers |
| False positive (legit flagged) | Low | Medium | Clear explanations, user can override |
| Novel scam tactics | Medium | High | Regular model updates, rule additions |
| Sophisticated social engineering | High | High | Cannot be fully prevented, user awareness |
| User ignores warnings | Medium | High | Clear communication, severity levels |

## Compliance and Legal

### Regulatory Compliance
- **CFAA**: No unauthorized access
- **ECPA**: No interception without consent
- **TCPA**: No robocalling or auto-dialing
- **GDPR**: Privacy by design, local data storage
- **CCPA**: User data rights respected

### Ethical Guidelines
1. **Defensive Only**: No offensive capabilities
2. **Privacy First**: No data sharing
3. **Transparency**: Open source, auditable
4. **User Control**: User-initiated analysis
5. **Harm Prevention**: Focus on protection

## Incident Response

### If ScamShield Misses a Scam
1. User reports false negative
2. Analyze why detection failed
3. Add pattern to training data
4. Retrain model if needed
5. Update rules database
6. Notify users of update

### If ScamShield False Positive
1. User reports false positive
2. Review analysis reasoning
3. Adjust detection thresholds if needed
4. Add legitimate pattern to whitelist
5. Improve explanation clarity

## Future Threat Considerations

### Emerging Threats
1. **AI-Generated Scams**: Deepfake voices, ChatGPT scripts
2. **Blockchain Scams**: Cryptocurrency schemes
3. **IoT-Based Attacks**: Smart device exploitation
4. **5G Network Attacks**: New protocol vulnerabilities
5. **Quantum Computing**: Breaking current encryption

### Planned Defenses
- Continuous model retraining
- Behavioral analysis addition
- Voice pattern detection
- Community threat intelligence
- Federated learning for privacy-preserving updates

---

**Last Updated**: 2024
**Version**: 1.0
**Review Cycle**: Quarterly
