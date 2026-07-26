# safelinks
SafeLink is an AI-powered phishing URL detection system that identifies malicious websites before users interact with them. Using a hybrid approach combining machine learning, heuristic analysis, similarity detection, and URL feature extraction, it classifies URLs as Safe, Suspicious, or Phishing while providing multilingual threat explanations.
# 🛡️ SafeLink – AI-Powered Phishing URL Detection System

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black.svg)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-orange.svg)
![MySQL](https://img.shields.io/badge/MySQL-Database-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Overview

SafeLink is an AI-powered phishing URL detection system designed to identify malicious websites before users interact with them. The application uses a hybrid detection approach that combines Machine Learning, heuristic analysis, URL similarity detection, and feature extraction to classify URLs as **Safe**, **Suspicious**, or **Phishing**.

The system aims to improve cybersecurity awareness by providing real-time phishing detection along with easy-to-understand explanations and multilingual warning messages.

---

Features

- 🔍 Real-time phishing URL detection
- 🤖 Machine Learning-based URL classification
- ⚡ Hybrid detection using heuristic analysis
- 🔤 Levenshtein Distance for typosquatting detection
- 🌐 Homoglyph attack detection
- 📊 Hybrid risk scoring mechanism
- 🌍 Multilingual warning and explanation support
- 💾 Database storage for analyzed URLs
- 🎨 Simple and user-friendly web interface
- 📈 High phishing detection accuracy

---

System Architecture

```text
                User
                  │
                  ▼
          URL Input Interface
                  │
                  ▼
        Feature Extraction Engine
                  │
      ┌───────────┼────────────┐
      ▼           ▼            ▼
 Machine      Heuristic    Similarity
 Learning      Analysis     Detection
(Random Forest)             (Levenshtein &
                            Homoglyph)
      └───────────┼────────────┘
                  ▼
         Hybrid Risk Calculation
                  ▼
      Safe / Suspicious / Phishing
                  ▼
     Explanation + Warning Message
                  ▼
             Database Storage
```

---

 Detection Techniques

Machine Learning

- Random Forest Classifier

 Similarity Detection

- Levenshtein Distance
- Homoglyph Detection

 Rule-Based Detection

- Heuristic Risk Analysis

Hybrid Decision Engine

Combines machine learning probability with heuristic risk scores to generate the final phishing prediction.

---

 URL Features Analyzed

The system extracts and analyzes multiple URL characteristics, including:

- URL Length
- Number of Subdomains
- Domain Age
- HTTPS Availability
- IP Address Usage
- URL Shortening Services
- Prefix/Suffix Symbols
- Special Characters
- Redirect Patterns
- External Requests
- Anchor Links
- Server Form Handler (SFH)
- Favicon Source
- Port Usage

---

 Technology Stack

## Frontend

- HTML5
- CSS3
- JavaScript

## Backend

- Python
- Flask

## Machine Learning

- Scikit-learn
- Random Forest

## Database

- MySQL

## Libraries

- Flask-SQLAlchemy
- Pandas
- NumPy
- Joblib
- Whois
- Google Translator

---

 Project Structure

```
SafeLink/
│
├── app.py
├── model/
│   ├── model.pkl
│   ├── scaler.pkl
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── templates/
│   ├── index.html
│   ├── login.html
│   └── dashboard.html
│
├── database/
│
├── utils/
│   ├── feature_extraction.py
│   ├── heuristic.py
│   ├── levenshtein.py
│   ├── homoglyph.py
│   └── translator.py
│
├── dataset/
├── requirements.txt
└── README.md
```

---

Workflow

1. User enters a URL.
2. URL features are extracted.
3. Similarity analysis detects typosquatting and homoglyph attacks.
4. Heuristic rules calculate an initial risk score.
5. Random Forest predicts phishing probability.
6. Hybrid scoring combines both results.
7. URL is classified as:

- ✅ Safe
- ⚠️ Suspicious
- ❌ Phishing

8. Warning messages and explanations are displayed.
9. Results are stored in the database.

---

Performance

| Metric | Score |
|---------|------:|
| Accuracy | **96.02%** |
| Precision | **93.01%** |
| Recall | **91.02%** |

The hybrid detection approach improves phishing detection accuracy while reducing false positives by combining machine learning with heuristic and similarity-based analysis.

---

Applications

- Phishing URL Detection
- Web Security
- Email Security
- SMS Scam Detection
- QR Code Verification
- Browser Security
- Cybersecurity Awareness

---

 Future Improvements

- Browser Extension
- Mobile Application
- Deep Learning-based Detection
- Real-Time Threat Intelligence
- Browser History Scanning
- QR Code Scanner Integration
- Cloud Deployment
- REST API Support

---

 Algorithms Used

- Random Forest
- Heuristic Rule-Based Analysis
- Levenshtein Distance
- Homoglyph Detection

---

 Developed By

**Anusree K P**

Bachelor of Technology (Computer Science & Engineering)

---

 License

This project is developed for educational and research purposes.


