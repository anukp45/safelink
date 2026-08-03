import re
import numpy as np # type: ignore
from urllib.parse import urlparse
import whois # type: ignore
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier # type: ignore
from sklearn.preprocessing import StandardScaler # type: ignore
import joblib # type: ignore
from deep_translator import GoogleTranslator # type: ignore
from official_domains import OFFICIAL_DOMAINS # type: ignore
import os

# ==============================
# Configuration & Caching
# ==============================
MODEL_PATH = "hybrid_phishing_model.pkl"
SCALER_PATH = "hybrid_scaler.pkl"
WHOIS_CACHE: Dict[str, int] = {}
__all__ = ["hybrid_predict_phishing"]

# ==============================
# Homoglyph Detection logic
# ==============================
def normalize_homoglyphs(text: str) -> str:
    """Basic normalization of common homoglyphs to Latin equivalents."""
    homoglyphs = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'і': 'i', 'ј': 'j', 'м': 'm', 'н': 'h', 'х': 'x',
        'ɑ': 'a', 'ｅ': 'e', 'ｏ': 'o', 'ｐ': 'p', 'ｓ': 'c', 'ｙ': 'y', 'ｉ': 'i', 'ｊ': 'j'
    }
    return "".join(homoglyphs.get(c, c) for c in text)

# ==============================
# Feature Extraction
# ==============================
def levenshtein_distance(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_brand_similarity(domain: str) -> Tuple[int, Optional[str]]:
    domain = domain.lower().replace("www.", "").split(":")[0]  # Remove port
    normalized_domain = normalize_homoglyphs(domain)
    
    # CRITICAL: Homoglyph detection - high risk of phishing
    if normalized_domain != domain:
        return 80, f"[ALERT] HOMOGLYPH ATTACK DETECTED! Domain '{domain}' uses non-Latin/Unicode characters to mimic a legitimate site."

    # Enhanced small-modification check: compare full domain to official list
    for official in OFFICIAL_DOMAINS:
        dist_full = levenshtein_distance(domain, official)
        if dist_full == 1:
            # One character off from an official domain is a high threat
            return 95, f"[ALERT] Domain differs by a single character from official domain '{official}'."
        if dist_full == 2 and len(official) > 5:
            # still suspicious but slightly lower
            return 80, f"[WARNING] Domain is two characters away from official domain '{official}'."

    # Check exact matches in official domains
    for official in OFFICIAL_DOMAINS:
        if domain == official:
            return 0, None

        base_official = official.split(".")[0]
        base_domain = domain.split(".")[0]

        # Exact match on brand name (high suspicion)
        if base_official == base_domain and domain != official:
            # Check if it's using a different TLD
            return 70, f"[ALERT] Domain impersonates official brand '{base_official}' with a different TLD."

        # Check for direct typo (one character difference) - very suspicious
        distance = levenshtein_distance(base_domain, base_official)
        if distance == 1 and len(base_official) >= 3:
            return 95, f"[ALERT] Domain closely resembles official site '{official}' - possible typosquatting (1 char difference)."
        
        # Check for 2 character differences (still suspicious)
        if distance == 2 and len(base_official) >= 3:
            return 80, f"[WARNING] Domain slightly resembles official site '{official}' (2 char difference)."
        
        # Check for brand name as substring combined with other words
        if len(base_official) >= 3 and base_official in base_domain and base_official != base_domain:
            # Check if it's a legitimate subdomain or just suspicious
            if "-" in domain or "_" in domain:
                return 55, f"[WARNING] Domain contains official brand name '{base_official}' in suspicious context with special characters."
            elif len(base_domain) < len(base_official) + 8:  # Not too much extra
                return 45, f"[WARNING] Domain contains official brand name '{base_official}' combined with other words."

    return 0, None

def extract_features(url: str) -> List[float]:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url.lower())
    netloc = parsed.netloc
    path = parsed.path

    # Core Features
    length = len(url)
    dots = netloc.count(".")
    hyphens = netloc.count("-")
    digits = sum(c.isdigit() for c in netloc)
    subdomains = max(0, dots - 1)
    
    suspicious_words = ["login", "secure", "account", "update", "verify", "bank", "paypal", "password", "wallet", "crypto", "free", "gift"]
    tokens = sum(word in url.lower() for word in suspicious_words)

    has_at = 1 if "@" in netloc else 0
    has_ip = 1 if re.match(r"\d{1,3}(\.\d{1,3}){3}", netloc) else 0
    abnormal = 1 if "//" in path or "/http" in path else 0
    
    # New Extended Features
    path_depth = path.count("/")
    special_chars = sum(c in url for c in ['%', '?', '=', '&', '#', '+'])
    hostname_len = len(netloc)
    
    # Port Check
    has_port = 0
    if ":" in netloc:
        parts = netloc.split(":")
        if len(parts) > 1 and parts[1].isdigit():
            port = int(parts[1])
            if port not in [80, 443]:
                has_port = 1
    
    # WHOIS Age with Caching
    if netloc in WHOIS_CACHE:
        age = WHOIS_CACHE[netloc]
    else:
        age = -1
        try:
            domain_for_whois = netloc.replace("www.", "").split(":")[0]
            w = whois.whois(domain_for_whois)
            creation_date = None
            if isinstance(w, dict):
                creation_date = w.get("creation_date")
            else:
                creation_date = getattr(w, "creation_date", None)
            
            if creation_date:
                reg = creation_date[0] if isinstance(creation_date, list) else creation_date
                if reg:
                    if isinstance(reg, str):
                        reg = datetime.fromisoformat(reg.replace('Z', '+00:00'))
                    age = (datetime.now() - reg).days
                    if age < 0 or age > 50000: age = -1
        except Exception:
            age = -1
        WHOIS_CACHE[netloc] = age

    https = 1 if parsed.scheme == "https" else 0
    suspicious_tld = 1 if netloc.split(".")[-1] in ["xyz", "top", "pw", "ga", "cf", "ml", "tk", "icu", "buzz", "loan"] else 0
    digit_ratio = digits / len(netloc) if len(netloc) > 0 else 0

    return [
        float(length), float(dots), float(hyphens), float(tokens), float(has_ip), 
        float(age), float(https), float(suspicious_tld), float(digit_ratio), float(has_at),
        float(path_depth), float(special_chars), float(hostname_len), float(has_port), float(abnormal)
    ]

# ==============================
# Model Management
# ==============================
def train_model():
    dataset_path = "phishing_dataset.csv"
    
    if not os.path.exists(dataset_path):
        print(f"Dataset {dataset_path} not found. Using small synthetic fallback...")
        # Updated to 15 features
        training_data = [
            [20, 1, 0, 0, 0, 3650, 1, 0, 0.0, 0, 0, 0, 20, 0, 0],  # Safe: google.com
            [35, 2, 0, 1, 0, 10, 0, 1, 0.2, 0, 1, 0, 35, 0, 0],   # Phishing: login-secure.xyz
            [80, 4, 2, 2, 0, -1, 0, 0, 0.1, 1, 3, 2, 80, 0, 1],   # Phishing: long-url-with-@
            [15, 1, 0, 0, 1, 5, 0, 0, 0.8, 0, 0, 0, 15, 0, 0],    # Phishing: IP address
            [25, 1, 0, 0, 0, 5000, 1, 0, 0.0, 0, 0, 0, 25, 0, 0],  # Safe: sbi.co.in
            [40, 3, 1, 1, 0, 20, 0, 1, 0.1, 0, 2, 0, 40, 0, 0],   # Phishing: verify-account.top
            [18, 1, 0, 0, 0, 1200, 1, 0, 0.0, 0, 0, 0, 18, 0, 0], # Safe: amazon.in
            [55, 2, 3, 1, 0, 15, 0, 0, 0.0, 0, 2, 1, 55, 0, 0],   # Phishing: amazon-support-update.com
            [12, 1, 0, 0, 0, 2500, 1, 0, 0.0, 0, 0, 0, 12, 0, 0], # Safe: bbc.com
            [45, 2, 1, 2, 0, 45, 0, 1, 0.3, 0, 2, 2, 45, 0, 0],   # Phishing: claim-your-gift.buzz
        ]
        labels = [0, 1, 1, 1, 0, 1, 0, 1, 0, 1]
    else:
        print(f"Loading dataset from {dataset_path}...")
        import pandas as pd
        df = pd.read_csv(dataset_path)
        
        # The dataset has 'Domain' and 'Label' columns. 
        # We need to extract our specific features from the 'Domain' column.
        # Note: We simulate 'age' to avoid 10k slow WHOIS lookups during training.
        
        training_data = []
        labels = []
        
        print("Extracting features from dataset (this may take a moment)...")
        # Sample if too large for quick training, but 10k is usually fine for RandomForest
        for _, row in df.iterrows():
            url = row['Domain']
            label = row['Label']
            
            # Simple feature extraction without active WHOIS (simulate age based on label)
            # Safe: age 365+ days, Phishing: age < 30 days
            simulated_age = 1000 if label == 0 else 15
            
            # Manual extraction to match our feature vector:
            # [length, dots, hyphens, tokens, ip, age, https, tld, digit_ratio, has_at]
            
            netloc = url.lower()
            length = len(netloc)
            dots = netloc.count(".")
            hyphens = netloc.count("-")
            
            suspicious_words = ["login", "secure", "account", "update", "verify", "bank", "paypal", "password", "wallet", "crypto", "free", "gift"]
            tokens = sum(word in netloc for word in suspicious_words)
            
            has_ip = 1 if re.match(r"\d{1,3}(\.\d{1,3}){3}", netloc) else 0
            has_at = 1 if "@" in netloc else 0
            
            suspicious_tlds = ["xyz", "top", "pw", "ga", "cf", "ml", "tk", "icu", "buzz", "loan"]
            tld = 1 if netloc.split(".")[-1] in suspicious_tlds else 0
            
            digits = sum(c.isdigit() for c in netloc)
            digit_ratio = digits / len(netloc) if len(netloc) > 0 else 0
            
            https = 0 # Dataset domains usually don't have protocol, assume 0 for training consistency
            
            training_data.append([
                float(length), float(dots), float(hyphens), float(tokens), 
                float(has_ip), float(simulated_age), float(https), 
                float(tld), float(digit_ratio), float(has_at),
                0.0, 0.0, float(length), 0.0, 0.0 # Placeholder for new features
            ])
            labels.append(label)

    X = np.array(training_data)
    y = np.array(labels)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Use more estimators for the larger dataset
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, y)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"Model trained on {len(training_data)} samples and saved.")
    return model, scaler

def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        return train_model()
    
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        
        # Verification: model and scaler must expect 15 features
        if hasattr(scaler, "n_features_in_") and scaler.n_features_in_ != 15:
            print(f"Feature count mismatch (Found {scaler.n_features_in_}, expected 15). Retraining...")
            return train_model()
            
        return model, scaler
    except Exception as e:
        print(f"Error loading model: {e}. Retraining...")
        return train_model()

model, scaler = load_model()

# ==============================
# Scoring logic
# ==============================
def heuristic_score(f: List[float]) -> int:
    # length, dots, hyphens, tokens, ip, age, https, tld, dratio, at, depth, special, hostlen, port, abnormal
    score = 0
    
    # URL length (graded)
    if f[0] > 120: score += 12
    elif f[0] > 90: score += 8
    elif f[0] > 75: score += 5
    
    # Dots (graded)
    if f[1] > 5: score += 12
    elif f[1] > 4: score += 8
    elif f[1] > 3: score += 5
    
    # Hyphens
    if f[2] > 3: score += 8
    elif f[2] > 1: score += 4
    
    # Tokens (damped)
    score += min(f[3] * 6, 20)
    
    # Critical indicators
    if f[4]: score += 30 # IP
    if f[9]: score += 20 # @
    if f[7]: score += 18 # TLD
    
    # New Features Scoring
    if f[10] > 5: score += 10 # depth
    if f[11] > 5: score += 12 # special chars
    if f[13]: score += 15    # non-standard port
    if f[14]: score += 10    # abnormal path
    
    # Digit Ratio
    if f[8] > 0.5: score += 15
    elif f[8] > 0.3: score += 8
    
    # Domain Age
    if f[5] != -1:
        if f[5] < 3: score += 35   
        elif f[5] < 7: score += 25  
        elif f[5] < 14: score += 18 
        elif f[5] < 30: score += 12 
        elif f[5] < 90: score += 6  
        elif f[5] < 180: score += 3 
    else:
        score += 10
        
    if not f[6]: score += 8 # https
    
    return int(min(100, max(0, int(score))))

def hybrid_calculation(heur: int, ml_prob: float, brand_score: int, features: List[float]) -> int:
    # Blend scores with balanced weights
    # ML prob is usually already a float 0-100
    
    # High risk indicators check
    has_high_risk = any([features[4], features[9], features[7]]) # IP, @, TLD
    
    if heur < 15 and not has_high_risk:
        # Heavily favor heuristics for very clean-looking sites
        final_score = int(0.75 * heur + 0.25 * ml_prob)
    else:
        # Standard blending
        final_score = int(0.5 * heur + 0.5 * ml_prob)
    
    # Brand score contributes but is damped to avoid immediate 100
    # unless it's a very clear impersonation
    if brand_score > 0:
        final_score += int(brand_score * 0.8)
    
    return min(100, max(final_score, 0))

def generate_description(features: List[float], final_score: int) -> str:
    # length, dots, hyphens, tokens, ip, age, https, tld, dratio, at, depth, special, hostlen, port, abnormal
    f = features
    reasons: List[str] = []

    # 1. Structural Analysis
    struct = []
    if f[0] > 75: struct.append(f"Abnormally long URL ({int(f[0])} chars).")
    if f[1] > 3: struct.append(f"High number of dots ({int(f[1])}) - potential subdomain spoofing.")
    if f[2] > 2: struct.append(f"Multiple hyphens ({int(f[2])}) often used in phishing domains.")
    if f[10] > 4: struct.append(f"Complex directory structure (depth: {int(f[10])}).")
    if f[11] > 3: struct.append(f"High count of special characters ({int(f[11])}) commonly used for obfuscation.")
    if f[14]: struct.append("Abnormal path formatting (double slashes or nested protocols).")
    
    # 2. Domain & Identity
    ident = []
    if f[4]: ident.append("Direct IP address used instead of a domain name.")
    if f[9]: ident.append("'@' symbol detected in URL - usually hides the true destination.")
    if f[7]: ident.append(f"Suspicious TLD (.{str(f[7])}) frequently linked to malicious activities.")
    if f[8] > 0.3: ident.append(f"High digit-to-letter ratio ({f[8]:.2f}) in domain name.")
    if f[13]: ident.append("Non-standard port detected in URL - potential hidden service.")
    
    # Age details
    age = f[5]
    if age != -1:
        if age < 7: ident.append(f"DOMAIN CRITICALLY NEW: Created only {int(age)} days ago.")
        elif age < 30: ident.append(f"Domain is very young (created {int(age)} days ago).")
        elif age < 365: ident.append(f"Domain is less than a year old ({int(age)} days).")
        else: ident.append(f"Domain appears established (Age: {int(age)} days).")
    else:
        ident.append("Domain age could not be verified - common for newer/private registrations.")

    # 3. Security & Content
    content = []
    if f[3] > 0: content.append(f"Contains {int(f[3])} suspicious keyword(s) (e.g., login, secure, update).")
    if not f[6]: content.append("UNSECURE: Missing HTTPS encryption. Data sent is not protected.")
    else: content.append("Encryption: HTTPS is enabled (verified connection).")

    # 4. Final Risk Assessment
    risk_level = "LOW"
    risk_msg = "No significant threats detected. Domain appears safe."
    if final_score >= 90: 
        risk_level = "CRITICAL"
        risk_msg = "EXTREME THREAT: High probability of phishing or malware. Do not enter any info."
    elif final_score >= 75: 
        risk_level = "HIGH"
        risk_msg = "SIGNIFICANT RISK: Multiple malicious indicators found. Proceed with extreme caution."
    elif final_score >= 25: 
        risk_level = "MODERATE"
        risk_msg = "CAUTION: Some suspicious elements detected. Verify sender identity."

    desc = f"🔍 SECURITY AUDIT REPORT\n"
    desc += f"---------------------------\n"
    desc += f"OVERALL RISK: {risk_level}\n"
    desc += f"SUMMARIZED VERDICT: {risk_msg}\n\n"
    
    desc += "📊 DETAILED INDICATORS:\n"
    if struct:
        desc += "\n[Structural Analysis]\n" + "\n".join([f"  • {r}" for r in struct])
    
    if ident:
        desc += "\n\n[Domain Identity & Infrastructure]\n" + "\n".join([f"  • {r}" for r in ident])
    
    if content:
        desc += "\n\n[Security & Content Analysis]\n" + "\n".join([f"  • {r}" for r in content])

    if not (struct or ident or content):
        desc += "\n[OK] No major anomalies found in the URL structure or domain identity."
    
    return desc

def hybrid_predict_phishing(url: str, lang: str = "en") -> Tuple[str, int, str, str, int, float, str]:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    parsed = urlparse(url.lower())
    domain = parsed.netloc
    
    # --- GLOBAL OFFICIAL NAMESPACE LOGIC ---
    # Patterns that are inherently trusted if the brand name is correct.
    # We check the suffix and then ensure the brand/labels aren't impersonations.
    official_patterns = [
        # India
        ".gov.in", ".nic.in", ".res.in", ".ac.in", ".bank.in", ".mil.in",
        # USA
        ".gov", ".mil", ".edu",
        # UK
        ".gov.uk", ".ac.uk", ".nhs.uk", ".mod.uk",
        # Canada
        ".gc.ca", ".edu.ca",
        # Australia
        ".gov.au", ".edu.au",
        # Others
        ".go.jp", ".ac.jp", ".go.kr", ".ac.kr", ".gob.es", ".gov.br", ".gov.sg", ".edu.sg"
    ]
    
    clean_domain = domain.replace("www.", "").split(":")[0]
    
    # Check if domain ends with any official pattern
    matched_pattern = next((p for p in official_patterns if clean_domain.endswith(p)), None)
    
    if matched_pattern:
        # Security Guard: Even in an official namespace, check for brand impersonation
        # Example: googIe.gov.in or sbi-portal.gov.in
        
        # Isolate the part before the official suffix
        # e.g., for "xyz.gov.in", base is "xyz"
        base_part = clean_domain[:-(len(matched_pattern))]
        labels = [l for l in base_part.split('.') if l]
        
        is_suspicious = False
        for lbl in labels:
            if len(lbl) <= 2: continue # Ignore similarity for very short labels like 'ox', 'i', etc.
            bs, br = check_brand_similarity(lbl)
            if bs >= 40: 
                is_suspicious = True
                break
        
        if not is_suspicious:
            msg = f"[OK] Verified official {matched_pattern} namespace. Safe."
            if lang != "en":
                try:
                    msg = GoogleTranslator(source="en", target=lang).translate(msg)
                except Exception:
                    pass
            return "SAFE", 0, "Verified Official Namespace", msg, 0, 0.0, "LOW"
        # If suspicious, we fall through to full hybrid analysis
    
    # Precise namespace check for remaining special cases (fallback)
    if clean_domain.endswith(".bank.in") or clean_domain.endswith(".gov.in"):
        # Split domain and check each part before the namespace
        parts = clean_domain.split('.')
        # For x.bank.in, parts are ['x', 'bank', 'in']
        # We check every label BEFORE the reserved namespace
        limit = -2 if clean_domain.endswith(".in") else -1
        sub_labels = parts[:limit]
        
        suspicious_namespace = False
        for lbl in sub_labels:
            if not lbl: continue
            bs, br = check_brand_similarity(lbl)
            if bs >= 40: # Catch distance matches and substring matches in sensitive namespaces
                suspicious_namespace = True
                break
        
        if not suspicious_namespace:
            msg = "[OK] Domain belongs to a recognised bank or government namespace. Safe."
            if lang != "en":
                try:
                    msg = GoogleTranslator(source="en", target=lang).translate(msg)
                except Exception:
                    pass
            return "SAFE", 0, "Verified Official Namespace", msg, 0, 0.0, "LOW"
        # If suspicious, fall through to full hybrid analysis
    
    # Check for exact match
    if clean_domain in OFFICIAL_DOMAINS:
        msg = "[OK] Verified official domain. Safe."
        if lang != "en":
            try:
                msg = GoogleTranslator(source="en", target=lang).translate(msg)
            except Exception:
                pass
        return "SAFE", 0, "Verified Official", msg, 0, 0.0, "LOW"
    
    # Check for subdomains of official domains (e.g., mail.google.com, secure.amazon.in)
    # Perform additional scrutiny on subdomain labels so that typos (onlinesbii) don't slip through.
    for official in OFFICIAL_DOMAINS:
        # Check if the domain is a subdomain of an official domain
        if clean_domain.endswith("." + official):
            # isolate the subdomain portion preceding the official root
            prefix = clean_domain[:-(len(official) + 1)]
            suspicious_sub = False
            if prefix:
                for lbl in prefix.split('.'):
                    if not lbl: continue
                    # evaluate label against official brands
                    bs, br = check_brand_similarity(lbl)
                    if bs > 0:
                        suspicious_sub = True
                        break
            if not suspicious_sub:
                msg = f"[OK] Verified subdomain of official site ({official}). Safe."
                if lang != "en":
                    try:
                        msg = GoogleTranslator(source="en", target=lang).translate(msg)
                    except Exception:
                        pass
                return "SAFE", 0, "Verified Official Subdomain", msg, 0, 0.0, "LOW"
            
            # Additional check: if the subdomain itself is just 'www' or empty, it's definitely safe
            if prefix.lower() in ["www", ""]:
                msg = f"[OK] Verified official site ({official}). Safe."
                if lang != "en": msg = GoogleTranslator(source="en", target=lang).translate(msg)
                return "SAFE", 0, "Verified Official", msg, 0, 0.0, "LOW"
            # otherwise fall through to full analysis (not auto-safe)

    # Feature Extraction & Brand Check
    features = extract_features(url)
    brand_score, brand_reason = check_brand_similarity(domain)
    
    heur = heuristic_score(features)
    scaled_features = scaler.transform(np.array(features).reshape(1, -1))
    
    # Get raw ML probability
    ml_prob_raw = model.predict_proba(scaled_features)[0][1] * 100
    
    # Damp ML probability slightly at the extremes to allow for more granularity
    if ml_prob_raw > 95:
        ml_prob = 95 + (ml_prob_raw - 95) * 0.5
    elif ml_prob_raw < 5:
        ml_prob = ml_prob_raw * 0.5
    else:
        ml_prob = ml_prob_raw
    
    # Hybrid Calculation - uses new helper for better granularity
    final_score = hybrid_calculation(heur, ml_prob, brand_score, features)
    
    prediction = "PHISHING" if final_score >= 50 else "SAFE"
    description = generate_description(features, final_score)
    
    if brand_reason:
        description += f"\n\nBrand Warning:\n{brand_reason}"
        
        # Suggest adding to official list if it's a known brand but different TLD
        clean_base = clean_domain.split(".")[0]
        for official in OFFICIAL_DOMAINS:
            if official.split(".")[0] == clean_base and clean_domain not in OFFICIAL_DOMAINS:
                description += (
                    "\n\nNote: this domain shares the official brand name but uses a different TLD. "
                    "If it is legitimately part of the brand, add it to OFFICIAL_DOMAINS to prevent false positives."
                )
                break

    warning = f"Risk Score: {final_score}/100 | Heuristic: {heur} | ML: {ml_prob:.1f}%"
    
    if lang != "en":
        try:
            description = GoogleTranslator(source="en", target=lang).translate(description)
            warning = GoogleTranslator(source="en", target=lang).translate(warning)
        except Exception:
            pass

    risk_level = "LOW"
    if final_score >= 90: risk_level = "CRITICAL"
    elif final_score >= 75: risk_level = "HIGH"
    elif final_score >= 25: risk_level = "MODERATE"
    
    return prediction, final_score, warning, description, heur, ml_prob, risk_level

if __name__ == "__main__":
    train_model()
