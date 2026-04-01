from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os

app = Flask(__name__)
CORS(app)

KEYWORDS = {
    'aadhaar': ['aadhaar', 'आधार', 'आधार'],
    'verify': ['verify', 'वेरीफाई', 'पडताळा', 'सत्यापित'],
    'urgent': ['urgent', 'तुरंत', 'तात्काळ', 'जल्दी'],
    'suspended': ['suspended', 'निलंबित', 'ब्लॉक', 'blocked'],
    'otp': ['otp', 'ओटीपी', 'one time password'],
    'password': ['password', 'पासवर्ड', 'कूटशब्द'],
    'bank': ['bank', 'बैंक', 'बँक', 'account'],
    'click': ['click here', 'यहाँ क्लिक करें', 'इथे क्लिक करा'],
}

@app.route('/')
def home():
    return jsonify({"status": "running", "message": "BharatShield API 🇮🇳"})

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url', '').lower()
    text = data.get('text', '').lower()
    
    score = 0
    reasons = []
    
    for domain in ['.xyz', '.top', '.click', '.loan', '.gq', '.ml']:
        if domain in url:
            score += 30
            reasons.append(f"Suspicious domain: {domain}")
            break
    if any(w in url for w in ['verify', 'secure', 'login', 'update']):
        score += 20
        reasons.append("Suspicious URL keywords")
    
    for category, words in KEYWORDS.items():
        for word in words:
            if word in text:
                score += 15
                reasons.append(f"Found: {word}")
                break
    
    if re.search(r'\d{10}', text):
        score += 10
        reasons.append("Contains phone number")
    
    if text.count('!') > 3:
        score += 10
        reasons.append("Excessive exclamation marks")
    
    score = min(score, 100)
    
    if score >= 70:
        level, msg = 'DANGER', '🚨 PHISHING DETECTED! Do not enter any information.'
    elif score >= 40:
        level, msg = 'WARNING', '⚠️ Be cautious. This might be suspicious.'
    else:
        level, msg = 'SAFE', '✅ Appears safe.'
    
    return jsonify({
        'threat_level': level,
        'score': score,
        'message': msg,
        'reasons': reasons
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
