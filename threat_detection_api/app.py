from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import re

app = Flask(__name__)
print("Flask name:", app.name)
print("__name__ value:", __name__)


MAX_LOGIN_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 5
RATE_LIMIT_MAX = 10
RATE_LIMIT_WINDOW = 60

login_attempts = {}
blocked_ips = {}
rate_limit_tracker = {}

security_events = []




def is_blocked(ip):
    if ip in blocked_ips:
        print("IP Blocked")
        if  datetime.now() > blocked_ips[ip]:
            return False
        else:
            print("Still blocked")
            return True
    else:
        print("IP not in dictionary at all it is blocked")

        return False
    
    
def block_ip(ip, reason):
    # step 1: add to blocked_ips dictionary
    # step 2: log the event
    blocked_ips[ip] = datetime.now() + timedelta(minutes=BLOCK_DURATION_MINUTES)
    security_events.append({
        "timestamp" : datetime.now().isoformat(),
        "event_type" : "IP_BLOCKED",
        "ip" : ip ,
        "details" : reason

    })


        
def check_rate_limit(ip):
    now = datetime.now()
    if ip not in rate_limit_tracker:
        rate_limit_tracker[ip] = []
    else:
        list_of_timestamp = rate_limit_tracker.get(ip)
        for timestamp in list_of_timestamp:
            if (now - timestamp).seconds > RATE_LIMIT_WINDOW:
                list_of_timestamp.remove(timestamp)

    print(rate_limit_tracker)
    rate_limit_tracker[ip].append(now)
    print(rate_limit_tracker,"qqqqqqqqqqqqqqq")

    if len(rate_limit_tracker[ip]) > RATE_LIMIT_MAX:
        return False
    return True


def detect_sql_injection(value):
    patterns = [
        r"OR\s+\d+=\d+",      # OR 1=1
        r"(DROP|DELETE|INSERT|UPDATE|SELECT|UNION)\s+",  # SQL commands
        r"';\s*--",            # '; --
    ]
    
    for pattern in patterns:
        if re.search(pattern, value, re.IGNORECASE):                # what goes here?
            return True                                             # found — what do you return?
    return False                                                    # nothing found — what do you return?



def detect_xss(value):
    patterns = [r"<script.*?>",r"javascript:", r"on\w+\s*=",r"<iframe.*?>",
        ]
    for pattern in patterns:
        # your code here
        if re.search(pattern,value,re.IGNORECASE):
            return True
    return False

@app.before_request
def security_middleware():
    ip= request.remote_addr
    if not check_rate_limit(ip):
        block_ip(ip,"rate limmit exceded")
        return jsonify({ 
            "error": 'rate limit exceede',
            "status": 'blocked'
        }), 429
    
    
@app.after_request
def add_security_headers(response):
    print("Adding security headers...")
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'

    return response


@app.route('/')
def home():
    return jsonify({
        "service": "FinSec Threat Detection API",
        "version": "1.0",
        "status": "running"
    })

@app.route('/api/login', methods=['POST'])
def login():
    ip = request.remote_addr               # get IP address
    data = request.get_json()              # get JSON body
    username = data.get('username')          # get username from data
    password = data.get('password')          # get password from data

    if is_blocked(ip):
        return jsonify({
            "error": "Your IP is blocked due to suspicious activity",
            "status": "blocked"
        }),403
    
    if detect_sql_injection(username) or detect_sql_injection(password):
        block_ip(ip,"SQL injection attempt")
        return jsonify({
            "error": 'Malicious input detected',
            "status": "Blocked"
        }),400
    
    if detect_xss(username) or detect_xss(password):
        block_ip(ip,"XSS attempt")
        return jsonify({
            "error": 'Malicious input detected',
            "status": "Blocked"
        }),400
    
    now = datetime.now()
    if ip not in login_attempts:
       
        login_attempts[ip] = []
    login_attempts[ip].append(now)

    if len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS:
        block_ip(ip, 'More Login attempts')
        return jsonify({
            "error": "Too many failed attempts. IP blocked for 5 minutess.",
            "status":"Blocked",

        }),403
    
    if username == "admin" and password == "password123":
        # success — what do you return?
        return jsonify({
            "message": "Succesfull Login", 
            "status":"Done"
        }),200
    else:
        # failed — what do you return?
        return jsonify({
            "error": "Username or password wrong", 
            "attempts_remaining": MAX_LOGIN_ATTEMPTS - len(login_attempts[ip])

        }),401

@app.route('/api/unblock', methods=['POST'])
def unblock():
    blocked_ips.clear()
    login_attempts.clear()
    return jsonify({"message": "All IPs unblocked"}), 200

@app.route('/api/security/events', methods=['GET'])
def get_security_events():
    return jsonify({
        "events":security_events,
        "count": len(security_events)
    }), 200

@app.route('/api/security/blocked', methods=['GET'])
def get_blocked_ips():
    active_blocks = {}
    for ip, blocked_until in blocked_ips.items():
        active_blocks[ip] = blocked_until.isoformat()
    return jsonify({
        "blocked_ips": active_blocks,
        "count": len(active_blocks)
    }), 200



if __name__ == "__main__":
    print("FinSec Threat Detection API starting...")
    app.run(debug=False, host='0.0.0.0', port=5000)