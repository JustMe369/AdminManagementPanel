# security.py
import re
from functools import wraps
from flask import request, jsonify

def sanitize_input(input_string):
    """Sanitize user input to prevent XSS and injection attacks"""
    if not input_string:
        return input_string
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;\\\'"<>]', '', str(input_string))
    return sanitized.strip()

def validate_mac_address(mac):
    """Validate MAC address format"""
    return re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac) is not None

def validate_ip_address(ip):
    """Validate IP address format"""
    return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) is not None

def require_secure_headers(f):
    """Add security headers to responses"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    return decorated_function