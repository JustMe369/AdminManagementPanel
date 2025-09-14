# advanced_security.py
import os
import ssl
import time
import hashlib
import secrets
import hmac
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps
from flask import request, jsonify, session, current_app
import bcrypt
import jwt
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from error_handling import logger
from db_config import get_db_connection

class SecurityManager:
    def __init__(self, config):
        self.config = config
        self.rate_limits = defaultdict(lambda: deque(maxlen=100))
        self.failed_attempts = defaultdict(int)
        self.blocked_ips = defaultdict(datetime)
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Security settings
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.rate_limit_window = 60  # seconds
        self.max_requests_per_window = 100
        
        # Password policy
        self.password_policy = {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
            'special_chars': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
    
    def _get_or_create_encryption_key(self):
        """Get or create encryption key for data protection"""
        key_file = os.path.join(os.path.dirname(__file__), '.security_key')
        
        try:
            with open(key_file, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            # Generate new key
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict permissions
            return key
    
    def generate_ssl_certificate(self, hostname='adminmanagement', days=365):
        """Generate self-signed SSL certificate for HTTPS"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "AdminManagement"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Router"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AdminManagement System"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.IPAddress(ipaddress.IPv4Address("192.168.1.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Save certificate and key
            cert_dir = os.path.join(os.path.dirname(__file__), 'ssl')
            os.makedirs(cert_dir, exist_ok=True)
            
            cert_path = os.path.join(cert_dir, 'cert.pem')
            key_path = os.path.join(cert_dir, 'key.pem')
            
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Restrict permissions
            os.chmod(cert_path, 0o644)
            os.chmod(key_path, 0o600)
            
            logger.info(f"SSL certificate generated: {cert_path}")
            return cert_path, key_path
            
        except Exception as e:
            logger.error(f"Failed to generate SSL certificate: {e}")
            return None, None
    
    def create_ssl_context(self):
        """Create SSL context for HTTPS"""
        cert_path, key_path = self.generate_ssl_certificate()
        
        if cert_path and key_path:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.load_cert_chain(cert_path, key_path)
            return context
        
        return None
    
    def rate_limit(self, key=None, max_requests=None, window=None):
        """Rate limiting decorator"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Get client identifier
                if key:
                    client_id = key
                else:
                    client_id = request.remote_addr
                
                # Use default values if not specified
                max_reqs = max_requests or self.max_requests_per_window
                time_window = window or self.rate_limit_window
                
                now = time.time()
                requests = self.rate_limits[client_id]
                
                # Clean old requests
                while requests and requests[0] < now - time_window:
                    requests.popleft()
                
                # Check limit
                if len(requests) >= max_reqs:
                    logger.warning(f"Rate limit exceeded for {client_id}")
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': int(time_window - (now - requests[0]))
                    }), 429
                
                # Add current request
                requests.append(now)
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def validate_password(self, password):
        """Validate password against security policy"""
        errors = []
        
        if len(password) < self.password_policy['min_length']:
            errors.append(f"Password must be at least {self.password_policy['min_length']} characters long")
        
        if self.password_policy['require_uppercase'] and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.password_policy['require_lowercase'] and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.password_policy['require_numbers'] and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if self.password_policy['require_special']:
            special_chars = self.password_policy['special_chars']
            if not any(c in special_chars for c in password):
                errors.append(f"Password must contain at least one special character: {special_chars}")
        
        # Check for common weak passwords
        weak_passwords = ['password', '123456', 'admin', 'root', 'guest']
        if password.lower() in weak_passwords:
            errors.append("Password is too common and weak")
        
        return errors
    
    def hash_password(self, password):
        """Hash password using bcrypt with salt"""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password, hashed):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_secure_token(self, user_id, expires_in=3600):
        """Generate secure JWT token"""
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),
            'jti': secrets.token_hex(16)  # Unique token ID
        }
        
        token = jwt.encode(payload, self.encryption_key, algorithm='HS256')
        return token
    
    def verify_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.encryption_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return {'error': 'Token has expired'}
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}
    
    def encrypt_sensitive_data(self, data):
        """Encrypt sensitive data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.cipher_suite.encrypt(data).decode('utf-8')
    
    def decrypt_sensitive_data(self, encrypted_data):
        """Decrypt sensitive data"""
        try:
            decrypted = self.cipher_suite.decrypt(encrypted_data.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def check_ip_blocked(self, ip_address):
        """Check if IP is blocked due to failed attempts"""
        if ip_address in self.blocked_ips:
            block_time = self.blocked_ips[ip_address]
            if datetime.now() < block_time:
                return True
            else:
                # Unblock expired IPs
                del self.blocked_ips[ip_address]
                if ip_address in self.failed_attempts:
                    del self.failed_attempts[ip_address]
        return False
    
    def record_failed_attempt(self, identifier):
        """Record failed login attempt"""
        self.failed_attempts[identifier] += 1
        
        if self.failed_attempts[identifier] >= self.max_login_attempts:
            # Block IP
            block_until = datetime.now() + self.lockout_duration
            self.blocked_ips[identifier] = block_until
            
            logger.warning(f"IP {identifier} blocked due to {self.max_login_attempts} failed attempts")
            
            # Log to database
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO network_logs (branch_id, log_type, message, details, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        1,  # Default branch
                        'security',
                        f"IP {identifier} blocked due to failed login attempts",
                        f'{{"failed_attempts": {self.failed_attempts[identifier]}, "blocked_until": "{block_until.isoformat()}"}}',
                        datetime.now().isoformat()
                    ))
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")
    
    def clear_failed_attempts(self, identifier):
        """Clear failed attempts for successful login"""
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]
        if identifier in self.blocked_ips:
            del self.blocked_ips[identifier]
    
    def secure_headers(self):
        """Add security headers to response"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                response = f(*args, **kwargs)
                
                # Add security headers
                if hasattr(response, 'headers'):
                    response.headers['X-Content-Type-Options'] = 'nosniff'
                    response.headers['X-Frame-Options'] = 'DENY'
                    response.headers['X-XSS-Protection'] = '1; mode=block'
                    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
                    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:;"
                    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
                    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
                
                return response
            return decorated_function
        return decorator
    
    def sanitize_input(self, input_string, max_length=255):
        """Sanitize user input to prevent XSS and injection attacks"""
        if not isinstance(input_string, str):
            return str(input_string)[:max_length]
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n']
        sanitized = input_string
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Limit length
        sanitized = sanitized[:max_length]
        
        # Remove SQL injection patterns
        sql_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
            r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
            r'(\b(OR|AND)\s+[\'"].*[\'"])',
            r'(--|/\*|\*/)',
        ]
        
        for pattern in sql_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()
    
    def validate_csrf_token(self, token):
        """Validate CSRF token"""
        try:
            if 'csrf_token' not in session:
                return False
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(session['csrf_token'], token)
        except Exception:
            return False
    
    def generate_csrf_token(self):
        """Generate CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    def audit_log(self, user_id, action, resource, details=None):
        """Create audit log entry"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO network_logs (branch_id, log_type, message, details, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    1,  # Default branch - would get from user context
                    'audit',
                    f"User {user_id} performed {action} on {resource}",
                    str(details) if details else None,
                    datetime.now().isoformat()
                ))
                logger.info(f"Audit: User {user_id} - {action} on {resource}")
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
    
    def check_session_validity(self, user_id, session_token):
        """Check if user session is valid"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT token_expires, status FROM users 
                    WHERE id = ? AND session_token = ?
                """, (user_id, session_token))
                
                result = cursor.fetchone()
                if not result:
                    return False
                
                # Check if token expired
                if result['token_expires']:
                    expires = datetime.fromisoformat(result['token_expires'])
                    if expires < datetime.now():
                        return False
                
                # Check if user is still active
                return result['status'] == 'Active'
                
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False
    
    def invalidate_user_sessions(self, user_id):
        """Invalidate all sessions for a user"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET session_token = NULL, token_expires = NULL 
                    WHERE id = ?
                """, (user_id,))
                logger.info(f"Invalidated all sessions for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to invalidate sessions: {e}")

# Security decorators for Flask routes
def require_secure_auth(roles=None):
    """Enhanced authentication decorator with security features"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get security manager
            security_manager = current_app.security_manager
            
            # Check IP blocking
            client_ip = request.remote_addr
            if security_manager.check_ip_blocked(client_ip):
                return jsonify({'error': 'IP address is temporarily blocked'}), 403
            
            # Get token from header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            
            # Verify token
            payload = security_manager.verify_token(token)
            if 'error' in payload:
                return jsonify({'error': payload['error']}), 401
            
            # Check session validity
            user_id = payload.get('user_id')
            if not security_manager.check_session_validity(user_id, token):
                return jsonify({'error': 'Session expired or invalid'}), 401
            
            # Get user details and check roles
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT id, username, user_type, branch_id, status 
                        FROM users WHERE id = ?
                    """, (user_id,))
                    
                    user = cursor.fetchone()
                    if not user or user['status'] != 'Active':
                        return jsonify({'error': 'User account is not active'}), 401
                    
                    # Check role authorization
                    if roles and user['user_type'] not in roles:
                        return jsonify({'error': 'Insufficient permissions'}), 403
                    
                    # Store user in request context
                    request.current_user = dict(user)
                    
            except Exception as e:
                logger.error(f"User lookup error: {e}")
                return jsonify({'error': 'Authentication error'}), 500
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Initialize security manager
def init_security_manager(app):
    """Initialize security manager with Flask app"""
    app.security_manager = SecurityManager(app.config)
    return app.security_manager