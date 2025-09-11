# auth.py
import bcrypt
import secrets
import sqlite3
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session, g
from db_config import get_db_connection
from error_handling import logger

def hash_password(password):
    """Secure password hashing with bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def validate_session_token(token):
    """Validate a session token and return the associated user"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, username, branch_id, user_type as role, token_expires 
            FROM users 
            WHERE session_token = ? AND status != 'Blocked'
            """, (token,))
            
            user = cursor.fetchone()
            
            if not user:
                return None
            
            # Check if token has expired
            expires = datetime.fromisoformat(user['token_expires'])
            if expires < datetime.now():
                return None
                
            return dict(user)
    except Exception as e:
        logger.error(f"Error validating session token: {e}")
        return None

def require_auth(roles=None):
    """Enhanced authentication decorator with role support"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return jsonify({'error': 'Authentication required'}), 401
            
            # Validate token and check expiration
            user = validate_session_token(token)
            if not user:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Role-based access control
            if roles and user['role'] not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add user to request context
            request.current_user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator


class UserManager:
    """Class to handle user management operations"""
    
    def __init__(self, config):
        self.config = config
        self.max_failed_attempts = config.MAX_FAILED_LOGIN_ATTEMPTS
        self.lockout_duration = config.ACCOUNT_LOCKOUT_DURATION
    
    def create_user(self, username, password, user_type='User', branch_id=1):
        """Create a new user"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    return {'error': 'Username already exists'}, 409
                
                # Validate password against policy
                password_validation = self._validate_password(password)
                if 'error' in password_validation:
                    return password_validation, 400
                
                # Create user
                hashed_password = hash_password(password)
                cursor.execute("""
                INSERT INTO users (username, password_hash, user_type, branch_id, status, created_at) 
                VALUES (?, ?, ?, ?, 'Active', ?)
                """, (username, hashed_password, user_type, branch_id, datetime.now().isoformat()))
                
                user_id = cursor.lastrowid
                
                return {
                    'id': user_id,
                    'username': username,
                    'user_type': user_type,
                    'branch_id': branch_id,
                    'created_at': datetime.now().isoformat()
                }, 201
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return {'error': 'Failed to create user'}, 500
    
    def update_user(self, user_id, data):
        """Update user information"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
                if not cursor.fetchone():
                    return {'error': 'User not found'}, 404
                
                # Build update query
                update_fields = []
                params = []
                
                if 'username' in data:
                    # Check if username is already taken
                    cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", 
                                 (data['username'], user_id))
                    if cursor.fetchone():
                        return {'error': 'Username already exists'}, 409
                    
                    update_fields.append("username = ?")
                    params.append(data['username'])
                
                if 'password' in data:
                    # Validate password against policy
                    password_validation = self._validate_password(data['password'])
                    if 'error' in password_validation:
                        return password_validation, 400
                    
                    hashed_password = hash_password(data['password'])
                    update_fields.append("password_hash = ?")
                    params.append(hashed_password)
                
                if 'user_type' in data:
                    update_fields.append("user_type = ?")
                    params.append(data['user_type'])
                
                if 'branch_id' in data:
                    update_fields.append("branch_id = ?")
                    params.append(data['branch_id'])
                
                if 'status' in data:
                    update_fields.append("status = ?")
                    params.append(data['status'])
                
                if not update_fields:
                    return {'error': 'No fields to update'}, 400
                
                # Add updated_at timestamp
                update_fields.append("updated_at = ?")
                params.append(datetime.now().isoformat())
                
                # Add user_id to params
                params.append(user_id)
                
                # Execute update
                query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
                cursor.execute(query, params)
                
                return {'message': 'User updated successfully'}, 200
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            return {'error': 'Failed to update user'}, 500
    
    def delete_user(self, user_id):
        """Delete a user"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
                if not cursor.fetchone():
                    return {'error': 'User not found'}, 404
                
                # Delete user
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                
                return {'message': 'User deleted successfully'}, 200
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return {'error': 'Failed to delete user'}, 500
    
    def handle_failed_login(self, username):
        """Handle failed login attempt"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Update failed login attempts
                cursor.execute("""
                UPDATE users 
                SET login_attempts = login_attempts + 1,
                    last_failed_login = ?
                WHERE username = ?
                """, (datetime.now().isoformat(), username))
                
                # Check if account should be locked
                cursor.execute("""
                SELECT login_attempts FROM users WHERE username = ?
                """, (username,))
                
                user = cursor.fetchone()
                if user and user['login_attempts'] >= self.max_failed_attempts:
                    # Lock account
                    cursor.execute("""
                    UPDATE users 
                    SET status = 'Locked',
                        lockout_until = ?
                    WHERE username = ?
                    """, ((datetime.now() + timedelta(minutes=self.lockout_duration)).isoformat(), username))
                    
                    return {'error': f'Account locked for {self.lockout_duration} minutes due to too many failed attempts'}, 403
                
                return {'error': 'Invalid credentials'}, 401
        except Exception as e:
            logger.error(f"Error handling failed login: {e}")
            return {'error': 'Authentication error'}, 500
    
    def _validate_password(self, password):
        """Validate password against policy"""
        if len(password) < self.config.PASSWORD_MIN_LENGTH:
            return {'error': f'Password must be at least {self.config.PASSWORD_MIN_LENGTH} characters long'}
        
        if self.config.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return {'error': 'Password must contain at least one uppercase letter'}
        
        if self.config.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return {'error': 'Password must contain at least one lowercase letter'}
        
        if self.config.PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            return {'error': 'Password must contain at least one digit'}
        
        if self.config.PASSWORD_REQUIRE_SPECIAL and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`' for c in password):
            return {'error': 'Password must contain at least one special character'}
        
        return {'valid': True}