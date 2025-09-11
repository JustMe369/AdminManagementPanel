# validation.py
from functools import wraps
from flask import request, jsonify

def validate_json(schema):
    """JSON validation decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Request must be JSON'}), 400
            
            data = request.get_json()
            errors = {}
            
            for field, rules in schema.items():
                if rules.get('required', False) and field not in data:
                    errors[field] = 'This field is required'
                    continue
                
                if field in data:
                    value = data[field]
                    
                    # Type validation
                    expected_type = rules.get('type', str)
                    if not isinstance(value, expected_type):
                        errors[field] = f'Must be {expected_type.__name__}'
                        continue
                    
                    # Custom validation functions
                    for validator in rules.get('validators', []):
                        error = validator(value)
                        if error:
                            errors[field] = error
                            break
            
            if errors:
                return jsonify({'error': 'Validation failed', 'details': errors}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Validation schemas
USER_SCHEMA = {
    'username': {
        'type': str,
        'required': True,
        'validators': [
            lambda x: None if 3 <= len(x) <= 20 else 'Username must be 3-20 characters',
            lambda x: None if re.match(r'^[a-zA-Z0-9_]+$', x) else 'Invalid characters'
        ]
    },
    'password': {
        'type': str,
        'required': True,
        'validators': [
            lambda x: None if len(x) >= 8 else 'Password must be at least 8 characters'
        ]
    }
}