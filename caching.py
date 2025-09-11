# caching.py
import time
from functools import wraps

class ResponseCache:
    def __init__(self, ttl=300):  # 5 minutes default
        self.cache = {}
        self.ttl = ttl
    
    def get(self, key):
        if key in self.cache:
            data, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return data
            else:
                del self.cache[key]
        return None
    
    def set(self, key, value):
        self.cache[key] = (value, time.time())
    
    def clear(self):
        self.cache.clear()

# Global cache instance
cache = ResponseCache()

def cached_response(ttl=300):
    """Cache decorator for API responses"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            cache_key = f"{f.__name__}:{str(args)}:{str(kwargs)}"
            
            # Try to get from cache
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
            
            # Generate response
            response = f(*args, **kwargs)
            
            # Cache the response
            cache.set(cache_key, response)
            
            return response
        return decorated_function
    return decorator