# intelligent_guest_system.py
import random

class IntelligentGuestSystem:
    def personalize_guest_portal(self, mac_address):
        """Personalize the guest portal based on device type and previous visits"""
        device_type = self.detect_device_type(mac_address)
        visit_count = self.get_visit_count(mac_address)
        
        # Custom welcome messages based on visit count
        if visit_count == 0:
            welcome_message = "Welcome to our WiFi! Enjoy your first visit."
            time_limit = "1 hour"
        elif visit_count == 1:
            welcome_message = "Welcome back! We've extended your access time."
            time_limit = "2 hours"
        else:
            welcome_message = "Welcome back, valued guest! Enjoy premium access."
            time_limit = "4 hours"
        
        # Special offers based on time of day
        current_hour = datetime.now().hour
        if 7 <= current_hour < 10:
            promotion = "Morning Special: 10% off breakfast items!"
        elif 14 <= current_hour < 16:
            promotion = "Afternoon Deal: Buy one coffee, get one free!"
        else:
            promotion = "Enjoy your stay with us!"
        
        return {
            'welcome_message': welcome_message,
            'time_limit': time_limit,
            'promotion': promotion,
            'personalized_background': self.select_background(device_type)
        }
    
    def detect_device_type(self, mac_address):
        """Determine device type from MAC address prefix"""
        apple_prefixes = ['00:1C:B3', '00:23:DF', '00:3E:E1']
        samsung_prefixes = ['00:1E:7D', '00:1F:FA', '00:23:39']
        
        if any(mac_address.startswith(p) for p in apple_prefixes):
            return 'apple'
        elif any(mac_address.startswith(p) for p in samsung_prefixes):
            return 'samsung'
        else:
            return 'generic'
    
    def select_background(self, device_type):
        """Select appropriate background based on device type"""
        backgrounds = {
            'apple': 'premium_modern_design.html',
            'samsung': 'android_optimized_design.html',
            'generic': 'default_design.html'
        }
        return backgrounds.get(device_type, 'default_design.html')