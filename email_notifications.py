# email_notifications.py
import smtplib
import ssl
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import threading
import queue
import time
from jinja2 import Template

from error_handling import logger
from db_config import get_db_connection

class EmailNotificationManager:
    def __init__(self, config):
        self.config = config
        self.email_queue = queue.Queue()
        self.worker_thread = None
        self.running = False
        
        # SMTP Configuration
        self.smtp_server = getattr(config, 'SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = getattr(config, 'SMTP_PORT', 587)
        self.smtp_username = getattr(config, 'SMTP_USERNAME', '')
        self.smtp_password = getattr(config, 'SMTP_PASSWORD', '')
        self.smtp_use_tls = getattr(config, 'SMTP_USE_TLS', True)
        self.from_email = getattr(config, 'FROM_EMAIL', self.smtp_username)
        self.from_name = getattr(config, 'FROM_NAME', 'AdminManagement System')
        
        # Default recipients
        self.default_admin_email = getattr(config, 'ADMIN_EMAIL', 'admin@company.com')
        self.default_it_email = getattr(config, 'IT_SUPPORT_EMAIL', 'it@company.com')
        
        # Email templates
        self.templates = self._load_email_templates()
        
        # Start email worker
        self.start_email_worker()
    
    def _load_email_templates(self):
        """Load email templates for different notification types"""
        templates = {}
        
        # Ticket created template
        templates['ticket_created'] = Template("""
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .header { background: #007bff; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .ticket-info { background: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .priority-high { border-left: 4px solid #dc3545; }
                .priority-medium { border-left: 4px solid #ffc107; }
                .priority-low { border-left: 4px solid #28a745; }
                .priority-critical { border-left: 4px solid #6f42c1; }
                .footer { background: #333; color: white; padding: 15px; text-align: center; font-size: 12px; }
                .btn { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎫 New Support Ticket Created</h1>
            </div>
            <div class="content">
                <h2>Ticket Details</h2>
                <div class="ticket-info priority-{{ priority.lower() }}">
                    <h3>{{ title }}</h3>
                    <p><strong>Ticket #:</strong> {{ ticket_number }}</p>
                    <p><strong>Reporter:</strong> {{ reporter_name }}</p>
                    {% if reporter_email %}<p><strong>Email:</strong> {{ reporter_email }}</p>{% endif %}
                    <p><strong>Category:</strong> {{ category }}</p>
                    <p><strong>Priority:</strong> <span style="font-weight: bold; color: {% if priority == 'Critical' %}#6f42c1{% elif priority == 'High' %}#dc3545{% elif priority == 'Medium' %}#ffc107{% else %}#28a745{% endif %}">{{ priority }}</span></p>
                    <p><strong>Branch:</strong> {{ branch_name }}</p>
                    <p><strong>Created:</strong> {{ created_at }}</p>
                    
                    <h4>Description:</h4>
                    <div style="background: #f8f9fa; padding: 10px; border-radius: 3px; white-space: pre-wrap;">{{ description }}</div>
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <a href="{{ admin_url }}/tickets/{{ ticket_id }}" class="btn">View Ticket</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from AdminManagement System</p>
                <p>Please do not reply to this email. For support, contact your IT administrator.</p>
            </div>
        </body>
        </html>
        """)
        
        # Ticket updated template
        templates['ticket_updated'] = Template("""
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .header { background: #28a745; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .ticket-info { background: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .update-info { background: #e7f3ff; padding: 10px; border-radius: 3px; border-left: 4px solid #007bff; }
                .footer { background: #333; color: white; padding: 15px; text-align: center; font-size: 12px; }
                .btn { background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📝 Ticket Updated</h1>
            </div>
            <div class="content">
                <h2>Ticket: {{ title }}</h2>
                <div class="ticket-info">
                    <p><strong>Ticket #:</strong> {{ ticket_number }}</p>
                    <p><strong>Status:</strong> {{ status }}</p>
                    {% if assigned_to %}<p><strong>Assigned to:</strong> {{ assigned_to }}</p>{% endif %}
                    <p><strong>Updated by:</strong> {{ updated_by }}</p>
                    <p><strong>Updated at:</strong> {{ updated_at }}</p>
                </div>
                
                {% if update_message %}
                <div class="update-info">
                    <h4>Update Notes:</h4>
                    <div style="white-space: pre-wrap;">{{ update_message }}</div>
                </div>
                {% endif %}
                
                <div style="text-align: center; margin: 20px 0;">
                    <a href="{{ admin_url }}/tickets/{{ ticket_id }}" class="btn">View Ticket</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from AdminManagement System</p>
            </div>
        </body>
        </html>
        """)
        
        # System alert template
        templates['system_alert'] = Template("""
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .alert-info { background: white; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #dc3545; }
                .footer { background: #333; color: white; padding: 15px; text-align: center; font-size: 12px; }
                .btn { background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>⚠️ System Alert</h1>
            </div>
            <div class="content">
                <div class="alert-info">
                    <h3>{{ alert_title }}</h3>
                    <p><strong>Severity:</strong> {{ severity }}</p>
                    <p><strong>Time:</strong> {{ timestamp }}</p>
                    <p><strong>Branch:</strong> {{ branch_name }}</p>
                    
                    <h4>Details:</h4>
                    <div style="background: #f8f9fa; padding: 10px; border-radius: 3px; white-space: pre-wrap;">{{ alert_message }}</div>
                    
                    {% if recommended_action %}
                    <h4>Recommended Action:</h4>
                    <div style="background: #fff3cd; padding: 10px; border-radius: 3px;">{{ recommended_action }}</div>
                    {% endif %}
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <a href="{{ admin_url }}" class="btn">Access Admin Panel</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated alert from AdminManagement System</p>
            </div>
        </body>
        </html>
        """)
        
        # Device alert template
        templates['device_alert'] = Template("""
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .header { background: #ffc107; color: #212529; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .device-info { background: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .footer { background: #333; color: white; padding: 15px; text-align: center; font-size: 12px; }
                .btn { background: #ffc107; color: #212529; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🖥️ Device Alert</h1>
            </div>
            <div class="content">
                <div class="device-info">
                    <h3>{{ alert_type }}: {{ device_name }}</h3>
                    <p><strong>Device:</strong> {{ device_name }} ({{ mac_address }})</p>
                    <p><strong>IP Address:</strong> {{ ip_address }}</p>
                    <p><strong>Alert Type:</strong> {{ alert_type }}</p>
                    <p><strong>Time:</strong> {{ timestamp }}</p>
                    <p><strong>Branch:</strong> {{ branch_name }}</p>
                    
                    {% if details %}
                    <h4>Details:</h4>
                    <div style="background: #f8f9fa; padding: 10px; border-radius: 3px;">{{ details }}</div>
                    {% endif %}
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <a href="{{ admin_url }}/devices" class="btn">Manage Devices</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated notification from AdminManagement System</p>
            </div>
        </body>
        </html>
        """)
        
        return templates
    
    def start_email_worker(self):
        """Start the email worker thread"""
        if not self.running:
            self.running = True
            self.worker_thread = threading.Thread(target=self._email_worker, daemon=True)
            self.worker_thread.start()
            logger.info("Email notification worker started")
    
    def stop_email_worker(self):
        """Stop the email worker thread"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info("Email notification worker stopped")
    
    def _email_worker(self):
        """Background worker to process email queue"""
        while self.running:
            try:
                # Get email from queue (with timeout)
                email_data = self.email_queue.get(timeout=1)
                self._send_email_internal(email_data)
                self.email_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Email worker error: {e}")
                time.sleep(1)
    
    def _send_email_internal(self, email_data):
        """Internal method to send email via SMTP"""
        try:
            if not self.smtp_server or not self.smtp_username:
                logger.warning("SMTP not configured, skipping email")
                return False
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = email_data['subject']
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = ', '.join(email_data['to'])
            
            if email_data.get('cc'):
                msg['Cc'] = ', '.join(email_data['cc'])
            
            # Add HTML content
            html_part = MIMEText(email_data['html_body'], 'html')
            msg.attach(html_part)
            
            # Add plain text fallback
            if email_data.get('text_body'):
                text_part = MIMEText(email_data['text_body'], 'plain')
                msg.attach(text_part)
            
            # Add attachments if any
            if email_data.get('attachments'):
                for attachment in email_data['attachments']:
                    self._add_attachment(msg, attachment)
            
            # Send email
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls(context=context)
                
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                
                # Combine all recipients
                all_recipients = email_data['to']
                if email_data.get('cc'):
                    all_recipients.extend(email_data['cc'])
                
                server.send_message(msg, to_addrs=all_recipients)
            
            logger.info(f"Email sent successfully: {email_data['subject']} to {email_data['to']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            # Log to database
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO network_logs (branch_id, log_type, message, details, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        1,
                        'email_error',
                        f"Failed to send email: {email_data['subject']}",
                        str(e),
                        datetime.now().isoformat()
                    ))
            except:
                pass
            return False
    
    def _add_attachment(self, msg, attachment):
        """Add attachment to email message"""
        try:
            with open(attachment['path'], 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {attachment["filename"]}'
            )
            msg.attach(part)
        except Exception as e:
            logger.error(f"Failed to add attachment {attachment['path']}: {e}")
    
    def send_email(self, to, subject, template_name, template_data, cc=None, attachments=None, priority='normal'):
        """Queue an email to be sent"""
        try:
            if not isinstance(to, list):
                to = [to]
            
            # Render template
            template = self.templates.get(template_name)
            if not template:
                logger.error(f"Template '{template_name}' not found")
                return False
            
            html_body = template.render(**template_data)
            
            # Create plain text version (basic HTML stripping)
            import re
            text_body = re.sub('<[^<]+?>', '', html_body)
            text_body = re.sub(r'\s+', ' ', text_body).strip()
            
            email_data = {
                'to': to,
                'cc': cc or [],
                'subject': subject,
                'html_body': html_body,
                'text_body': text_body,
                'attachments': attachments or [],
                'priority': priority,
                'template_name': template_name,
                'queued_at': datetime.now().isoformat()
            }
            
            self.email_queue.put(email_data)
            logger.info(f"Email queued: {subject} to {to}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to queue email: {e}")
            return False
    
    def send_ticket_notification(self, ticket_id, notification_type='created', update_details=None):
        """Send ticket-related notification"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Get ticket details
                cursor.execute("""
                    SELECT t.*, b.name as branch_name 
                    FROM tickets t
                    JOIN branches b ON t.branch_id = b.id
                    WHERE t.id = ?
                """, (ticket_id,))
                
                ticket = cursor.fetchone()
                if not ticket:
                    logger.error(f"Ticket {ticket_id} not found")
                    return False
                
                # Get recipients based on ticket priority and type
                recipients = self._get_ticket_recipients(ticket, notification_type)
                
                if not recipients:
                    logger.info(f"No recipients configured for ticket notifications")
                    return True
                
                # Prepare template data
                template_data = dict(ticket)
                template_data.update({
                    'admin_url': f"http://{self.config.ROUTER_IP}:5000",
                    'created_at': self._format_datetime(ticket['created_at']),
                    'updated_at': self._format_datetime(ticket.get('updated_at', ticket['created_at']))
                })
                
                if update_details:
                    template_data.update(update_details)
                
                # Determine subject and template
                if notification_type == 'created':
                    subject = f"🎫 New Support Ticket: {ticket['title']} [#{ticket['ticket_number']}]"
                    template_name = 'ticket_created'
                elif notification_type == 'updated':
                    subject = f"📝 Ticket Updated: {ticket['title']} [#{ticket['ticket_number']}]"
                    template_name = 'ticket_updated'
                else:
                    subject = f"Ticket Notification: {ticket['title']} [#{ticket['ticket_number']}]"
                    template_name = 'ticket_updated'
                
                # Send email
                return self.send_email(
                    to=recipients,
                    subject=subject,
                    template_name=template_name,
                    template_data=template_data,
                    priority='high' if ticket['priority'] in ['High', 'Critical'] else 'normal'
                )
                
        except Exception as e:
            logger.error(f"Failed to send ticket notification: {e}")
            return False
    
    def send_system_alert(self, alert_title, alert_message, severity='medium', branch_id=1, recommended_action=None):
        """Send system alert notification"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM branches WHERE id = ?", (branch_id,))
                branch = cursor.fetchone()
                branch_name = branch['name'] if branch else f"Branch {branch_id}"
            
            recipients = self._get_system_alert_recipients(severity)
            
            template_data = {
                'alert_title': alert_title,
                'alert_message': alert_message,
                'severity': severity.title(),
                'branch_name': branch_name,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'admin_url': f"http://{self.config.ROUTER_IP}:5000",
                'recommended_action': recommended_action
            }
            
            subject = f"⚠️ System Alert: {alert_title} [{severity.upper()}]"
            
            return self.send_email(
                to=recipients,
                subject=subject,
                template_name='system_alert',
                template_data=template_data,
                priority='high' if severity in ['high', 'critical'] else 'normal'
            )
            
        except Exception as e:
            logger.error(f"Failed to send system alert: {e}")
            return False
    
    def send_device_alert(self, device_id, alert_type, details=None):
        """Send device-related alert"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT d.*, b.name as branch_name 
                    FROM devices d
                    JOIN branches b ON d.branch_id = b.id
                    WHERE d.id = ?
                """, (device_id,))
                
                device = cursor.fetchone()
                if not device:
                    logger.error(f"Device {device_id} not found")
                    return False
            
            recipients = self._get_device_alert_recipients()
            
            template_data = {
                'device_name': device['name'],
                'mac_address': device['mac_address'],
                'ip_address': device['ip_address'],
                'alert_type': alert_type,
                'branch_name': device['branch_name'],
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'admin_url': f"http://{self.config.ROUTER_IP}:5000",
                'details': details
            }
            
            subject = f"🖥️ Device Alert: {alert_type} - {device['name']}"
            
            return self.send_email(
                to=recipients,
                subject=subject,
                template_name='device_alert',
                template_data=template_data,
                priority='normal'
            )
            
        except Exception as e:
            logger.error(f"Failed to send device alert: {e}")
            return False
    
    def _get_ticket_recipients(self, ticket, notification_type):
        """Get email recipients for ticket notifications"""
        recipients = []
        
        # Always include IT support email
        if self.default_it_email:
            recipients.append(self.default_it_email)
        
        # Include admin for high/critical priority tickets
        if ticket['priority'] in ['High', 'Critical'] and self.default_admin_email:
            recipients.append(self.default_admin_email)
        
        # Include reporter email if available
        if ticket.get('reporter_email'):
            recipients.append(ticket['reporter_email'])
        
        # Remove duplicates
        return list(set(recipients))
    
    def _get_system_alert_recipients(self, severity):
        """Get email recipients for system alerts"""
        recipients = []
        
        # Always include admin email for system alerts
        if self.default_admin_email:
            recipients.append(self.default_admin_email)
        
        # Include IT support for medium+ severity
        if severity in ['medium', 'high', 'critical'] and self.default_it_email:
            recipients.append(self.default_it_email)
        
        return list(set(recipients))
    
    def _get_device_alert_recipients(self):
        """Get email recipients for device alerts"""
        recipients = []
        
        if self.default_it_email:
            recipients.append(self.default_it_email)
        
        return recipients
    
    def _format_datetime(self, dt_string):
        """Format datetime string for display"""
        try:
            if isinstance(dt_string, str):
                dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
            else:
                dt = dt_string
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(dt_string)
    
    def test_email_configuration(self):
        """Test email configuration by sending a test email"""
        try:
            if not self.smtp_server or not self.smtp_username:
                return {'success': False, 'error': 'SMTP configuration is incomplete'}
            
            test_data = {
                'alert_title': 'Email Configuration Test',
                'alert_message': 'This is a test email to verify that email notifications are working correctly.',
                'severity': 'Low',
                'branch_name': 'Test Branch',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'admin_url': f"http://{self.config.ROUTER_IP}:5000",
                'recommended_action': 'No action required - this is just a test.'
            }
            
            success = self.send_email(
                to=[self.default_admin_email or self.smtp_username],
                subject='📧 AdminManagement Email Test',
                template_name='system_alert',
                template_data=test_data
            )
            
            return {
                'success': success,
                'message': 'Test email queued successfully' if success else 'Failed to queue test email'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_email_stats(self):
        """Get email notification statistics"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Get email-related logs from last 7 days
                week_ago = (datetime.now() - timedelta(days=7)).isoformat()
                
                cursor.execute("""
                    SELECT log_type, COUNT(*) as count
                    FROM network_logs 
                    WHERE log_type IN ('email_sent', 'email_error', 'ticket_notification')
                    AND timestamp >= ?
                    GROUP BY log_type
                """, (week_ago,))
                
                stats = {row['log_type']: row['count'] for row in cursor.fetchall()}
                
                return {
                    'queue_size': self.email_queue.qsize(),
                    'worker_running': self.running,
                    'stats_last_7_days': stats,
                    'smtp_configured': bool(self.smtp_server and self.smtp_username)
                }
                
        except Exception as e:
            logger.error(f"Failed to get email stats: {e}")
            return {'error': str(e)}

def init_email_notifications(app):
    """Initialize email notification system"""
    email_manager = EmailNotificationManager(app.config)
    app.email_manager = email_manager
    return email_manager