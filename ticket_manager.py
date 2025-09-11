# ticket_manager.py
import json
import uuid
import time
from datetime import datetime
import sqlite3
from error_handling import logger
from db_config import get_db_connection

class TicketManager:
    def __init__(self, config):
        self.config = config
        self.ticket_table = config.TICKET_TABLE
        self.ticket_history_table = config.TICKET_HISTORY_TABLE
        self.ticket_attachment_table = config.TICKET_ATTACHMENT_TABLE
        self._ensure_tables_exist()
    
    def _ensure_tables_exist(self):
        """Ensure that all required tables exist in the database"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Create tickets table if it doesn't exist
                cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {self.ticket_table} (
                    id TEXT PRIMARY KEY,
                    branch_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    category TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    assigned_to TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    due_date INTEGER,
                    tags TEXT,
                    related_devices TEXT
                )
                ''')
                
                # Create ticket history table if it doesn't exist
                cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {self.ticket_history_table} (
                    id TEXT PRIMARY KEY,
                    ticket_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    performed_by TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    FOREIGN KEY (ticket_id) REFERENCES {self.ticket_table}(id)
                )
                ''')
                
                # Create ticket attachments table if it doesn't exist
                cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {self.ticket_attachment_table} (
                    id TEXT PRIMARY KEY,
                    ticket_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    uploaded_by TEXT NOT NULL,
                    uploaded_at INTEGER NOT NULL,
                    FOREIGN KEY (ticket_id) REFERENCES {self.ticket_table}(id)
                )
                ''')
                
                conn.commit()
        except Exception as e:
            logger.error(f"Error ensuring ticket tables exist: {e}")
            raise
    
    def create_ticket(self, ticket_data):
        """Create a new ticket"""
        try:
            # Validate required fields
            required_fields = ['branch_id', 'title', 'description', 'priority', 'category', 'created_by']
            for field in required_fields:
                if field not in ticket_data:
                    return {'error': f'Missing required field: {field}'}
            
            # Generate a unique ID for the ticket
            ticket_id = str(uuid.uuid4())
            
            # Set default values for optional fields
            ticket_data['status'] = ticket_data.get('status', 'open')
            ticket_data['assigned_to'] = ticket_data.get('assigned_to', None)
            ticket_data['tags'] = json.dumps(ticket_data.get('tags', []))
            ticket_data['related_devices'] = json.dumps(ticket_data.get('related_devices', []))
            
            # Set timestamps
            current_time = int(time.time())
            ticket_data['created_at'] = current_time
            ticket_data['updated_at'] = current_time
            
            # Convert due_date to timestamp if provided
            if 'due_date' in ticket_data and ticket_data['due_date']:
                if isinstance(ticket_data['due_date'], str):
                    # Convert ISO format date string to timestamp
                    due_date = datetime.fromisoformat(ticket_data['due_date'].replace('Z', '+00:00'))
                    ticket_data['due_date'] = int(due_date.timestamp())
            else:
                ticket_data['due_date'] = None
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Insert the ticket
                cursor.execute(f'''
                INSERT INTO {self.ticket_table} (
                    id, branch_id, title, description, status, priority, category,
                    created_by, assigned_to, created_at, updated_at, due_date, tags, related_devices
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ticket_id, ticket_data['branch_id'], ticket_data['title'], ticket_data['description'],
                    ticket_data['status'], ticket_data['priority'], ticket_data['category'],
                    ticket_data['created_by'], ticket_data['assigned_to'], ticket_data['created_at'],
                    ticket_data['updated_at'], ticket_data['due_date'], ticket_data['tags'], ticket_data['related_devices']
                ))
                
                # Add ticket creation to history
                history_id = str(uuid.uuid4())
                cursor.execute(f'''
                INSERT INTO {self.ticket_history_table} (
                    id, ticket_id, action, details, performed_by, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, ticket_id, 'created', 'Ticket created', ticket_data['created_by'], current_time
                ))
                
                conn.commit()
                
                # Return the created ticket with its ID
                ticket_data['id'] = ticket_id
                return {
                    'success': True,
                    'ticket': ticket_data,
                    'message': 'Ticket created successfully'
                }
                
        except Exception as e:
            logger.error(f"Error creating ticket: {e}")
            return {'error': str(e)}
    
    def get_ticket(self, ticket_id):
        """Get a ticket by ID"""
        try:
            with get_db_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get the ticket
                cursor.execute(f'''
                SELECT * FROM {self.ticket_table} WHERE id = ?
                ''', (ticket_id,))
                
                ticket = cursor.fetchone()
                if not ticket:
                    return {'error': f'Ticket with ID {ticket_id} not found'}
                
                # Convert to dict
                ticket_dict = dict(ticket)
                
                # Parse JSON fields
                ticket_dict['tags'] = json.loads(ticket_dict['tags']) if ticket_dict['tags'] else []
                ticket_dict['related_devices'] = json.loads(ticket_dict['related_devices']) if ticket_dict['related_devices'] else []
                
                # Get ticket history
                cursor.execute(f'''
                SELECT * FROM {self.ticket_history_table} WHERE ticket_id = ? ORDER BY timestamp DESC
                ''', (ticket_id,))
                
                history = [dict(row) for row in cursor.fetchall()]
                
                # Get ticket attachments
                cursor.execute(f'''
                SELECT * FROM {self.ticket_attachment_table} WHERE ticket_id = ? ORDER BY uploaded_at DESC
                ''', (ticket_id,))
                
                attachments = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'ticket': ticket_dict,
                    'history': history,
                    'attachments': attachments
                }
                
        except Exception as e:
            logger.error(f"Error getting ticket: {e}")
            return {'error': str(e)}
    
    def update_ticket(self, ticket_id, update_data, performed_by):
        """Update a ticket"""
        try:
            # Get the current ticket to ensure it exists
            current_ticket = self.get_ticket(ticket_id)
            if 'error' in current_ticket:
                return current_ticket
            
            # Fields that can be updated
            allowed_fields = [
                'title', 'description', 'status', 'priority', 'category',
                'assigned_to', 'due_date', 'tags', 'related_devices'
            ]
            
            # Filter out fields that are not allowed to be updated
            update_fields = {k: v for k, v in update_data.items() if k in allowed_fields}
            
            if not update_fields:
                return {'error': 'No valid fields to update'}
            
            # Set updated timestamp
            update_fields['updated_at'] = int(time.time())
            
            # Convert due_date to timestamp if provided
            if 'due_date' in update_fields and update_fields['due_date']:
                if isinstance(update_fields['due_date'], str):
                    # Convert ISO format date string to timestamp
                    due_date = datetime.fromisoformat(update_fields['due_date'].replace('Z', '+00:00'))
                    update_fields['due_date'] = int(due_date.timestamp())
            
            # Convert list fields to JSON strings
            if 'tags' in update_fields:
                update_fields['tags'] = json.dumps(update_fields['tags'])
            
            if 'related_devices' in update_fields:
                update_fields['related_devices'] = json.dumps(update_fields['related_devices'])
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Build the update query
                set_clause = ', '.join([f"{field} = ?" for field in update_fields.keys()])
                values = list(update_fields.values())
                values.append(ticket_id)  # For the WHERE clause
                
                # Update the ticket
                cursor.execute(f'''
                UPDATE {self.ticket_table} SET {set_clause} WHERE id = ?
                ''', values)
                
                # Add update to history
                history_id = str(uuid.uuid4())
                details = json.dumps({
                    'updated_fields': list(update_fields.keys()),
                    'old_values': {k: current_ticket['ticket'][k] for k in update_fields.keys() if k in current_ticket['ticket']},
                    'new_values': update_fields
                })
                
                cursor.execute(f'''
                INSERT INTO {self.ticket_history_table} (
                    id, ticket_id, action, details, performed_by, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, ticket_id, 'updated', details, performed_by, update_fields['updated_at']
                ))
                
                conn.commit()
                
                # Return the updated ticket
                return {
                    'success': True,
                    'message': 'Ticket updated successfully',
                    'ticket_id': ticket_id
                }
                
        except Exception as e:
            logger.error(f"Error updating ticket: {e}")
            return {'error': str(e)}
    
    def add_comment(self, ticket_id, comment_data):
        """Add a comment to a ticket"""
        try:
            # Validate required fields
            required_fields = ['comment', 'created_by']
            for field in required_fields:
                if field not in comment_data:
                    return {'error': f'Missing required field: {field}'}
            
            # Check if ticket exists
            ticket = self.get_ticket(ticket_id)
            if 'error' in ticket:
                return ticket
            
            # Add comment to history
            history_id = str(uuid.uuid4())
            current_time = int(time.time())
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute(f'''
                INSERT INTO {self.ticket_history_table} (
                    id, ticket_id, action, details, performed_by, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, ticket_id, 'comment', comment_data['comment'],
                    comment_data['created_by'], current_time
                ))
                
                # Update the ticket's updated_at timestamp
                cursor.execute(f'''
                UPDATE {self.ticket_table} SET updated_at = ? WHERE id = ?
                ''', (current_time, ticket_id))
                
                conn.commit()
                
                return {
                    'success': True,
                    'message': 'Comment added successfully',
                    'ticket_id': ticket_id,
                    'comment_id': history_id
                }
                
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return {'error': str(e)}
    
    def add_attachment(self, ticket_id, attachment_data):
        """Add an attachment to a ticket"""
        try:
            # Validate required fields
            required_fields = ['filename', 'file_path', 'file_type', 'file_size', 'uploaded_by']
            for field in required_fields:
                if field not in attachment_data:
                    return {'error': f'Missing required field: {field}'}
            
            # Check if ticket exists
            ticket = self.get_ticket(ticket_id)
            if 'error' in ticket:
                return ticket
            
            # Generate a unique ID for the attachment
            attachment_id = str(uuid.uuid4())
            current_time = int(time.time())
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Insert the attachment
                cursor.execute(f'''
                INSERT INTO {self.ticket_attachment_table} (
                    id, ticket_id, filename, file_path, file_type, file_size, uploaded_by, uploaded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    attachment_id, ticket_id, attachment_data['filename'], attachment_data['file_path'],
                    attachment_data['file_type'], attachment_data['file_size'],
                    attachment_data['uploaded_by'], current_time
                ))
                
                # Add attachment to history
                history_id = str(uuid.uuid4())
                details = f"Attached file: {attachment_data['filename']} ({attachment_data['file_size']} bytes)"
                
                cursor.execute(f'''
                INSERT INTO {self.ticket_history_table} (
                    id, ticket_id, action, details, performed_by, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, ticket_id, 'attachment', details,
                    attachment_data['uploaded_by'], current_time
                ))
                
                # Update the ticket's updated_at timestamp
                cursor.execute(f'''
                UPDATE {self.ticket_table} SET updated_at = ? WHERE id = ?
                ''', (current_time, ticket_id))
                
                conn.commit()
                
                return {
                    'success': True,
                    'message': 'Attachment added successfully',
                    'ticket_id': ticket_id,
                    'attachment_id': attachment_id
                }
                
        except Exception as e:
            logger.error(f"Error adding attachment: {e}")
            return {'error': str(e)}
    
    def get_tickets(self, filters=None, sort_by='updated_at', sort_order='desc', page=1, page_size=20):
        """Get tickets with optional filtering and sorting"""
        try:
            with get_db_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Build the query
                query = f"SELECT * FROM {self.ticket_table}"
                params = []
                
                # Apply filters if provided
                if filters:
                    where_clauses = []
                    
                    # Filter by branch_id
                    if 'branch_id' in filters:
                        where_clauses.append("branch_id = ?")
                        params.append(filters['branch_id'])
                    
                    # Filter by status
                    if 'status' in filters:
                        where_clauses.append("status = ?")
                        params.append(filters['status'])
                    
                    # Filter by priority
                    if 'priority' in filters:
                        where_clauses.append("priority = ?")
                        params.append(filters['priority'])
                    
                    # Filter by category
                    if 'category' in filters:
                        where_clauses.append("category = ?")
                        params.append(filters['category'])
                    
                    # Filter by assigned_to
                    if 'assigned_to' in filters:
                        where_clauses.append("assigned_to = ?")
                        params.append(filters['assigned_to'])
                    
                    # Filter by created_by
                    if 'created_by' in filters:
                        where_clauses.append("created_by = ?")
                        params.append(filters['created_by'])
                    
                    # Filter by due_date (before)
                    if 'due_date_before' in filters:
                        if isinstance(filters['due_date_before'], str):
                            due_date = datetime.fromisoformat(filters['due_date_before'].replace('Z', '+00:00'))
                            filters['due_date_before'] = int(due_date.timestamp())
                        where_clauses.append("due_date <= ?")
                        params.append(filters['due_date_before'])
                    
                    # Filter by due_date (after)
                    if 'due_date_after' in filters:
                        if isinstance(filters['due_date_after'], str):
                            due_date = datetime.fromisoformat(filters['due_date_after'].replace('Z', '+00:00'))
                            filters['due_date_after'] = int(due_date.timestamp())
                        where_clauses.append("due_date >= ?")
                        params.append(filters['due_date_after'])
                    
                    # Filter by created_at (before)
                    if 'created_at_before' in filters:
                        if isinstance(filters['created_at_before'], str):
                            created_at = datetime.fromisoformat(filters['created_at_before'].replace('Z', '+00:00'))
                            filters['created_at_before'] = int(created_at.timestamp())
                        where_clauses.append("created_at <= ?")
                        params.append(filters['created_at_before'])
                    
                    # Filter by created_at (after)
                    if 'created_at_after' in filters:
                        if isinstance(filters['created_at_after'], str):
                            created_at = datetime.fromisoformat(filters['created_at_after'].replace('Z', '+00:00'))
                            filters['created_at_after'] = int(created_at.timestamp())
                        where_clauses.append("created_at >= ?")
                        params.append(filters['created_at_after'])
                    
                    # Filter by search term (in title or description)
                    if 'search' in filters:
                        where_clauses.append("(title LIKE ? OR description LIKE ?)")
                        search_term = f"%{filters['search']}%"
                        params.append(search_term)
                        params.append(search_term)
                    
                    if where_clauses:
                        query += " WHERE " + " AND ".join(where_clauses)
                
                # Apply sorting
                valid_sort_fields = ['created_at', 'updated_at', 'due_date', 'priority', 'status']
                valid_sort_orders = ['asc', 'desc']
                
                if sort_by not in valid_sort_fields:
                    sort_by = 'updated_at'
                
                if sort_order.lower() not in valid_sort_orders:
                    sort_order = 'desc'
                
                query += f" ORDER BY {sort_by} {sort_order}"
                
                # Apply pagination
                offset = (page - 1) * page_size
                query += f" LIMIT {page_size} OFFSET {offset}"
                
                # Execute the query
                cursor.execute(query, params)
                tickets = [dict(row) for row in cursor.fetchall()]
                
                # Parse JSON fields
                for ticket in tickets:
                    ticket['tags'] = json.loads(ticket['tags']) if ticket['tags'] else []
                    ticket['related_devices'] = json.loads(ticket['related_devices']) if ticket['related_devices'] else []
                
                # Get total count for pagination
                count_query = f"SELECT COUNT(*) as count FROM {self.ticket_table}"
                if 'WHERE' in query:
                    count_query += " " + query.split('WHERE')[1].split('ORDER BY')[0]
                
                cursor.execute(count_query, params[:params.index(search_term)] if 'search' in filters else params)
                total_count = cursor.fetchone()['count']
                
                return {
                    'tickets': tickets,
                    'total': total_count,
                    'page': page,
                    'page_size': page_size,
                    'total_pages': (total_count + page_size - 1) // page_size
                }
                
        except Exception as e:
            logger.error(f"Error getting tickets: {e}")
            return {'error': str(e)}
    
    def get_ticket_statistics(self, branch_id=None, time_period=None):
        """Get statistics about tickets"""
        try:
            with get_db_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Base query and params
                query_params = []
                where_clause = ""
                
                # Filter by branch_id if provided
                if branch_id:
                    where_clause = "WHERE branch_id = ?"
                    query_params.append(branch_id)
                
                # Filter by time period if provided
                if time_period:
                    # Calculate timestamp for the start of the period
                    now = int(time.time())
                    period_start = now
                    
                    if time_period == 'day':
                        period_start = now - (24 * 60 * 60)  # 1 day ago
                    elif time_period == 'week':
                        period_start = now - (7 * 24 * 60 * 60)  # 7 days ago
                    elif time_period == 'month':
                        period_start = now - (30 * 24 * 60 * 60)  # 30 days ago
                    elif time_period == 'year':
                        period_start = now - (365 * 24 * 60 * 60)  # 365 days ago
                    
                    if where_clause:
                        where_clause += " AND created_at >= ?"
                    else:
                        where_clause = "WHERE created_at >= ?"
                    
                    query_params.append(period_start)
                
                # Get total tickets
                total_query = f"SELECT COUNT(*) as count FROM {self.ticket_table} {where_clause}"
                cursor.execute(total_query, query_params)
                total_tickets = cursor.fetchone()['count']
                
                # Get tickets by status
                status_query = f"SELECT status, COUNT(*) as count FROM {self.ticket_table} {where_clause} GROUP BY status"
                cursor.execute(status_query, query_params)
                status_counts = {row['status']: row['count'] for row in cursor.fetchall()}
                
                # Get tickets by priority
                priority_query = f"SELECT priority, COUNT(*) as count FROM {self.ticket_table} {where_clause} GROUP BY priority"
                cursor.execute(priority_query, query_params)
                priority_counts = {row['priority']: row['count'] for row in cursor.fetchall()}
                
                # Get tickets by category
                category_query = f"SELECT category, COUNT(*) as count FROM {self.ticket_table} {where_clause} GROUP BY category"
                cursor.execute(category_query, query_params)
                category_counts = {row['category']: row['count'] for row in cursor.fetchall()}
                
                # Get average resolution time (for closed tickets)
                resolution_query = f"""
                SELECT AVG(updated_at - created_at) as avg_resolution_time 
                FROM {self.ticket_table} 
                WHERE status = 'closed' {'AND ' + where_clause.replace('WHERE', '') if where_clause else ''}
                """
                cursor.execute(resolution_query, query_params)
                avg_resolution_time = cursor.fetchone()['avg_resolution_time']
                
                # Get tickets created over time (grouped by day)
                time_query = f"""
                SELECT strftime('%Y-%m-%d', datetime(created_at, 'unixepoch')) as date, COUNT(*) as count 
                FROM {self.ticket_table} 
                {where_clause}
                GROUP BY date
                ORDER BY date
                """
                cursor.execute(time_query, query_params)
                time_distribution = {row['date']: row['count'] for row in cursor.fetchall()}
                
                return {
                    'total_tickets': total_tickets,
                    'status_distribution': status_counts,
                    'priority_distribution': priority_counts,
                    'category_distribution': category_counts,
                    'avg_resolution_time': avg_resolution_time,
                    'time_distribution': time_distribution,
                    'branch_id': branch_id,
                    'time_period': time_period
                }
                
        except Exception as e:
            logger.error(f"Error getting ticket statistics: {e}")
            return {'error': str(e)}
    
    def delete_ticket(self, ticket_id, performed_by):
        """Delete a ticket (soft delete by marking as deleted)"""
        try:
            # Check if ticket exists
            ticket = self.get_ticket(ticket_id)
            if 'error' in ticket:
                return ticket
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Mark the ticket as deleted
                current_time = int(time.time())
                cursor.execute(f'''
                UPDATE {self.ticket_table} SET status = 'deleted', updated_at = ? WHERE id = ?
                ''', (current_time, ticket_id))
                
                # Add deletion to history
                history_id = str(uuid.uuid4())
                cursor.execute(f'''
                INSERT INTO {self.ticket_history_table} (
                    id, ticket_id, action, details, performed_by, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, ticket_id, 'deleted', 'Ticket marked as deleted',
                    performed_by, current_time
                ))
                
                conn.commit()
                
                return {
                    'success': True,
                    'message': 'Ticket deleted successfully',
                    'ticket_id': ticket_id
                }
                
        except Exception as e:
            logger.error(f"Error deleting ticket: {e}")
            return {'error': str(e)}
    
    def assign_ticket(self, ticket_id, assigned_to, performed_by):
        """Assign a ticket to a user"""
        try:
            # Check if ticket exists
            ticket = self.get_ticket(ticket_id)
            if 'error' in ticket:
                return ticket
            
            current_time = int(time.time())
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Update the ticket
                cursor.execute(f'''
                UPDATE {self.ticket_table} SET assigned_to = ?, updated_at = ? WHERE id = ?
                ''', (assigned_to, current_time, ticket_id))
                
                # Add assignment to history
                history_id = str(uuid.uuid4())
                details = f"Ticket assigned to {assigned_to}"
                
                cursor.execute(f'''
                INSERT INTO {self.ticket_history_table} (
                    id, ticket_id, action, details, performed_by, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, ticket_id, 'assigned', details,
                    performed_by, current_time
                ))
                
                conn.commit()
                
                return {
                    'success': True,
                    'message': f'Ticket assigned to {assigned_to} successfully',
                    'ticket_id': ticket_id
                }
                
        except Exception as e:
            logger.error(f"Error assigning ticket: {e}")
            return {'error': str(e)}
    
    def change_ticket_status(self, ticket_id, new_status, performed_by, comment=None):
        """Change the status of a ticket"""
        try:
            # Check if ticket exists
            ticket = self.get_ticket(ticket_id)
            if 'error' in ticket:
                return ticket
            
            # Validate status
            valid_statuses = ['open', 'in_progress', 'pending', 'resolved', 'closed', 'reopened']
            if new_status not in valid_statuses:
                return {'error': f'Invalid status: {new_status}. Valid statuses are: {valid_statuses}'}
            
            current_time = int(time.time())
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Update the ticket
                cursor.execute(f'''
                UPDATE {self.ticket_table} SET status = ?, updated_at = ? WHERE id = ?
                ''', (new_status, current_time, ticket_id))
                
                # Add status change to history
                history_id = str(uuid.uuid4())
                details = f"Status changed from {ticket['ticket']['status']} to {new_status}"
                if comment:
                    details += f"\nComment: {comment}"
                
                cursor.execute(f'''
                INSERT INTO {self.ticket_history_table} (
                    id, ticket_id, action, details, performed_by, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, ticket_id, 'status_change', details,
                    performed_by, current_time
                ))
                
                conn.commit()
                
                return {
                    'success': True,
                    'message': f'Ticket status changed to {new_status} successfully',
                    'ticket_id': ticket_id
                }
                
        except Exception as e:
            logger.error(f"Error changing ticket status: {e}")
            return {'error': str(e)}