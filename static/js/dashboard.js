// Dashboard JavaScript - AdminManagement System

class AdminDashboard {
    constructor() {
        this.currentUser = null;
        this.currentBranch = 1;
        this.authToken = localStorage.getItem('authToken');
        this.currentSection = 'dashboard';
        this.refreshInterval = null;
        
        this.init();
    }
    
    init() {
        this.checkAuth();
        this.setupEventListeners();
        this.loadUserInfo();
        this.loadBranches();
        this.loadDashboardData();
        this.setupAutoRefresh();
    }
    
    checkAuth() {
        if (!this.authToken) {
            window.location.href = '../login.html';
            return;
        }
        
        // Set default authorization header for all API calls
        this.setAuthHeader(this.authToken);
    }
    
    setAuthHeader(token) {
        // This would be used in API calls
        this.authToken = token;
    }
    
    setupEventListeners() {
        // Sidebar menu items
        document.querySelectorAll('.menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const section = e.currentTarget.dataset.section;
                this.switchSection(section);
            });
        });
        
        // Sidebar toggle for mobile
        const sidebarToggle = document.querySelector('.sidebar-toggle');
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                document.querySelector('.sidebar').classList.toggle('show');
            });
        }
        
        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', (e) => {
            const sidebar = document.querySelector('.sidebar');
            const sidebarToggle = document.querySelector('.sidebar-toggle');
            
            if (window.innerWidth <= 768 && 
                !sidebar.contains(e.target) && 
                !sidebarToggle.contains(e.target)) {
                sidebar.classList.remove('show');
            }
        });
        
        // Chart time period buttons
        document.querySelectorAll('.chart-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.updateChart(e.target.textContent);
            });
        });
        
        // Close notification dropdown when clicking outside
        document.addEventListener('click', (e) => {
            const dropdown = document.getElementById('notificationDropdown');
            const btn = document.querySelector('.notification-btn');
            
            if (!btn.contains(e.target) && !dropdown.contains(e.target)) {
                dropdown.classList.remove('show');
            }
        });
    }
    
    switchSection(section) {
        // Update active menu item
        document.querySelectorAll('.menu-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-section="${section}"]`).classList.add('active');
        
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(sec => {
            sec.classList.remove('active');
        });
        
        // Show selected section
        const targetSection = document.getElementById(`${section}-section`);
        if (targetSection) {
            targetSection.classList.add('active');
        }
        
        // Update page title
        const titles = {
            'dashboard': 'Dashboard Overview',
            'devices': 'Device Management',
            'users': 'User Management',
            'firewall': 'Firewall Rules',
            'guest': 'Guest Network',
            'tickets': 'Support Tickets',
            'branches': 'Branch Management',
            'monitoring': 'Network Monitoring',
            'settings': 'System Settings'
        };
        
        document.getElementById('pageTitle').textContent = titles[section] || 'AdminControl';
        this.currentSection = section;
        
        // Load section-specific data
        this.loadSectionData(section);
    }
    
    async loadUserInfo() {
        try {
            const response = await fetch('/api/user/profile', {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const userData = await response.json();
                this.currentUser = userData;
                document.getElementById('currentUser').textContent = userData.username;
                document.getElementById('currentRole').textContent = userData.user_type;
            }
        } catch (error) {
            console.error('Error loading user info:', error);
        }
    }
    
    async loadBranches() {
        try {
            const response = await fetch('/api/branches', {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                const branchSelect = document.getElementById('branchSelect');
                branchSelect.innerHTML = '';
                
                data.branches.forEach(branch => {
                    const option = document.createElement('option');
                    option.value = branch.id;
                    option.textContent = branch.name;
                    if (branch.id === this.currentBranch) {
                        option.selected = true;
                    }
                    branchSelect.appendChild(option);
                });
            }
        } catch (error) {
            console.error('Error loading branches:', error);
        }
    }
    
    async loadDashboardData() {
        try {
            // Load dashboard statistics
            await Promise.all([
                this.loadDeviceStats(),
                this.loadUserStats(),
                this.loadTicketStats(),
                this.loadNetworkStats(),
                this.loadRecentActivity(),
                this.loadTrafficChart()
            ]);
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }
    
    async loadDeviceStats() {
        try {
            const response = await fetch(`/api/devices/summary?branch_id=${this.currentBranch}`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                document.getElementById('totalDevices').textContent = data.total_devices || 0;
            }
        } catch (error) {
            console.error('Error loading device stats:', error);
        }
    }
    
    async loadUserStats() {
        try {
            const response = await fetch(`/api/users?branch_id=${this.currentBranch}`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                const activeUsers = data.users.filter(user => user.status === 'Active').length;
                document.getElementById('activeUsers').textContent = activeUsers;
            }
        } catch (error) {
            console.error('Error loading user stats:', error);
        }
    }
    
    async loadTicketStats() {
        try {
            const response = await fetch(`/api/tickets?branch_id=${this.currentBranch}&status=Open`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                document.getElementById('openTickets').textContent = data.count || 0;
            }
        } catch (error) {
            console.error('Error loading ticket stats:', error);
        }
    }
    
    async loadNetworkStats() {
        // Simulated network load - in production this would come from monitoring
        const networkLoad = Math.floor(Math.random() * 30) + 30; // 30-60%
        document.getElementById('networkLoad').textContent = `${networkLoad}%`;
    }
    
    async loadRecentActivity() {
        try {
            const response = await fetch(`/api/network-logs?branch_id=${this.currentBranch}&limit=5`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayRecentActivity(data.logs || []);
            } else {
                // Fallback to sample data
                this.displayRecentActivity([
                    { message: 'New device connected: Laptop-001', timestamp: new Date().toISOString(), log_type: 'connection' },
                    { message: 'User john.doe logged in', timestamp: new Date(Date.now() - 300000).toISOString(), log_type: 'security' },
                    { message: 'Bandwidth limit applied to device MAC: aa:bb:cc:dd:ee:ff', timestamp: new Date(Date.now() - 600000).toISOString(), log_type: 'bandwidth' }
                ]);
            }
        } catch (error) {
            console.error('Error loading recent activity:', error);
        }
    }
    
    displayRecentActivity(activities) {
        const container = document.getElementById('recentActivity');
        container.innerHTML = '';
        
        if (activities.length === 0) {
            container.innerHTML = '<p class="text-secondary">No recent activity</p>';
            return;
        }
        
        activities.forEach(activity => {
            const activityItem = document.createElement('div');
            activityItem.className = 'activity-item';
            activityItem.style.cssText = 'padding: 12px 0; border-bottom: 1px solid #e5e7eb;';
            
            const timeAgo = this.getTimeAgo(new Date(activity.timestamp));
            const icon = this.getActivityIcon(activity.log_type);
            
            activityItem.innerHTML = `
                <div style="display: flex; align-items: center; gap: 12px;">
                    <i class="fas ${icon}" style="color: #6b7280; width: 16px;"></i>
                    <div>
                        <p style="margin: 0; font-size: 14px; color: #111827;">${activity.message}</p>
                        <small style="color: #6b7280;">${timeAgo}</small>
                    </div>
                </div>
            `;
            
            container.appendChild(activityItem);
        });
    }
    
    getActivityIcon(type) {
        const icons = {
            'connection': 'fa-wifi',
            'security': 'fa-shield-alt',
            'bandwidth': 'fa-tachometer-alt',
            'error': 'fa-exclamation-triangle'
        };
        return icons[type] || 'fa-info-circle';
    }
    
    getTimeAgo(date) {
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        return `${days}d ago`;
    }
    
    async loadTrafficChart() {
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;
        
        // Generate sample data for the chart
        const hours = [];
        const uploadData = [];
        const downloadData = [];
        
        for (let i = 23; i >= 0; i--) {
            const hour = new Date(Date.now() - i * 3600000);
            hours.push(hour.getHours() + ':00');
            uploadData.push(Math.floor(Math.random() * 50) + 20);
            downloadData.push(Math.floor(Math.random() * 80) + 40);
        }
        
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: hours,
                datasets: [{
                    label: 'Download (Mbps)',
                    data: downloadData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Upload (Mbps)',
                    data: uploadData,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: '#e5e7eb'
                        }
                    },
                    x: {
                        grid: {
                            color: '#e5e7eb'
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                    }
                }
            }
        });
    }
    
    async loadSectionData(section) {
        switch (section) {
            case 'devices':
                await this.loadDevices();
                break;
            case 'users':
                await this.loadUsers();
                break;
            case 'tickets':
                await this.loadTickets();
                break;
            case 'guest':
                await this.loadGuestPasswords();
                break;
        }
    }
    
    async loadDevices() {
        try {
            const response = await fetch(`/api/devices?branch_id=${this.currentBranch}`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayDevices(data.devices || []);
            }
        } catch (error) {
            console.error('Error loading devices:', error);
        }
    }
    
    displayDevices(devices) {
        const tbody = document.getElementById('devicesTableBody');
        tbody.innerHTML = '';
        
        devices.forEach(device => {
            const row = document.createElement('tr');
            const statusClass = device.status === 'Active' ? 'text-success' : 
                              device.status === 'Blocked' ? 'text-danger' : 'text-secondary';
            
            row.innerHTML = `
                <td>${device.name}</td>
                <td>${device.ip_address}</td>
                <td><code>${device.mac_address}</code></td>
                <td>${device.device_type}</td>
                <td><span class="${statusClass}">${device.status}</span></td>
                <td>${this.formatDateTime(device.last_seen)}</td>
                <td>
                    <button class="btn-secondary" onclick="dashboard.editDevice('${device.id}')" style="margin-right: 8px;">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn-secondary" onclick="dashboard.toggleDeviceBlock('${device.mac_address}', '${device.status}')">
                        <i class="fas fa-${device.status === 'Blocked' ? 'unlock' : 'ban'}"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }
    
    async loadUsers() {
        try {
            const response = await fetch(`/api/users?branch_id=${this.currentBranch}`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayUsers(data.users || []);
            }
        } catch (error) {
            console.error('Error loading users:', error);
        }
    }
    
    displayUsers(users) {
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = '';
        
        users.forEach(user => {
            const row = document.createElement('tr');
            const statusClass = user.status === 'Active' ? 'text-success' : 'text-secondary';
            
            row.innerHTML = `
                <td>${user.username}</td>
                <td>${user.user_type}</td>
                <td>Branch ${user.branch_id}</td>
                <td><span class="${statusClass}">${user.status}</span></td>
                <td>${user.last_login ? this.formatDateTime(user.last_login) : 'Never'}</td>
                <td>
                    <button class="btn-secondary" onclick="dashboard.editUser('${user.id}')" style="margin-right: 8px;">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn-secondary" onclick="dashboard.deleteUser('${user.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }
    
    async loadTickets() {
        try {
            const response = await fetch(`/api/tickets?branch_id=${this.currentBranch}`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayTickets(data.tickets || []);
                this.updateTicketStats(data.tickets || []);
            }
        } catch (error) {
            console.error('Error loading tickets:', error);
        }
    }
    
    displayTickets(tickets) {
        const tbody = document.getElementById('ticketsTableBody');
        tbody.innerHTML = '';
        
        tickets.forEach(ticket => {
            const row = document.createElement('tr');
            const priorityClass = ticket.priority === 'High' ? 'text-danger' : 
                                ticket.priority === 'Medium' ? 'text-warning' : 'text-secondary';
            const statusClass = ticket.status === 'Open' ? 'text-danger' : 
                              ticket.status === 'In Progress' ? 'text-warning' : 'text-success';
            
            row.innerHTML = `
                <td>${ticket.ticket_number}</td>
                <td>${ticket.title}</td>
                <td>${ticket.reporter_name}</td>
                <td>${ticket.category}</td>
                <td><span class="${priorityClass}">${ticket.priority}</span></td>
                <td><span class="${statusClass}">${ticket.status}</span></td>
                <td>${this.formatDateTime(ticket.created_at)}</td>
                <td>
                    <button class="btn-secondary" onclick="dashboard.viewTicket('${ticket.id}')" style="margin-right: 8px;">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn-secondary" onclick="dashboard.editTicket('${ticket.id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }
    
    updateTicketStats(tickets) {
        const openCount = tickets.filter(t => t.status === 'Open').length;
        const inProgressCount = tickets.filter(t => t.status === 'In Progress').length;
        const resolvedCount = tickets.filter(t => t.status === 'Resolved').length;
        
        document.getElementById('openTicketsCount').textContent = openCount;
        document.getElementById('inProgressTicketsCount').textContent = inProgressCount;
        document.getElementById('resolvedTicketsCount').textContent = resolvedCount;
    }
    
    async loadGuestPasswords() {
        try {
            const response = await fetch(`/api/guest-passwords?branch_id=${this.currentBranch}`, {
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.displayGuestPasswords(data.passwords || []);
            }
        } catch (error) {
            console.error('Error loading guest passwords:', error);
            // Show sample data
            this.displayGuestPasswords([]);
        }
    }
    
    displayGuestPasswords(passwords) {
        const container = document.getElementById('guestPasswordList');
        container.innerHTML = '';
        
        if (passwords.length === 0) {
            container.innerHTML = '<p class="text-secondary">No active guest passwords</p>';
            return;
        }
        
        passwords.forEach(password => {
            const passwordItem = document.createElement('div');
            passwordItem.className = 'password-item';
            passwordItem.style.cssText = 'padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 12px;';
            
            passwordItem.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <code style="font-size: 18px; font-weight: bold;">${password.password}</code>
                        <div style="margin-top: 8px;">
                            <small class="text-secondary">
                                Time: ${password.time_limit}min | 
                                Speed: ${password.speed_limit_down/1024}Mbps | 
                                Usage: ${password.current_usage}/${password.max_usage}
                            </small>
                        </div>
                    </div>
                    <button class="btn-secondary" onclick="dashboard.deactivatePassword('${password.id}')">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            
            container.appendChild(passwordItem);
        });
    }
    
    formatDateTime(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleString();
    }
    
    setupAutoRefresh() {
        // Refresh data every 5 minutes
        this.refreshInterval = setInterval(() => {
            if (this.currentSection === 'dashboard') {
                this.loadDashboardData();
            } else {
                this.loadSectionData(this.currentSection);
            }
        }, 300000); // 5 minutes
    }
    
    // Event handlers for UI interactions
    async toggleDeviceBlock(macAddress, currentStatus) {
        const action = currentStatus === 'Blocked' ? 'unblock' : 'block';
        const endpoint = `/api/devices/${macAddress}/${action}`;
        
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ branch_id: this.currentBranch })
            });
            
            if (response.ok) {
                this.showNotification(`Device ${action}ed successfully`, 'success');
                this.loadDevices();
            } else {
                this.showNotification(`Failed to ${action} device`, 'error');
            }
        } catch (error) {
            console.error(`Error ${action}ing device:`, error);
            this.showNotification(`Error ${action}ing device`, 'error');
        }
    }
    
    showNotification(message, type = 'info') {
        // Create a simple toast notification
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 24px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 9999;
            animation: slideIn 0.3s ease-out;
        `;
        
        const colors = {
            'success': '#10b981',
            'error': '#ef4444',
            'warning': '#f59e0b',
            'info': '#3b82f6'
        };
        
        notification.style.backgroundColor = colors[type] || colors.info;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
}

// Global functions for HTML onclick handlers
function toggleSidebar() {
    document.querySelector('.sidebar').classList.toggle('show');
}

function toggleNotifications() {
    document.getElementById('notificationDropdown').classList.toggle('show');
}

function switchBranch() {
    const branchId = document.getElementById('branchSelect').value;
    dashboard.currentBranch = parseInt(branchId);
    dashboard.loadSectionData(dashboard.currentSection);
}

function logout() {
    localStorage.removeItem('authToken');
    window.location.href = '../login.html';
}

function refreshActivity() {
    dashboard.loadRecentActivity();
}

function refreshDevices() {
    dashboard.loadDevices();
}

function refreshUsers() {
    dashboard.loadUsers();
}

function addDevice() {
    dashboard.showModal('Add Device', `
        <form onsubmit="dashboard.saveDevice(event)">
            <div class="form-group">
                <label>Device Name</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label>IP Address</label>
                <input type="text" name="ip_address" required>
            </div>
            <div class="form-group">
                <label>MAC Address</label>
                <input type="text" name="mac_address" required>
            </div>
            <div class="form-group">
                <label>Device Type</label>
                <select name="device_type" required>
                    <option value="laptop">Laptop</option>
                    <option value="desktop">Desktop</option>
                    <option value="smartphone">Smartphone</option>
                    <option value="tablet">Tablet</option>
                    <option value="other">Other</option>
                </select>
            </div>
            <button type="submit" class="btn-primary">Add Device</button>
        </form>
    `);
}

function addUser() {
    dashboard.showModal('Add User', `
        <form onsubmit="dashboard.saveUser(event)">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label>User Type</label>
                <select name="user_type" required>
                    <option value="User">Regular User</option>
                    <option value="Admin">Administrator</option>
                    <option value="Support">Support</option>
                </select>
            </div>
            <button type="submit" class="btn-primary">Add User</button>
        </form>
    `);
}

function createTicket() {
    dashboard.showModal('Create Support Ticket', `
        <form onsubmit="dashboard.saveTicket(event)">
            <div class="form-group">
                <label>Title</label>
                <input type="text" name="title" required>
            </div>
            <div class="form-group">
                <label>Description</label>
                <textarea name="description" rows="4" required></textarea>
            </div>
            <div class="form-group">
                <label>Reporter Name</label>
                <input type="text" name="reporter_name" required>
            </div>
            <div class="form-group">
                <label>Category</label>
                <select name="category" required>
                    <option value="Hardware">Hardware</option>
                    <option value="Software">Software</option>
                    <option value="Network">Network</option>
                    <option value="Access">Access</option>
                    <option value="Other">Other</option>
                </select>
            </div>
            <div class="form-group">
                <label>Priority</label>
                <select name="priority">
                    <option value="Low">Low</option>
                    <option value="Medium" selected>Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                </select>
            </div>
            <button type="submit" class="btn-primary">Create Ticket</button>
        </form>
    `);
}

function generateGuestPassword() {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let password = '';
    for (let i = 0; i < 8; i++) {
        password += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    
    const form = document.getElementById('guestPasswordForm');
    const timeLimit = form.guestTimeLimit.value;
    const speedLimit = form.guestSpeedLimit.value;
    const maxUsage = form.guestMaxUsage.value;
    
    dashboard.showModal('Generated Guest Password', `
        <div style="text-align: center; padding: 20px;">
            <h3>Guest WiFi Password</h3>
            <div style="font-size: 36px; font-weight: bold; margin: 20px 0; padding: 20px; background: #f3f4f6; border-radius: 8px;">
                ${password}
            </div>
            <div style="color: #6b7280;">
                <p>Time Limit: ${timeLimit} minutes</p>
                <p>Speed Limit: ${speedLimit} Mbps</p>
                <p>Max Usage: ${maxUsage} devices</p>
            </div>
            <button class="btn-primary" onclick="closeModal()" style="margin-top: 20px;">Close</button>
        </div>
    `);
}

function createGuestPassword(event) {
    event.preventDefault();
    generateGuestPassword();
}

function closeModal() {
    document.getElementById('modal').classList.remove('show');
}

function markAllRead() {
    // Mark all notifications as read
    document.getElementById('notificationCount').textContent = '0';
    toggleNotifications();
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new AdminDashboard();
    
    // Add CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .notification {
            animation: slideIn 0.3s ease-out;
        }
        
        .modal {
            transition: opacity 0.3s ease-in-out;
        }
        
        .modal.show {
            opacity: 1;
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
    `;
    document.head.appendChild(style);
});

// Export dashboard methods for modal forms
AdminDashboard.prototype.showModal = function(title, content) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = content;
    document.getElementById('modal').classList.add('show');
};

AdminDashboard.prototype.saveDevice = async function(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const deviceData = {
        name: formData.get('name'),
        ip_address: formData.get('ip_address'),
        mac_address: formData.get('mac_address'),
        device_type: formData.get('device_type'),
        branch_id: this.currentBranch
    };
    
    try {
        const response = await fetch('/api/devices', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(deviceData)
        });
        
        if (response.ok) {
            this.showNotification('Device added successfully', 'success');
            closeModal();
            this.loadDevices();
        } else {
            const error = await response.json();
            this.showNotification(error.error || 'Failed to add device', 'error');
        }
    } catch (error) {
        console.error('Error adding device:', error);
        this.showNotification('Error adding device', 'error');
    }
};

AdminDashboard.prototype.saveUser = async function(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const userData = {
        username: formData.get('username'),
        password: formData.get('password'),
        user_type: formData.get('user_type'),
        branch_id: this.currentBranch
    };
    
    try {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        });
        
        if (response.ok) {
            this.showNotification('User added successfully', 'success');
            closeModal();
            this.loadUsers();
        } else {
            const error = await response.json();
            this.showNotification(error.error || 'Failed to add user', 'error');
        }
    } catch (error) {
        console.error('Error adding user:', error);
        this.showNotification('Error adding user', 'error');
    }
};

AdminDashboard.prototype.saveTicket = async function(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const ticketData = {
        title: formData.get('title'),
        description: formData.get('description'),
        reporter_name: formData.get('reporter_name'),
        category: formData.get('category'),
        priority: formData.get('priority'),
        branch_id: this.currentBranch
    };
    
    try {
        const response = await fetch('/api/tickets', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(ticketData)
        });
        
        if (response.ok) {
            this.showNotification('Ticket created successfully', 'success');
            closeModal();
            this.loadTickets();
        } else {
            const error = await response.json();
            this.showNotification(error.error || 'Failed to create ticket', 'error');
        }
    } catch (error) {
        console.error('Error creating ticket:', error);
        this.showNotification('Error creating ticket', 'error');
    }
};