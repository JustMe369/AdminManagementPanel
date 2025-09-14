-- Updated users table schema
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,  -- Added salt storage
    branch_id INTEGER NOT NULL,
    time_limit TEXT DEFAULT '1 hour',
    speed_limit TEXT DEFAULT '5 Mbps',
    status TEXT DEFAULT 'Inactive' CHECK(status IN ('Active', 'Inactive', 'Suspended', 'Blocked')),
    user_type TEXT DEFAULT 'Regular' CHECK(user_type IN ('Regular', 'Admin', 'Guest')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP,
    login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    mfa_secret TEXT,  -- For two-factor authentication
    session_token TEXT UNIQUE,
    token_expires DATETIME,
    FOREIGN KEY (branch_id) REFERENCES branches (id),
    UNIQUE(username, branch_id)
);

-- Add indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_branch ON users(branch_id);
CREATE INDEX IF NOT EXISTS idx_users_session ON users(session_token);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    device_type TEXT DEFAULT 'unknown',
    anydesk_id TEXT,
    serial_number TEXT,
    branch_id INTEGER NOT NULL,
    status TEXT DEFAULT 'Active' CHECK(status IN ('Active', 'Inactive', 'Blocked')),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (branch_id) REFERENCES branches (id),
    UNIQUE(mac_address, branch_id)
);

-- Device activity tracking table
CREATE TABLE IF NOT EXISTS device_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    activity_type TEXT NOT NULL CHECK(activity_type IN ('connect', 'disconnect', 'block', 'unblock', 'bandwidth_change')),
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices (id)
);

-- Device bandwidth usage table
CREATE TABLE IF NOT EXISTS device_bandwidth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    download_bytes BIGINT DEFAULT 0,
    upload_bytes BIGINT DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices (id)
);

-- Sync status table for cloud synchronization
CREATE TABLE IF NOT EXISTS sync_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sync_type TEXT NOT NULL,
    branch_id INTEGER NOT NULL,
    last_sync TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(sync_type, branch_id),
    FOREIGN KEY (branch_id) REFERENCES branches(id)
);

-- Add indexes for device tables
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_branch ON devices(branch_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_device_activity_device ON device_activity(device_id);
CREATE INDEX IF NOT EXISTS idx_device_activity_timestamp ON device_activity(timestamp);
CREATE INDEX IF NOT EXISTS idx_device_bandwidth_device ON device_bandwidth(device_id);
CREATE INDEX IF NOT EXISTS idx_device_bandwidth_timestamp ON device_bandwidth(timestamp);
CREATE INDEX IF NOT EXISTS idx_sync_status_branch ON sync_status(branch_id);
CREATE INDEX IF NOT EXISTS idx_sync_status_type ON sync_status(sync_type);

-- Branches table
CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    location TEXT,
    ip_address TEXT NOT NULL,
    router_model TEXT DEFAULT 'TP-Link Archer C7 v5',
    status TEXT DEFAULT 'Active' CHECK(status IN ('Active', 'Inactive', 'Maintenance')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tickets table for IT support system
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_number TEXT UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    branch_id INTEGER NOT NULL,
    reporter_name TEXT NOT NULL,
    reporter_email TEXT,
    category TEXT NOT NULL CHECK(category IN ('Hardware', 'Software', 'Network', 'Access', 'Other')),
    priority TEXT DEFAULT 'Medium' CHECK(priority IN ('Low', 'Medium', 'High', 'Critical')),
    status TEXT DEFAULT 'Open' CHECK(status IN ('Open', 'In Progress', 'Resolved', 'Closed')),
    assigned_to TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    FOREIGN KEY (branch_id) REFERENCES branches (id)
);

-- Guest passwords table for NoDogSplash integration
CREATE TABLE IF NOT EXISTS guest_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL UNIQUE,
    branch_id INTEGER NOT NULL,
    time_limit INTEGER DEFAULT 60, -- minutes
    speed_limit_down INTEGER DEFAULT 5120, -- kbps (5 Mbps)
    speed_limit_up INTEGER DEFAULT 1024, -- kbps (1 Mbps)
    max_usage INTEGER DEFAULT 1, -- number of times password can be used
    current_usage INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (branch_id) REFERENCES branches (id)
);

-- Internet policies table
CREATE TABLE IF NOT EXISTS internet_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    branch_id INTEGER NOT NULL,
    description TEXT,
    time_limit INTEGER, -- minutes per day
    speed_limit_down INTEGER, -- kbps
    speed_limit_up INTEGER, -- kbps
    blocked_categories TEXT, -- JSON array of blocked categories
    blocked_sites TEXT, -- JSON array of blocked sites
    allowed_times TEXT, -- JSON array of time ranges
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (branch_id) REFERENCES branches (id)
);

-- Firewall rules table
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    branch_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL CHECK(rule_type IN ('ALLOW', 'DENY', 'DROP', 'REDIRECT')),
    source TEXT,
    destination TEXT,
    port TEXT,
    protocol TEXT CHECK(protocol IN ('tcp', 'udp', 'icmp', 'all')),
    is_active BOOLEAN DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (branch_id) REFERENCES branches (id)
);

-- Network monitoring logs
CREATE TABLE IF NOT EXISTS network_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL,
    log_type TEXT NOT NULL CHECK(log_type IN ('connection', 'bandwidth', 'security', 'error')),
    device_mac TEXT,
    message TEXT NOT NULL,
    details TEXT, -- JSON for additional data
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (branch_id) REFERENCES branches (id)
);

-- Add indexes for new tables
CREATE INDEX IF NOT EXISTS idx_branches_status ON branches(status);
CREATE INDEX IF NOT EXISTS idx_tickets_branch ON tickets(branch_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets(priority);
CREATE INDEX IF NOT EXISTS idx_guest_passwords_branch ON guest_passwords(branch_id);
CREATE INDEX IF NOT EXISTS idx_guest_passwords_active ON guest_passwords(is_active);
CREATE INDEX IF NOT EXISTS idx_internet_policies_branch ON internet_policies(branch_id);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_branch ON firewall_rules(branch_id);
CREATE INDEX IF NOT EXISTS idx_network_logs_branch ON network_logs(branch_id);
CREATE INDEX IF NOT EXISTS idx_network_logs_timestamp ON network_logs(timestamp);

-- Insert default branch if not exists
INSERT OR IGNORE INTO branches (id, name, location, ip_address) 
VALUES (1, 'Main Branch', 'Headquarters', '192.168.1.1');

-- Create default admin user if not exists
INSERT OR IGNORE INTO users (username, password_hash, password_salt, branch_id, user_type, status)
VALUES ('admin', 'pbkdf2:sha256:260000$salt$hash', 'salt', 1, 'Admin', 'Active');
