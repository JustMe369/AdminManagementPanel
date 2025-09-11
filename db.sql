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

-- Add indexes for device tables
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_branch ON devices(branch_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_device_activity_device ON device_activity(device_id);
CREATE INDEX IF NOT EXISTS idx_device_activity_timestamp ON device_activity(timestamp);
CREATE INDEX IF NOT EXISTS idx_device_bandwidth_device ON device_bandwidth(device_id);
CREATE INDEX IF NOT EXISTS idx_device_bandwidth_timestamp ON device_bandwidth(timestamp);