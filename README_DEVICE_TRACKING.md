# Device Tracking API Documentation

This document provides information about the Device Tracking API endpoints and monitoring services.

## Database Schema

The device tracking system uses the following database tables:

### devices

Stores information about network devices.

```sql
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    device_type TEXT NOT NULL,
    manufacturer TEXT,
    model TEXT,
    branch_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(mac_address, branch_id),
    CHECK(status IN ('Active', 'Blocked', 'Archived')),
    FOREIGN KEY (branch_id) REFERENCES branches(id)
);
```

### device_activity

Tracks device activities such as connections, disconnections, blocks, and bandwidth changes.

```sql
CREATE TABLE IF NOT EXISTS device_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    activity_type TEXT NOT NULL,
    activity_data TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    CHECK(activity_type IN ('connect', 'disconnect', 'block', 'unblock', 'bandwidth_change', 'registration'))
);
```

### device_bandwidth_usage

Stores bandwidth usage statistics for devices.

```sql
CREATE TABLE IF NOT EXISTS device_bandwidth_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    download_bytes BIGINT NOT NULL,
    upload_bytes BIGINT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
```

## API Endpoints

### Device Information

#### GET /api/devices

Retrieve a list of all devices, optionally filtered by branch.

**Query Parameters:**
- `branch_id` (optional): Filter devices by branch ID

**Response:**
```json
{
  "devices": [
    {
      "id": 1,
      "name": "User's Laptop",
      "ip_address": "192.168.1.100",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "device_type": "laptop",
      "manufacturer": "Dell",
      "model": "XPS 13",
      "branch_id": 1,
      "status": "Active",
      "first_seen": "2023-06-01T10:00:00",
      "last_seen": "2023-06-02T15:30:00"
    }
  ]
}
```

#### POST /api/devices

Add a new device to the system.

**Request Body:**
```json
{
  "name": "User's Laptop",
  "ip_address": "192.168.1.100",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "device_type": "laptop",
  "manufacturer": "Dell",
  "model": "XPS 13",
  "branch_id": 1
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Device added successfully",
  "device_id": 1
}
```

#### GET /api/devices/info/<string:mac_address>

Get detailed information about a specific device.

**Response:**
```json
{
  "device": {
    "id": 1,
    "name": "User's Laptop",
    "ip_address": "192.168.1.100",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "device_type": "laptop",
    "manufacturer": "Dell",
    "model": "XPS 13",
    "branch_id": 1,
    "status": "Active",
    "first_seen": "2023-06-01T10:00:00",
    "last_seen": "2023-06-02T15:30:00",
    "created_at": "2023-06-01T10:00:00",
    "updated_at": "2023-06-02T15:30:00"
  }
}
```

### Device Activity Tracking

#### GET /api/devices/activity/<string:mac_address>

Get activity history for a specific device.

**Query Parameters:**
- `limit` (optional): Maximum number of activities to return (default: 50)
- `offset` (optional): Offset for pagination (default: 0)
- `activity_type` (optional): Filter by activity type

**Response:**
```json
{
  "activities": [
    {
      "id": 1,
      "device_id": 1,
      "activity_type": "connect",
      "activity_data": {"auto_detected": true},
      "timestamp": "2023-06-01T10:00:00"
    },
    {
      "id": 2,
      "device_id": 1,
      "activity_type": "block",
      "activity_data": {"duration": 3600, "reason": "Policy violation"},
      "timestamp": "2023-06-01T14:30:00"
    }
  ],
  "total": 2
}
```

#### POST /api/devices/activity/<string:mac_address>

Record a new activity for a device.

**Request Body:**
```json
{
  "activity_type": "connect",
  "activity_data": {"location": "Main Office"}
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Activity recorded successfully",
  "activity_id": 3
}
```

### Device Bandwidth Tracking

#### GET /api/devices/bandwidth/<string:mac_address>

Get bandwidth usage history for a specific device.

**Query Parameters:**
- `limit` (optional): Maximum number of records to return (default: 50)
- `offset` (optional): Offset for pagination (default: 0)
- `start_date` (optional): Filter by start date (ISO format)
- `end_date` (optional): Filter by end date (ISO format)

**Response:**
```json
{
  "bandwidth_usage": [
    {
      "id": 1,
      "device_id": 1,
      "download_bytes": 1048576,
      "upload_bytes": 524288,
      "timestamp": "2023-06-01T10:15:00"
    },
    {
      "id": 2,
      "device_id": 1,
      "download_bytes": 2097152,
      "upload_bytes": 1048576,
      "timestamp": "2023-06-01T10:30:00"
    }
  ],
  "total": 2
}
```

#### POST /api/devices/bandwidth/<string:mac_address>

Update bandwidth usage for a device.

**Request Body:**
```json
{
  "download_bytes": 3145728,
  "upload_bytes": 1572864
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Bandwidth usage updated successfully",
  "usage_id": 3
}
```

### Device Control

#### POST /api/devices/<string:mac_address>/block

Block a device from accessing the network.

**Request Body:**
```json
{
  "duration": 3600,
  "reason": "Policy violation"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Device blocked successfully",
  "blocked_until": "2023-06-01T15:30:00"
}
```

#### POST /api/devices/<string:mac_address>/unblock

Unblock a previously blocked device.

**Request Body:**
```json
{
  "reason": "Block duration expired"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Device unblocked successfully"
}
```

#### POST /api/devices/<string:mac_address>/bandwidth

Limit bandwidth for a specific device.

**Request Body:**
```json
{
  "download_limit": 1024,
  "upload_limit": 512
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Bandwidth limited successfully"
}
```

### Device Summary

#### GET /api/devices/summary

Get a summary of device statistics.

**Query Parameters:**
- `branch_id` (optional): Filter by branch ID

**Response:**
```json
{
  "total_devices": 100,
  "active_devices": 80,
  "blocked_devices": 5,
  "archived_devices": 15,
  "device_types": {
    "laptop": 40,
    "smartphone": 35,
    "tablet": 15,
    "other": 10
  },
  "recent_activities": {
    "connect": 150,
    "disconnect": 120,
    "block": 10,
    "unblock": 8,
    "bandwidth_change": 25
  },
  "total_bandwidth": {
    "download_bytes": 1073741824,
    "upload_bytes": 536870912
  }
}
```

## Monitoring Services

### Starting the Monitoring Services

#### POST /api/device-monitoring/start

Start the device monitoring services (connection and bandwidth monitoring).

**Response:**
```json
{
  "status": "success",
  "message": "Device monitoring services started",
  "started_by": "admin"
}
```

### Stopping the Monitoring Services

#### POST /api/device-monitoring/stop

Stop the device monitoring services.

**Response:**
```json
{
  "status": "success",
  "message": "Device monitoring services stopped",
  "stopped_by": "admin"
}
```

## Monitoring Scripts

### device_bandwidth_monitor.py

Monitors bandwidth usage for all active devices and updates the database at regular intervals.

### device_connection_monitor.py

Monitors device connections and disconnections, recording activities in the database.

### run_device_monitors.py

A helper script to run both monitoring services and manage their lifecycle.