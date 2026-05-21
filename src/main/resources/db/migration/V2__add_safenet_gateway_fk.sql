-- Migration: Add SafeNet Gateway table and Foreign Key constraint
-- Date: 2026-01-27
-- Purpose: Create safenet_gateway table and establish FK relationship with Users table

-- Create safenet_gateway table if it doesn't exist
CREATE TABLE IF NOT EXISTS safenet_gateway (
    device_cpu_id VARCHAR(255) PRIMARY KEY,
    device_mac_address VARCHAR(255),
    owner_id INT,
    last_connected_time TIMESTAMP,
    license_id VARCHAR(255),
    subscription_start_date DATE,
    subscription_end_date DATE
);

-- Add foreign key constraint from Users to safenet_gateway
ALTER TABLE Users ADD CONSTRAINT fk_users_safenet_device
FOREIGN KEY (connected_safenet_device_id) 
REFERENCES safenet_gateway(device_cpu_id)
ON DELETE RESTRICT
ON UPDATE CASCADE;
