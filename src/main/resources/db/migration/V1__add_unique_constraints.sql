-- Migration: Add unique constraints to Users table for data validation
-- Date: 2026-01-25
-- Purpose: Enforce uniqueness at database level for mobile number and device ID

-- Add unique constraint for mobile number
ALTER TABLE Users ADD CONSTRAINT unique_mobile_number UNIQUE (mobilenumber);

-- Add unique constraint for connected safenet device ID
ALTER TABLE Users ADD CONSTRAINT unique_device_id UNIQUE (connected_safenet_device_id);
