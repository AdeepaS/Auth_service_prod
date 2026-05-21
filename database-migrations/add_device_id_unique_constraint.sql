-- Add unique constraint to prevent duplicate device IDs
-- Auth Service Users table

ALTER TABLE Users 
ADD CONSTRAINT uk_connected_safenet_device_id UNIQUE (connected_safenet_device_id);
