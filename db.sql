-- Create the database if not exists
CREATE DATABASE IF NOT EXISTS rest_apisec;

-- Use the database
USE rest_apisec;

-- Create the rest_user table
CREATE TABLE IF NOT EXISTS rest_user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL
);

-- Insert sample data (optional)
INSERT INTO rest_user (name, password, email, role) VALUES
    ('user', '1rdTeqlm2g', 'user@mail.com', 'user'),
    ('admin', '9yRyb5P9k7', 'admin@mail.com', 'admin');

-- Add 'DESCRIPTION' column to 'rest_user' table
ALTER TABLE rest_user
ADD COLUMN DESCRIPTION VARCHAR(255);

-- Add 'api_key' column to 'rest_user' table
ALTER TABLE rest_user
ADD COLUMN api_key VARCHAR(16);

-- Update 'api_key' with random 16-bit key for existing users
UPDATE rest_user
SET api_key = SUBSTRING(MD5(RAND()), 1, 16);

-- Display the updated table structure
DESCRIBE rest_user;

-- Create the old_db table
CREATE TABLE IF NOT EXISTS old_db (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    admin INT DEFAULT 1,
    api_key VARCHAR(32) DEFAULT NULL,
    chat VARCHAR(255) DEFAULT NULL
);

-- Insert sample data
INSERT INTO old_db (username, password, email, admin, api_key, chat)
VALUES
    ('admin', '404mJX6ez3', 'admin@mail.com', 0, '7N6X50Ev14WcoX851023x4242pW10IyT', 'I am admin user'),
    ('user', 'U4gOSJ7OS9', 'user@mail.com', 1, 'pgO3Lo4MqQiK6Mg0w0k587O258d47FaE', 'I am a normal user');

-- Add 'session' column to 'old_db' table
ALTER TABLE old_db
ADD COLUMN session VARCHAR(255);
