-- Add migration script here
ALTER TABLE users ADD client_salt TEXT NOT NULL;