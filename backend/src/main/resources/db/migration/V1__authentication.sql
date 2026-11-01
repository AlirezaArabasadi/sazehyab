CREATE TABLE users (
 id VARCHAR(36) PRIMARY KEY,
 name VARCHAR(100) NOT NULL,
 phone VARCHAR(11) NOT NULL UNIQUE,
 password_hash VARCHAR(100) NOT NULL,
 role VARCHAR(20) NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE auth_sessions (
 token_hash VARCHAR(64) PRIMARY KEY,
 user_id VARCHAR(36) NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX idx_session_expiry ON auth_sessions(expires_at);
