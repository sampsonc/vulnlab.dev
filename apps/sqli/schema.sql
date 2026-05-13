-- vulnlab_sqli schema + seed data.
-- Idempotent: safe to re-run via scripts/bootstrap-sqli-db.sh.

CREATE TABLE IF NOT EXISTS users (
    id       INT PRIMARY KEY AUTO_INCREMENT,
    -- 255 because the second-order lab stores payloads here and the
    -- canonical payload is ~70 chars. Real apps often use TEXT/VARCHAR(255)
    -- for usernames anyway.
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email    VARCHAR(255),
    role     VARCHAR(32) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS products (
    id          INT PRIMARY KEY AUTO_INCREMENT,
    name        VARCHAR(128) NOT NULL,
    description TEXT,
    price       DECIMAL(10,2) NOT NULL,
    category    VARCHAR(64) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS secrets (
    id    INT PRIMARY KEY AUTO_INCREMENT,
    name  VARCHAR(64) UNIQUE NOT NULL,
    value TEXT NOT NULL
) ENGINE=InnoDB;

-- Second-order lab uses this: notes get attached to a username at insert
-- time (parameterized), but a downstream profile-view query concatenates
-- the username back into another SELECT.
CREATE TABLE IF NOT EXISTS notes (
    id    INT PRIMARY KEY AUTO_INCREMENT,
    owner VARCHAR(64) NOT NULL,
    body  TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (owner)
) ENGINE=InnoDB;

-- Schema migrations (idempotent): widen username so second-order payloads fit.
ALTER TABLE users    MODIFY COLUMN username VARCHAR(255) NOT NULL;
ALTER TABLE notes    MODIFY COLUMN owner    VARCHAR(255) NOT NULL;

-- Seed users (REPLACE to keep idempotent).
REPLACE INTO users (id, username, password, email, role) VALUES
    (1, 'alice', 'alice-hunter2-NOTREAL',  'alice@vulnlab.dev', 'admin'),
    (2, 'bob',   'bob-correct-horse-NOTREAL', 'bob@vulnlab.dev', 'user'),
    (3, 'carol', 'carol-stapler-NOTREAL',  'carol@vulnlab.dev', 'user');

REPLACE INTO products (id, name, description, price, category) VALUES
    (1, 'Widget Pro',   'The classic premium widget. Battle-tested.', 19.99, 'widgets'),
    (2, 'Widget Lite',  'Lightweight widget for casual use.',          9.99, 'widgets'),
    (3, 'Sprocket Maxi','Heavy-duty industrial sprocket.',            29.99, 'sprockets'),
    (4, 'Sprocket Mini','Compact sprocket for tight spaces.',         14.99, 'sprockets'),
    (5, 'Gadget Deluxe','Top-of-the-line gadget with extras.',        49.99, 'gadgets'),
    (6, 'Gadget Basic', 'No-frills gadget. Just works.',              24.99, 'gadgets');

REPLACE INTO secrets (id, name, value) VALUES
    (1, 'sqli-union',         'VULNLAB{sqli-union-based-extraction}'),
    (2, 'sqli-error',         'VULNLAB{sqli-error-based-extraction}'),
    (3, 'sqli-blind-bool',    'VULNLAB{sqli-blind-boolean-oracle}'),
    (4, 'sqli-blind-time',    'VULNLAB{sqli-blind-time-based-oracle}'),
    (5, 'sqli-second-order',  'VULNLAB{sqli-second-order-via-stored-input}');
