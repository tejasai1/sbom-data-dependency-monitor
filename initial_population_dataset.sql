USE SBOM_Monitoring_DB;

CREATE TABLE IF NOT EXISTS monitored_targets (
    target_pk INT AUTO_INCREMENT PRIMARY KEY,
    target_id VARCHAR(500) NOT NULL UNIQUE,
    target_type VARCHAR(50) DEFAULT 'linux_binary',
    source_name VARCHAR(100) DEFAULT 'dr_charles_bash',
    active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scan_time DATETIME NULL,
    notes VARCHAR(255) NULL
);

INSERT INTO monitored_targets (target_id, target_type, source_name, active, notes)
VALUES
('mysql', 'linux_binary', 'dr_charles_bash', 1, 'Original Dr. Charles script item'),
('dockerd', 'linux_binary', 'dr_charles_bash', 1, 'Original Dr. Charles script item'),
('apt', 'linux_binary', 'dr_charles_bash', 1, 'Original Dr. Charles script item'),
('apache2', 'linux_binary', 'dr_charles_bash', 1, 'Original Dr. Charles script item'),
('nginx', 'linux_binary', 'dr_charles_bash', 1, 'Original Dr. Charles script item'),
('python3.12', 'linux_binary', 'dr_charles_bash', 1, 'Original Dr. Charles script item'),
('git', 'linux_binary', 'dr_charles_bash', 1, 'Original Dr. Charles script item'),
('curl', 'linux_binary', 'extended_seed', 1, 'Common transfer utility for monitoring'),
('wget', 'linux_binary', 'extended_seed', 1, 'Common download utility for monitoring'),
('bash', 'linux_binary', 'extended_seed', 1, 'Shell runtime frequently present in Linux'),
('ssh', 'linux_binary', 'extended_seed', 1, 'Secure shell client'),
('scp', 'linux_binary', 'extended_seed', 1, 'Secure copy utility'),
('tar', 'linux_binary', 'extended_seed', 1, 'Archive utility'),
('gzip', 'linux_binary', 'extended_seed', 1, 'Compression utility'),
('openssl', 'linux_binary', 'extended_seed', 1, 'Cryptographic toolkit'),
('python3', 'linux_binary', 'extended_seed', 1, 'General Python runtime alias'),
('pip3', 'linux_binary', 'extended_seed', 1, 'Python package manager'),
('perl', 'linux_binary', 'extended_seed', 1, 'Legacy scripting runtime'),
('php', 'linux_binary', 'extended_seed', 1, 'Web scripting runtime'),
('node', 'linux_binary', 'extended_seed', 1, 'JavaScript runtime'),
('npm', 'linux_binary', 'extended_seed', 1, 'Node package manager'),
('java', 'linux_binary', 'extended_seed', 1, 'Java runtime'),
('systemctl', 'linux_binary', 'extended_seed', 1, 'System service manager'),
('dpkg', 'linux_binary', 'extended_seed', 1, 'Debian package database tool'),
('journalctl', 'linux_binary', 'extended_seed', 1, 'System log query utility')
ON DUPLICATE KEY UPDATE
    target_type = VALUES(target_type),
    source_name = VALUES(source_name),
    active = VALUES(active),
    notes = VALUES(notes);
