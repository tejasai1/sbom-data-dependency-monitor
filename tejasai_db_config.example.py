import pymysql

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "your_password_here",
    "database": "sbom_monitoring_tejasai",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "connect_timeout": 30,
    "read_timeout": 30,
    "write_timeout": 30,
    "autocommit": False,
}
