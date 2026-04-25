import os

TEST_MODE = os.environ.get("TEST_MODE", "mock")

REQUEST_TIMEOUT = 30
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60

MAX_RETRIES = 3
RETRY_DELAY = 1.0
RETRY_BACKOFF_FACTOR = 2.0

MAX_CONCURRENT_REQUESTS = 10
RATE_LIMIT_REQUESTS_PER_SECOND = 5

TEST_DATA_DIR = os.path.dirname(os.path.abspath(__file__))

MOCK_SERVER_HOST = "127.0.0.1"
MOCK_SERVER_PORT = 8888
MOCK_SERVER_URL = f"http://{MOCK_SERVER_HOST}:{MOCK_SERVER_PORT}"

DATABASE_CONFIG = {
    "test": {
        "host": "localhost",
        "port": 5432,
        "database": "toskill_test",
        "user": "test_user",
        "password": "test_password"
    }
}

REDIS_CONFIG = {
    "test": {
        "host": "localhost",
        "port": 6379,
        "db": 1,
        "password": None
    }
}

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "standard",
            "stream": "ext://sys.stdout"
        },
        "file": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": "tests/test.log",
            "mode": "a"
        }
    },
    "loggers": {
        "toskill": {
            "level": "DEBUG",
            "handlers": ["console", "file"],
            "propagate": False
        }
    }
}

SCAN_CONFIG = {
    "port_scan": {
        "common_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017],
        "timeout": 5,
        "max_threads": 100
    },
    "subdomain_scan": {
        "wordlist": "common_subdomains.txt",
        "timeout": 10,
        "max_threads": 50
    },
    "dir_scan": {
        "wordlist": "common_directories.txt",
        "timeout": 10,
        "max_threads": 50,
        "extensions": [".php", ".asp", ".aspx", ".jsp", ".html", ".js"]
    },
    "vuln_scan": {
        "timeout": 30,
        "max_threads": 20
    }
}

REPORT_CONFIG = {
    "output_dir": "reports",
    "formats": ["json", "html", "markdown"],
    "include_evidence": True,
    "max_evidence_size_mb": 10
}

AI_CONFIG = {
    "enabled": True,
    "model": "gpt-4",
    "max_tokens": 4096,
    "temperature": 0.7,
    "timeout": 60
}

FEATURE_FLAGS = {
    "enable_ai_analysis": True,
    "enable_auto_poc": True,
    "enable_real_time_reporting": True,
    "enable_websocket_notifications": True,
    "mock_external_services": True
}

CLEANUP_CONFIG = {
    "auto_cleanup": True,
    "cleanup_on_success": True,
    "cleanup_on_failure": True,
    "temp_dir_retention_hours": 24
}

def get_test_config():
    return {
        "test_mode": TEST_MODE,
        "timeout": {
            "request": REQUEST_TIMEOUT,
            "connect": CONNECT_TIMEOUT,
            "read": READ_TIMEOUT
        },
        "retry": {
            "max_retries": MAX_RETRIES,
            "delay": RETRY_DELAY,
            "backoff_factor": RETRY_BACKOFF_FACTOR
        },
        "concurrency": {
            "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
            "rate_limit": RATE_LIMIT_REQUESTS_PER_SECOND
        },
        "mock_server": {
            "url": MOCK_SERVER_URL,
            "host": MOCK_SERVER_HOST,
            "port": MOCK_SERVER_PORT
        },
        "database": DATABASE_CONFIG["test"],
        "redis": REDIS_CONFIG["test"],
        "logging": LOGGING_CONFIG,
        "scan": SCAN_CONFIG,
        "report": REPORT_CONFIG,
        "ai": AI_CONFIG,
        "features": FEATURE_FLAGS,
        "cleanup": CLEANUP_CONFIG
    }

def get_mock_response_path(response_type: str) -> str:
    return os.path.join(TEST_DATA_DIR, "mock_responses.json")

def get_test_targets_path() -> str:
    return os.path.join(TEST_DATA_DIR, "test_targets.json")
