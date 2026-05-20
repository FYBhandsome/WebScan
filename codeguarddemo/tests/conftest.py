import sys
import os
import asyncio
import pytest
from pathlib import Path

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

os.environ.setdefault("CODE_GUARD_DB_URL", "sqlite://./test_codeguard.db")


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_code():
    return """
def hello():
    print("safe")
"""


@pytest.fixture
def danger_code():
    return """
password = "Admin@123456"
eval("print('danger')")
import os
os.system("ls")
cursor.execute(f"SELECT * FROM user WHERE name='admin'")
"""


@pytest.fixture
def syntax_error_code():
    return """
def broken(:
    pass
"""


@pytest.fixture
def hardcode_code():
    return """
api_key = "sk-1234567890abcdef"
secret = "mysecret123"
"""


@pytest.fixture
def sql_code():
    return """
cursor.execute("SELECT * FROM users")
cursor.executemany("INSERT INTO users VALUES (?)")
"""


@pytest.fixture
def safe_code():
    return """
def add(a, b):
    return a + b

class Calculator:
    def multiply(self, x, y):
        return x * y
"""


@pytest.fixture
def danger_functions_code():
    return """
eval(user_input)
exec("print('test')")
os.system("ls -la")
subprocess.call(["ls", "-la"])
import popen
popen("command")
"""


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_db():
    yield
    import os as _os
    db_path = Path(__file__).parent.parent / "test_codeguard.db"
    if db_path.exists():
        _os.remove(db_path)
