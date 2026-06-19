from hackertrap.config import DEFAULT_REPO_PATH, DEFAULT_REPO_URL
from hackertrap.system_ops import repo_dir


def test_repo_dir_defaults():
    path = repo_dir("", "")
    assert str(path) == DEFAULT_REPO_PATH


def test_default_repo_url():
    assert "marckranat/hackertrap" in DEFAULT_REPO_URL
