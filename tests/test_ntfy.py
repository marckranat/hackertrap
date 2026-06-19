from hackertrap.config import normalize_ntfy_topic


def test_normalize_ntfy_topic_plain():
    assert normalize_ntfy_topic("JkdQO4P") == "JkdQO4P"


def test_normalize_ntfy_topic_full_url():
    assert normalize_ntfy_topic("https://ntfy.sh/JkdQO4P") == "JkdQO4P"
    assert normalize_ntfy_topic("http://ntfy.sh/my-topic") == "my-topic"


def test_normalize_ntfy_topic_strips_whitespace():
    assert normalize_ntfy_topic("  JkdQO4P  ") == "JkdQO4P"
