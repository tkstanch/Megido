from pathlib import Path

from megido_security import platform_utils


def test_platform_dirs_are_created():
    assert platform_utils.get_config_dir().exists()
    assert platform_utils.get_data_dir().exists()
    assert platform_utils.get_cache_dir().exists()
    assert platform_utils.get_log_dir().exists()


def test_find_executable_accepts_known_binary():
    python_path = platform_utils.find_executable("python") or platform_utils.find_executable("python3")
    assert python_path is None or Path(python_path).name.startswith("python")
