"""pytest 公共夹具：每个测试使用独立数据目录，并构建一次 ELF 固件。"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "built"


@pytest.fixture(scope="session", autouse=True)
def build_fixtures():
    marker = FIXTURE_DIR / ".ok"
    if not marker.exists():
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["bash", str(ROOT / "scripts" / "build_fixtures.sh"), str(FIXTURE_DIR)],
            check=True,
        )
        marker.touch()
    yield


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    d.mkdir()
    # 兜底：任何走默认配置的初始化也落到测试目录（测试里 Store 均显式传 data_dir）
    monkeypatch.setenv("SYMBOL_DATA_DIR", str(d))
    return str(d)


@pytest.fixture()
def store(data_dir):
    from app.storage import Store

    s = Store(data_dir=data_dir)
    yield s
    s.close()


@pytest.fixture()
def client(data_dir):
    from fastapi.testclient import TestClient

    from app import main as main_module
    from app.storage import Store

    test_store = Store(data_dir=data_dir)
    main_module._store = test_store
    with TestClient(main_module.app) as c:
        yield c, test_store
    main_module._store = None
    test_store.close()
