"""回归测试：提交暂停时的已提交快照、失败回滚后换同号文件重传、重启一致性。

对应事故：首次补传某 Build ID 的 ELF 时，查询发生在 SQLite 提交前，共享连接
读到未提交映射并把第一份 ELF 按 Build ID 缓存；提交失败回滚后，换一份同号
不同内容的 ELF 重传成功，原报告在同进程内仍指向第一次的源码，而重启后缓存
清空又指向新文件——重启前后不一致。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

import httpx
import pytest
from elftools.elf.elffile import ELFFile

from app.storage import Store

FIX = Path(__file__).resolve().parent / "fixtures" / "built"
BUILD_ID_A = "a" * 40


def read_fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


def func_address(elf_path: Path, func: str) -> int:
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_SYMTAB":
                continue
            for sym in section.iter_symbols():
                if sym.name == func and sym["st_info"]["type"] == "STT_FUNC":
                    return sym["st_value"]
    raise AssertionError(f"符号 {func} 未在 {elf_path} 中找到")


@pytest.fixture()
def report_with_a_frame(store):
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    report_id = store.create_report(
        [{"build_id": BUILD_ID_A, "address": hex(addr)}]
    )
    return report_id, addr


# ---------------------------------------------------------------------------
# 1. 提交暂停 / 存在未提交事务时，查询只能看到开始时已提交的版本
# ---------------------------------------------------------------------------
def test_query_inside_uncommitted_publish_sees_committed_snapshot(
    store, data_dir, report_with_a_frame
):
    report_id, _addr = report_with_a_frame
    blob = read_fixture("demo-aaaa.elf")
    digest = hashlib.sha256(blob).hexdigest()
    staged = Path(data_dir) / "elfs" / f"{digest}.elf"
    staged.write_bytes(blob)

    # 模拟 publish_batch 已完成 INSERT/UPDATE、但尚未 COMMIT 的“提交暂停”状态
    with store._lock:
        store._conn.execute(
            "INSERT INTO elfs(build_id, sha256, path, version) VALUES(?,?,?,?)",
            (BUILD_ID_A, digest, str(staged), 1),
        )
        store._conn.execute(
            "UPDATE meta SET value=1 WHERE key='symbol_version'"
        )
        # 注意：此处故意不 commit，事务保持打开

        result = store.resolve_report(report_id)

    try:
        # 未提交的版本 1 对查询不可见，快照停留在已提交的 0
        assert result["snapshot_symbol_version"] == 0
        assert result["current_symbol_version"] == 0
        frame = result["frames"][0]
        assert frame["status"] == "unresolved"
        assert frame["reason"] == "build_id_not_published_at_snapshot"
        assert frame["function"] is None
    finally:
        store._conn.rollback()


def test_query_while_commit_paused_in_worker_thread(store, report_with_a_frame):
    """真实 publish_batch 在工作线程内停在提交闸门，主线程并发查栈。"""
    report_id, _addr = report_with_a_frame
    entered = threading.Event()
    release = threading.Event()
    holder: dict = {}

    def pause_gate():
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError("release event timeout")

    store._commit_gate = pause_gate

    def publish():
        try:
            holder["result"] = store.publish_batch(
                [("demo.elf", read_fixture("demo-aaaa.elf"))]
            )
        except BaseException as exc:  # noqa: BLE001 - 测试需要回传任何异常
            holder["error"] = exc

    t = threading.Thread(target=publish)
    t.start()
    try:
        assert entered.wait(timeout=5)
        # 提交暂停中：查栈不被写事务阻塞，且只看到已提交的 v0
        paused = store.resolve_report(report_id)
        assert paused["snapshot_symbol_version"] == 0
        assert paused["frames"][0]["status"] == "unresolved"
    finally:
        release.set()
        t.join(timeout=10)
    assert not t.is_alive()
    assert "error" not in holder, holder.get("error")
    assert holder["result"]["symbol_version"] == 1

    after = store.resolve_report(report_id)
    assert after["snapshot_symbol_version"] == 1
    assert after["frames"][0]["function"] == "crash_here"
    assert after["frames"][0]["source_file"].endswith("demo.c")


# ---------------------------------------------------------------------------
# 2. 首次提交失败回滚 -> 帧保持未解析 -> 换同号文件重传 -> 指向新发布源码，
#    且同进程与重启后的结果完全一致
# ---------------------------------------------------------------------------
def test_rollback_then_different_content_same_buildid_reupload(
    store, data_dir, report_with_a_frame
):
    report_id, _addr = report_with_a_frame
    elf_dir = os.path.join(data_dir, "elfs")

    def fail_gate():
        raise RuntimeError("simulated SQLite commit failure")

    store._commit_gate = fail_gate
    with pytest.raises(RuntimeError):
        store.publish_batch([("first.elf", read_fixture("demo-aaaa.elf"))])

    # 回滚干净：版本不前进、无映射、暂存内容文件已清理、写连接无残留事务
    assert store.symbol_version == 0
    assert store.list_build_ids() == []
    assert os.listdir(elf_dir) == []

    between = store.resolve_report(report_id)
    assert between["snapshot_symbol_version"] == 0
    frame = between["frames"][0]
    assert frame["status"] == "unresolved"
    assert frame["reason"] == "build_id_not_published_at_snapshot"

    # CI 用另一份“同 Build ID、不同内容”的 ELF 补传成功
    store._commit_gate = lambda: None
    uploaded = store.publish_batch(
        [("replacement.elf", read_fixture("demo-aaaa-CONFLICT.elf"))]
    )
    assert uploaded["symbol_version"] == 1
    assert uploaded["new_build_ids"] == [BUILD_ID_A]

    same_process = store.resolve_report(report_id)
    new_frame = same_process["frames"][0]
    assert new_frame["status"] == "resolved"
    assert new_frame["source_file"].endswith("demo_conflict.c")

    # 关键回归断言：同进程结果必须等于“重启后”的结果（旧代码此处指向 demo.c）
    store.close()
    restarted = Store(data_dir=data_dir)
    try:
        after_restart = restarted.resolve_report(report_id)
        restart_frame = after_restart["frames"][0]
        assert after_restart["snapshot_symbol_version"] == 1
        for key in ("status", "function", "source_file", "source_line"):
            assert new_frame[key] == restart_frame[key], key
        assert restart_frame["source_file"].endswith("demo_conflict.c")
    finally:
        restarted.close()


def test_symbolizer_cache_distinguishes_content_by_path_or_hash():
    """单元级：同一 Build ID 换了文件路径/哈希，不得命中旧解析缓存。"""
    from app.elftools_ext import Symbolizer

    sym = Symbolizer()
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    first = sym.symbolize(str(FIX / "demo-aaaa.elf"), BUILD_ID_A, addr, cache_key="hash-a")
    # 同 build_id、不同 cache_key/path，必须重新解析第二份内容
    second = sym.symbolize(
        str(FIX / "demo-aaaa-CONFLICT.elf"), BUILD_ID_A, addr, cache_key="hash-b"
    )
    assert first.file.endswith("demo.c")
    assert second.file.endswith("demo_conflict.c")

    # 收回 hash-a 后不影响 hash-b
    sym.evict_key("hash-a")
    again_b = sym.symbolize(
        str(FIX / "demo-aaaa-CONFLICT.elf"), BUILD_ID_A, addr, cache_key="hash-b"
    )
    assert again_b.file.endswith("demo_conflict.c")


# ---------------------------------------------------------------------------
# 3. 控制文件闸门（Docker 演练入口）：fail_next_commit 一次性，触发后可正常发布
# ---------------------------------------------------------------------------
def test_commit_control_file_fail_once(store, data_dir):
    ctl = Path(data_dir) / "commit-control.json"
    ctl.write_text(json.dumps({"pause_seconds": 0, "fail_next_commit": True}))
    with pytest.raises(RuntimeError):
        store.publish_batch([("a.elf", read_fixture("demo-aaaa.elf"))])
    # 一次性开关已自动清零，版本/映射未落库
    assert json.loads(ctl.read_text())["fail_next_commit"] is False
    assert store.symbol_version == 0
    assert store.list_build_ids() == []
    # 控制文件仍在但 fail 已清零：后续发布正常
    ok = store.publish_batch([("a.elf", read_fixture("demo-aaaa.elf"))])
    assert ok["symbol_version"] == 1


# ---------------------------------------------------------------------------
# 4. TestClient + conftest.client 注入路径：夹具交出的 store 就是在线实例，
#    可直接装闸门；失败回滚后换文件重传（TestClient 默认重抛 5xx 异常）
# ---------------------------------------------------------------------------
def test_testclient_injected_store_is_live_and_rollback_replace(client):
    from app.main import get_store

    c, store = client
    assert get_store() is store  # lifespan 不得覆盖测试注入的实例

    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    report_id = c.post(
        "/reports",
        json={"frames": [{"build_id": BUILD_ID_A, "address": hex(addr)}]},
    ).json()["report_id"]

    def fail_gate():
        raise RuntimeError("simulated commit failure")

    store._commit_gate = fail_gate
    with pytest.raises(RuntimeError):
        c.post(
            "/symbols/batch",
            files=[("files", ("first.elf", read_fixture("demo-aaaa.elf"),
                              "application/octet-stream"))],
        )

    assert store.symbol_version == 0
    assert store.list_build_ids() == []
    mid = c.get(f"/reports/{report_id}").json()
    assert mid["frames"][0]["status"] == "unresolved"

    store._commit_gate = lambda: None
    ok = c.post(
        "/symbols/batch",
        files=[("files", ("second.elf", read_fixture("demo-aaaa-CONFLICT.elf"),
                          "application/octet-stream"))],
    )
    assert ok.status_code == 200
    body = c.get(f"/reports/{report_id}").json()
    assert body["frames"][0]["source_file"].endswith("demo_conflict.c")


# ---------------------------------------------------------------------------
# 5. 真实 uvicorn + HTTP：分别演练“提交暂停时查栈”和“回滚后换文件重传”
# ---------------------------------------------------------------------------
def test_http_commit_pause_and_rollback_replace_flow(data_dir):
    import socket
    import uvicorn

    from app.main import app, get_store

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                httpx.get(f"{base}/health", timeout=1)
                break
            except httpx.HTTPError:
                import time

                time.sleep(0.1)

        addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
        report_id = httpx.post(
            f"{base}/reports",
            json={"frames": [{"build_id": BUILD_ID_A, "address": hex(addr)}]},
            timeout=10,
        ).json()["report_id"]

        store = get_store()
        entered = threading.Event()
        release = threading.Event()
        should_fail = {"value": True}

        def gate():
            entered.set()
            if not release.wait(timeout=15):
                raise RuntimeError("gate timeout")
            if should_fail["value"]:
                raise RuntimeError("simulated SQLite commit failure")

        store._commit_gate = gate

        upload_holder: dict = {}

        def upload_first():
            try:
                with open(FIX / "demo-aaaa.elf", "rb") as fh:
                    upload_holder["response"] = httpx.post(
                        f"{base}/symbols/batch",
                        files=[("files", ("first.elf", fh.read(), "application/octet-stream"))],
                        timeout=30,
                    )
            except BaseException as exc:  # noqa: BLE001
                upload_holder["error"] = exc

        ut = threading.Thread(target=upload_first)
        ut.start()
        assert entered.wait(timeout=5)

        # (a) 提交暂停时查栈：服务可用，版本停留在 0，帧未解析
        paused = httpx.get(f"{base}/reports/{report_id}", timeout=10).json()
        assert paused["snapshot_symbol_version"] == 0
        assert paused["frames"][0]["status"] == "unresolved"
        health = httpx.get(f"{base}/health", timeout=10).json()
        assert health["symbol_version"] == 0

        # 放行并令首次提交失败 -> 整批 500/回滚
        release.set()
        ut.join(timeout=30)
        assert not ut.is_alive()
        assert "error" not in upload_holder
        assert upload_holder["response"].status_code == 500

        # (b) 失败到重传成功之间：仍然未解析
        between = httpx.get(f"{base}/reports/{report_id}", timeout=10).json()
        assert between["snapshot_symbol_version"] == 0
        assert between["frames"][0]["status"] == "unresolved"

        # (c) 换一份同号不同内容的 ELF 重传成功
        store._commit_gate = lambda: None
        with open(FIX / "demo-aaaa-CONFLICT.elf", "rb") as fh:
            reup = httpx.post(
                f"{base}/symbols/batch",
                files=[("files", ("second.elf", fh.read(), "application/octet-stream"))],
                timeout=30,
            )
        assert reup.status_code == 200, reup.text
        assert reup.json()["symbol_version"] == 1

        final = httpx.get(f"{base}/reports/{report_id}", timeout=10).json()
        assert final["frames"][0]["status"] == "resolved"
        assert final["frames"][0]["source_file"].endswith("demo_conflict.c")

        # (d) 模拟重启：同数据目录新建 Store，结果必须一致
        restarted = Store(data_dir=data_dir)
        try:
            reboot = restarted.resolve_report(report_id)
            rf, ff = reboot["frames"][0], final["frames"][0]
            assert rf["source_file"] == ff["source_file"]
            assert rf["source_line"] == ff["source_line"]
            assert rf["function"] == ff["function"]
        finally:
            restarted.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
