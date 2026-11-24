"""FastAPI 入口：崩溃栈提交、按报告号查询、CI 批量补传 ELF。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from . import __version__
from .config import settings
from .storage import BatchRejected, Store

_store: Optional[Store] = None


def get_store() -> Store:
    # 测试可通过 dependency_overrides 替换
    if _store is None:
        raise RuntimeError("Store 尚未初始化")
    return _store


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store
    _store = Store()
    yield
    if _store is not None:
        _store.close()
        _store = None


app = FastAPI(
    title="Linux 崩溃栈还原服务",
    version=__version__,
    description=(
        "值班员提交各帧的 ELF Build ID 与扣除装载偏移后的地址，凭报告号查询函数与源码行；"
        "CI 可批量补传带 Build ID 与 DWARF 调试信息的 x86-64 ELF。"
        "查询绑定开始解析时的符号版本快照，查栈与发布可并行。"
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# 请求/响应模型
# ---------------------------------------------------------------------------
class FrameIn(BaseModel):
    build_id: Optional[str] = Field(
        default=None,
        description="GNU Build ID（十六进制，不带 0x）；未知时可留空，该帧保留原地址",
    )
    address: str = Field(
        ...,
        description="已扣除装载偏移的地址，支持 0x 前缀十六进制或十进制字符串",
    )


class ReportIn(BaseModel):
    frames: List[FrameIn] = Field(..., min_length=1, description="崩溃栈各帧，自底向上或自顶向下均可，按提交顺序保存")


class FrameOut(BaseModel):
    position: int
    build_id: Optional[str]
    address: str
    status: str
    reason: Optional[str]
    function: Optional[str]
    source_file: Optional[str]
    source_line: Optional[int]


class ReportOut(BaseModel):
    report_id: int
    created_at: str
    snapshot_symbol_version: int
    current_symbol_version: int
    frame_count: int
    resolved_count: int
    frames: List[FrameOut]


class BatchResult(BaseModel):
    accepted: int
    new_build_ids: List[str]
    redundant: int
    symbol_version: int


# ---------------------------------------------------------------------------
# 接口
# ---------------------------------------------------------------------------
@app.get("/health", tags=["运维"])
def health():
    store = get_store()
    return {
        "status": "ok",
        "version": __version__,
        "symbol_version": store.symbol_version,
        "published_build_ids": len(store.list_build_ids()),
        "data_dir": settings.data_dir,
    }


@app.post("/reports", response_model=ReportOut, status_code=201, tags=["崩溃报告"])
def submit_report(payload: ReportIn):
    """提交崩溃栈并立即按当前已发布符号做一次解析，返回报告号。"""
    store = get_store()
    frames = [f.model_dump() for f in payload.frames]
    report_id = store.create_report(frames)
    return store.resolve_report(report_id)


@app.get("/reports/{report_id}", response_model=ReportOut, tags=["崩溃报告"])
def get_report(report_id: int):
    """凭报告号查询；补传 ELF 后用同一报告号再查即可得到新解析结果。

    每次查询只使用本次开始解析时已发布的符号版本（快照）。
    """
    store = get_store()
    result = store.resolve_report(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return result


@app.get("/reports/{report_id}/raw", tags=["崩溃报告"])
def get_report_raw(report_id: int):
    """查看报告原始帧（地址原样保留）。"""
    store = get_store()
    raw = store.get_report_raw(report_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return raw


@app.post("/symbols/batch", response_model=BatchResult, tags=["符号发布"])
def upload_batch(files: List[UploadFile] = File(..., description="一批 x86-64 ELF 文件")):
    """CI 整批补传 ELF。

    - Build ID 从文件内部的 NT_GNU_BUILD_ID 注释读取；
    - 任一文件缺标识、缺调试信息、非 x86-64，或与同 Build ID 已发布/同批文件内容不同，
      整批退回（422），不留任何部分结果；
    - 相同文件重传视为成功，计入 redundant。

    同步端点：阻塞式校验/落盘由 Starlette 放到线程池执行，不卡住事件循环。
    """
    if not files:
        raise HTTPException(status_code=422, detail="未上传任何文件")
    blobs: list[tuple[str, bytes]] = []
    for upload in files:
        blob = upload.file.read()
        if not blob:
            raise HTTPException(status_code=422, detail=f"文件 {upload.filename} 为空")
        blobs.append((upload.filename or "unnamed", blob))

    store = get_store()
    try:
        return store.publish_batch(blobs)
    except BatchRejected as exc:
        raise HTTPException(status_code=422, detail={"message": "整批退回", "errors": exc.errors})


@app.get("/symbols", tags=["符号发布"])
def list_symbols():
    """列出当前已发布的 Build ID。"""
    store = get_store()
    return {"symbol_version": store.symbol_version, "build_ids": store.list_build_ids()}
