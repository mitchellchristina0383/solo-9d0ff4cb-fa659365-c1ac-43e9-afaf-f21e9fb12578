"""运行期配置，全部可通过环境变量覆盖。"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _data_dir() -> str:
    return os.environ.get("SYMBOL_DATA_DIR", "/data")


@dataclass(frozen=True)
class Settings:
    data_dir: str = _data_dir()
    elf_dir_name: str = "elfs"
    db_name: str = "service.sqlite3"

    @property
    def elf_dir(self) -> str:
        return os.path.join(self.data_dir, self.elf_dir_name)

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, self.db_name)


settings = Settings()
