#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import Any

from .bakery_api.v1 import OS, FileGenerator, Plugin, register


def get_fail2ban_files(conf: Any) -> FileGenerator:
    if conf.get("activated"):
        yield Plugin(base_os=OS.LINUX,
                     source=Path("fail2ban"),
                     interval=conf.get('interval'))


register.bakery_plugin(
    name="fail2ban",
    files_function=get_fail2ban_files,
)

