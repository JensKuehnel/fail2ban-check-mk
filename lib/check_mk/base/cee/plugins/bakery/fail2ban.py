#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: Checkmk Enterprise License
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from pathlib import Path
from typing import Any, Dict

from .bakery_api.v1 import FileGenerator, OS, Plugin, PluginConfig, register

def get_fail2ban_files(conf: Dict[str, Any]) -> FileGenerator:
    interval = conf.get('interval')
    yield Plugin(base_os=OS.LINUX,
                 source=Path("fail2ban"),
                 interval=interval)

register.bakery_plugin(
    name="fail2ban",
    files_function=get_fail2ban_files,
)
