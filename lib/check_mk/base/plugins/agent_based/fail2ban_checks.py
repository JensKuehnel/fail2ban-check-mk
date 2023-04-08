#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# (c) Jens Kühnel <fail2ban-checkmk@jens.kuehnel.org> 2021
#
# Information about fail2ban check_mk module see:
# https://github.com/JensKuehnel/fail2ban-check-mk
#
# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  check_mk is  distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.


# Example for output from agent
# ---------------------------------------------------------
# <<<fail2ban>>>
# Detected jails: 	postfix-sasl  sshd
# Status for the jail: postfix-sasl
# |- Filter
# |  |- Currently failed:	7
# |  |- Total failed:	1839
# |  `- Journal matches:	_SYSTEMD_UNIT=postfix.service
# `- Actions
#    |- Currently banned:	1
#    |- Total banned:	76
#    `- Banned IP list:	212.70.149.71
# Status for the jail: sshd
# |- Filter
# |  |- Currently failed:	6
# |  |- Total failed:	1066
# |  `- Journal matches:	_SYSTEMD_UNIT=sshd.service + _COMM=sshd
# `- Actions
#    |- Currently banned:	5
#    |- Total banned:	50
#    `- Banned IP list:	192.0.2.162 198.51.100.184 203.0.113.89

from .agent_based_api.v1 import register, check_levels, Service
from .agent_based_api.v1.type_defs import (
    DiscoveryResult,
    CheckResult,
    StringTable,
)

from typing import Any, Mapping


Section = Mapping[str, Mapping[str, str]]


def parse_fail2ban(string_table: StringTable) -> Section:
    parsed = {}
    currentjail = None
    for line in string_table:
        if ' ' not in line[0]:
            # Re-split on : instead of space
            line = " ".join(line).split(":")

        if len(line) != 2:
            # Not a key-value pair
            continue

        key = line[0].strip("|-` ")
        value = line[1].strip()

        if key == 'Status for the jail':
            currentjail = value
            parsed[currentjail] = dict()
        elif currentjail is not None:
            try:
                parsed[currentjail][key] = int(value)
            except ValueError:
                # we are only interested in the numeric values
                pass
    return parsed


register.agent_section(
    name="fail2ban",
    parse_function=parse_fail2ban,
)


def discovery_fail2ban(section: Section) -> DiscoveryResult:
    for jail in section:
        yield Service(item=jail)


def check_fail2ban(
    item: str,
    params: Mapping[str, Any],
    section: Section,
) -> CheckResult:
    try:
        data = section[item]
    except KeyError:
        # removed jails should not create a crash,
        # so we dont yield anything and simply return without anything
        return

    for what in ("failed", "banned"):
        current_key = f"Currently {what}"
        total_key = f"Total {what}"
        yield from check_levels(
            metric_name=f"current_{what}",
            value=data[current_key],
            levels_upper=params[what],
            label=current_key,
            render_func=int,
        )
        yield from check_levels(
            metric_name=f"total_{what}",
            value=data[total_key],
            notice_only=True,
            label=total_key,
            render_func=int,
        )


register.check_plugin(
    name="fail2ban",
    service_name="Jail %s",
    discovery_function=discovery_fail2ban,
    check_function=check_fail2ban,
    check_default_parameters={'banned': (10, 20), 'failed': (30, 40)},
    check_ruleset_name="fail2ban",
)
