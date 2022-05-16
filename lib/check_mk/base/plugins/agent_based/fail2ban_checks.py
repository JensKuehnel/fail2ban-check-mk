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
#    `- Banned IP list:	112.122.54.162 144.135.85.184 103.200.21.89 1.14.61.204

from .agent_based_api.v1 import *


def parse_fail2ban(string_table):
    parsed = {}

    for line in string_table:
        if line[:4] ==  ['Status', 'for', 'the', 'jail:']:
            jail = line[4]
            parsed[jail] = {}

        if (line[:4]) == ['|', '|-', 'Currently', 'failed:']:
            parsed[jail]['currentfailed'] = int(line[4])
        elif (line[:4]) == ['|', '|-', 'Total', 'failed:']:
            parsed[jail]['totalfailed'] = int(line[4])
        elif (line[:3]) == ['|-', 'Currently', 'banned:']:
            parsed[jail]['currentbanned'] = int(line[3])
        elif (line[:3]) == ['|-', 'Total', 'banned:']:
            parsed[jail]['totalbanned'] = int(line[3])

    return parsed


def discovery_fail2ban(section):
    for name in section:
        yield Service(item=name)


def check_fail2ban(item, params, section):
    currentfailedcrit = None if params["failed"][1] == 0 else params["failed"][1]
    currentfailedwarn = None if params["failed"][0] == 0 else params["failed"][0]
    currentbannedcrit = None if params["banned"][1] == 0 else params["banned"][1]
    currentbannedwarn = None if params["banned"][0] == 0 else params["banned"][0]

    if item in section:
        currentfailed = section[item]['currentfailed']
        currentbanned = section[item]['currentbanned']
        totalfailed   = section[item]['totalfailed']
        totalbanned   = section[item]['totalbanned']
    else:
        yield Result(state=State.UNKNOWN, summary="Jail status not found in agent output.")
        return

    yield from check_levels(
        currentfailed,
        levels_upper=(currentfailedwarn, currentfailedcrit),
        metric_name="current_failed",
        render_func=lambda v: "%d" % v,
        label=f"Total failed: {totalfailed}, Current failed",
        boundaries=(0, None)
        )

    yield Metric(
        name="total_failed",
        value=totalfailed,
        )

    yield from check_levels(
        currentbanned,
        levels_upper=(currentbannedwarn,  currentbannedcrit),
        metric_name="current_banned",
        render_func=lambda v: "%d" % v,
        label=f"Total banned: {totalbanned}, Current banned",
        boundaries=(0, None)
        )

    yield Metric(
        name="total_banned",
        value=totalbanned,
        )

    return


register.check_plugin(
        name="fail2ban",
        service_name="Jail %s",
        discovery_function=discovery_fail2ban,
        check_function=check_fail2ban,
        check_default_parameters={'banned': (25, 50), 'failed': (50, 100)},
        check_ruleset_name="fail2ban",
        )

register.agent_section(
    name = "fail2ban",
    parse_function = parse_fail2ban,
)
