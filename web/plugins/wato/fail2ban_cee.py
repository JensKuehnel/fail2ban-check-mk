#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: Checkmk Enterprise License
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.gui.i18n import _
from cmk.gui.plugins.wato import (
    HostRulespec,
    rulespec_registry,
)
from cmk.gui.cee.plugins.wato.agent_bakery.rulespecs.utils import RulespecGroupMonitoringAgentsAgentPlugins
from cmk.gui.valuespec import (
    Age,
    Alternative,
    Dictionary,
    FixedValue,
    Password,
    TextAscii,
    Tuple,
)


def _valuespec_agent_config_fail2ban():
    return Alternative(
        title = _("Fail2Ban (Linux)"),
        help  = _("This will deploy the agent plugin <tt>fail2ban</tt> to check various jails."),
        elements=[
            Dictionary(
                title=_("Deploy the Fail2Ban plugin"),
                elements=[
                    (
                        "interval",
                        Age(title=_("Run asynchronously"),
                            label=_("Interval for collecting data"),
                            default_value=300),
                    ),
                ],
            ),
            FixedValue(
                None,
                title=_("Do not deploy the Fail2Ban plugin"),
                totext=_("(disabled)"),
            ),
        ],
    )


rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupMonitoringAgentsAgentPlugins,
        name="agent_config:fail2ban",
        valuespec=_valuespec_agent_config_fail2ban,
    ))
