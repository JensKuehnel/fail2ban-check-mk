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
    return Dictionary(
        title = _("Fail2Ban (Linux)"),
        help  = _("This will deploy the agent plugin <tt>fail2ban</tt> to check various jails."),
        elements=[
            (
            "activated",
            DropdownChoice(
                title=_("Activation"),
                help=_(
                    "Do not forget to activate the plugin in at least one of your rules. "
                    "It can be useful to create rules that are only partially filled out. "
                    "Since the rule execution is done on a <i>per parameter</i> base "
                    "you can for example create one rule at the top of your list that "
                    "just sets the activation to <i>no</i> for just some of your hosts without "
                    "setting any of the other parameters."
                ),
                choices=[
                    (False, _("Do not deploy fail2ban plugin")),
                    (True, _("Deploy fail2ban plugin")),
                ],
                default_value=True,
                ),
            ),
        ],
    ),



rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupMonitoringAgentsAgentPlugins,
        name="agent_config:fail2ban",
        valuespec=_valuespec_agent_config_fail2ban,
    ))
