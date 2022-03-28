#!/usr/bin/python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Rule for Plugins -> Agent Bakery

register_rule(
    "agents/" + _("Agent Plugins"),
    "agent_config:fail2ban",
    Dictionary(
        title=_("fail2ban Plugin"),
        help=_(
            "This will deploy the agent plugin <tt>fail2ban</tt> on linux systems."),
        elements=[
            ("activated",
             DropdownChoice(
                 title=_("Activation"),
                 help=
                 _("Do not forget to activate the plugin in at least one of your rules. "
                   "It can be useful to create rules that are only partially filled out. "
                   "Since the rule execution is done on a <i>per parameter</i> base "
                   "you can for example create one rule at the top of your list that "
                   "just sets the activation to <i>no</i> for just some of your hosts without "
                   "setting any of the other parameters."),
                 choices=[
                     (False, _("Do not deploy fail2ban plugin")),
                     (True, _("Deploy fail2ban plugin")),
                 ],
                 default_value=True)),
            ("interval",
             Age(title=_("Run asynchronously"),
                 label=_("Interval for collecting data"),
                 default_value=300)),
        ],
        required_keys=["activated"],
    ),
    match="dict",
)
