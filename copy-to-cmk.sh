#!/bin/bash

cp web/plugins/wato/fail2ban_parameters.py ~/local/share/check_mk/web/plugins/wato/fail2ban_parameters.py
chown $USER ~/local/share/check_mk/web/plugins/wato/fail2ban_parameters.py
chmod 755   ~/local/share/check_mk/web/plugins/wato/fail2ban_parameters.py

cp web/plugins/metrics/fail2ban_metric.py ~/local/share/check_mk/web/plugins/metrics/fail2ban_metric.py
chown $USER ~/local/share/check_mk/web/plugins/metrics/fail2ban_metric.py
chmod 755   ~/local/share/check_mk/web/plugins/metrics/fail2ban_metric.py

cp lib/check_mk/base/cee/plugins/bakery/fail2ban.py   ~/local/lib/check_mk/base/cee/plugins/bakery/fail2ban.py
chown $USER ~/local/lib/check_mk/base/cee/plugins/bakery/fail2ban.py
chmod 755   ~/local/lib/check_mk/base/cee/plugins/bakery/fail2ban.py

cp share/check_mk/checkman/fail2ban ~/local/share/check_mk/checkman/fail2ban
chown $USER ~/local/share/check_mk/checkman/fail2ban
chmod 755   ~/local/share/check_mk/checkman/fail2ban

cp lib/check_mk/base/plugins/agent_based/fail2ban_checks.py ~/local/lib/check_mk/base/plugins/agent_based/fail2ban_checks.py
chown $USER ~/local/lib/check_mk/base/plugins/agent_based/fail2ban_checks.py
chmod 755   ~/local/lib/check_mk/base/plugins/agent_based/fail2ban_checks.py

cp agents/plugins/fail2ban ~/local/share/check_mk/agents/plugins/fail2ban
chown $USER ~/local/share/check_mk/agents/plugins/fail2ban
chmod 755   ~/local/share/check_mk/agents/plugins/fail2ban





