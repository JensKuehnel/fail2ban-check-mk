# fail2ban plugin for check_mk
This plugin should replace the fail2ban plugin from notes.benv.junerules.com/fail2ban/.
The original plugin does not work correctly with check_mk 2.0. So this a completly new write.

This is my first plugin with the new API. 
I followed [Writing you own check plug-ins](https://docs.checkmk.com/latest/en/devel_check_plugins.html) and the [Guidelines](https://docs.checkmk.com/latest/en/dev_guidelines.html).

## Install from source 
* clone repo as site user and run copy-to-mk.sh

## Install from package
* Download mkp.
* Install with cmk -P install fail2ban*.mkp

## Parameter to configure

## TODO
* use parse functions?
* Add Agent Bakery support (I use core only)
* Decide if total banned/failed are something you want to graph and altering on
