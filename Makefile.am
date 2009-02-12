#
# linux-ha: Linux-HA code
#
# Copyright (C) 2002 Alan Robertson
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

EXTRA_DIST              = bootstrap ConfigureMe README.in libltdl.tar
AUTOMAKE_OPTIONS	= foreign

MAINTAINERCLEANFILES    = Makefile.in aclocal.m4 configure DRF/config-h.in \
                        DRF/stamp-h.in libtool.m4 ltdl.m4 libltdl.tar
coredir = 		@HA_COREDIR@
hauser = 		@HA_CCMUSER@

TARFILE			= pacemaker-mgmt.tar.gz
LAST_RELEASE		= pacemaker-mgmt-1.99.0

if CIM_PROVIDER_BUILD
CIM_PROVIDER_DIR = cim
endif

if TSA_PLUGIN_BUILD
TSA_PLUGIN_DIR = tsa_plugin
endif

if SNMP_SUBAGENT_BUILD
SNMP_SUBAGENT_DIR = snmp_subagent
endif

SUBDIRS	= $(LIBLTDL_DIR) replace include lib mgmt $(CIM_PROVIDER_DIR) $(TSA_PLUGIN_DIR) $(SNMP_SUBAGENT_DIR)

tgz:
	rm -f $(TARFILE)
	hg archive -t tgz $(TARFILE)
	echo Rebuilt $(TARFILE) on `date`

changes:
	printf "$(PACKAGE) ($(VERSION)-1) stable; urgency=medium\n"
	printf "  * Update source tarball to revision: `hg id`\n"
	printf "  * Statistics:\n"
	printf "      Changesets: `hg log -M --template "{desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | wc -l`\n"
	printf "      Diff:           "
	hg diff -r $(LAST_RELEASE):tip | diffstat | tail -n 1
	printf "\n  * Testing Notes:\n"
	printf "\n  + Test hardware:\n"
	printf "\n  + All testing was performed with STONITH enabled\n"
	printf "\n  + Pending bugs encountered during testing:\n"
	printf "\n  * Changes since $(LAST_RELEASE)\n"
	hg log -M --template "  + {desc|firstline|strip}\n" -r $(LAST_RELEASE):tip | grep -v Low: | sort -uf 
	printf "\n -- Andrew Beekhof <abeekhof@suse.de>  `date +"%a, %d %b %Y %T %z"`\n"

stable:	tgz
	make changes > .changes
	scp .changes $(TARFILE) c001n16.suse.de:Development/obs/server:ha-clustering/pacemaker-mgmt/

unstable:	tgz
	make changes > .changes
	scp .changes $(TARFILE) c001n16.suse.de:Development/obs/server:ha-clustering:UNSTABLE/pacemaker-mgmt/

install-exec-local:
	-mkdir -p $(DESTDIR)$(bindir)
	-cd $(DESTDIR)$(libdir)/heartbeat-gui && rm -f haclient.py && ln -s $(datadir)/heartbeat-gui/haclient.py .
	-cd $(DESTDIR)$(bindir) && rm -f crm_gui && ln -s $(datadir)/heartbeat-gui/haclient.py crm_gui
	-cd $(DESTDIR)$(bindir) && rm -f hb_gui && ln -s $(datadir)/heartbeat-gui/haclient.py hb_gui

dist-clean-local:
	rm -f autoconf automake autoheader

maintainer-clean-local:
	rm -f libltdl.tar

