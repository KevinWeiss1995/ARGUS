# Build the ARGUS SELinux policy module.
#
# On Rocky 8 / RHEL 8:
#   dnf install -y selinux-policy-devel
#   make
#   sudo make install
#
# This produces argus.pp which the RPM ships under
# /usr/share/argus/selinux/ and loads via semodule -i in its %post.
#
# To inspect after install:
#   semodule -l | grep argus
#   sesearch -A -s argusd_t | head
#
# If a denial appears in audit.log that this policy doesn't yet cover,
# generate a diff with:
#   ausearch -m AVC -ts recent | audit2allow -R

MODULE := argus
TARGETS := $(MODULE).pp

PREFIX ?= /usr
DATAROOT ?= $(PREFIX)/share/argus/selinux

# Default selinux-policy-devel Makefile location
SELINUX_DEVEL_MAKEFILE := /usr/share/selinux/devel/Makefile

.PHONY: all install reload clean check

all: $(TARGETS)

$(TARGETS): $(MODULE).te $(MODULE).fc $(MODULE).if
	@if [ ! -f "$(SELINUX_DEVEL_MAKEFILE)" ]; then \
		echo "Missing $(SELINUX_DEVEL_MAKEFILE). Install: dnf install -y selinux-policy-devel" >&2; \
		exit 1; \
	fi
	$(MAKE) -f $(SELINUX_DEVEL_MAKEFILE) $(MODULE).pp

install: $(MODULE).pp
	install -d $(DESTDIR)$(DATAROOT)
	install -m 0644 $(MODULE).pp $(DESTDIR)$(DATAROOT)/$(MODULE).pp
	install -m 0644 $(MODULE).te $(DESTDIR)$(DATAROOT)/$(MODULE).te
	install -m 0644 $(MODULE).fc $(DESTDIR)$(DATAROOT)/$(MODULE).fc
	install -m 0644 $(MODULE).if $(DESTDIR)$(DATAROOT)/$(MODULE).if

# Load the compiled module and re-label paths
reload: install
	semodule -i $(DESTDIR)$(DATAROOT)/$(MODULE).pp
	restorecon -RFv /usr/bin/argusd /etc/argus /var/lib/argus /run/argus 2>/dev/null || true

check:
	@command -v checkmodule >/dev/null || { echo "install policycoreutils-python-utils + selinux-policy-devel"; exit 1; }
	checkmodule -M -m -o $(MODULE).mod $(MODULE).te
	semodule_package -o $(MODULE).pp -m $(MODULE).mod -f $(MODULE).fc

clean:
	rm -f $(MODULE).pp $(MODULE).mod tmp/*
	rm -rf tmp
