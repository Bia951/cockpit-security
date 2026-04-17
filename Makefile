PACKAGE = cockpit-security
DISTDIR = dist
DESTDIR ?=
PREFIX ?= /usr/local
COCKPITDIR = $(DESTDIR)$(PREFIX)/share/cockpit/$(PACKAGE)
LOCALDIR = $(HOME)/.local/share/cockpit/$(PACKAGE)

.PHONY: build install devel-install devel-uninstall clean watch

build:
	node ./build.js

watch:
	node ./build.js -w

install: build
	mkdir -p "$(COCKPITDIR)"
	cp -R "$(DISTDIR)"/. "$(COCKPITDIR)"/

devel-install: build
	mkdir -p "$(HOME)/.local/share/cockpit"
	rm -rf "$(LOCALDIR)"
	ln -s "$(PWD)/$(DISTDIR)" "$(LOCALDIR)"

devel-uninstall:
	rm -rf "$(LOCALDIR)"

clean:
	rm -rf "$(DISTDIR)" metafile.json runtime-npm-modules.txt
