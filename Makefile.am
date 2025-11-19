# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	include \
	src \
	doc

if ENABLE_TESTS
SUBDIRS += tests
else
check-local:
	@echo
	@echo '╔─────────────────────────────────────────────────────────────────╗'
	@echo "│ ⚠️ WARNING: Make won't build and run tests because they were    │"
	@echo '│             disabled at configuration time (`--disable-tests`). │'
	@echo '╚─────────────────────────────────────────────────────────────────╝'
	@echo
endif

dist_doc_DATA = \
	ChangeLog \
	CONTRIBUTING.adoc \
	LICENSE \
	README.adoc

dist_noinst_DATA = CodingStyle.md

EXTRA_DIST = \
	.reuse/dep5 \
	LICENSES/Autoconf-exception-2.0.txt \
	LICENSES/BSD-2-Clause.txt \
	LICENSES/BSD-4-Clause.txt \
	LICENSES/BSL-1.0.txt \
	LICENSES/CC0-1.0.txt \
	LICENSES/CC-BY-SA-4.0.txt \
	LICENSES/FSFAP.txt \
	LICENSES/FSFULLR.txt \
	LICENSES/GPL-2.0-only.txt \
	LICENSES/GPL-2.0-or-later.txt \
	LICENSES/GPL-3.0-or-later.txt \
	LICENSES/LGPL-2.1-only.txt \
	LICENSES/LicenseRef-Autoconf-exception-macro.txt \
	LICENSES/MIT.txt \
	LICENSES/PSF-2.0.txt \
	std-ext-lib.md \
	version \
	zsh-completion
