#
bin_PROGRAMS =
noinst_PROGRAMS =
lib_LTLIBRARIES =

AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/include
AM_LDFLAGS =
LDADD =
# LDADD += $(top_srcdir)/mod.ld

if ENABLE_DEBUG
AM_CPPFLAGS += -g
else
AM_CPPFLAGS += -O -ffunction-sections -fdata-sections
AM_LDFLAGS += -Wl,--gc-sections
endif

lib_LTLIBRARIES += libadmin.la
libadmin_la_SOURCES = misc.c time.c ev.c unitest.c

if ENABLE_AIR192
libadmin_la_SOURCES += misc_air192.cpp
endif

compatopenbsdsysincludedir= $(includedir)/admin/compat/openbsd/sys
compatopenbsdsysinclude_HEADERS=include/admin/compat/openbsd/sys/queue.h 
compatopenbsdsysinclude_HEADERS+=include/admin/compat/openbsd/sys/tree.h 

adminincludedir= $(includedir)/admin
admininclude_HEADERS=include/admin/ev.h include/admin/admin.h \
  include/admin/air192.h include/admin/sa7715.h


bin_PROGRAMS += admin
admin_SOURCES = admin.cpp mod_cli.cpp \
  fwupd.cpp \
  spkcal.cpp \
  wificfg.cpp \
  ethcfg.cpp \
  acccfg.cpp

admin_LDADD = libadmin.la
admin_LDFLAGS =
# admin_LDFLAGS += -static

if WITH_GPIOD
admin_SOURCES += mod_gpio.cpp
admin_LDFLAGS += -lgpiod
endif

admin_LDFLAGS += -luriparser -lcjson

noinst_PROGRAMS += test1
test1_SOURCES = test1.cpp
test1_LDADD = libadmin.la
test1_LDFLAGS =
# test1_LDFLAGS += -static

if WITH_GPIOD
test1_LDFLAGS += -lgpiod
endif

test1_LDFLAGS += -luriparser -lcjson
