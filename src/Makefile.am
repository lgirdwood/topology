
COMPATNUM=@LIBTOOL_VERSION_INFO@

AM_CFLAGS = \
	-I$(top_srcdir)/src -Wall -Werror -D __EXPORTED_HEADERS__ -I $(LINUX_DIR)/include/uapi -I $(LINUX_DIR)/include

bin_PROGRAMS = socfw

socfw_SOURCES = socfw.c socfw.h parser.c builder.c topology.h

socfw_CFLAGS = $(AM_CFLAGS)
socfw_LDADD = -lasound

include_HEADERS = \
	socfw.h

