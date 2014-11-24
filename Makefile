PROJECTS = \
symbol \
libpdb

CFLAGS += -Werror -march=corei7 -g -Wno-unused-function -Wno-unused-parameter

include 3rdparty/build/Common.mk
