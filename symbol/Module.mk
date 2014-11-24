symbol_HEADERS :=
symbol_SOURCES := entry.c

symbol_DEPENDS := libpdb

$(eval $(call CREATE_MODULE,symbol,EXE))
