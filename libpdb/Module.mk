libpdb_HEADERS := pdb.h tpi.h
libpdb_SOURCES := pdb.c tpi.c

$(eval $(call CREATE_MODULE,libpdb,LIB))
