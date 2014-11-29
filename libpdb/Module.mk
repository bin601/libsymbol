libpdb_HEADERS := pdb.h pe.h tpi.h
libpdb_SOURCES := pdb.c pe.c tpi.c

$(eval $(call CREATE_MODULE,libpdb,LIB))
