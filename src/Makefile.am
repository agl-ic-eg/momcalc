AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

bin_PROGRAMS = momicalc

momicalc_SOURCES = \
	momicalc.c

# options
# Additional library
momicalc_LDADD =

# C compiler options
momicalc_CFLAGS = \
	-g -Wall -Wno-unused-but-set-variable \
	-D_GNU_SOURCE

# Linker options
momicalc_LDFLAGS = 

# configure option 
if ENABLE_ADDRESS_SANITIZER
CFLAGS   += -fsanitize=address
endif

if ENABLE_GCOV
CFLAGS   += -coverage
endif

if ENABLE_PRINTFDEBUG
momicalc_CFLAGS   += -D_PRINTF_DEBUG_
endif

CLEANFILES = *.gcda *.gcno
