# include Husky-Makefile-Config
include ../huskymak.cfg

ifeq ($(DEBUG), 1)
  COPT= -I$(INCDIR) $(DEBCFLAGS) $(WARNFLAGS)
  LFLAGS=$(DEBLFLAGS)
else
  COPT= -I$(INCDIR) $(OPTCFLAGS) $(WARNFLAGS)
  LFLAGS=$(OPTLFLAGS)
endif

CDEFS=-D$(OSTYPE) $(ADDCDEFS)

LIBS=-L$(LIBDIR) -lsmapi

all: mpost$(EXE)

%$(OBJ): %.c
	$(CC) $(COPT) $(CDEFS) $*.c

mpost$(EXE): mpostp$(OBJ)
	$(CC) $(LFLAGS) -o mpost$(EXE) mpostp$(OBJ) $(LIBS)

clean:
	-$(RM) *$(OBJ)
	-$(RM) *~
	-$(RM) core

distclean: clean
	-$(RM) mpost$(EXE)

install: mpost$(EXE)
	$(INSTALL) $(IBOPT) mpost$(EXE) $(BINDIR)

