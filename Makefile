# include Husky-Makefile-Config
include ../huskymak.cfg

ifeq ($(DEBUG), 1)
  COPT= -Ih -I$(INCDIR) $(DEBCFLAGS) $(WARNFLAGS)
  LFLAGS=$(DEBLFLAGS)
else
  COPT= -Ih -I$(INCDIR) $(OPTCFLAGS) $(WARNFLAGS)
  LFLAGS=$(OPTLFLAGS)
endif

CDEFS=-D$(OSTYPE) $(ADDCDEFS)

LIBS=-L$(LIBDIR) -lsmapi -lhusky

all: mpost$(EXE)

%$(OBJ): %.c
	$(CC) $(COPT) $(CDEFS) $*.c

mpost$(EXE): mpostp$(OBJ)
	$(CC) $(LFLAGS) -o mpost$(EXE) mpostp$(OBJ) $(LIBS)

clean:
	-$(RM) $(RMOPT) *$(OBJ)
	-$(RM) $(RMOPT) *~
	-$(RM) $(RMOPT) core

distclean: clean
	-$(RM) $(RMOPT) mpost$(EXE)

install: mpost$(EXE)
	$(INSTALL) $(IBOPT) mpost$(EXE) $(BINDIR)

uninstall:
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)mpost$(EXE)

