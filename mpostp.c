/*****************************************************************************
 +===========================================================================+
 | MsgPost/2 Version 1.21 TE, Dec 1999       (C) 1992 by CodeLand Australia, |
 |                                                      All Rights Reserved. |
 | Written by Colin Wheat of Fidonet 3:690/613                               |
 | Compiled using C SET/2                                                    |
 |                                                                           |
 | Modified to use 32-bit Squish API DLL and netmail bug fixed               |
 | by Wouter Cloetens, 2:292/608.18@fidonet, 81:432/109@os2net               |
 |                                                                           |
 | Modified to use the SMAPI, added CHRS kludge,                             |
 | fixed Y2K problems, ported to DOS, Unix and NT                            |
 | by Tobias Ernst, 2:2476/418@fidonet, tobi@bland.fido.de                   |
 |                                                                           |
 |            MsgPost uses the Squish Message Base Level 0 MsgAPI            |
 |                  Squish is a trademark of Scott J. Dudley                 |
 |                                                                           |
 |                                                                           |
 | COMMAND LINE:                                                             |
 |                                                                           |
 |              COMMAND LINE ONLY                                            |
 | -T<name>     Text source file path & name                                 |
 | -K           Kill text file after processing                              |
 | -C<name>     Configuration file path & name                               |
 | -@<name>     List file name                                               |
 | -?           Program help screen                                          |
 |                                                                           |
 |              CONFIGURATION OVERRIDES                                      |
 | -M<name>     Message area path & name                                     |
 | -N<addr>     Netmail format - send to address                             |
 | -O<addr>     [Zone:]Net/Node[.Point][@Domain]                             |
 | -P[cfhdkpru] Message priority flag(s)                                     |
 | -F<fname>    Message addressed to first name                              |
 | -L<lname>    Message addressed to last name                               |
 | -W<name>     Message addressed from name                                  |
 | -J<subj>     Message subject                                              |
 | -1           First line of text file is subject line                      |
 | -S<##>       Split long messages to ## Kb size (0-16)                     |
 | -h<charset>  Specify charset kludge name to use, like "IBMPC" or "LATIN-1"|
 |                                                                           |
 | CONFIGURATION FILE:                                                       |
 |                                                                           |
 | Address:     [Zone:]Net/Node[.Point][@Domain]                             |
 | Origin:      <Your system echomail identification>                        |
 | Area:        <Message area path & name>                                   |
 | Netmail:     [Zone:]Net/Node[.Point][@Domain]                             |
 | MsgType:     <Echomail | Conference | Local | Matrix>                     |
 | To:          <Some Name>                                                  |
 | From:        <Your Name>                                                  |
 | Subj:        <Your Subject>                                               |
 | Attr:        <c|f|h|d|k|p|r|u|l>                                          |
 | FakeNet:     <###>                                                        |
 | NoSeenBy:                                                                 |
 | Split:       <###>                                                        |
 | Charset:     <charset kludge name>                                        |
 |                                                                           |
 | ERROR LEVELS:                                                             |
 |                                                                           |
 | 0 - Normal exit                                                           |
 | 1 - Syntax exit                                                           |
 | 2 - Out of memory                                                         |
 | 3 - Configuration or text file not found                                  |
 | 4 - No system address set                                                 |
 | 5 - Message base open failed                                              |
 | 6 - Names list file not found                                             |
 +===========================================================================+
 ****************************************************************************/

#ifdef OS2

#define INCL_DOSDATETIME
#include <os2.h>

#ifdef EXPENTRY
#undef EXPENTRY
#endif

#elif defined(UNIX)
#elif defined(__NT__)
#elif defined(__DJGPP__)
#else
#error Unsupported environment.
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#if defined(OS2) || defined(__DJGPP__) || defined(__NT__)
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <share.h>
#endif

#if defined(__NT__)
#define NOUSER
#include <windows.h>
#endif

#if defined(UNIX) || defined(__DJGPP__) || defined(__MINGW32__)
#define _MAX_DRIVE FILENAME_MAX
#define _MAX_DIR FILENAME_MAX
#define _MAX_FNAME FILENAME_MAX
#define _MAX_EXT FILENAME_MAX
#endif

#ifdef UNIX
#ifndef O_TEXT
#define O_TEXT 0
#endif
#ifndef S_IREAD
#define S_IREAD 0
#endif
#ifndef S_IWRITE
#define S_IWRITE 0
#endif
#endif

#include <fcntl.h>
#include "prog.h"               /* Squish API header */
#include "alc.h"                /* Squish API header */
#include "msgapi.h"             /* Squish API header */

#ifndef UNAME
#ifdef OS2
#define UNAME "2"
#elif defined(__DJGPP__)
#define UNAME "386"
#elif defined(__NT__)
#define UNAME "NT"
#else
#define UNAME "UNX"
#endif
#endif

#define VERSION     "1.21 TE"   /* MsgPost version   */
#define SVERSON     "1.21"      /* Short version     */
#define MAX_BLOCK   16000       /* Maximum text size */
#define MAX_LINE    10000       /* Maximum lines     */

#define MSGTYP_ECHO 1           /* Echomail msg type */
#define MSGTYP_CONF 2           /* Conf. msg type    */
#define MSGTYP_LOCL 3           /* Local msg type    */
#define MSGTYP_MATX 4           /* Netmail msg type  */

/*
    Echomail    - DestAddr=NO  PID=NO  Tear=YES Origin=YES SeenBy=YES
    Conference  - DestAddr=NO  PID=YES Tear=NO  Origin=NO  SeenBy=NO
    Local       - DestAddr=NO  PID=NO  Tear=YES Origin=NO  SeenBy=NO
    Matrix      - DestAddr=YES PID=YES Tear=NO  Origin=NO  SeenBy=NO
*/

#define DEF_NADDR {0,0,0,0,{0}}

typedef struct _naddr {
    word zone;
    word net;
    word node;
    word point;
    char domain[64];
} NADDR;

char *def_orig = "^KD <Esc> <F2> ^Z ^C (damnit!) q e quit exit !Q system";

NADDR sy_addr=DEF_NADDR;        /* System address    */
NADDR fm_addr=DEF_NADDR;        /* Origin address    */
NADDR to_addr=DEF_NADDR;        /* Destination addr  */
unsigned int fakenet=0;         /* System fakenet    */

int listflg=0;                  /* Run in list mode  */
int killtxtflg=0;               /* Txtfile kill flag */
int seenbyflg=1;                /* Seenby line flag  */
int addrflg=0;                  /* Address flag      */
int msgtyp=MSGTYP_ECHO;         /* Message type      */
int split_k=12;                 /* Message split     */
unsigned long seed;             /* MSGID seed        */
time_t time_now;                /* Creation time     */
int mn;                         /* Split unique #    */

char exepath[80];               /* Executable path   */
char msgpath[80];               /* Message area name */
char txtpath[80];               /* Import text file  */
char cfgpath[80];               /* MsgPost CFG file  */
char lstpath[80];               /* Names list file   */
char charset[80];               /* charset kluge     */

char str_to[XMSG_TO_SIZE];      /* Message to field  */
char str_from[XMSG_FROM_SIZE];  /* Message from fld  */
char str_subj[XMSG_SUBJ_SIZE];  /* Message subj fld  */
char str_orig[80];              /* Echo origin line  */
dword attr=MSGLOCAL;            /* Message attr      */

char *lines[MAX_LINE];          /* Line ptr array    */
int linescount=0;               /* Line ptr count    */
long linesbytes=0L;             /* Total text bytes  */
int linesidx;                   /* Line ptr index    */

char *textbuf=NULL;             /* Msg text buffer   */
long textcount;                 /* Msg text length   */

static void  Quit (int status);
static int  ReadCfg (void);
static int  ReadTxt (void);
static int  SetMsgCfg (char *s);
static int  Process (MSG *ap);
static void  WriteMsg (MSG *ap);
static int  GetNum (int splitbytes);
static int  BuildText (int limit);
static void  SetAttr (char *p);
static int  ReadOrig (void);
static void  BuildTear (char *s);
static void  BuildHdr (XMSG *x, int num, int maxnum);
static void  BuildCtrl (char *str, int *len, int num, int maxnum);
static char *  AddrToStr (NADDR *addr);
static unsigned long  HsecTime (void);
static void  GetAddr (char *str, NADDR *addr);
static void  AddSlash (char *str);
static void  StripSlash(char *str);
static void  StripCr (char *str);
static void  StrTrim (char *str);
static int  StrBlank (char *str);
static void  CvtUs (char *s);
static int  IsSpace (char c);
static char *  FancyStr (char *string);
static void  MakeExePath (char *pth);
static FILE *  ShFopen (char *name, char *fpmode);
static void  SetUp (int argc, char *argv[]);
static void  GetCmdLine (int argc, char *argv[]);
static void  Usage (void);


int main (int argc, char *argv[])
{
    int status=0;               /* Exit status                  */
    int areatyp;                /* Message area type            */
    struct _minf mi;            /* API structure                */
    MSG *ap;                    /* API area pointer             */

    printf("\nMPost/"UNAME" v" VERSION " - the Fidonet/Squish Message Base Writer"
           "\n   (C) Copyright 1992 by CodeLand, All Rights Reserved\n\n");

    SetUp(argc,argv);           /* Read initial command line    */
    if(!ReadCfg()) {            /* Read configuration file      */
        printf("\n%cERROR: Configuration file not found!\n\n",0x07);
        Quit(3);
    }

    if(!ReadTxt()) {       /* Read the message source text file */
        printf("\n%cERROR: Text file not found!\n\n",0x07);
        Quit(3);
    }

    GetCmdLine(argc,argv);      /* Get command line overrides   */

    if(!addrflg) {              /* If no system address         */
        printf("\n%cERROR: No address set!\n\n",0x07);
        Quit(4);
    }

    /* Setup MsgApi */
    mi.req_version=0;
    mi.def_zone=(msgtyp==MSGTYP_MATX?sy_addr.zone:fm_addr.zone);

    /* If no origin set, try from the message area, else use default */
    if(msgtyp==MSGTYP_ECHO)
        if(!*str_orig) if(!ReadOrig()) strcpy(str_orig,def_orig);

    MsgOpenApi(&mi); /* Open the MsgApi */
    areatyp=(*msgpath=='$'?MSGTYPE_SQUISH:MSGTYPE_SDM);
    if(areatyp==MSGTYPE_SDM&&msgtyp!=MSGTYP_MATX) areatyp|=MSGTYPE_ECHO;

    /* Open the message base */
    if((ap=MsgOpenArea((byte *)msgpath+(*msgpath=='$'),
                       MSGAREA_NORMAL | MSGAREA_CRIFNEC,areatyp)
       )==NULL) {
        printf("\n%cERROR: Message base open failed with error code %d!\n\n",
               0x07, msgapierr);
        Quit(5);
    }

    MsgLock(ap); /* Lock the base */

    /* Write the message(s) */
    if((status=Process(ap))!=0) {
        printf("\n%cERROR: List file not found!\n\n",0x07);
    }

    MsgUnlock(ap); MsgCloseArea(ap);    /* Unlock & close the base  */
    MsgCloseApi();                      /* Close the API            */

    if(killtxtflg) unlink(txtpath);     /* Delete text source file  */
    Quit(status);
    return 0; /* remove bogus warnings */
}


/*
** Quit ()
** Exit the program
*/

static void  Quit (int status)
{
    /* Release allocated memory */
    while(linescount) free(lines[--linescount]);
    if(textbuf) free(textbuf);

    if(!status) printf("\nDone! (exit 0)\n");
    exit(status);
}


/*
** ReadCfg ()
** Read configuration file
*/

static int  ReadCfg (void)
{
    FILE *fp;
    char line[4098];

    if((fp=ShFopen(cfgpath,"r"))==NULL) return 0;
    while(fgets(line,4096,fp)!=NULL) SetMsgCfg(line);
    fclose(fp);

    return 1;
}


/*
** ReadTxt ()
** Read complete text file into line pointer array
*/

static int  ReadTxt (void)
{
    int llen, checkcfg=1, trimleading=1;
    FILE *fp;
    char *fbuf=NULL;
    char line[4098];

    if(!*txtpath) { /* Allow for a blank msg */
        lines[linescount]=strdup("");
        ++linescount;
        return 1;
    }

    printf("Reading %s\n",FancyStr(txtpath));

    if((fp=ShFopen(txtpath,"r"))==NULL) return 0;
    fbuf=(char *)malloc(4096); /* Get extended file buffer */
    if(fbuf!=NULL) setvbuf(fp,fbuf,_IOFBF,4096);

    while(fgets(line,4096,fp)!=NULL) {

        if(checkcfg) { /* Check for override configuration */
            switch (SetMsgCfg(line))
            {
            case  1: continue;
            case  0: checkcfg = 0; break;
            case -1: checkcfg = 0; continue;
            }
        }

        StripCr(line); StrTrim(line); /* Clean up */

        /* Ignore leading blank lines */
        if(trimleading) {
            if(StrBlank(line)) continue;
            else trimleading=0;
        }

        strcat(line,"\r"); llen=strlen(line);
        if((lines[linescount]=(char *)malloc(llen+1))==NULL) {
            printf("\n%cERROR: Out of memory!\n\n",0x07);
            fclose(fp);
            Quit(2);
        }

        memcpy(lines[linescount],line,llen+1);
        linesbytes+=(long)llen;
        if(++linescount>=MAX_LINE) break;
    }

    if(linescount) {
        for(;;) { /* Strip trailing blank lines */
            if(!StrBlank(lines[linescount-1])&&lines[linescount-1][0]!='\r')
                break;
            linesbytes-=(long)strlen(lines[linescount-1]);
            if(!--linescount) break;
        }
    }

    fclose(fp);
    if(fbuf) free(fbuf);
    return 1;
}


/*
** SetMsgCfg ()
** Set message configuration from configuration string
** Returns TRUE for a valid cfg line processed
*/

static int  SetMsgCfg (char *s)
{
    char *p, *q, *r, sbuf[4098];

    strcpy(sbuf,s); /* Clone the line so we don't change the original */

    if((p=strtok(sbuf," \t\n\r"))!=NULL) {
        if(*p==';'||*p=='%') return 1;
        if((q=strtok(NULL,"\n\r"))!=NULL) {
            r=q; while(*r==' '||*r=='\t') ++r; /* Strip leading */
            StrTrim(r); /* Strip trailing */
            if(*r) {
                if(!stricmp(p,"TO:")) {
                    strncpy(str_to,r,XMSG_TO_SIZE-1);
                    str_to[XMSG_TO_SIZE-1]='\0';
                    return 1;
                }
                else if(!stricmp(p,"FROM:")) {
                    strncpy(str_from,r,XMSG_FROM_SIZE-1);
                    str_from[XMSG_FROM_SIZE-1]='\0';
                    return 1;
                }
                else if(!stricmp(p,"SUBJ:")) {
                    strncpy(str_subj,r,XMSG_SUBJ_SIZE-1);
                    str_subj[XMSG_SUBJ_SIZE-1]='\0';
                    return 1;
                }
                else if(!stricmp(p,"ORIGIN:")) {
                    strncpy(str_orig,r,59);
                    str_orig[59]='\0';
                    return 1;
                }
                else if(!stricmp(p,"ADDRESS:")) {
                    /* System address */
                    GetAddr(r,&sy_addr);
                    /* Set default message from address to system address */
                    fm_addr=sy_addr;
                    ++addrflg;
                    return 1;
                }
                else if(!stricmp(p,"ATTR:")) {
                    SetAttr(r);
                    return 1;
                }
                else if(!stricmp(p,"AREA:")) {
                    strncpy(msgpath,r,78); msgpath[78]='\0';
                    StripSlash(msgpath);
                    return 1;
                }
                else if(!stricmp(p,"NETMAIL:")) {
                    GetAddr(r,&to_addr); msgtyp=MSGTYP_MATX;
                    return 1;
                }
                else if(!stricmp(p,"MSGTYPE:")) {
                    if(!stricmp(r,"ECHOMAIL")) {
                        msgtyp=MSGTYP_ECHO; return 1;
                    }
                    else if(!stricmp(r,"CONFERENCE")) {
                        msgtyp=MSGTYP_CONF; return 1;
                    }
                    else if(!stricmp(r,"LOCAL")) {
                        msgtyp=MSGTYP_LOCL; return 1;
                    }
                    else if(!stricmp(r,"MATRIX")) {
                        msgtyp=MSGTYP_MATX; return 1;
                    }
                }
                else if(!stricmp(p,"FAKENET:")) {
                    fakenet=(unsigned int)atol(r);
                    return 1;
                }
                else if(!stricmp(p,"NOSEENBY:")) {
                    seenbyflg=0;
                    return 1;
                }
                else if(!stricmp(p,"SPLIT:")) {
                    split_k=atoi(r);
                    if(split_k<0||split_k>16) split_k=12;
                    return 1;
                }
                else if (!stricmp(p,"CHARSET:")) {
                    strncpy(charset,r,50);
                    return 1;
                }
                else if ((!stricmp(p,"END")) && (!stricmp(r,"OF CONFIG"))) {
                    return -1;
                }
            }
        }
    }

    return 0;
}


/*
** Process ()
** Write out the messages
*/

static int  Process (MSG *ap)
{
    int i=0, oldmsgtyp;
    FILE *fp;
    char *p, *q, line[4098];

    if(listflg) { /* List mode */
        printf("Reading %s\n",FancyStr(lstpath));

        if((fp=ShFopen(lstpath,"r"))==NULL) return 6; /* Open list file */
        oldmsgtyp=msgtyp;
        for(;;) {
            if(fgets(line,4096,fp)==NULL) break;
            p=line; while(*p==' '||*p=='\t') ++p; /* Strip leading */
            if((q=strchr(p,','))!=NULL) { /* Get optional netmail addr */
                GetAddr(q+1,&to_addr); msgtyp=MSGTYP_MATX;
                *q='\0';
            }
            else msgtyp=oldmsgtyp;
            StripCr(p); StrTrim(p); /* Strip trailing */
            if(!StrBlank(p)) {
                strncpy(str_to,p,XMSG_TO_SIZE-1);
                str_to[XMSG_TO_SIZE-1]='\0';
                printf("List message %3d to: %s\n",++i,str_to);
                WriteMsg(ap);
            }
        }
        fclose(fp);
    }
    else WriteMsg(ap); /* Normal mode */

    return 0;
}


/*
** WriteMsg ()
** Write message(s)
*/

static void  WriteMsg (MSG *ap)
{
    int i;
    int split_num=1;                /* How many msgs        */
    int splitbytes;                 /* Split size           */
    MSGH *msg;                      /* Message pointer      */
    XMSG xmsg;                      /* Xmsg structure       */
    int ctrllen;                    /* Control info size    */
    char ctrl[256];                 /* Control info         */
    char tear[256];                 /* Tear line, origin    */

    time_now=time(NULL);            /* Get message time     */
    seed=HsecTime();                /* Get MSGID seed       */

    linesidx=0;  /* Start loading from start of lines array */

    /* Get split messages unique number */
    srand((unsigned)seed); mn=rand();

    /* Make tear/origin line for echomail/local */
    BuildTear(tear);

    /* Set split message size */
    if(!split_k) splitbytes=MAX_BLOCK;
    else splitbytes=split_k*1024;
    if(splitbytes>MAX_BLOCK) splitbytes=MAX_BLOCK;

    /* Adjust for tear and header */
    if(msgtyp==MSGTYP_ECHO||msgtyp==MSGTYP_LOCL) splitbytes-=strlen(tear);
    splitbytes-=250;

    /* Split or cut the text */
    if(split_k&&linesbytes>(long)splitbytes) {
        split_num=GetNum(splitbytes); /* Compute number of messages */

        /* Set to average message size */
        splitbytes=(int)(linesbytes/(long)split_num);

        for(;;) { /* And adjust size back up so no text is lost */
            if(GetNum(splitbytes)<=split_num) break;
            ++splitbytes;
        }
    }

    printf("Writing %s  01/%02u ",FancyStr(msgpath),split_num);

    for(i=0;i<split_num;i++) {
        printf("\b\b\b\b\b\b%02u/%02u ",i+1,split_num);

        if(!BuildText(splitbytes)) break;

        if(msgtyp==MSGTYP_ECHO||msgtyp==MSGTYP_LOCL) {
            strcat(textbuf,tear); textcount+=(long)strlen(tear);
        }

        if(i) attr&=~MSGFILE; /* Kill file attaches on 2nd, 3rd, etc */
        BuildHdr(&xmsg,i+1,split_num);

        msg=MsgOpenMsg(ap,MOPEN_CREATE,0L); /* Create new message */
        BuildCtrl(ctrl,&ctrllen,i+1,split_num);
        MsgWriteMsg(msg,FALSE,&xmsg,NULL,0L,textcount,ctrllen,(byte *)ctrl);
        MsgWriteMsg(msg,TRUE,NULL,(byte *)textbuf,textcount,textcount,0L,NULL);
        MsgCloseMsg(msg);
    }

    printf("\n");
}


/*
** GetNum ()
** Compute how many split messages to generate
*/

static int  GetNum (int splitbytes)
{
    int i, result=1;
    long len=0L;

    for(i=0;i<linescount;i++) { /* Scan through the lines */
        len+=(long)strlen(lines[i]);
        if(len>(long)splitbytes) {
            ++result;
            len=(long)strlen(lines[i]);
        }
    }
    return result;
}


/*
** BuildText ()
** Fill the text buffer from the lines array
*/

static int  BuildText (int limit)
{
    int len;
    char *p;

    if(!linescount) {
        *textbuf='\0'; textcount=1L;
        return 1; /* Allow for blank msg */
    }
    if(linesidx>=linescount) return 0;

    p=textbuf; textcount=0L;

    for(;;) {
        len=strlen(lines[linesidx]);
        if(textcount+(long)len>limit) break;
        memcpy(p,lines[linesidx],len);
        p+=len; textcount+=(long)len;
        if(++linesidx>=linescount) break;
    }
    *p='\0'; ++textcount;

    return 1;
}


/*
** SetAttr ()
** Set message attribute flags
*/

static void  SetAttr (char *p)
{
    while(*p) {
        *p=tolower(*p);
        switch (*p) {
        case 'p': /* Private */
                  attr|=MSGPRIVATE; break;
        case 'c': /* Crash */
                  attr|=MSGCRASH; attr&=~MSGHOLD;
                  break;
        case 'd': /* Direct */
                  attr|=MSGXX2;
                  break;
        case 'f': /* File attach */
                  attr|=MSGFILE; break;
        case 'h': /* Hold */
                  attr|=MSGHOLD; attr&=~MSGCRASH;
                  break;
        case 'k': /* Kill after sending */
                  attr|=MSGKILL; break;
        case 'r': /* File Request */
                  attr|=MSGFRQ; break;
        case 'u': /* File Update Request */
                  attr|=MSGURQ; break;
        case 'l': /* Local flag */
                  attr&=~MSGLOCAL; /* Turn local flag OFF */
                  break;
        }
        ++p;
    }
}


/*
** ReadOrig ()
** Read message area origin file
*/

static int  ReadOrig (void)
{
    FILE *fp;
    char *p, buf[128];

    if(*msgpath=='$') { strcpy(buf,msgpath+1); strcat(buf,".SQO"); }
    else { strcpy(buf,msgpath); strcat(buf,"\\ORIGIN."); }
    printf("Reading %s\n",FancyStr(buf));

    if((fp=ShFopen(buf,"r"))==NULL) return 0;
    fgets(buf,128,fp);
    fclose(fp);

    p=buf; while(*p==' '||*p=='\t') ++p; /* Strip leading */
    if(strlen(p)>59) p[59]='\0';
    StripCr(p); StrTrim(p);
    strcpy(str_orig,p);
    return 1;
}


/*
** BuildTear ()
** Make tear, origin, & seenby lines
*/

static void  BuildTear (char *s)
{
    char line[128];

    *s='\0';
    if(msgtyp==MSGTYP_ECHO||msgtyp==MSGTYP_LOCL) {
        strcpy(s,"\r--- MPost/"UNAME" v" SVERSON "\r"); /* Tear line */

        if(msgtyp==MSGTYP_ECHO) {
            /* Origin line */
            sprintf(line," * Origin: %s (%s)\r",str_orig,AddrToStr(&fm_addr));
            strcat(s,line);

            /* Seen-by line */
            if(seenbyflg) {
                if(fm_addr.point&&fakenet) { /* Use point's fakenet */
                    sprintf(line,"SEEN-BY: %u/%u\r",fakenet,fm_addr.point);
                }
                else sprintf(line,"SEEN-BY: %u/%u\r",fm_addr.net,fm_addr.node);
                strcat(s,line);
            }
        }
    }
}


/*
** BuildHdr ()
** Set message header information
*/

static void  BuildHdr (XMSG *x, int num, int maxnum)
{
    union stamp_combo combo;
    struct tm *tmdate;

    memset(x,'\0',sizeof(XMSG));

    x->attr=attr; /* Set message attributes */

    /* Set source and destination addresses */
    x->orig=x->dest=*((struct _netaddr *)&fm_addr);
    if(msgtyp==MSGTYP_MATX) x->dest=*((struct _netaddr *)&to_addr);

    strcpy((char *)x->to,str_to); strcpy((char *)x->from,str_from);

    if(maxnum>1) {
        sprintf((char *)x->subj,"[%d of %d] ",num,maxnum);
        strncat((char *)x->subj,str_subj,
            XMSG_SUBJ_SIZE-1-strlen((char *)x->subj));
        (x->subj)[XMSG_SUBJ_SIZE-1]='\0';
    }
    else strcpy((char *)x->subj,str_subj);

    tmdate=localtime(&time_now);
    x->date_written=x->date_arrived=(TmDate_to_DosDate(tmdate,&combo))->msg_st;
}


/*
** BuildCtrl ()
** Set message control information
*/

static void  BuildCtrl (char *str, int *len, int num, int maxnum)
{
    struct tm *t;
    unsigned long time_new;
    char ubuf[20], sbuf[80];
    char *const Months[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    *len=0;
    time_new=HsecTime(); if(seed<time_new) seed=time_new;

    sprintf(str,"\01MSGID: %s %08lx",AddrToStr(&fm_addr),seed);

    if(msgtyp==MSGTYP_CONF||msgtyp==MSGTYP_MATX) {
        sprintf(sbuf,"\01PID: MPost/"UNAME" %s",SVERSON);
        strcat(str,sbuf);
    }

    sprintf(sbuf,"\01CHRS: %s 2",charset);
    strcat(str,sbuf);

    /* ^ASPLIT: 30 Mar 90 11:12:34 @494/4       12345 02/03 +++++++++++ */
    if(maxnum>1) {
        t=localtime(&time_now);
        sprintf(ubuf,"@%u/%u",fm_addr.net,fm_addr.node); ubuf[12]='\0';
        sprintf(sbuf,"\01SPLIT: %02u %s %02u %02u:%02u:%02u %-12s %05u %02u/%02u +++++++++++",
            t->tm_mday,Months[t->tm_mon],t->tm_year % 100,
            t->tm_hour,t->tm_min,t->tm_sec,ubuf,mn,num,maxnum);
        strcat(str,sbuf);
    }

    *len=strlen(str)+1; ++seed;
}


/*
** AddrToStr ()
** Build address string
*/

static char *  AddrToStr (NADDR *addr)
{
    static char str[256];
    char point[20], domain[70];

    if(addr->point) sprintf(point,".%u",addr->point);
    else *point='\0';
    if(*(addr->domain)) sprintf(domain,"@%s",addr->domain);
    else *domain='\0';

    sprintf(str,"%u:%u/%u%s%s",addr->zone,addr->net,addr->node,point,domain);
    return str;
}


/*
** HsecTime ()
** Get system date/time in hsec's
** This function is required to return a unique number for MSGID creation.
*/

static unsigned long  HsecTime (void)
{
    unsigned long i,j;

#if defined(OS2) || defined(__NT__)
#ifdef OS2
    DATETIME dt;
    APIRET rc;
#else
    SYSTEMTIME st;
#endif

    j = 0;
    while (i==j || j == 0)
    {
#ifdef OS2
        rc = DosGetDateTime(&dt);
        i=((dt.day+(((unsigned)dt.month*3057-3007)/100))*144000L) +
            (dt.hours*360000L) +                    /* hours today: hsec    */
            (dt.minutes*6000L) +                    /* minutes: hsec        */
            (dt.seconds*100L) +                     /* seconds: hsec        */
            dt.hundredths;                          /* hundreds of seconds  */
#else
        GetSystemTime(&st);
        i=((st.wDay+(((unsigned)st.wMonth*3057-3007)/100))*144000L) +
            (st.wHour*360000L) +                    /* hours today: hsec    */
            (st.wMinute*6000L) +                    /* minutes: hsec        */
            (st.wSecond*100L) +                     /* seconds: hsec        */
            (st.wMilliseconds/10);                  /* hundreds of seconds  */
#endif
        if (j == 0)
        j = i;
    }
#else
    j = time(NULL);
    for (i=time(NULL); i==j; i=time(NULL));  /* this is extremely nasty! */
#endif

    return i;
}


/*
** GetAddr ()
** Get command line system address
*/

static void  GetAddr (char *str, NADDR *addr)
{
    char *p;

    /* Zone */
    if((p=strchr(str,':'))!=NULL) {
        addr->zone=(unsigned int)atol(str); str=p+1;
    }
    else addr->zone=sy_addr.zone;

    /* Net */
    if((p=strchr(str,'/'))!=NULL) {
        addr->net=(unsigned int)atol(str); str=p+1;
    }
    else addr->net=sy_addr.net;

    /* Node */
    addr->node=(unsigned int)atol(str);

    /* Point */
    if((p=strchr(str,'.'))!=NULL) {
        str=p+1; addr->point=(unsigned int)atol(str);
    }
    else addr->point=0;

    /* Domain */
    if((p=strchr(str,'@'))!=NULL) {
        str=p+1; strcpy(addr->domain,str);
    }
    else *(addr->domain)='\0';
}


/*
** AddSlash (char *str)
** Add trailing back slash
*/

static void  AddSlash (char *str)
{
    char *p;

    p=str; while(*p) ++p;
    if(p!=str)
    {
       p--;
#if defined(OS2) || defined(__NT__) || defined(__DJGPP__)
       if(*p!='\\') strcat(str,"\\");
#else
       if(*p!='/') strcat(str,"/");
#endif
    }
}


/*
** StripSlash ()
** Strip trailing back slash
*/

static void  StripSlash (char *str)
{
    int i;

    for(i=strlen(str)-1;(str[i]=='\\')&&i>=0;i--) ;
    str[i+1]='\0';
}


/*
** StripCr ()
** Strip trailing cr/lf
*/

static void  StripCr (char *str)
{
    int i;

    for(i=strlen(str)-1;(str[i]=='\r'||str[i]=='\n')&&i>=0;i--) ;
    str[i+1]='\0';
}


/*
** StrTrim ()
** Strip trailing white space
*/

static void  StrTrim (char *str)
{
    int i;

    for(i=strlen(str)-1;IsSpace(str[i])&&i>=0;i--) ;
    str[i+1]='\0';
}


/*
** StrBlank ()
** Is string blank?
*/

static int  StrBlank (char *str)
{
    for(;*str;str++) {
        if(!IsSpace(*str)) return 0;
    }
    return 1;
}


/*
** CvtUs ()
** Convert underscore characters to spaces
*/

static void  CvtUs (char *s)
{
    while(*s) { if(*s=='_') *s=' '; ++s; }
}


/*
** IsSpace ()
** If the character is whitespace
*/

static int  IsSpace (char c)
{
    if(c==' '||c=='\t') return 1;
    return 0;
}


/*
** FancyStr ()
** Make It Look Like This
*/

static char *  FancyStr (char *string)
{
    int flag=0;
    char *s;

    s=string;
#ifdef UNIX
    return s;
#endif
    while(*string) {
        if(isalpha(*string)) {                  /* If alphabetic,     */
            if(flag) *string=tolower(*string);  /* already saw one?   */
            else {
                flag = 1;                       /* first one, flag it */
                *string=toupper(*string);       /* Uppercase it       */
            }
        }
        else flag=0;                            /* reset alpha flag   */
        ++string;
    }
    return s;
}


/*
** MakeExePath ()
** Get executable path
*/

static void  MakeExePath (char *pth)
{
    char drive[_MAX_DRIVE], dir[_MAX_DIR], name[_MAX_FNAME], ext[_MAX_EXT];

#ifdef EMX
    _splitpath(pth,drive,dir,name,ext);
    strcpy(exepath,drive); strcat(exepath,dir);
    AddSlash(exepath);
#else
    char *cp;

    strcpy(exepath, pth);
    for (cp = exepath + strlen(exepath); *cp != '/' && *cp != '\\'; cp--)
    {
        if (cp == exepath)
        {
            break;
        }
    }
    if (cp == exepath)
    {
        strcpy(exepath, "./");
    }
    else
    {
        *(cp+1) = '\0';
    }
#endif

}


/*
** ShFopen ()
** Share aware fopen function using SH_DENYNONE attribute
*/

static FILE *  ShFopen (char *name, char *fpmode)
{
    FILE *fp;           /* Temporary stram pointer */
    int fd;             /* Temporary file handle   */
    unsigned access=0;  /* Required access         */
    unsigned mode=0;    /* Required access mode    */
    char *fpm=fpmode;
    char c;

    /* Check first mode character */
    if((c=*fpmode++) == 'r') { access=O_RDONLY; }
    else if(c=='w') { access=O_CREAT|O_WRONLY|O_TRUNC; mode=S_IWRITE; }
    else if(c=='a') { access=O_WRONLY|O_CREAT|O_APPEND; mode=S_IWRITE; }
    else return NULL;

    /* Check for '+' read/write */
    c=*fpmode++;
    if(c=='+'||(*fpmode=='+'&&c=='b')) {
        if(c=='+') c=*fpmode;
        /* Same modes, but both read and write */
        access=(access&~(O_WRONLY|O_RDONLY))|O_RDWR;
        mode=S_IREAD|S_IWRITE;
    }

    /* Set text or binary access */
    if('b'==c) { access|=O_BINARY; }
    else { access|=O_TEXT; }

    /* Open the file */
    if((fd=sopen(name,access,SH_DENYNONE,mode))==-1) return NULL;

    /* Open the stream */
    if((fp=fdopen(fd,fpm))==NULL) close(fd);

    return fp; /* Return the stream pointer */
}


/*
** SetUp ()
** Initial program setup
*/

static void  SetUp (int argc, char *argv[])
{
    int i;
    int textflg=0;
    char *p;

    if(argc<2) Usage();
    MakeExePath(argv[0]);

    *str_orig=*msgpath=*txtpath='\0';
    sprintf(cfgpath,"%sMPost.Cfg",exepath);
    sprintf(lstpath,"%sMPost.Lst",exepath);
    strcpy(str_to,"All");
    strcpy(str_from,"MPost/"UNAME" " SVERSON);
    strcpy(str_subj,"Automated Posting");
    strcpy(charset,"IBMPC");

    /* Get initial command line */
    for(i=1;i<argc;i++) {
        p=argv[i];
        if(*p=='-'||*p=='/') {
            switch(tolower(*(++p))) {
                case 't': strcpy(txtpath,++p);
                          ++textflg;
                          break;
                case 'c': strcpy(cfgpath,++p);
                          break;
                case 'k': killtxtflg=1;
                          break;
                case '@': listflg=1; if(*++p) strcpy(lstpath,p);
                          break;
                case 'm': /* Process these commands later */
                case 'n':
                case 'p':
                case 'f':
                case 'l':
                case 'j':
                case 'w':
                case 'o':
                case 'h':
                case 's': break;
                case '?':
                default : Usage();
            }
        }
        else Usage();
    }

    if(!textflg) {
        printf("\n%cERROR: No text file supplied!\n\n",0x07);
        Quit(3);
    }

    /* Get the text storage */
    if((textbuf=malloc(MAX_BLOCK+1024))==NULL) {
        printf("\n%cERROR: Out of memory!\n\n",0x07);
        Quit(2);
    }
    memset(textbuf,'\0',MAX_BLOCK+1024);
}


/*
** GetCmdLine ()
** Get command line parameters
*/

static void  GetCmdLine (int argc, char *argv[])
{
    int i, gotsubj=0;
    char *p, s[60], f[XMSG_TO_SIZE], l[XMSG_TO_SIZE];

    *f=*l='\0'; /* Clear the name buffers */
    for(i=1;i<argc;i++) {
        p=argv[i];
        if(*p=='-'||*p=='/') {
            switch(tolower(*(++p))) {
                case 'h': strcpy(charset,++p);
                          break;
                case 'm': strcpy(msgpath,++p); StripSlash(msgpath);
                          break;
                case 'n': strcpy(s,++p); GetAddr(s,&to_addr);
                          msgtyp=MSGTYP_MATX;
                          break;
                case 'p': attr=MSGLOCAL; SetAttr(++p);
                          break;
                case 'f': strncpy(f,++p,XMSG_TO_SIZE-1);
                          f[XMSG_TO_SIZE-1]='\0';
                          CvtUs(f);
                          break;
                case 'l': strncpy(l,++p,XMSG_TO_SIZE-1);
                          l[XMSG_TO_SIZE-1]='\0';
                          CvtUs(l);
                          break;
                case 'j': strncpy(str_subj,++p,XMSG_SUBJ_SIZE-1);
                          str_subj[XMSG_SUBJ_SIZE-1]='\0';
                          ++gotsubj;
                          break;
                case 'w': strncpy(str_from,++p,XMSG_FROM_SIZE-1);
                          str_from[XMSG_FROM_SIZE-1]='\0';
                          CvtUs(str_from);
                          break;
                case 'o': strcpy(s,++p); GetAddr(s,&fm_addr);
                          if(sy_addr.net==0&&sy_addr.node==0) {
                              /* Set system address to message from address */
                              sy_addr=fm_addr;
                          }
                          ++addrflg;
                          break;
                case 's': split_k=atoi(++p);
                          if(split_k<0||split_k>16) split_k=12;
                          break;
            }
        }
    }

    if(gotsubj) {
        if( (!(attr&MSGFILE)) &&
            (!(attr&MSGFRQ)) &&
            (!(attr&MSGURQ))
        ) CvtUs(str_subj);
    }

    if(*f||*l) { /* Load command line name override */
        strncpy(str_to,f,XMSG_TO_SIZE-1);
        str_to[XMSG_TO_SIZE-1]='\0';
        if(*l&&strcmp(l,"NLN")) { /* Use last name if exist & is valid */
            i=XMSG_TO_SIZE-1-strlen(f);
            strncat(str_to," ",i); strncat(str_to,l,i-1);
            str_to[XMSG_TO_SIZE-1]='\0';
        }
    }
}


/*
** Usage ()
** Syntax command line display and exit
*/

static void  Usage (void)
{
   puts("    Syntax:  MPostP [-switch -switch ... ]\n\n"
        "\t                   COMMAND LINE ONLY\n"
        "\t     -T<name>      Text source file path & name\n"
        "\t     -K            Kill text file after processing\n"
        "\t     -C<name>      Configuration file path & name\n"
        "\t     -@<name>      Names list file mode\n"
        "\t     -?            Program help screen\n\n"
        "\t                   CONFIGURATION OVERRIDES\n"
        "\t     -M<name>      Message area path & name\n"
        "\t     -N<addr>      Netmail format - send to address\n"
        "\t     -O<addr>      Message origin address\n"
        "\t     -P<cfhdkprul> Message priority flag(s)\n"
        "\t     -F<fname>     Message addressed to first name\n"
        "\t     -L<lname>     Message addressed to last name\n"
        "\t     -W<name>      Message addressed from name\n"
        "\t     -J<subj>      Message subject (NO spaces)\n"
        "\t     -1            First line of text file is subject line\n"
        "\t     -S<##>        Split long messages to ## Kb size (0-16)\n"
        "\t     -h<charset>   Specify charset kludge name to use"
    );

    Quit(1);
}


