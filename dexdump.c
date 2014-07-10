/*
 *  Collin's Dynamic Dalvik Instrumentation Toolkit for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

#include <jni.h>
#include <stdlib.h>

#include "hook.h"
#include "dexstuff.h"
#include "dalvik_hook.h"
#include "base.h"

#undef log

#define log(...) \
        {FILE *fp = fopen("/data/local/tmp/dexdump.log", "a+");\
        fprintf(fp, __VA_ARGS__);\
        fclose(fp);}

static struct hook_t eph;
static struct dexstuff_t d;
static struct dalvik_hook_t dpdu,d_sendT,smsM_sTM,smsM_sDM,smsM_sMpTM;

// switch for debug output of dalvikhook and dexstuff code
static int debug;

static void my_log(char *msg)
{
	log(msg)
}
static void my_log2(char *msg)
{
	if (debug)
		log(msg);
}

static int my_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	int (*orig_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
	orig_epoll_wait = (void*)eph.orig;
	// remove hook for epoll_wait
	hook_precall(&eph);

	// resolve symbols from DVM
	dexstuff_resolv_dvm(&d);
	
	log ("Dumping Classes\n")
	// dump all classes
	dalvik_dump_class(&d, 0);
//	dalvik_dump_class(&d, "Lcom/android/internal/telephony/SMSDispatcher;");
	
	log ("SMSDispatcher Class Dumped\n")	
//	log ("Dumping SMSmanager\n")
//	dalvik_dump_class(&d, "Landroid/telephony/SmsManager;");

	log("calling orig epoll\n")
	// call original epoll function
	int res = orig_epoll_wait(epfd, events, maxevents, timeout);    
	return res;
}



// set my_init as the entry point
void __attribute__ ((constructor)) my_init(void);

void my_init(void)
{
	log("libsmsdispatch: started\n")
 
 	debug = 1;
 	// set log function for  libbase (very important!)
	set_logfunction(my_log2);
	// set log function for libdalvikhook (very important!)
	dalvikhook_set_logfunction(my_log2);

	hook(&eph, getpid(), "libc.", "epoll_wait", my_epoll_wait, 0);
}
