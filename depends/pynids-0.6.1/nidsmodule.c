/*
	nidsmodule.c - C implementation of pynids
	Copyright (c) 2003  Michael J. Pomraning <mjp@pilcrow.madison.wi.us>
	$Id: nidsmodule.c,v 1.11 2005/02/01 05:50:06 mjp Exp $

	This file is part of the pynids package, a python interface to libnids.

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111, USA
 */

#include "Python.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <nids.h>
#include <pcap.h>

#ifdef DEBUG
#define DBG(f, ...)		fprintf(stderr, f, ##__VA_ARGS__)
#else
#define DBG(p, ...)		
#endif /* DEBUG */

#ifndef Py_RETURN_NONE
# define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif /* Py_RETURN_NONE */

/* ====================================================================== */
/* Module Globals and Utility Functions                                   */
/* ====================================================================== */

static PyObject *pynids_error;         /* nids.error */

static int pynids_offline_read = 0;    /* see nids.init(), nids.next() */

static PyObject *tcpFunc  = NULL;
static PyObject *udpFunc  = NULL;
static PyObject *ipFunc   = NULL;
static PyObject *fragFunc = NULL;

static struct nids_prm origNidsParams;

typedef struct {
	PyObject_HEAD
	struct tcp_stream *tcps;
	PyObject *client;
	PyObject *server;
} TcpStream;

typedef struct {
	PyObject_HEAD
	struct half_stream *hlfs;
} HalfStream;

staticforward PyTypeObject TcpStream_Type;
staticforward PyTypeObject HalfStream_Type;

/* wrapHalfStream used by TcpStream getter */
static HalfStream *wrapHalfStream(struct half_stream *);

static char pynidsmodule__doc__[] =
"A wrapper around the libnids Network Intrusion Detection library.\n\
\n\
Functions:\n\
\n\
param() -- set various libnids parameters\n\
init() -- open the capture stream, prepare internal \n\
getfd() -- return the file descriptor associated with the capture stream\n\
get_pkt_ts() -- return the timestamp of the most recently received packet\n\
get_pcap_stats() -- return num packets rcvd, num pkts dropped,\n\
                   	num pkts dropped by interface as a tuple\n\
register_ip_frag() -- install a callback for IP fragment processing\n\
register_ip() -- install a callback for reassembled IP packet processing\n\
register_tcp() -- install a callback for reaseembled TCP packet processing\n\
register_udp() -- install a callback for reassembled UDP packet processing\n\
chksum_ctl() -- control whether packets are checksum by source address\n\
next() -- process one packet from the capture stream, invoking callbacks\n\
run() -- process all packets from the capture stream, invoking callbacks\n\
\n\
Special objects and classes:\n\
\n\
error -- exception raised for serious libnids/pcap errors\n\
TcpStream -- class of argument to TCP callback function.  Features:\n\
             addr -- Connection tuple: ((src, sport), (dst, dport))\n\
             discard(n) -- purge n bytes from the data buffer\n\
             kill() -- send symmetric RSTs to tear down the connection\n\
             nids_state -- see 'Constants,' below\n\
             client -- half of the connection; a TcpStream object\n\
             server -- half of the connection; a TcpStream object\n\
HalfStream -- class of TcpStream 'client' and 'server' members.  Features:\n\
              collect -- boolean controlling whether data is collected\n\
              collect_urg -- boolean controlling URG data collection\n\
              count -- number of bytes appended to 'data' since creation\n\
              count_new -- number of newly collected bytes in 'data'\n\
              count_new_urg -- number of new urgent bytes\n\
              data -- string buffer of normal (non-urgent) data\n\
              urgdata -- one-byte string buffer\n\
              offset -- offset of newly collected bytes in 'data'\n\
              state -- [*] numeric socket state\n\
\n\
  * TCP state constants (e.g., TCP_ESTABLISHED) are not supplied by pynids\n\
\n\
See the libnids documentation or the pynids README for more information\n\
on the TcpStream and HalfStream objects.\n\
\n\
Constants:\n\
\n\
NIDS_CLOSE, NIDS_DATA, NIDS_EXITING, NIDS_JUST_EST, NIDS_RESET,\n\
NIDS_TIMED_OUT, NIDS_TIMEOUT -- possible values of the 'nids_state' member\n\
of a TcpStream object.\n";

static PyObject *
raisePynidsError(void)
{
	extern char nids_errbuf[];

	PyErr_SetString(pynids_error, nids_errbuf);
	return NULL;
}

/* nids_dispatch_exc()
 *
 * Like nids_dispatch, but setting a Python exception upon serious error.
 * Non-serious error conditions (timeout, EOF) do not raise an exception.
 *
 * args: none
 * rtrn: >0 on successfully processing one packet
 *       0 timeout or EOF
 *       -1 exception thrown (either in user callback or in nids/pcap)
 *
 */
static int
nids_dispatch_exc(int n)
{
	int ret;

	DBG("nids_dispatch_exc(%d)\n", n);
	ret = nids_dispatch(n);
	if (ret == -1) { /* pcap error trumps user callback exception */
		raisePynidsError();
		return -1;
	}
	if (PyErr_Occurred()) return -1; /* check for callback exception */
	return ret;
}

/* pytuple4(tuple4): ((src, sport), (dst, dport)) */
static PyObject *
pytuple4(struct tuple4 *addr)
{
	struct in_addr in;
	PyObject *t1, *t2, *ret;
	
	in.s_addr = addr->saddr;
	t1 = Py_BuildValue("si", inet_ntoa(in), addr->source);
	if (! t1) return NULL;

	in.s_addr = addr->daddr;
	t2 = Py_BuildValue("si", inet_ntoa(in), addr->dest);
	if (! t2) {
		Py_DECREF(t1);
		return NULL;
	}

	ret = Py_BuildValue("OO", t1, t2);
	Py_DECREF(t1);
	Py_DECREF(t2);
	return ret;
}

/* ====================================================================== */
/* pynids Object Implementation                                           */
/* ====================================================================== */

/* TcpStream ctor -- called by callTcpFunc, not user */
static TcpStream *
wrapTcpStream(struct tcp_stream *t)
{
	TcpStream *self;
	self = PyObject_New(TcpStream, &TcpStream_Type);
	if (self == NULL) return NULL;
	self->tcps = t;
	self->client = NULL;
	self->server = NULL;
	DBG("TcpStream_ctor(%p)\n", self);
	/*
	 * wrap half streams on demand, if demanded...
	self->client = (PyObject *) wrapHalfStream(&t->client);
	self->server = (PyObject *) wrapHalfStream(&t->server);
	 */
	return self;
}

static void
TcpStream_dealloc(TcpStream *self)
{
	DBG("TcpStream_dealloc(%p)\n", self);
    self->tcps = NULL;  /* libnids will free this when approp. */
	if (self->client) {
		Py_DECREF(self->client);
		self->client = NULL;
	}
	if (self->server) {
		Py_DECREF(self->server);
		self->server = NULL;
	}
	PyObject_Del(self);
}

/* ====================================================================== */
/* TcpStreams: ctor, dtor, methods, members and type                      */
/* ====================================================================== */

static PyObject *
TcpStream_discard(TcpStream *self, PyObject *args)
{
	int i;
	if (!PyArg_ParseTuple(args, "i:discard", &i))
		return NULL;
 
	nids_discard(self->tcps, i);
 
	Py_RETURN_NONE;
}

static PyObject *
TcpStream_kill(TcpStream *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ":kill")) return NULL;
 
	nids_killtcp(self->tcps);

	Py_RETURN_NONE;
}

static PyMethodDef TcpStream_methods[] = {
	{"discard",	(PyCFunction)TcpStream_discard,	METH_VARARGS},
	{"kill",	(PyCFunction)TcpStream_kill,	METH_VARARGS},
	{NULL,		NULL}		/* sentinel */
};

#define TS_GET_HLFS(ATTR)													\
	static PyObject * ts_get_##ATTR(TcpStream *self, void *unused) {		\
		if (!self->ATTR) {													\
			self->ATTR = (PyObject *) wrapHalfStream(&self->tcps->ATTR);	\
			if (!self->ATTR) return NULL;									\
		}																	\
		Py_INCREF(self->ATTR);												\
		return self->ATTR;													\
	}

/* RO attributes */
TS_GET_HLFS(client)
TS_GET_HLFS(server)
static PyObject *
ts_get_addr(TcpStream *self, void *unused) {
	return pytuple4(&self->tcps->addr);
}
static PyObject *
ts_get_nids_state(TcpStream *self, void *unused) {
	return PyInt_FromLong((long)self->tcps->nids_state);
}

static PyGetSetDef TcpStream_getsets[] = {
	{"client",     (getter)ts_get_client},
	{"server",     (getter)ts_get_server},
	{"addr",       (getter)ts_get_addr},
	{"nids_state", (getter)ts_get_nids_state},
	{NULL} /* Sentinel */
};

statichere PyTypeObject TcpStream_Type = {
	/* The ob_type field must be initialized in the module init function
	 * to be portable to Windows without using C++. */
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"TcpStream",			/*tp_name*/
	sizeof(TcpStream),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	/* methods */
	(destructor)TcpStream_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,          /*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
	0,          /*tp_call*/
	0,          /*tp_str*/
	PyObject_GenericGetAttr,          /*tp_getattro*/
	0,          /*tp_setattro*/
	0,          /*tp_as_buffer*/
	Py_TPFLAGS_HAVE_CLASS,          /*tp_flags*/
	0,     /*tp_doc*/
	0,          /*tp_traverse*/
	0,          /*tp_clear*/
	0,          /*tp_richcompare*/
	0,          /*tp_weaklistoffset*/
	0,          /*tp_iter*/
	0,          /*tp_iternext*/
	TcpStream_methods, /*tp_methods*/
	0,          /*tp_members*/
	TcpStream_getsets, /*tp_getset*/
	0,          /*tp_base*/
};

/* ====================================================================== */
/* HalfStreams: ctor, dtor, methods, members and type                     */
/* ====================================================================== */

static HalfStream *
wrapHalfStream(struct half_stream *h) { /* called by TcpStream ctor */
	HalfStream *self;
	self = PyObject_New(HalfStream, &HalfStream_Type);
	if (self == NULL) return NULL;
	self->hlfs = h;
	DBG("HalfStream_ctor(%p)\n", self);
	return self;
}

static void
HalfStream_dealloc(HalfStream *self) {
	DBG("HalfStream_dealloc(%p, %d)\n", self, self->ob_refcnt);
	self->hlfs = NULL;
	PyObject_Del(self);
}

#define HS_GET_INT(ATTR)												\
	static PyObject * hs_get_##ATTR(HalfStream *self, void *unused) {	\
		return PyInt_FromLong((long)self->hlfs->ATTR);					\
	}

/* FIXME - true bool support */
#define HS_GET_BOOL(ATTR)												\
	static PyObject * hs_get_##ATTR(HalfStream *self, void *unused) {	\
		return PyInt_FromLong(self->hlfs->ATTR ? 1L : 0L);				\
	}

#define HS_SET_BOOL(ATTR)												\
	static int hs_set_##ATTR(HalfStream *self, PyObject *val, void *closure) {	\
		if (val == NULL) {												\
			PyErr_SetString(PyExc_TypeError,							\
							"Cannot delete the " #ATTR "attribute");	\
			return -1;													\
		}																\
		DBG("hs_set_" #ATTR "(HalfStream * %p, bool %d)\n",				\
			self, PyObject_IsTrue(val));								\
		self->hlfs->ATTR = PyObject_IsTrue(val);						\
		return 0; /* success */											\
	}

/* RW attributes */
HS_GET_BOOL(collect)
HS_SET_BOOL(collect)
HS_GET_BOOL(collect_urg)
HS_SET_BOOL(collect_urg)
/* RO attributes */
HS_GET_INT(state)
static PyObject *hs_get_data(HalfStream *self, void *unused) {
	/* data may not be allocated if the conn/libnids has seen no data */
	if (! self->hlfs->data) return PyString_FromStringAndSize("", 0);
	/* bufsize is an undocumented member */
	return PyString_FromStringAndSize(self->hlfs->data, self->hlfs->bufsize);
}
static PyObject *hs_get_urgdata(HalfStream *self, void *unused) {
	/* u_char urgdata */
	return PyString_FromStringAndSize(&(self->hlfs->urgdata),
									sizeof(self->hlfs->urgdata));
}
HS_GET_INT(count)
HS_GET_INT(offset)
HS_GET_INT(count_new)
HS_GET_INT(count_new_urg)

static PyGetSetDef HalfStream_getsets[] = {
	{"state",         (getter)hs_get_state},
	{"collect",       (getter)hs_get_collect,     (setter)hs_set_collect},
	{"collect_urg",   (getter)hs_get_collect_urg, (setter)hs_set_collect_urg},
	{"data",          (getter)hs_get_data},
	{"urgdata",       (getter)hs_get_urgdata},
	{"count",         (getter)hs_get_count},
	{"offset",        (getter)hs_get_offset},
	{"count_new",     (getter)hs_get_count_new},
	{"count_new_urg", (getter)hs_get_count_new_urg},
	{NULL} /* Sentinel */
};

statichere PyTypeObject HalfStream_Type = {
	/* The ob_type field must be initialized in the module init function
	 * to be portable to Windows without using C++. */
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"HalfStream",			/*tp_name*/
	sizeof(HalfStream),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	/* methods */
	(destructor)HalfStream_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
	0,          /*tp_call*/
	0,          /*tp_str*/
	PyObject_GenericGetAttr,          /*tp_getattro*/
	PyObject_GenericSetAttr,          /*tp_setattro*/
	0,          /*tp_as_buffer*/
	Py_TPFLAGS_HAVE_CLASS,          /*tp_flags*/
	0,          /*tp_doc*/
	0,          /*tp_traverse*/
	0,          /*tp_clear*/
	0,          /*tp_richcompare*/
	0,          /*tp_weaklistoffset*/
	0,          /*tp_iter*/
	0,          /*tp_iternext*/
	0,          /*tp_methods*/
	0,          /*tp_members*/
	HalfStream_getsets, /*tp_getset*/
	0,          /*tp_base*/
};

/* ====================================================================== */
/* User-Defined libnids Handler Hooks                                     */
/* ====================================================================== */

static void
callTcpFunc(struct tcp_stream *ts, void **param)
{
	PyObject *ret = NULL;
	TcpStream *tso = NULL;

	DBG("callTcpFunc - init tso\n");
	tso = wrapTcpStream(ts);
	if (! tso) return;

	DBG("callTcpFunc - call func %p(%p)\n", tcpFunc, tso);
	ret = PyObject_CallFunction(tcpFunc, "O", tso);

	DBG("callTcpFunc - dealloc tso (ret: %p)\n", ret);
	Py_DECREF(tso);
	if (ret) {
		Py_DECREF(ret);
	}
	return;
}

static void
callUdpFunc(struct tuple4 *addr, u_char *data, int len, struct ip *pkt)
{
	PyObject *ret = NULL;

	DBG("callUdpFunc...\n");
	ret = PyObject_CallFunction(udpFunc, "(Ns#s#)",
										pytuple4(addr),
						                data, len,
										pkt, ntohs(pkt->ip_len));
	if (ret) {
		Py_DECREF(ret);
	}
	return;
}

static void
callIpFunc(struct ip *pkt)
{
	PyObject *ret = NULL;

	DBG("callIpFunc...\n");
	ret = PyObject_CallFunction(ipFunc, "s#", pkt, ntohs(pkt->ip_len));
	if (ret) {
		Py_DECREF(ret);
	}
	return;
}

static void
callFragFunc(struct ip *pkt)
{
	PyObject *ret = NULL;

	ret = PyObject_CallFunction(fragFunc, "s#", pkt, ntohs(pkt->ip_len));
	if (ret) {
		Py_DECREF(ret);
	}
	return;
}

/* makeRegisterFunc(type, static PyFunction ptr, dispatch)
 *
 * what     PyObject *     Invoker
 * -----------------------------------
 * tcp       tcpFunc       callTcpFunc
 * udp       udpFunc       callUdpFunc
 * ip         ipFunc       callIpFunc
 * ip_frag  fragFunc       callFragFunc
 */

#define makeRegisterFunc(WHAT, FP, PYDISPATCH)					\
																\
static char pynids_register_##WHAT##__doc__[] = 				\
"register_" #WHAT "(func) -> None\n"							\
"\n"															\
"Register the given user-defined function as a callback handler.\n";	\
																\
static PyObject *												\
pynids_register_##WHAT (PyObject *na, PyObject *args) 			\
{ 																\
	PyObject *pyFunc = NULL;									\
	if (!PyArg_ParseTuple(args, "O:register_" #WHAT, &pyFunc))	\
		return NULL;											\
																\
	if (FP != NULL) {											\
		/* (re-)set single, global func ptr */					\
		PyObject_Del(FP);										\
	} else {													\
		nids_register_##WHAT(PYDISPATCH);						\
	}															\
	DBG("Inside register_" #WHAT "(%p)\n", pyFunc);				\
	FP = pyFunc;												\
	Py_INCREF(FP);												\
	Py_RETURN_NONE;												\
}

/*               What     PyFunc *  C-level Dispatch */
/*               ----     --------  ---------------- */

makeRegisterFunc(tcp,     tcpFunc,  callTcpFunc);
makeRegisterFunc(udp,     udpFunc,  callUdpFunc);
makeRegisterFunc(ip,      ipFunc,   callIpFunc);
makeRegisterFunc(ip_frag, fragFunc, callFragFunc);

/* ====================================================================== */
/* Module Functions                                                       */
/* ====================================================================== */

static char pynids_chksum_ctl__doc__[] =
"chksum_ctl([(addr1, True), (addr2, False)], ...) -> None\n\
\n\
takes as arguments an list of tuples where a tuple should have the\n\
following format:\n\
    (Source address in CIDR format, Boolean whether to apply checksum)\n\
    e.g. (\"192.168.1.10/24\", True)\n\
Internal checksumming functions will first check elements of this\n\
list one by one, and if the source ip of the current packet\n\
matches the source address and mask of a tuple then the packet with either\n\
be checksummed if the apply boolean is set to True, or not checksummed if\n\
the boolean is set to False. If the packet matches none of the list\n\
elements, the default action is to perform checksumming.\n";

static int
_parse_prefix(char *prefix, u_int *netaddr, u_int *mask)
{
	struct in_addr in;
	char    *ptr, *data;
	u_int	m;
	
	/* eat up white space */
	data = prefix;
	while (*data == ' ' && *data == '\t')
		data++;
	
	/* find end */
	ptr = data;
	while (*ptr != '/' && *ptr != '\n' && *ptr != '\0')
		ptr++;
	
	if (*ptr == '/')
	{
		*ptr = '\0';
		ptr++;
		
		/* convert the ip to binary */
		if (inet_pton(AF_INET, data, &in) < 0)
		{
			PyErr_SetFromErrno(PyExc_OSError);
			return -1;
		}
		*netaddr = in.s_addr;
		
		/* get mask */
		m = 32 - atoi(ptr);
		*mask = (m >= 32) ? 0 : htonl((0xffffffff >> m) << m);
	}
	else if (strlen(data) >= 7)
	{
		/* convert the ip to binary */
		if (inet_pton(AF_INET, data, &in) < 0)
		{
			PyErr_SetFromErrno(PyExc_OSError);
			return -1;
		}
		*netaddr = in.s_addr;
		*mask = 0xffffffff;
	}

	return 0;
}

static int
_parse_chksum_tuple(struct nids_chksum_ctl *ctl, int i, PyObject *tuple)
{
	PyObject *addr, *action;
	
	addr = PyTuple_GET_ITEM(tuple, 0);
	if (PyString_Check(addr) <= 0)
	{
		PyErr_SetString(PyExc_TypeError,
			"in (cidr_address, action) cidr_address must be string");
		return -1;
	}
	if (_parse_prefix(PyString_AS_STRING(addr), &ctl[i].netaddr,
		&ctl[i].mask) < 0)
		return -1;
	
	action = PyTuple_GET_ITEM(tuple, 1);
	if (PyBool_Check(action) <= 0)
	{
		PyErr_SetString(PyExc_TypeError,
			"in (cidr_address, action) action must be boolean");
		return -1;
	}
	if (action == Py_False)
		ctl[i].action = NIDS_DONT_CHKSUM;
	else
		ctl[i].action = NIDS_DO_CHKSUM;

	return 0;
}

static PyObject *
pynids_chksum_ctl(PyObject *na, PyObject *args)
{
	PyObject *items, *tuple;
	int i, n;
	struct nids_chksum_ctl *ctl = NULL;
	
	/* parse args */
	if (!PyArg_ParseTuple(args, "O:chksum_ctl", &items))
		return NULL;
	
	/* parse list of address/action tuples */
	if (PyList_Check(items) > 0)
	{
		n = PyList_Size(items);
		ctl = (struct nids_chksum_ctl *) \
			malloc(sizeof(struct nids_chksum_ctl) * n);
		if (ctl == NULL)
		{
			PyErr_SetString(PyExc_OSError,
				"could not allocate temp memory storage");
			return NULL;
		}
		for (i=0; i<n; i++)
		{
			tuple = PyList_GetItem(items, i);
			if (PyTuple_Check(tuple) <= 0 || PyTuple_GET_SIZE(tuple) != 2)
			{
				PyErr_SetString(PyExc_TypeError,
					"list must contain (cidr_address, action) tuples");
				free(ctl);
				return NULL;
			}
			if (_parse_chksum_tuple(ctl, i, tuple) < 0)
			{
				free(ctl);
				return NULL;
			}
		}
	}
	else
	{
		PyErr_SetString(PyExc_TypeError, "chksum_ctl requires a list param");
		return NULL;
	}

	nids_register_chksum_ctl(ctl, n);

	Py_RETURN_NONE;
}

static char pynids_param__doc__[] =
"param(name[, new_value]) -> old_value\n\
\n\
If new_value is specified, set the named nids attribute to the new value.\n\
Returns the previous value in any case.  Supported parameters and their\n\
defaults are:\n\
\n\
device -- network device to use as input (None); see also 'filename'\n\
filename -- pcap filename to use as input (None); see also 'device'\n\
dev_addon -- number of bytes in struct sk_buff for layer 2 info (-1)\n\
one_loop_less -- undocumented\n\
n_hosts -- size of IP defragmentation info hash table (256)\n\
n_tcp_streams -- size of TCP connection hash table (1024)\n\
pcap_filter -- pcap filter string applied to unassembled packets (None)\n"
#if (NIDS_MAJOR > 1 || (NIDS_MAJOR == 1 && NIDS_MINOR >= 19))
"pcap_timeout -- pcap capture timeout, in milliseconds (1024)\n"
#endif /* libnids >= 1.19 */
"promisc -- non-zero if promiscuous mode is desired on capture device (1)\n\
sk_buff_size -- size of struct skbuff, used for queueing packets (168)\n\
syslog_level -- log level used when syslogging events (LOG_ALERT)\n\
scan_num_hosts -- hash table size for portscan detection (256)\n\
scan_num_ports -- minimum ports per src. host to qualify as a portscan (10)\n\
scan_delay -- maximum delay in milliseconds between (3000)\n\
\n\
Either 'device' or 'filename' must be specified before calling nids_init().\n\
Portscan detection may be disabled by setting 'scan_num_hosts' to zero.  See\n\
the libnids documentation for more details.\n";

static PyObject *
pynids_param(PyObject *na, PyObject *args)
{
	PyObject *v = NULL;
	PyObject *ret = NULL;
	int *int_p = NULL;
	char **char_pp = NULL;
	char *name;

	if (!PyArg_ParseTuple(args, "s|O", &name, &v)) return NULL;

	/* is it an int parameter? */
	if (!strcmp(name, "n_tcp_streams"))
		int_p = &nids_params.n_tcp_streams;
	else if (!strcmp(name, "n_hosts"))
		int_p = &nids_params.n_hosts;
	else if (!strcmp(name, "sk_buff_size"))
		int_p = &nids_params.sk_buff_size;
	else if (!strcmp(name, "dev_addon"))
		int_p = &nids_params.dev_addon;
	else if (!strcmp(name, "syslog_level"))
		int_p = &nids_params.syslog_level;
	else if (!strcmp(name, "scan_num_hosts"))
		int_p = &nids_params.scan_num_hosts;
	else if (!strcmp(name, "scan_num_ports"))
		int_p = &nids_params.scan_num_ports;
	else if (!strcmp(name, "scan_delay"))
		int_p = &nids_params.scan_delay;
	else if (!strcmp(name, "promisc"))
		int_p = &nids_params.promisc;
	else if (!strcmp(name, "one_loop_less"))
		int_p = &nids_params.one_loop_less;
#if (NIDS_MAJOR > 1 || (NIDS_MAJOR == 1 && NIDS_MINOR >= 19))
	else if (!strcmp(name, "pcap_timeout"))
		int_p = &nids_params.pcap_timeout;
#endif /* libnids >= 1.19 */

	if (int_p) {
		/* FIXME - type check val for intishness */
		ret = PyInt_FromLong((long) *int_p);
		if (v) *int_p = (int) PyInt_AsLong(v);
		return ret;
	}

	/* is it a char * param? */
	if (!strcmp(name, "device"))
		char_pp = &nids_params.device;
	else if (!strcmp(name, "pcap_filter"))
		char_pp = &nids_params.pcap_filter;
	else if (!strcmp(name, "filename"))
		char_pp = &nids_params.filename;

	if (char_pp) {
		/* XXX - error checking, PyMem alloc/free */
		ret = Py_BuildValue("s", *char_pp);
		if (v) {
			/* free previous strdup -- fortunately libnids inits these to
			 * NULL...
			 */
			if (*char_pp) free(*char_pp);
			*char_pp = (v == Py_None) ? NULL : strdup(PyString_AsString(v));
		}
		return ret;
	}

	/******
	if (!strcmp(name, "syslog"))
		func_pp = &nids.syslog;
	else if (!strcmp(name, "ip_filter"))
		func_pp = &nids.ip_filter;
	else if (!strcmp(name, "no_mem"))
		func_pp = &nids.no_mem;
    ******/

	Py_RETURN_NONE;
}

static char pynids_getfd__doc__[] =
"getfd() -> fd\n\
\n\
Returns the integral file descriptor of the live capture device or pcap\n\
savefile specified during the call to init().  The resultant fd is suitable\n\
for I/O polling with select.select(), for example.\n";

static PyObject *
pynids_getfd(PyObject *na, PyObject *args)
{
	int pcap_fd;
	
	if (!PyArg_ParseTuple(args, ":getfd")) return NULL;

	if ((pcap_fd = nids_getfd()) == -1) return raisePynidsError();
    return PyInt_FromLong((long) pcap_fd);
}

static char pynids_next__doc__[] =
"next() -> r\n\
\n\
Attempt to process one packet, returning 1 if a packet was processed and 0\n\
on timeout or EOF, as appropriate to the capture stream.  Serious errors in\n\
pcap raise a nids.error exception.\n";

static PyObject *
pynids_next(PyObject *na, PyObject *args)
{
	int ret;

	if (!PyArg_ParseTuple(args, ":next")) return NULL;

	ret = nids_dispatch_exc(1);
	if (PyErr_Occurred()) return NULL; /* python callback error */

	return PyInt_FromLong((long) ret);
}

static char pynids_dispatch__doc__[] =
"dispatch(cnt) -> processed\n\
\n\
UNDOCUMENTED -- this function does not exist in libnids <= 1.19.\n";

static PyObject *
pynids_dispatch(PyObject *na, PyObject *args)
{
	int ret, cnt;

	if (!PyArg_ParseTuple(args, "i:dispatch", &cnt)) return NULL;

	ret = nids_dispatch_exc(cnt);
	if (ret == -1) return NULL;

	return PyInt_FromLong((long) ret);
}

static char pynids_run__doc__[] =
"run() -> None\n\
\n\
On a live capture, process packets ad infinitum; on an offline read, process\n\
packets until EOF.  In either case, an exception thrown in a user callback\n\
or in nids/pcap (as nids.error) may abort processing.\n";

static PyObject *
pynids_run(PyObject *na, PyObject *args)
{
    int r;

	if (!PyArg_ParseTuple(args, ":run")) return NULL;

	if (pynids_offline_read) {
		/* read until EOF, checking for exceptions along the way */
		do { r = nids_dispatch_exc(1); } while (r > 0);
	} else {
		/* read forever, checking for exceptions along the way */
		do { r = nids_dispatch_exc(1); } while (r >= 0);
	}

	if (r == -1) return NULL;

#if 0
	if (r != 0) runtime error!
#endif

	Py_RETURN_NONE;
}

static char pynids_init__doc__[] =
"init() -> None\n\
\n\
Initialize the nids library, as specified by previous calls to param().  In\n\
particular, the capture device 'device' or pcap savefile 'filename' is\n\
opened, the 'pcap_filter' compiled, and various internal mechanisms prepared.\n\
\n\
It is appropriate and recommended to drop process privileges after making\n\
this call.\n";

static PyObject *
pynids_init(PyObject *na, PyObject *args)
{
	int ok;
	if (!PyArg_ParseTuple(args, ":init")) return NULL;

	ok = nids_init();
	if (! ok) return raisePynidsError();
	if (nids_params.filename) pynids_offline_read = 1;
	else pynids_offline_read = 0;

	Py_RETURN_NONE;
}

static char pynids_get_pkt_ts__doc__[] =
"get_pkt_time() -> float\n\
\n\
Returns the timestamp of the most recent packet as a float.\n";

static PyObject *
pynids_get_pkt_ts(PyObject *na, PyObject *args)
{
	double pkt_time;
	
	if (!PyArg_ParseTuple(args, ":get_pkt_ts")) return NULL;

	pkt_time = nids_last_pcap_header->ts.tv_sec +
        (nids_last_pcap_header->ts.tv_usec / 1000000.0);
    return PyFloat_FromDouble(pkt_time);
}

static char pynids_get_pcap_stats__doc__[] =
"get_pcap_stats() -> tuple\n\
\n\
Returns the pcap recv, drop and interface drop statistics as a tuple.\n";

static PyObject *
pynids_get_pcap_stats(PyObject *na, PyObject *args)
{
	static struct pcap_stat ps;
	PyObject *pcap_stats_tuple;
	
	if (!PyArg_ParseTuple(args, ":get_pcap_stats")) return NULL;

	if (nids_params.pcap_desc == NULL ||
        pcap_stats(nids_params.pcap_desc, &ps) != 0) {
		raisePynidsError();
        return NULL;
    }

	pcap_stats_tuple = Py_BuildValue("III", ps.ps_recv, ps.ps_drop,
        ps.ps_ifdrop);

	if (! pcap_stats_tuple) return NULL;

	return pcap_stats_tuple;
}

/* List of functions defined in the module */

#define mkMethod(x)    \
    {#x, pynids_##x, METH_VARARGS, pynids_##x##__doc__}

static PyMethodDef pynids_methods[] = {
    mkMethod(run),
    mkMethod(dispatch),
    mkMethod(getfd),
    mkMethod(next),
    mkMethod(register_tcp),
    mkMethod(register_udp),
    mkMethod(register_ip),
    mkMethod(register_ip_frag),
    mkMethod(chksum_ctl),
    mkMethod(init),
    mkMethod(param),
    mkMethod(get_pkt_ts),
    mkMethod(get_pcap_stats),
	{NULL,		NULL}		/* sentinel */
};

#undef mkMethod

/* ====================================================================== */
/* Module Initialization                                                  */
/* ====================================================================== */

DL_EXPORT(void)
initnids(void)
{
	PyObject *m;

	/* Initialize the type of the new type object here; doing it here
	 * is required for portability to Windows without requiring C++. */
	TcpStream_Type.ob_type = &PyType_Type;
	HalfStream_Type.ob_type = &PyType_Type;

	/* Create the module and add the functions */
	m = Py_InitModule3("nids", pynids_methods, pynidsmodule__doc__);

	/* Initialize, add our exception object */
	pynids_error = PyErr_NewException("nids.error", NULL, NULL);
	Py_INCREF(pynids_error);
	PyModule_AddObject(m, "error", pynids_error);

	/* Add versioning info */
	PyModule_AddStringConstant(m, "__version__", "0.6.1");
	PyModule_AddObject(m, "__nids_version__",
						PyString_FromFormat("%d.%d", NIDS_MAJOR, NIDS_MINOR));

	/* Add NIDS_ symbolic constants to the module */
#define setConst(CONST)	\
	PyModule_AddIntConstant(m, #CONST, CONST)

	setConst(NIDS_JUST_EST);
	setConst(NIDS_DATA);
	setConst(NIDS_CLOSE);
	setConst(NIDS_RESET);
	setConst(NIDS_TIMED_OUT);
#ifndef NIDS_TIMEOUT
#define NIDS_TIMEOUT NIDS_TIMED_OUT
#endif
	setConst(NIDS_TIMEOUT);  /* compat. w/ manpage */
	setConst(NIDS_EXITING);

	/* Save the original nids_params */
	origNidsParams = nids_params;
}

/*
 * vim:noet:ts=4:
 */
