/*  
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nfstat.c 69 2010-09-09 07:17:43Z haag $
 *
 *  $LastChangedRevision: 69 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "nfnet.h"
#include "netflow_v5_v7.h"
#include "nf_common.h"
#include "util.h"
#include "nflowcache.h"
#include "nfstat.h"

extern int hash_hit;
extern int hash_miss;
extern int hash_skip;
extern extension_map_list_t extension_map_list;

struct flow_element_s {
	uint32_t	offset0;
	uint32_t	offset1;	// set in the netflow record block
	uint64_t	mask;		// mask for value in 64bit word
	uint32_t	shift;		// number of bits to shift right to get final value
};

enum { IS_NUMBER = 1, IS_IPADDR, IS_MACADDR, IS_MPLS_LBL };

struct StatParameter_s {
	char					*statname;		// name of -s option
	char					*HeaderInfo;	// How to name the field in the output header line
	struct flow_element_s	element[2];		// what element(s) in flow record is used for statistics.
											// need 2 elements to be able to get src/dst stats in one stat record
	uint8_t					num_elem;		// number of elements used. 1 or 2
	uint8_t					type;			// Type of element: Number, IP address, MAC address etc. 
} StatParameters[] ={
	// flow record stat
	{ "record",	 "", 			
		{ {0,0, 0,0},										{0,0,0,0} },
			1, 0},

	// 9 possible flow element stats 
	{ "srcip",	 "Src IP Addr", 
		{ {OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "dstip",	 "Dst IP Addr", 
		{ {OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "ip",	 	"IP Addr", 
		{ {OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0},	{OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6} },
			2, IS_IPADDR },

	{ "nhip",	 "Nexthop IP", 
		{ {OffsetNexthopv6a, OffsetNexthopv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "nhbip",	 "Nexthop BGP IP", 
		{ {OffsetBGPNexthopv6a, OffsetBGPNexthopv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "router",	 "Router IP", 
		{ {OffsetRouterv6a, OffsetRouterv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "srcport", "Src Port", 
		{ {0, OffsetPort, MaskSrcPort, ShiftSrcPort}, 		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstport", "Dst Port", 
		{ {0, OffsetPort, MaskDstPort, ShiftDstPort}, 		{0,0,0,0} },
			1, IS_NUMBER },

	{ "port", 	 "Port", 
		{ {0, OffsetPort, MaskSrcPort, ShiftSrcPort}, 		{0, OffsetPort, MaskDstPort, ShiftDstPort}},
			2, IS_NUMBER },

	{ "proto", 	 "Protocol", 
		{ {0, OffsetProto, MaskProto, ShiftProto}, 			{0,0,0,0} },
			1, IS_NUMBER },

	{ "tos", 	 "Tos", 
		{ {0, OffsetTos, MaskTos, ShiftTos}, 				{0,0,0,0} },
			1, IS_NUMBER },

	{ "srctos",  "Tos", 
		{ {0, OffsetTos, MaskTos, ShiftTos}, 				{0,0,0,0} },
			1, IS_NUMBER },

	{ "dsttos",	 "Dst Tos", 
		{ {0, OffsetDstTos, MaskDstTos, ShiftDstTos},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dir",	 "Dir", 
		{ {0, OffsetDir, MaskDir, ShiftDir},		  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "srcas",	 "Src AS", 
		{ {0, OffsetAS, MaskSrcAS, ShiftSrcAS},		  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstas",	 "Dst AS", 
		{ {0, OffsetAS, MaskDstAS, ShiftDstAS},  	  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "as",	 	 "AS", 
		{ {0, OffsetAS, MaskSrcAS, ShiftSrcAS},  	  		{0, OffsetAS, MaskDstAS, ShiftDstAS} },
			2, IS_NUMBER },

	{ "inif", 	 "Input If", 
		{ {0, OffsetInOut, MaskInput, ShiftInput}, 			{0,0,0,0} },
			1, IS_NUMBER },

	{ "outif", 	 "Output If", 
		{ {0, OffsetInOut, MaskOutput, ShiftOutput},		{0,0,0,0} },
			1, IS_NUMBER },

	{ "if", 	 "In/Out If", 
		{ {0, OffsetInOut, MaskInput, ShiftInput},			{0, OffsetInOut, MaskOutput, ShiftOutput} },
			2, IS_NUMBER },

	{ "srcmask",	 "Src Mask", 
		{ {0, OffsetMask, MaskSrcMask, ShiftSrcMask},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstmask",	 "Dst Mask", 
		{ {0, OffsetMask, MaskDstMask, ShiftDstMask},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "mask",	 "Mask", 
		{ {0, OffsetMask, MaskSrcMask, ShiftSrcMask},  		{0, OffsetMask, MaskDstMask, ShiftDstMask} },
			2, IS_NUMBER },

	{ "srcvlan",	 "Src Vlan", 
		{ {0, OffsetVlan, MaskSrcVlan, ShiftSrcVlan},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstvlan",	 "Dst Vlan", 
		{ {0, OffsetVlan, MaskDstVlan, ShiftDstVlan},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "vlan",	 "Vlan", 
		{ {0, OffsetVlan, MaskSrcVlan, ShiftSrcVlan},  		{0, OffsetVlan, MaskDstVlan, ShiftDstVlan} },
			2, IS_NUMBER },

	{ "insrcmac",	 "In Src Mac", 
		{ {0, OffsetInSrcMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "outdstmac",	 "Out Dst Mac", 
		{ {0, OffsetOutDstMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "indstmac",	 "In Dst Mac", 
		{ {0, OffsetInDstMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "outsrcmac",	 "Out Src Mac", 
		{ {0, OffsetOutSrcMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "srcmac",	 "Src Mac", 
		{ {0, OffsetInSrcMAC, MaskMac, 0},  		{0, OffsetOutSrcMAC, MaskMac, 0}},
			2, IS_MACADDR },

	{ "dstmac",	 "Dst Mac", 
		{ {0, OffsetOutDstMAC, MaskMac, 0},  		{0, OffsetInDstMAC, MaskMac, 0} },
			2, IS_MACADDR },

	{ "inmac",	 "In Src Mac", 
		{ {0, OffsetInSrcMAC, MaskMac, 0},  		{0, OffsetInDstMAC, MaskMac, 0} },
			1, IS_MACADDR },

	{ "outmac",	 "Out Src Mac", 
		{ {0, OffsetOutSrcMAC, MaskMac, 0},  		{0, OffsetOutDstMAC, MaskMac, 0} },
			2, IS_MACADDR },

	{ "mpls1",	 " MPLS lab 1", 
		{ {0, OffsetMPLS12, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls2",	 " MPLS lab 2", 
		{ {0, OffsetMPLS12, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls3",	 " MPLS lab 3", 
		{ {0, OffsetMPLS34, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls4",	 " MPLS lab 4", 
		{ {0, OffsetMPLS34, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls5",	 " MPLS lab 5", 
		{ {0, OffsetMPLS56, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls6",	 " MPLS lab 6", 
		{ {0, OffsetMPLS56, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls7",	 " MPLS lab 7", 
		{ {0, OffsetMPLS78, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls8",	 " MPLS lab 8", 
		{ {0, OffsetMPLS78, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls9",	 " MPLS lab 9", 
		{ {0, OffsetMPLS910, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls10",	 "MPLS lab 10", 
		{ {0, OffsetMPLS910, MaskMPLSlabelEven, 0}, {0,0,0,0} },
			1, IS_MPLS_LBL },

	{ NULL, 	 NULL, 			
		{ {0,0,0,0},	{0,0,0,0} },
			1, 0 }
};

static const uint32_t NumOrders = 6;	// Number of Stats in enum StatTypes

enum CntIndices { FLOWS = 0, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES };

#define MaxStats 16
struct StatRequest_s {
	uint16_t	order_bits;		// bits 0: flows 1: packets 2: bytes 3: pps 4: bps, 5 bpp
	int16_t		StatType;		// value out of enum StatTypes
	uint8_t		order_proto;	// protocol separated statistics
} StatRequest[MaxStats];		// This number should do it for a single run

uint32_t	flow_stat_order;

/* 
 * pps, bps and bpp are not directly available in the flow/stat record
 * therefore we need a function to calculate these values
 */
typedef uint32_t (*order_proc_record_t)(FlowTableRecord_t *);
typedef uint32_t (*order_proc_element_t)(StatRecord_t *);

/* order functions */
static inline uint32_t	pps_record(FlowTableRecord_t *record);
static inline uint32_t	bps_record(FlowTableRecord_t *record);
static inline uint32_t	bpp_record(FlowTableRecord_t *record);

static inline uint32_t	pps_element(StatRecord_t *record);
static inline uint32_t	bps_element(StatRecord_t *record);
static inline uint32_t	bpp_element(StatRecord_t *record);

struct order_mode_s {
	char		 *string;	// Stat name 
	int			 val;		// order bit set results in this value
	order_proc_record_t  record_function;	// Function to call for record stats
	order_proc_element_t element_function;	// Function to call for element stats
} order_mode[] = {
	{ "flows",    1, NULL, NULL},
	{ "packets",  2, NULL, NULL},
	{ "bytes",    4, NULL, NULL},
	{ "pps", 	  8, pps_record, pps_element},
	{ "bps", 	 16, bps_record, bps_element},
	{ "bpp", 	 32, bpp_record, bpp_element},
	{ NULL,       0, NULL}
};

static uint64_t	byte_limit, packet_limit;
static int byte_mode, packet_mode;
enum { NONE = 0, LESS, MORE };

/* function prototypes */
static int ParseStatString(char *str, int16_t	*StatType, uint16_t *order_bits, int *flow_record_stat, uint16_t *order_proto);

static inline StatRecord_t *stat_hash_lookup(uint64_t *value, uint8_t prot, int hash_num);

static inline StatRecord_t *stat_hash_insert(uint64_t *value, uint8_t prot, int hash_num);

static void Expand_StatTable_Blocks(int hash_num);

static void PrintStatLine(stat_record_t	*stat, StatRecord_t *StatData, int type, int order_proto, int tag);

static void PrintPipeStatLine(StatRecord_t *StatData, int type, int order_proto, int tag);

static void PrintCvsStatLine(stat_record_t	*stat, StatRecord_t *StatData, int type, int order_proto, int tag);

static void Create_topN_FlowStat(SortElement_t **topN_lists, int order, int topN, uint32_t *count );

static inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 );

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order );

static inline void RankValue(FlowTableRecord_t *r, uint64_t val, int topN, SortElement_t *topN_list);

static void SwapFlow(master_record_t *flow_record);

/* locals */
static hash_StatTable *StatTable;
static int initialised = 0;

static int	NumStats = 0, DefaultOrder;

/* Functions */

#include "nffile_inline.c"
#include "heapsort_inline.c"
#include "applybits_inline.c"

static uint32_t	pps_record(FlowTableRecord_t *record) {
uint64_t		duration;

	/* duration in msec */
	duration = 1000*(record->flowrecord.last - record->flowrecord.first) + record->flowrecord.msec_last - record->flowrecord.msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 1000LL * (uint64_t)record->counter[INPACKETS] ) / duration;

} // End of pps_record

static uint32_t	bps_record(FlowTableRecord_t *record) {
uint64_t		duration;

	duration = 1000*(record->flowrecord.last - record->flowrecord.first) + record->flowrecord.msec_last - record->flowrecord.msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 8000LL * (uint64_t)record->counter[INBYTES] ) / duration;	/* 8 bits per Octet - x 1000 for msec */

} // End of bps_record

static uint32_t	bpp_record(FlowTableRecord_t *record) {
	
	return record->counter[INPACKETS] ? record->counter[INBYTES] / record->counter[INPACKETS] : 0;

} // End of bpp_record

static uint32_t	pps_element(StatRecord_t *record) {
uint64_t		duration;

	/* duration in msec */
	duration = 1000*(record->last - record->first) + record->msec_last - record->msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 1000LL * (uint64_t)record->counter[INPACKETS] ) / duration;

} // End of pps_element

static uint32_t	bps_element(StatRecord_t *record) {
uint64_t		duration;

	duration = 1000*(record->last - record->first) + record->msec_last - record->msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 8000LL * (uint64_t)record->counter[INBYTES] ) / duration;	/* 8 bits per Octet - x 1000 for msec */

} // End of bps_element

static uint32_t	bpp_element(StatRecord_t *record) {
	
	return record->counter[INPACKETS] ? record->counter[INBYTES] / record->counter[INPACKETS] : 0;

} // End of bpp_element


static inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 ) {
    if ( t1 > t2 )
        return 1;
    if ( t2 > t1 ) 
        return 2;
    // else t1 == t2 - offset is now relevant
    if ( offset1 > offset2 )
        return 1;
    if ( offset2 > offset1 )
        return 2;
    else
        // both times are the same
        return 0;
} // End of TimeMsec_CMP


void SetLimits(int stat, char *packet_limit_string, char *byte_limit_string ) {
char 		*s, c;
uint32_t	len,scale;

	if ( ( stat == 0 ) && ( packet_limit_string || byte_limit_string )) {
		fprintf(stderr,"Options -l and -L do not make sense for plain packet dumps.\n");
		fprintf(stderr,"Use -l and -L together with -s -S or -a.\n");
		fprintf(stderr,"Use netflow filter syntax to limit the number of packets and bytes in netflow records.\n");
		exit(250);
	}
	packet_limit = byte_limit = 0;
	if ( packet_limit_string ) {
		switch ( packet_limit_string[0] ) {
			case '-':
				packet_mode = LESS;
				s = &packet_limit_string[1];
				break;
			case '+':
				packet_mode = MORE;
				s = &packet_limit_string[1];
				break;
			default:
				if ( !isdigit((int)packet_limit_string[0])) {
					fprintf(stderr,"Can't understand '%s'\n", packet_limit_string);
					exit(250);
				}
				packet_mode = MORE;
				s = packet_limit_string;
		}
		len = strlen(packet_limit_string);
		c = packet_limit_string[len-1];
		switch ( c ) {
			case 'B':
			case 'b':
				scale = 1;
				break;
			case 'K':
			case 'k':
				scale = 1000;
				break;
			case 'M':
			case 'm':
				scale = 1000 * 1000;
				break;
			case 'G':
			case 'g':
				scale = 1000 * 1000 * 1000;
				break;
			default:
				scale = 1;
				if ( isalpha((int)c) ) {
					fprintf(stderr,"Can't understand '%c' in '%s'\n", c, packet_limit_string);
					exit(250);
				}
		}
		packet_limit = (uint64_t)atol(s) * (uint64_t)scale;
	}

	if ( byte_limit_string ) {
		switch ( byte_limit_string[0] ) {
			case '-':
				byte_mode = LESS;
				s = &byte_limit_string[1];
				break;
			case '+':
				byte_mode = MORE;
				s = &byte_limit_string[1];
				break;
			default:
				if ( !isdigit((int)byte_limit_string[0])) {
					fprintf(stderr,"Can't understand '%s'\n", byte_limit_string);
					exit(250);
				}
				byte_mode = MORE;
				s = byte_limit_string;
		}
		len = strlen(byte_limit_string);
		c = byte_limit_string[len-1];
		switch ( c ) {
			case 'B':
			case 'b':
				scale = 1;
				break;
			case 'K':
			case 'k':
				scale = 1000;
				break;
			case 'M':
			case 'm':
				scale = 1000 * 1000;
				break;
			case 'G':
			case 'g':
				scale = 1000 * 1000 * 1000;
				break;
			default:
				if ( isalpha((int)c) ) {
					fprintf(stderr,"Can't understand '%c' in '%s'\n", c, byte_limit_string);
					exit(250);
				}
				scale = 1;
		}
		byte_limit = (uint64_t)atol(s) * (uint64_t)scale;
	}

	if ( byte_limit )
		printf("Byte limit: %c %llu bytes\n", byte_mode == LESS ? '<' : '>', byte_limit);

	if ( packet_limit )
		printf("Packet limit: %c %llu packets\n", packet_mode == LESS ? '<' : '>', packet_limit);


} // End of SetLimits

int Init_StatTable(uint16_t NumBits, uint32_t Prealloc) {
uint32_t maxindex;
int		 hash_num;

	if ( NumBits == 0 || NumBits > 31 ) {
		fprintf(stderr, "Numbits outside 1..31\n");
		exit(255);
	}

	maxindex = (1 << NumBits);

	StatTable = (hash_StatTable *)calloc(NumStats, sizeof(hash_StatTable));
	if ( !StatTable ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}

	for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
		StatTable[hash_num].IndexMask   = maxindex -1;
		StatTable[hash_num].NumBits     = NumBits;
		StatTable[hash_num].Prealloc    = Prealloc;
		StatTable[hash_num].bucket	  	= (StatRecord_t **)calloc(maxindex, sizeof(StatRecord_t *));
		StatTable[hash_num].bucketcache = (StatRecord_t **)calloc(maxindex, sizeof(StatRecord_t *));
		if ( !StatTable[hash_num].bucket || !StatTable[hash_num].bucketcache ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return 0;
		}
		StatTable[hash_num].memblock = (StatRecord_t **)calloc(MaxMemBlocks, sizeof(StatRecord_t *));
		if ( !StatTable[hash_num].memblock ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return 0;
		}
		StatTable[hash_num].memblock[0] = (StatRecord_t *)calloc(Prealloc, sizeof(StatRecord_t));
		if ( !StatTable[hash_num].memblock[0] ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return 0;
		}
	
		StatTable[hash_num].NumBlocks = 1;
		StatTable[hash_num].MaxBlocks = MaxMemBlocks;
		StatTable[hash_num].NextBlock = 0;
		StatTable[hash_num].NextElem  = 0;

		if ( StatRequest[hash_num].order_bits == 0 ) {
			StatRequest[hash_num].order_bits = DefaultOrder;
		}
	}

	initialised = 1;
	return 1;

} // End of Init_StatTable

void Dispose_StatTable() {
unsigned int i, hash_num;

	if ( !initialised ) 
		return;

	for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
		free((void *)StatTable[hash_num].bucket);
		for ( i=0; i<StatTable[hash_num].NumBlocks; i++ ) 
			free((void *)StatTable[hash_num].memblock[i]);
		free((void *)StatTable[hash_num].memblock);
	}

} // End of Dispose_Tables

int SetStat(char *str, int *element_stat, int *flow_stat) {
int			flow_record_stat = 0;
int16_t 	StatType    = 0;
uint16_t	order_bits  = 0;
uint16_t	order_proto = 0;

	if ( NumStats == MaxStats ) {
		fprintf(stderr, "Too many stat options! Stats are limited to %i stats per single run!\n", MaxStats);
		return 0;
	}

	if ( ParseStatString(str, &StatType, &order_bits, &flow_record_stat, &order_proto) ) {
		if ( flow_record_stat ) {
			flow_stat_order = order_bits ? order_bits : DefaultOrder;
			*flow_stat = 1;
		} else {
			StatRequest[NumStats].StatType 	  = StatType;
			StatRequest[NumStats].order_bits  = order_bits;
			StatRequest[NumStats].order_proto = order_proto;
			NumStats++;
			*element_stat = 1;
		}
		return 1;
	} else {
		fprintf(stderr, "Unknown stat: '%s'!\n", str);
		return 0;
	}

} // End of SetStat

static int ParseStatString(char *str, int16_t	*StatType, uint16_t *order_bits, int *flow_record_stat, uint16_t *order_proto) {
char	*s, *p, *q, *r;
int i=0;

	if ( NumStats >= MaxStats )
		return 0;

	s = strdup(str);
	q = strchr(s, '/');
	if ( q ) 
		*q = 0;

	*order_proto = 0;
	p = strchr(s, ':');
	if ( p ) {
		*p = 0;
		*order_proto = 1;
	}

	i = 0;
	// check for a valid stat name
	while ( StatParameters[i].statname ) {
		if ( strncasecmp(s, StatParameters[i].statname ,16) == 0 ) {
			// set flag if it's the flow record stat request
			*flow_record_stat = strncasecmp(s, "record", 16) == 0;
			break;
		}
		i++;
	}

	// if so - initialize type and order_bits
 	if ( StatParameters[i].statname ) {
		*StatType = i;
		*order_bits = 0;
		if ( strncasecmp(StatParameters[i].statname, "proto", 16) == 0 ) 
			*order_proto = 1;
	} else {
		free(s);
		return 0;
	}

	// no order is given - default order applies;
	if ( !q ) {
		free(s);
		return 1;
	}

	// check if one or more orders are given
	r = ++q;
	while ( r ) {
		q = strchr(r, '/');
		if ( q ) 
			*q = 0;
		i = 0;
		while ( order_mode[i].string ) {
			if (  strcasecmp(order_mode[i].string, r ) == 0 )
				break;
			i++;
		}
		if ( order_mode[i].string ) {
			*order_bits |= order_mode[i].val;
		} else {
			free(s);
			return 0;
		}

		if ( !q ) {
			free(s);
			return 1;
		}

		r = ++q;
	}

	free(s);
	return 0;

} // End of ParseStatString

int SetStat_DefaultOrder(char *order) {
int order_index;

	order_index = 0;
	while ( order_mode[order_index].string ) {
		if (  strcasecmp(order_mode[order_index].string, order ) == 0 )
			break;
		order_index++;
	}
	if ( !order_mode[order_index].string )
		return 0;

	DefaultOrder = order_mode[order_index].val;
	return 1;

} // End of SetStat_DefaultOrder

static inline StatRecord_t *stat_hash_lookup(uint64_t *value, uint8_t prot, int hash_num) {
uint32_t		index;
StatRecord_t	*record;

	index = value[1] & StatTable[hash_num].IndexMask;

	if ( StatTable[hash_num].bucket[index] == NULL )
		return NULL;

	record = StatTable[hash_num].bucket[index];
	if ( StatRequest[hash_num].order_proto ) {
		while ( record && ( record->stat_key[1] != value[1] || record->stat_key[0] != value[0] || prot != record->prot ) ) {
			record = record->next;
		}
	} else {
		while ( record && ( record->stat_key[1] != value[1] || record->stat_key[0] != value[0] ) ) {
			record = record->next;
		}
	}
	return record;

} // End of stat_hash_lookup

static void Expand_StatTable_Blocks(int hash_num) {

	if ( StatTable[hash_num].NumBlocks >= StatTable[hash_num].MaxBlocks ) {
		StatTable[hash_num].MaxBlocks += MaxMemBlocks;
		StatTable[hash_num].memblock = (StatRecord_t **)realloc(StatTable[hash_num].memblock,
						StatTable[hash_num].MaxBlocks * sizeof(StatRecord_t *));
		if ( !StatTable[hash_num].memblock ) {
			fprintf(stderr, "realloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			exit(250);
		}
	}
	StatTable[hash_num].memblock[StatTable[hash_num].NumBlocks] = 
			(StatRecord_t *)calloc(StatTable[hash_num].Prealloc, sizeof(StatRecord_t));

	if ( !StatTable[hash_num].memblock[StatTable[hash_num].NumBlocks] ) {
		fprintf(stderr, "calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		exit(250);
	}
	StatTable[hash_num].NextBlock = StatTable[hash_num].NumBlocks++;
	StatTable[hash_num].NextElem  = 0;

} // End of Expand_StatTable_Blocks

static inline StatRecord_t *stat_hash_insert(uint64_t *value, uint8_t prot, int hash_num) {
uint32_t		index;
StatRecord_t	*record;

	if ( StatTable[hash_num].NextElem >= StatTable[hash_num].Prealloc )
		Expand_StatTable_Blocks(hash_num);

	record = &(StatTable[hash_num].memblock[StatTable[hash_num].NextBlock][StatTable[hash_num].NextElem]);
	StatTable[hash_num].NextElem++;
	record->next     	= NULL;
	record->stat_key[0] = value[0];
	record->stat_key[1] = value[1];
	record->prot		= prot;

	index = value[1] & StatTable[hash_num].IndexMask;
	if ( StatTable[hash_num].bucket[index] == NULL ) 
		StatTable[hash_num].bucket[index] = record;
	else
		StatTable[hash_num].bucketcache[index]->next = record;
	StatTable[hash_num].bucketcache[index] = record;
	
	return record;

} // End of stat_hash_insert

void AddStat(common_record_t *raw_record, master_record_t *flow_record ) {
StatRecord_t		*stat_record;
uint64_t			value[2][2];
int	j, i;

	// for every requested -s stat do
	for ( j=0; j<NumStats; j++ ) {
		int stat   = StatRequest[j].StatType;
		// for the number of elements in this stat type
		for ( i=0; i<StatParameters[stat].num_elem; i++ ) {
			uint32_t offset = StatParameters[stat].element[i].offset1;
			uint64_t mask	= StatParameters[stat].element[i].mask;
			uint32_t shift	= StatParameters[stat].element[i].shift;

			value[i][1] = (((uint64_t *)flow_record)[offset] & mask) >> shift;
			offset = StatParameters[stat].element[i].offset0;
			value[i][0] = offset ? ((uint64_t *)flow_record)[offset] : 0;

			/* 
			 * make sure each flow is counted once only
			 * if src and dst have the same values, count it once only
			 */
			if ( i == 1 && value[0][0] == value[1][0] && value[0][1] == value[1][1] ) {
				break;
			}
			stat_record = stat_hash_lookup(value[i], flow_record->prot, j);
			if ( stat_record ) {
				stat_record->counter[INBYTES] 	+= flow_record->dOctets;
				stat_record->counter[INPACKETS] += flow_record->dPkts;
		
				if ( TimeMsec_CMP(flow_record->first, flow_record->msec_first, stat_record->first, stat_record->msec_first) == 2) {
					stat_record->first 		= flow_record->first;
					stat_record->msec_first = flow_record->msec_first;
				}
				if ( TimeMsec_CMP(flow_record->last, flow_record->msec_last, stat_record->last, stat_record->msec_last) == 1) {
					stat_record->last 		= flow_record->last;
					stat_record->msec_last 	= flow_record->msec_last;
				}
				stat_record->counter[FLOWS]++;

			} else {
				stat_record = stat_hash_insert(value[i], flow_record->prot, j);
		
				stat_record->counter[INBYTES]   = flow_record->dOctets;
				stat_record->counter[INPACKETS]	= flow_record->dPkts;
				stat_record->first    			= flow_record->first;
				stat_record->msec_first 		= flow_record->msec_first;
				stat_record->last				= flow_record->last;
				stat_record->msec_last			= flow_record->msec_last;
				stat_record->record_flags		= flow_record->flags & 0x1;
				stat_record->counter[FLOWS] 	= 1;
			}
		} // for the number of elements in this stat type
	} // for every requested -s stat

} // End of AddStat

static void PrintStatLine(stat_record_t	*stat, StatRecord_t *StatData, int type, int order_proto, int tag) {
char		proto[16], valstr[40], datestr[64], flows_str[32], byte_str[32], packets_str[32], pps_str[32], bps_str[32];
char tag_string[2];
double		duration, flows_percent, packets_percent, bytes_percent;
uint32_t	pps, bps, bpp;
time_t		first;
struct tm	*tbuff;

	tag_string[0] = '\0';
	tag_string[1] = '\0';
	switch (type) {
		case NONE:
			break;
		case IS_NUMBER:
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->stat_key[1]);
			break;
		case IS_IPADDR:
			tag_string[0] = tag ? TAG_CHAR : '\0';
			if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
				StatData->stat_key[0] = htonll(StatData->stat_key[0]);
				StatData->stat_key[1] = htonll(StatData->stat_key[1]);
				inet_ntop(AF_INET6, StatData->stat_key, valstr, sizeof(valstr));
				if ( ! Getv6Mode() )
					condense_v6(valstr);
	
			} else {	// IPv4
				uint32_t	ipv4;
				ipv4 = htonl(StatData->stat_key[1]);
				inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
			}
			break;
		case IS_MACADDR: {
			int i;
			uint8_t mac[6];
			for ( i=0; i<6; i++ ) {
				mac[i] = ((unsigned long long)StatData->stat_key[1] >> ( i*8 )) & 0xFF;
			}
			snprintf(valstr, 40, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
			} break;
		case IS_MPLS_LBL: {
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->stat_key[1]);
			snprintf(valstr, 40,"%8llu-%1llu-%1llu", 
				(unsigned long long)StatData->stat_key[1] >> 4 , 
				((unsigned long long)StatData->stat_key[1] & 0xF ) >> 1, 
				(unsigned long long)StatData->stat_key[1] & 1);
			} break;
	}

	valstr[39] = 0;

	format_number(StatData->counter[FLOWS], flows_str, FIXED_WIDTH);
	format_number(StatData->counter[INPACKETS], packets_str, FIXED_WIDTH);
	format_number(StatData->counter[INBYTES], byte_str, FIXED_WIDTH);

	flows_percent   = (double)(StatData->counter[FLOWS] * 100 ) / (double)stat->numflows;
	packets_percent = (double)(StatData->counter[INPACKETS] * 100 ) / (double)stat->numpackets;
	bytes_percent   = (double)(StatData->counter[INBYTES] * 100 ) / (double)stat->numbytes;

	duration = StatData->last - StatData->first;
	duration += ((double)StatData->msec_last - (double)StatData->msec_first) / 1000.0;
	
	if ( duration != 0 ) {
		pps = (uint32_t)((double)StatData->counter[INPACKETS] / duration);
		bps = (uint32_t)((double)(8 * StatData->counter[INBYTES]) / duration);
	} else {
		pps = bps = 0;
	}

	if (StatData->counter[INPACKETS]) {
		bpp = StatData->counter[INBYTES] / StatData->counter[INPACKETS];
	} else {
		bpp = 0;
	}

	format_number(pps, pps_str, FIXED_WIDTH);
	format_number(bps, bps_str, FIXED_WIDTH);

	first = StatData->first;
	tbuff = localtime(&first);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	if ( order_proto ) {
		Proto_string(StatData->prot, proto);
	} else {
		snprintf(proto, 15, "any  ");
		proto[15] = 0;
	}

	if ( Getv6Mode() && ( type == IS_IPADDR ) )
		printf("%s.%03u %9.3f %s %s%39s %8s(%4.1f) %8s(%4.1f) %8s(%4.1f) %8s %8s %5u\n", 
				datestr, StatData->msec_first, duration, proto, tag_string, valstr, 
				flows_str, flows_percent, packets_str, packets_percent, byte_str, bytes_percent, pps_str, bps_str, bpp );
	else
		printf("%s.%03u %9.3f %s %s%17s %8s(%4.1f) %8s(%4.1f) %8s(%4.1f) %8s %8s %5u\n", 
				datestr, StatData->msec_first, duration, proto, tag_string, valstr, 
				flows_str, flows_percent, packets_str, packets_percent, byte_str, bytes_percent, pps_str, bps_str, bpp );

} // End of PrintStatLine

static void PrintPipeStatLine(StatRecord_t *StatData, int type, int order_proto, int tag) {
double		duration;
uint32_t	pps, bps, bpp;
uint32_t	sa[4];
int			af;

	sa[0] = sa[1] = sa[2] = sa[3] = 0;
	af = AF_UNSPEC;
	if ( type == IS_IPADDR ) {
		if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
			StatData->stat_key[0] = htonll(StatData->stat_key[0]);
			StatData->stat_key[1] = htonll(StatData->stat_key[1]);
			af = PF_INET6;

		} else {	// IPv4
			af = PF_INET;
		}
		// Make sure Endian does not screw us up
    	sa[0] = ( StatData->stat_key[0] >> 32 ) & 0xffffffffLL;
    	sa[1] = StatData->stat_key[0] & 0xffffffffLL;
    	sa[2] = ( StatData->stat_key[1] >> 32 ) & 0xffffffffLL;
    	sa[3] = StatData->stat_key[1] & 0xffffffffLL;
	} 
	duration = StatData->last - StatData->first;
	duration += ((double)StatData->msec_last - (double)StatData->msec_first) / 1000.0;
	
	if ( duration != 0 ) {
		pps = (uint32_t)((double)StatData->counter[INPACKETS] / duration);
		bps = (uint32_t)((double)(8 * StatData->counter[INBYTES]) / duration);
	} else {
		pps = bps = 0;
	}

	if ( StatData->counter[INPACKETS] )
		bpp = StatData->counter[INBYTES] / StatData->counter[INPACKETS];
	else
		bpp = 0;

	if ( !order_proto ) {
		StatData->prot = 0;
	}

	if ( type == IS_IPADDR )
		printf("%i|%u|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%llu|%llu|%u|%u|%u\n",
				af, StatData->first, StatData->msec_first ,StatData->last, StatData->msec_last, StatData->prot, 
				sa[0], sa[1], sa[2], sa[3], (long long unsigned)StatData->counter[FLOWS], 
				(long long unsigned)StatData->counter[INPACKETS], (long long unsigned)StatData->counter[INBYTES], 
				pps, bps, bpp);
	else
		printf("%i|%u|%u|%u|%u|%u|%llu|%llu|%llu|%llu|%u|%u|%u\n",
				af, StatData->first, StatData->msec_first ,StatData->last, StatData->msec_last, StatData->prot, 
				(long long unsigned)StatData->stat_key[1], (long long unsigned)StatData->counter[FLOWS], 
				(long long unsigned)StatData->counter[INPACKETS], (long long unsigned)StatData->counter[INBYTES], 
				pps, bps, bpp);

} // End of PrintPipeStatLine

static void PrintCvsStatLine(stat_record_t	*stat, StatRecord_t *StatData, int type, int order_proto, int tag) {
char		proto[16], valstr[40], datestr1[64], datestr2[64];
char tag_string[2];
double		duration, flows_percent, packets_percent, bytes_percent;
uint32_t	i, pps, bps, bpp;
time_t		when;
struct tm	*tbuff;

	tag_string[0] = '\0';
	tag_string[1] = '\0';
	switch (type) {
		case NONE:
			break;
		case IS_NUMBER:
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->stat_key[1]);
			break;
		case IS_IPADDR:
			tag_string[0] = tag ? TAG_CHAR : '\0';
			if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
				StatData->stat_key[0] = htonll(StatData->stat_key[0]);
				StatData->stat_key[1] = htonll(StatData->stat_key[1]);
				inet_ntop(AF_INET6, StatData->stat_key, valstr, sizeof(valstr));
	
			} else {	// IPv4
				uint32_t	ipv4;
				ipv4 = htonl(StatData->stat_key[1]);
				inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
			}
			break;
		case IS_MACADDR: {
			int i;
			uint8_t mac[6];
			for ( i=0; i<6; i++ ) {
				mac[i] = ((unsigned long long)StatData->stat_key[1] >> ( i*8 )) & 0xFF;
			}
			snprintf(valstr, 40, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
			} break;
		case IS_MPLS_LBL: {
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->stat_key[1]);
			snprintf(valstr, 40,"%8llu-%1llu-%1llu", 
				(unsigned long long)StatData->stat_key[1] >> 4 , 
				((unsigned long long)StatData->stat_key[1] & 0xF ) >> 1, 
				(unsigned long long)StatData->stat_key[1] & 1);
			} break;
	}

	valstr[39] = 0;

	flows_percent   = (double)(StatData->counter[FLOWS] * 100 ) / (double)stat->numflows;
	packets_percent = (double)(StatData->counter[INPACKETS] * 100 ) / (double)stat->numpackets;
	bytes_percent   = (double)(StatData->counter[INBYTES] * 100 ) / (double)stat->numbytes;

	duration = StatData->last - StatData->first;
	duration += ((double)StatData->msec_last - (double)StatData->msec_first) / 1000.0;
	
	if ( duration != 0 ) {
		pps = (uint32_t)((double)StatData->counter[INPACKETS] / duration);
		bps = (uint32_t)((double)(8 * StatData->counter[INBYTES]) / duration);
	} else {
		pps = bps = 0;
	}

	if (StatData->counter[INPACKETS]) {
		bpp = StatData->counter[INBYTES] / StatData->counter[INPACKETS];
	} else {
		bpp = 0;
	}

	when = StatData->first;
	tbuff = localtime(&when);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	when = StatData->last;
	tbuff = localtime(&when);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	if ( order_proto ) {
		Proto_string(StatData->prot, proto);
	} else {
		snprintf(proto, 15, "any  ");
		proto[15] = 0;
	}

	i=0;
	while ( proto[i] ) {
		if ( proto[i] == ' ' )
			proto[i] = '\0';
		i++;
	}

	printf("%s,%s,%.3f,%s,%s,%llu,%.1f,%llu,%.1f,%llu,%.1f,%u,%u,%u\n", 
		datestr1, datestr2, duration, proto, valstr, 
		(long long unsigned)StatData->counter[FLOWS], flows_percent, 
		(long long unsigned)StatData->counter[INPACKETS], packets_percent,
		(long long unsigned)StatData->counter[INBYTES], bytes_percent,
		pps,bps,bpp
	);

} // End of PrintCvsStatLine

void PrintFlowTable(printer_t print_record, uint32_t limitflows, int date_sorted, int tag, int GuessDir) {
hash_FlowTable *FlowTable;
FlowTableRecord_t	*r;
master_record_t		*aggr_record_mask;
SortElement_t 		*SortList;
uint32_t 			i;
uint32_t			maxindex, c;
char				*string;

	FlowTable = GetFlowTable();
	aggr_record_mask = GetMasterAggregateMask();
	c = 0;
	maxindex = FlowTable->NumRecords;
	if ( date_sorted ) {
		// Sort according the date
		SortList = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

		if ( !SortList ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return;
		}

		// preset SortList table - still unsorted
		for ( i=0; i<FlowTable->IndexMask; i++ ) {
			r = FlowTable->bucket[i];
			if ( !r ) 
				continue;

			// foreach elem in this bucket
			while ( r ) {
				// we want to sort only those flows which pass the packet or byte limits
				if ( byte_limit ) {
					if (( byte_mode == LESS && r->counter[INBYTES] >= byte_limit ) ||
						( byte_mode == MORE && r->counter[INBYTES]  <= byte_limit ) ) {
						r = r->next;
						continue;
					}
				}
				if ( packet_limit ) {
					if (( packet_mode == LESS && r->counter[INPACKETS] >= packet_limit ) ||
						( packet_mode == MORE && r->counter[INPACKETS]  <= packet_limit ) ) {
						r = r->next;
						continue;
					}
				}
				
				SortList[c].count  = 1000LL * r->flowrecord.first + r->flowrecord.msec_first;	// sort according the date
				SortList[c].record = (void *)r;
				c++;
				r = r->next;
			}
		}

		maxindex = c;

		if ( c >= 2 )
 			heapSort(SortList, c, 0);

		if ( limitflows && limitflows < maxindex )
			maxindex = limitflows;
		for ( i = 0; i < maxindex; i++ ) {
			master_record_t	*flow_record;
			common_record_t *raw_record;
			int map_id;

			r = (FlowTableRecord_t *)(SortList[i].record);
			raw_record = &(r->flowrecord);
			map_id = r->map_ref->map_id;

			flow_record = &(extension_map_list.slot[map_id]->master_record);
			ExpandRecord_v2( raw_record, extension_map_list.slot[map_id], flow_record);
			flow_record->dPkts 		= r->counter[INPACKETS];
			flow_record->dOctets 	= r->counter[INBYTES];
			flow_record->out_pkts 	= r->counter[OUTPACKETS];
			flow_record->out_bytes 	= r->counter[OUTBYTES];
			flow_record->aggr_flows 	= r->counter[FLOWS];
			
			// apply IP mask from aggregation, to provide a pretty output
			if ( FlowTable->has_masks ) {
				flow_record->v6.srcaddr[0] &= FlowTable->IPmask[0];
				flow_record->v6.srcaddr[1] &= FlowTable->IPmask[1];
				flow_record->v6.dstaddr[0] &= FlowTable->IPmask[2];
				flow_record->v6.dstaddr[1] &= FlowTable->IPmask[3];
			}

			if ( aggr_record_mask ) {
				ApplyAggrMask(flow_record, aggr_record_mask);
			}

			if ( GuessDir && ( flow_record->srcport < 1024 && flow_record->dstport > 1024 ) )
				SwapFlow(flow_record);
			print_record((void *)flow_record, &string, tag);
			printf("%s\n", string);
		}

	} else {
		// print them as they came
		c = 0;
		for ( i=0; i<FlowTable->IndexMask; i++ ) {
			r = FlowTable->bucket[i];
			while ( r ) {
				master_record_t	*flow_record;
				common_record_t *raw_record;
				int map_id;

				if ( limitflows && c >= limitflows )
					return;

				// we want to print only those flows which pass the packet or byte limits
				if ( byte_limit ) {
					if (( byte_mode == LESS && r->counter[INBYTES] >= byte_limit ) ||
						( byte_mode == MORE && r->counter[INBYTES]  <= byte_limit ) ) {
						r = r->next;
						continue;
					}
				}
				if ( packet_limit ) {
					if (( packet_mode == LESS && r->counter[INPACKETS] >= packet_limit ) ||
						( packet_mode == MORE && r->counter[INPACKETS]  <= packet_limit ) ) {
						r = r->next;
						continue;
					}
				}

				raw_record = &(r->flowrecord);
				map_id = r->map_ref->map_id;

				flow_record = &(extension_map_list.slot[map_id]->master_record);
				ExpandRecord_v2( raw_record, extension_map_list.slot[map_id], flow_record);
				flow_record->dPkts 		= r->counter[INPACKETS];
				flow_record->dOctets 	= r->counter[INBYTES];
				flow_record->out_pkts 	= r->counter[OUTPACKETS];
				flow_record->out_bytes 	= r->counter[OUTBYTES];
				flow_record->aggr_flows 	= r->counter[FLOWS];

				// apply IP mask from aggregation, to provide a pretty output
				if ( FlowTable->has_masks ) {
					flow_record->v6.srcaddr[0] &= FlowTable->IPmask[0];
					flow_record->v6.srcaddr[1] &= FlowTable->IPmask[1];
					flow_record->v6.dstaddr[0] &= FlowTable->IPmask[2];
					flow_record->v6.dstaddr[1] &= FlowTable->IPmask[3];
				}

				if ( aggr_record_mask ) {
					ApplyAggrMask(flow_record, aggr_record_mask);
				}
				if ( GuessDir && ( flow_record->srcport < 1024 && flow_record->dstport > 1024 ) )
					SwapFlow(flow_record);
				print_record((void *)flow_record, &string, tag);
				printf("%s\n", string);

				c++;
				r = r->next;
			}
		}
	}

} // End of PrintFlowTable

void PrintFlowStat(char *record_header, printer_t print_record, int topN, int tag, int quiet, int cvs_output) {
hash_FlowTable *FlowTable;
SortElement_t 	*topN_flow_list[NumOrders];
uint32_t		numflows;
int32_t 		i, order_index, order_bit;
char			*string;

	FlowTable = GetFlowTable();
	numflows = 0;
	for ( i=0; i<NumOrders; i++ ) {
		topN_flow_list[i] = (SortElement_t *)calloc(topN, sizeof(SortElement_t));
		if ( !topN_flow_list[i] ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return;
		}
	}

	Create_topN_FlowStat(topN_flow_list, flow_stat_order , topN, &numflows);
	if ( !(quiet || cvs_output) ) 
		printf("Aggregated flows %u\n", numflows);

	for ( order_index=0; order_index<NumOrders; order_index++ ) {
		order_bit = 1 << order_index;
		if ( flow_stat_order & order_bit ) {
			if ( !( quiet || cvs_output) ) 
				printf("Top %i flows ordered by %s:\n", topN, order_mode[order_index].string);
			if ( !quiet && record_header ) 
				printf("%s\n", record_header);
			for ( i=topN-1; i>=0; i--) {
				FlowTableRecord_t	*r;
				master_record_t		flow_record;
				common_record_t 	*raw_record;
				int map_id;

				if ( !topN_flow_list[order_index][i].count )
					break;

				r = (FlowTableRecord_t *)topN_flow_list[order_index][i].record;
				raw_record = &(r->flowrecord);
				map_id = r->map_ref->map_id;

				ExpandRecord_v2( raw_record, extension_map_list.slot[map_id], &flow_record);
				flow_record.dPkts 		= r->counter[INPACKETS];
				flow_record.dOctets 	= r->counter[INBYTES];
				flow_record.out_pkts 	= r->counter[OUTPACKETS];
				flow_record.out_bytes 	= r->counter[OUTBYTES];
				flow_record.aggr_flows 	= r->counter[FLOWS];

				// apply IP mask from aggregation, to provide a pretty output
				if ( FlowTable->has_masks ) {
					flow_record.v6.srcaddr[0] &= FlowTable->IPmask[0];
					flow_record.v6.srcaddr[1] &= FlowTable->IPmask[1];
					flow_record.v6.dstaddr[0] &= FlowTable->IPmask[2];
					flow_record.v6.dstaddr[1] &= FlowTable->IPmask[3];
				}

				if ( FlowTable->apply_netbits )
					ApplyNetMaskBits(&flow_record, FlowTable->apply_netbits);

				print_record((void *)&flow_record, &string, tag);
				printf("%s\n", string);
			}
			printf("\n");
		}
	}

	// free memory
	for ( i=0; i<NumOrders; i++ ) {
		free((void *)topN_flow_list[i]);
	}

} // End of PrintFlowStat

void PrintElementStat(stat_record_t	*sum_stat, char *record_header, printer_t print_record, int topN, int tag, int quiet, int pipe_output, int cvs_output) {
SortElement_t	*topN_element_list;
uint32_t		numflows, maxindex;
int32_t 		i, j, hash_num, order_index, order_bit;

	numflows = 0;
	// for every requested -s stat do
	for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
		int stat   = StatRequest[hash_num].StatType;
		int order  = StatRequest[hash_num].order_bits;
		int	type = StatParameters[stat].type;
		for ( order_index=0; order_index<NumOrders; order_index++ ) {
			order_bit = 1 << order_index;
			if ( order & order_bit ) {
				topN_element_list = StatTopN(topN, &numflows, hash_num, order_index);

				// this output formating is pretty ugly - and needs to be cleaned up - improved
				if ( !pipe_output && !cvs_output && !quiet  ) {
					printf("Top %i %s ordered by %s:\n", 
						topN, StatParameters[stat].HeaderInfo, order_mode[order_index].string);
					//      2005-07-26 20:08:59.197 1553.730      ss    65255   203435   52.2 M      130   281636   268
					if ( Getv6Mode() && (type == IS_IPADDR )) 
						printf("Date first seen          Duration Proto %39s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      bps   bpp\n",
							StatParameters[stat].HeaderInfo);
					else
						printf("Date first seen          Duration Proto %17s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      bps   bpp\n",
							StatParameters[stat].HeaderInfo);
				}

				if ( cvs_output ) {
					printf("ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,pps,pbs,bpp\n");
				}

				maxindex = ( StatTable[hash_num].NextBlock * StatTable[hash_num].Prealloc ) + StatTable[hash_num].NextElem;
				j = numflows - topN;
				j = j < 0 ? 0 : j;
				if ( topN == 0 )
					j = 0;
				for ( i=numflows-1; i>=j ; i--) {
					if ( !topN_element_list[i].count )
						break;

					// Again - ugly output formating - needs to be cleand up
					if ( pipe_output ) 
						PrintPipeStatLine((StatRecord_t *)topN_element_list[i].record, type, 
							StatRequest[hash_num].order_proto, tag);
					else if ( cvs_output ) 
						PrintCvsStatLine(sum_stat, (StatRecord_t *)topN_element_list[i].record, type, 
							StatRequest[hash_num].order_proto, tag);
					else
						PrintStatLine(sum_stat, (StatRecord_t *)topN_element_list[i].record, 
							type, StatRequest[hash_num].order_proto, tag);
				}
				free((void *)topN_element_list);
				printf("\n");
			}
		} // for every requested order
	} // for every requested -s stat do
} // End of PrintElementStat

/*
 * Generate the top N lists for packets and bytes in one run
 */
static void Create_topN_FlowStat(SortElement_t **topN_lists, int order, int topN, uint32_t *count ) {
hash_FlowTable *FlowTable;
FlowTableRecord_t	*r;
unsigned int		i;
int					order_bit, order_index;
uint64_t	   		c, value;

	FlowTable = GetFlowTable();
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable->IndexMask; i++ ) {
		r = FlowTable->bucket[i];
		// foreach elem in this bucket
		while ( r ) {

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->counter[INBYTES] >= byte_limit ) ||
					( byte_mode == MORE && r->counter[INBYTES]  <= byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->counter[INPACKETS] >= packet_limit ) ||
					( packet_mode == MORE && r->counter[INPACKETS]  <= packet_limit ) ) {
					r = r->next;
					continue;
				}
			}

			c++;
			for ( order_index=0; order_index<NumOrders; order_index++ ) {
				order_bit = 1 << order_index;
				/* if we have some different sort orders, which are not directly available in the FlowTableRecord_t
				 * we need to calculate this value first - such as bpp, bps etc.
				 */
				if ( order & order_bit ) {
					if ( order_mode[order_index].record_function ) 
						value  = order_mode[order_index].record_function(r);
					else
						value  = r->counter[order_index];
					RankValue(r, value, topN, topN_lists[order_index]);
				}
			}

			// next elem in bucket
			r = r->next;
		} // foreach element
	}
	*count = c;

} // End of Create_topN_FlowStat

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order ) {
SortElement_t 		*topN_list;
StatRecord_t		*r;
unsigned int		i;
uint32_t	   		c, maxindex;

	maxindex  = ( StatTable[hash_num].NextBlock * StatTable[hash_num].Prealloc ) + StatTable[hash_num].NextElem;
	topN_list = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

	if ( !topN_list ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_list table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= StatTable[hash_num].IndexMask; i++ ) {
		r = StatTable[hash_num].bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->counter[INBYTES] >= byte_limit ) ||
					( byte_mode == MORE && r->counter[INBYTES]  <= byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->counter[INPACKETS] >= packet_limit ) ||
					( packet_mode == MORE && r->counter[INPACKETS]  <= packet_limit ) ) {
					r = r->next;
					continue;
				}
			}

			if ( order_mode[order].element_function ) 
				topN_list[c].count  = order_mode[order].element_function(r);
			else
				topN_list[c].count  = r->counter[order];

			topN_list[c].record = (void *)r;
			r = r->next;
			c++;
		} // foreach element
	}
	*count = c;
	// printf ("Sort %u flows\n", c);
	
	/*
	for ( i = 0; i < maxindex; i++ ) 
		printf("%i, %llu %llu\n", i, topN_list[i].count, topN_list[i].record);
	*/

	// Sorting makes only sense, when 2 or more flows are left
	if ( c >= 2 )
 		heapSort(topN_list, c, topN);

	/*
	for ( i = 0; i < maxindex; i++ ) 
		printf("%i, %llu %llu\n", i, topN_list[i].count, topN_list[i].record);
	*/

	return topN_list;
	
} // End of StatTopN


static inline void RankValue(FlowTableRecord_t *r, uint64_t val, int topN, SortElement_t *topN_list) {
FlowTableRecord_t	*r1, *r2;
uint64_t	   		c1, c2;
int					j;


	if ( val >= (topN_list)[0].count ) {
		/* element value is bigger than smallest value in topN */
		c1 = val;
		r1 = r;
		for (j=topN-1; j>=0; j-- ) {
			if ( c1 >= topN_list[j].count ) {
				c2 = topN_list[j].count;
				r2 = topN_list[j].record;
				topN_list[j].count 	= c1;
				topN_list[j].record	= r1;
				c1 = c2; r1 = r2;
			}
		}
	} 

} // End of RankValue

static void SwapFlow(master_record_t *flow_record) {
uint64_t _tmp_ip[2];
uint64_t _tmp_l;
uint32_t _tmp;

	_tmp_ip[0] = flow_record->v6.srcaddr[0];
	_tmp_ip[1] = flow_record->v6.srcaddr[1];
	flow_record->v6.srcaddr[0] = flow_record->v6.dstaddr[0];
	flow_record->v6.srcaddr[1] = flow_record->v6.dstaddr[1];
	flow_record->v6.dstaddr[0] = _tmp_ip[0];
	flow_record->v6.dstaddr[1] = _tmp_ip[1];

	_tmp = flow_record->srcport;
	flow_record->srcport = flow_record->dstport;
	flow_record->dstport = _tmp;

	_tmp = flow_record->srcas;
	flow_record->srcas = flow_record->dstas;
	flow_record->dstas = _tmp;

	_tmp = flow_record->input;
	flow_record->input = flow_record->output;
	flow_record->output = _tmp;

	_tmp_l = flow_record->dPkts;
	flow_record->dPkts = flow_record->out_pkts;
	flow_record->out_pkts = _tmp_l;

	_tmp_l = flow_record->dOctets;
	flow_record->dOctets = flow_record->out_bytes;
	flow_record->out_bytes = _tmp_l;

} // End of SwapFlow
