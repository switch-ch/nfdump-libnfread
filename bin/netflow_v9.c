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
 *  $Id: netflow_v9.c 55 2010-02-02 16:02:58Z haag $
 *
 *  $LastChangedRevision: 55 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nfnet.h"
#include "nf_common.h"
#include "util.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

// a few handy macros
#define GET_FLOWSET_ID(p) 	  (Get_val16(p))
#define GET_FLOWSET_LENGTH(p) (Get_val16((void *)((p) + 2)))

#define GET_TEMPLATE_ID(p) 	  (Get_val16(p))
#define GET_TEMPLATE_COUNT(p) (Get_val16((void *)((p) + 2)))

#define GET_OPTION_TEMPLATE_ID(p) 	  		  		 (Get_val16(p))
#define GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(p)   (Get_val16((void *)((p) + 2)))
#define GET_OPTION_TEMPLATE_OPTION_LENGTH(p)   		 (Get_val16((void *)((p) + 4)))

#include "inline.c"

extern int verbose;
extern extension_descriptor_t extension_descriptor[];
extern uint32_t Max_num_extensions;
extern uint32_t default_sampling;
extern uint32_t overwrite_sampling;

typedef struct translation_element_s {
	uint16_t	input_offset;
	uint16_t	output_offset;
	uint16_t	length;
} translation_element_t;


typedef struct input_translation_s {
	struct input_translation_s	*next;
	uint32_t	flags;
	time_t		updated;
	uint32_t	id;
	uint32_t	input_record_size;
	uint32_t	output_record_size;
	uint32_t	input_index;
	uint32_t	zero_index;
	uint32_t	src_as_offset;
	uint32_t	dst_as_offset;
	uint32_t    packet_offset;
	uint32_t    byte_offset;
	uint32_t	ICMP_offset;
	uint32_t	sampler_offset;
	uint32_t	sampler_size;
	uint32_t	router_ip_offset;
	uint32_t	engine_offset;
	uint32_t	extension_map_changed;
	extension_info_t 	 extension_info;
	translation_element_t element[];
} input_translation_t;

typedef struct exporter_domain_s {
	struct exporter_domain_s	*next;

	// identifier
	uint32_t 	version;		// make sure it's a version 9 exporter 
	uint32_t	exporter_id;
	ip_addr_t	ip;
	uint32_t	sa_family;

	// exporter parameters
	uint64_t	boot_time;
	// sequence
	int64_t		last_sequence;
	int64_t		sequence;
	int			first;
	input_translation_t	*input_translation_table; 
	input_translation_t *current_table;
} exporter_domain_t;

/* module limited globals */
static struct element_info_s {
	// min number of bytes
	uint16_t	min;
	// max number of bytes
	uint16_t	max;
	// number of optional extension.
	// required extensions and v9 tags not mapping to any extension are set to 0
	// this field is used to form the extension map
	uint16_t	extension;
} element_info[128] = {
	{ 0, 0, 0 }, 	//  0 - empty
	{ 8, 8, 0 }, 	//  1 - NF9_IN_BYTES
	{ 8, 8, 0 }, 	//  2 - NF9_IN_PACKETS
	{ 4, 8, 18 }, 	//  3 - NF9_FLOWS
	{ 1, 1, 0 }, 	//  4 - NF9_IN_PROTOCOL
	{ 1, 1, 0 },	//  5 - NF9_SRC_TOS
	{ 1, 1, 0 },	//  6 - NF9_TCP_FLAGS
	{ 2, 2, 0 },	//  7 - NF9_L4_SRC_PORT
	{ 4, 4, 0 },	//  8 - NF9_IPV4_SRC_ADDR
	{ 1, 1, 8 },	//  9 - NF9_SRC_MASK
	{ 2, 4, 4 },	// 10 - NF9_INPUT_SNMP
	{ 2, 2, 0 },	// 11 - NF9_L4_DST_PORT
	{ 4, 4, 0 },	// 12 - NF9_IPV4_DST_ADDR
	{ 1, 1, 8 },	// 13 - NF9_DST_MASK
	{ 2, 4, 4 },	// 14 - NF9_OUTPUT_SNMP
	{ 4, 4, 9 },	// 15 - NF9_IPV4_NEXT_HOP
	{ 2, 4, 6 },	// 16 - NF9_SRC_AS
	{ 2, 4, 6 },	// 17 - NF9_DST_AS

	{ 4, 4, 11}, 	// 18 - NF9_BGP_V4_NEXT_HOP

	// 19 - 20 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, 				

	{ 4, 4, 0 },	// 21 - NF9_LAST_SWITCHED
	{ 4, 4, 0 },	// 22 - NF9_FIRST_SWITCHED
	{ 4, 8, 16 },	// 23 - NF9_OUT_BYTES
	{ 4, 8, 14 },	// 24 - NF9_OUT_PKTS

	{ 0, 0, 0}, { 0, 0, 0}, 					// 25 - 26 not implemented

	{ 16, 16, 0 },	// 27 - NF9_IPV6_SRC_ADDR
	{ 16, 16, 0 },	// 28 - NF9_IPV6_DST_ADDR
	{ 1, 1, 8 },	// 29 - NF9_IPV6_SRC_MASK
	{ 1, 1, 8 },	// 30 - NF9_IPV6_DST_MASK
	{ 4, 4, 0 },	// 31 - NF9_IPV6_FLOW_LABEL
	{ 2, 2, 0 },	// 32 - NF9_ICMP_TYPE

	{ 0, 0, 0},		// 33 - not implemented

	{ 4, 4, 0}, 	// 34 - NF9_SAMPLING_INTERVAL
	{ 1, 1, 0}, 	// 35 - NF9_SAMPLING_ALGORITHM

	{ 0, 0, 0}, { 0, 0, 0}, // 36 - 37 not implemented

	{ 1, 1, EX_ROUTER_ID },	// 38 - NF9_ENGINE_TYPE
	{ 1, 1, EX_ROUTER_ID },	// 39 - NF9_ENGINE_ID

	// 40 - 47   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 
	
	{ 1, 2, 0}, 	// 48 - NF9_FLOW_SAMPLER_ID
	{ 1, 1, 0}, 	// 49 - FLOW_SAMPLER_MODE
	{ 4, 4, 0}, 	// 50 - NF9_FLOW_SAMPLER_RANDOM_INTERVAL

	// 51 - 54 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	{ 1, 1, 8 }, 	// 55 - NF9_DST_TOS

	// 56 - 57   MACs
	{ 8, 8, 20}, 	// 56 NF9_IN_SRC_MAC
	{ 8, 8, 20}, 	// 57 NF9_OUT_DST_MAC

	{ 2, 2, 13}, 	// 58 - NF9_SRC_VLAN
	{ 2, 2, 13}, 	// 59 - NF9_DST_VLAN

	// 60   not implemented
	{ 0, 0, 0}, 

	{ 1, 1, 8 }, 	// 61 - NF9_DIRECTION

	{ 16, 16, 10}, 	// 62 - NF9_V6_NEXT_HOP
	{ 16, 16, 12}, 	// 63 - NF9_BPG_V6_NEXT_HOP

	// 64 - 69   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	// 70
	{ 4, 4, 22}, 	// 70 - MPLS_LABEL_1
	{ 4, 4, 22}, 	// 71 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 72 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 73 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 74 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 75 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 76 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 77 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 78 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 79 - MPLS_LABEL_2

	// 80 - 81   MACs
	{ 8, 8, 21}, 	// 80 NF9_IN_DST_MAC
	{ 8, 8, 21}, 	// 81 NF9_OUT_SRC_MAC

	// 82 - 87   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 
	// 88 not implemented
	{ 0, 0, 0}, 

	{ 1, 1, 0 }, 	// 89 - NF9_FORWARDING_STATUS

	// 90 - 95   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 
	// 96 - 103  not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 
	// 104 - 111 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 
	// 112 - 119 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 
	// 120 - 127 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}  

};

uint32_t Max_num_v9_tags;

typedef struct output_templates_s {
	struct output_templates_s 	*next;
	uint32_t			flags;
	extension_map_t		*extension_map;		// extension map;
	time_t				time_sent;
	uint32_t			record_length;		// length of the data record resulting from this template
	uint32_t			flowset_length;		// length of the flowset record
	template_flowset_t *template_flowset;
} output_template_t;

#define MAX_LIFETIME 60

static output_template_t	*output_templates;
static uint64_t	boot_time;	// in msec
static uint16_t				template_id;

static uint32_t	processed_records;

/* local function prototypes */
static inline uint16_t CheckElementLength(int element, uint16_t in_length);

static inline void FillElement(input_translation_t *table, int element, uint32_t *offset);

static inline void Process_v9_templates(exporter_domain_t *exporter, void *template_flowset, FlowSource_t *fs);

static inline void Process_v9_option_templates(exporter_domain_t *exporter, void *option_template_flowset, FlowSource_t *fs);

static inline void Process_v9_data(exporter_domain_t *exporter, void *data_flowset, FlowSource_t *fs, input_translation_t *table );

static inline void Process_v9_option_data(exporter_domain_t *exporter, void *data_flowset, FlowSource_t *fs);

static inline exporter_domain_t *GetExporter(FlowSource_t *fs, uint32_t exporter_id);

static inline input_translation_t *GetTranslationTable(exporter_domain_t *exporter, uint16_t id);

static input_translation_t *setup_translation_table (exporter_domain_t *exporter, uint16_t id, uint16_t input_record_size);

static input_translation_t *add_translation_table(exporter_domain_t *exporter, uint16_t id);

static output_template_t *GetOutputTemplate(uint32_t flags, extension_map_t *extension_map);

static void Append_Record(send_peer_t *peer, master_record_t *master_record);

static uint16_t	Get_val16(void *p);

static uint32_t	Get_val32(void *p);

static uint64_t	Get_val64(void *p);

/* local variables */

// template processing
static struct input_table_s {
	uint16_t	offset;
	uint16_t	length;
} input_template[128];

/* 
 * tmp cache while processing template records
 * array index = extension id, 
 * value = 1 -> extension exists, 0 -> extension does not exists
 */
static uint32_t	*map_table;


// for sending netflow v9
static netflow_v9_header_t	*v9_output_header;

/* functions */

#include "nffile_inline.c"

int Init_v9(void) {
int i;
output_templates = NULL;
template_id	 	 = NF9_MIN_RECORD_FLOWSET_ID;

	// set the max number of v9 tags, we support.
	Max_num_v9_tags = 0;
	for (i=0; i<128; i++) {
		if ( element_info[i].min )
			Max_num_v9_tags++;
	}

	map_table = (uint32_t *)calloc((Max_num_extensions+1), sizeof(uint32_t));
	if ( !map_table ) {
		syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return 0;
	}
	syslog(LOG_DEBUG,"Init v9: Recognised number of v9 tags: %u", Max_num_v9_tags);


	return 1;
	
} // End of Init_v9

static inline exporter_domain_t *GetExporter(FlowSource_t *fs, uint32_t exporter_id) {
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];
exporter_domain_t **e = (exporter_domain_t **)&(fs->exporter_data);

	while ( *e ) {
		if ( (*e)->exporter_id == exporter_id && (*e)->version == 9 && 
			 (*e)->ip.v6[0] == fs->ip.v6[0] && (*e)->ip.v6[1] == fs->ip.v6[1]) 
			return *e;
		e = &((*e)->next);
	}

	if ( fs->sa_family == AF_INET ) {
		uint32_t _ip = htonl(fs->ip.v4);
		inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
	} else if ( fs->sa_family == AF_INET6 ) {
		uint64_t _ip[2];
		_ip[0] = htonll(fs->ip.v6[0]);
		_ip[1] = htonll(fs->ip.v6[1]);
		inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
	} else {
		strncpy(ipstr, "<unknown>", IP_STRING_LEN);
	}

	dbg_printf("Process_v9: New exporter domain %u from: %s\n", exporter_id, ipstr);
	syslog(LOG_INFO, "Process_v9: New exporter domain %u from: %s\n", exporter_id, ipstr);

	// nothing found
	*e = (exporter_domain_t *)malloc(sizeof(exporter_domain_t));
	if ( !(*e)) {
		syslog(LOG_ERR, "Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_domain_t));
	(*e)->exporter_id 	= exporter_id;
	(*e)->ip.v6[0]		= fs->ip.v6[0];
	(*e)->ip.v6[1]		= fs->ip.v6[1];
	(*e)->sa_family		= fs->sa_family;
	(*e)->version 		= 9;
	(*e)->first	 		= 1;
	(*e)->next	 		= NULL;
	return (*e);

} // End of GetExporter

static inline input_translation_t *GetTranslationTable(exporter_domain_t *exporter, uint16_t id) {
input_translation_t *table;

	if ( exporter->current_table && ( exporter->current_table->id == id ) )
		return exporter->current_table;

	table = exporter->input_translation_table;
	while ( table ) {
		if ( table->id == id ) {
			exporter->current_table = table;
			return table;
		}

		table = table->next;
	}

	dbg_printf("[%u] Get translation table %u: %s\n", exporter->exporter_id, id, table == NULL ? "not found" : "found");

	exporter->current_table = table;
	return table;

} // End of GetTranslationTable

static input_translation_t *add_translation_table(exporter_domain_t *exporter, uint16_t id) {
input_translation_t **table;

	table = &(exporter->input_translation_table);
	while ( *table ) {
		table = &((*table)->next);
	}

	// Allocate enough space for all potential v9 tags, which we support
	// so template refreshing may change the table size without dange of overflowing 
	*table = malloc(sizeof(input_translation_t) + Max_num_v9_tags * sizeof(translation_element_t));
	if ( !(*table) ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}
	(*table)->id   = id;
	(*table)->next = NULL;

	dbg_printf("[%u] Get new translation table %u\n", exporter->exporter_id, id);

	return *table;

} // End of add_translation_table

static inline uint16_t CheckElementLength(int element, uint16_t in_length) {

	if ( in_length == 0 ) 
		return 0;
	if ( in_length <= element_info[element].min ) 
		return element_info[element].min;
	if ( in_length <= element_info[element].max ) 
		return element_info[element].max;

	return 0;

} // End of CheckElementLength


inline void FillElement(input_translation_t *table, int element, uint32_t *offset) {
uint16_t	output_length;
uint32_t	input_index = table->input_index;
uint32_t	zero_index  = table->zero_index;

	output_length = CheckElementLength(element, input_template[element].length);
	if ( output_length ) { 

		dbg_printf("Index: %u v9 id %i, Input Offset %u, Output Offset %u, ilen: %u, olen: %u\n", 
			input_index, element, input_template[element].offset, *offset, input_template[element].length, output_length);

		table->element[input_index].output_offset 	= *offset;
		table->element[input_index].input_offset 	= input_template[element].offset;
		table->element[input_index].length 			= input_template[element].length;
		(*offset)	+= output_length;
		table->input_index++;

		if ( input_template[element].length < output_length ) {

		}
	} else {

		dbg_printf("Zero: %u, v9: %i,  Output Offset %u, len: %u\n", 
			zero_index, element, *offset, element_info[element].min);

		table->element[zero_index].output_offset 	= *offset;
		table->element[zero_index].length 			= element_info[element].min;
		table->zero_index--;
		(*offset)	+= element_info[element].min;
	}

} // End of FillElement

static input_translation_t *setup_translation_table (exporter_domain_t *exporter, uint16_t id, uint16_t input_record_size) {
input_translation_t *table;
extension_map_t 	*extension_map;
uint32_t			i, ipv6, offset, next_extension;
size_t				size_required;

	ipv6 = 0;

	table = GetTranslationTable(exporter, id);
	if ( !table ) {
		syslog(LOG_INFO, "Process_v9: [%u] Add template %u", exporter->exporter_id, id);
		table = add_translation_table(exporter, id);
		if ( !table ) {
			return NULL;
		}
		// Add an extension map
		// The number of extensions for this template is currently unknown
		// Allocate enough space for all configured extensions - some may be unused later
		// make sure memory is 4byte alligned
		size_required = Max_num_extensions * sizeof(uint16_t) + sizeof(extension_map_t);
		size_required = (size_required + 3) &~(size_t)3;
		extension_map = malloc(size_required);
		if ( !extension_map ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return  NULL;
		}
		extension_map->type 	   = ExtensionMapType;
		// Set size to an empty tablee - will be adapted later
		extension_map->size 	   = sizeof(extension_map_t);
		extension_map->map_id 	   = INIT_ID;
		// packed record size still unknown at this point - will be added later
		extension_map->extension_size = 0;

		table->extension_info.map 	 = extension_map;
		table->extension_map_changed = 1;
 	} else {
		extension_map = table->extension_info.map;

		// reset size/extension size - it's refreshed automatically
		extension_map->size 	   	  = sizeof(extension_map_t);
		extension_map->extension_size = 0;

		dbg_printf("[%u] Refresh template %u\n", exporter->exporter_id, id);

		// very noisy with somee exporters
		// syslog(LOG_DEBUG, "Process_v9: [%u] Refresh template %u", exporter->exporter_id, id);
	}
	// clear current table
	memset((void *)table->element, 0, Max_num_v9_tags * sizeof(translation_element_t));
	table->updated  	= time(NULL);
	table->flags		= 0;
	table->ICMP_offset	= 0;
	table->sampler_offset 	= 0;
	table->sampler_size		= 0;
	table->engine_offset 	= 0;
	table->router_ip_offset = 0;

	dbg_printf("[%u] Fill translation table %u\n", exporter->exporter_id, id);

	// fill table
	table->id 			= id;
	table->input_index 	= 0;
	table->zero_index 	= Max_num_v9_tags - 1;

	/* 
	 * common data block: The common record is expected in the output stream. If not available
	 * in the template, fill values with 0
	 */

	// All required extensions
	offset = BYTE_OFFSET_first;
	FillElement( table, NF9_FIRST_SWITCHED, &offset);
	FillElement( table, NF9_LAST_SWITCHED, &offset);
	FillElement( table, NF9_FORWARDING_STATUS, &offset);
	FillElement( table, NF9_TCP_FLAGS, &offset);
	FillElement( table, NF9_IN_PROTOCOL, &offset);
	FillElement( table, NF9_SRC_TOS, &offset);
	FillElement( table, NF9_L4_SRC_PORT, &offset);
	FillElement( table, NF9_L4_DST_PORT, &offset);

	/* IP addresss record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty v4 address.
	 */
	if ( input_template[NF9_IPV4_SRC_ADDR].length ) {
		// IPv4 addresses 
		FillElement( table, NF9_IPV4_SRC_ADDR, &offset);
		FillElement( table, NF9_IPV4_DST_ADDR, &offset);
	} else if ( input_template[NF9_IPV6_SRC_ADDR].length == 16 ) {
		// IPv6 addresses 
		FillElement( table, NF9_IPV6_SRC_ADDR, &offset);
		FillElement( table, NF9_IPV6_DST_ADDR, &offset);
		// mark IPv6 
		table->flags	|= FLAG_IPV6_ADDR;
		ipv6 = 1;
	} else {
		// should not happen, assume empty IPv4 addresses
		FillElement( table, NF9_IPV4_SRC_ADDR, &offset);
		FillElement( table, NF9_IPV4_DST_ADDR, &offset);
	}

	/* packet counter
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty 4 bytes value
	 */
	if ( input_template[NF9_IN_PACKETS].length ) {
		table->packet_offset = offset;
		FillElement( table, NF9_IN_PACKETS, &offset);
		// fix: always have 64byte counters if ( input_template[NF9_IN_PACKETS].length == 8 )
		SetFlag(table->flags, FLAG_PKG_64);
	} else
		table->packet_offset = 0;

	/* byte record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty 4 bytes value
	 */
	if ( input_template[NF9_IN_BYTES].length ) {
		table->byte_offset = offset;
		FillElement( table, NF9_IN_BYTES, &offset);
		// fix: always have 64byte counters if ( input_template[NF9_IN_BYTES].length == 8 )
		SetFlag(table->flags, FLAG_BYTES_64);
	} else 
		table->byte_offset = 0;


	// Optional extensions
	next_extension = 0;
	for (i=4; i <= Max_num_extensions; i++ ) {
		uint32_t map_index = i;

		if ( map_table[i] == 0 )
			continue;

		switch(i) {
			case EX_IO_SNMP_2:
			case EX_IO_SNMP_4:
				// 2 byte length
				if ( input_template[NF9_INPUT_SNMP].length <= 2 || input_template[NF9_OUTPUT_SNMP].length <= 2) {
					FillElement( table, NF9_INPUT_SNMP, &offset);
					FillElement( table, NF9_OUTPUT_SNMP, &offset);
					map_index = EX_IO_SNMP_2;
				} else {
					FillElement( table, NF9_INPUT_SNMP, &offset);
					FillElement( table, NF9_OUTPUT_SNMP, &offset);
					map_index = EX_IO_SNMP_4;
				}
				break;
			case EX_AS_2:
			case EX_AS_4:
				if ( input_template[NF9_SRC_AS].length <= 2 || input_template[NF9_DST_AS].length <= 2) {
					table->src_as_offset = offset;
					FillElement( table, NF9_SRC_AS, &offset);
					table->dst_as_offset = offset;
					FillElement( table, NF9_DST_AS, &offset);
					map_index = EX_AS_2;
				} else {
					table->src_as_offset = offset;
					FillElement( table, NF9_SRC_AS, &offset);
					table->dst_as_offset = offset;
					FillElement( table, NF9_DST_AS, &offset);
					map_index = EX_AS_4;
				}
				break;
			case EX_MULIPLE:
				if ( ipv6 ) {
					// IPv6
					FillElement( table, NF9_DST_TOS, &offset);
					FillElement( table, NF9_DIRECTION, &offset);
					FillElement( table, NF9_IPV6_SRC_MASK, &offset);
					FillElement( table, NF9_IPV6_DST_MASK, &offset);
				} else {
					// IPv4
					FillElement( table, NF9_DST_TOS, &offset);
					FillElement( table, NF9_DIRECTION, &offset);
					FillElement( table, NF9_SRC_MASK, &offset);
					FillElement( table, NF9_DST_MASK, &offset);
				}
				break;
			case EX_NEXT_HOP_v4:
				FillElement( table, NF9_V4_NEXT_HOP, &offset);
				map_index = EX_NEXT_HOP_v4;
				break;
			case EX_NEXT_HOP_v6:
				FillElement( table, NF9_V6_NEXT_HOP, &offset);
				map_index = EX_NEXT_HOP_v6;
				table->flags	|= FLAG_IPV6_NH;
				break;
			case EX_NEXT_HOP_BGP_v4:
				FillElement( table, NF9_BGP_V4_NEXT_HOP, &offset);
				map_index = EX_NEXT_HOP_BGP_v4;
				break;
			case EX_NEXT_HOP_BGP_v6:
				FillElement( table, NF9_BPG_V6_NEXT_HOP, &offset);
				map_index = EX_NEXT_HOP_BGP_v6;
				table->flags	|= FLAG_IPV6_NHB;
				break;
			case EX_VLAN:
				FillElement( table, NF9_SRC_VLAN, &offset);
				FillElement( table, NF9_DST_VLAN, &offset);
				break;
			case EX_OUT_PKG_4:
			case EX_OUT_PKG_8:
				if ( input_template[NF9_OUT_PKTS].length <= 4 ) {
					FillElement( table, NF9_OUT_PKTS, &offset);
					map_index = EX_OUT_PKG_4;
				} else {
					FillElement( table, NF9_OUT_PKTS, &offset);
					map_index = EX_OUT_PKG_8;
				}
				break;
			case EX_OUT_BYTES_4:
			case EX_OUT_BYTES_8:
				if ( input_template[NF9_OUT_BYTES].length <= 4 ) {
					FillElement( table, NF9_OUT_BYTES, &offset);
					map_index = EX_OUT_BYTES_4;
				} else {
					FillElement( table, NF9_OUT_BYTES, &offset);
					map_index = EX_OUT_BYTES_8;
				}
				break;
			case EX_AGGR_FLOWS_4:
			case EX_AGGR_FLOWS_8:
				if ( input_template[NF9_FLOWS_AGGR].length <= 4 ) {
					FillElement( table, NF9_FLOWS_AGGR, &offset);
					map_index = EX_AGGR_FLOWS_4;
				} else {
					FillElement( table, NF9_FLOWS_AGGR, &offset);
					map_index = EX_AGGR_FLOWS_8;
				}
				break;
			case EX_MAC_1:
				FillElement( table, NF9_IN_SRC_MAC, &offset);
				FillElement( table, NF9_OUT_DST_MAC, &offset);
				break;
			case EX_MAC_2:
				FillElement( table, NF9_IN_DST_MAC, &offset);
				FillElement( table, NF9_OUT_SRC_MAC, &offset);
				break;
			case EX_MPLS:
				FillElement( table, NF9_MPLS_LABEL_1, &offset);
				FillElement( table, NF9_MPLS_LABEL_2, &offset);
				FillElement( table, NF9_MPLS_LABEL_3, &offset);
				FillElement( table, NF9_MPLS_LABEL_4, &offset);
				FillElement( table, NF9_MPLS_LABEL_5, &offset);
				FillElement( table, NF9_MPLS_LABEL_6, &offset);
				FillElement( table, NF9_MPLS_LABEL_7, &offset);
				FillElement( table, NF9_MPLS_LABEL_8, &offset);
				FillElement( table, NF9_MPLS_LABEL_9, &offset);
				FillElement( table, NF9_MPLS_LABEL_10, &offset);
				break;
			case EX_ROUTER_IP_v4:
			case EX_ROUTER_IP_v6:
				if ( exporter->sa_family == PF_INET6 ) {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv6: Offset: %u, olen: %u\n", offset, 16 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv6
					offset			 	   += 16;
					SetFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v6;
				} else {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv4: Offset: %u, olen: %u\n", offset, 4 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv4
					offset				   += 4;
					ClearFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v4;
				}
				break;
			case EX_ROUTER_ID:
				table->engine_offset = offset;
				dbg_printf("Engine offset: %u\n", offset);
				offset += 2;
				dbg_printf("Skip 2 unused bytes. Next offset: %u\n", offset);
				FillElement( table, NF9_ENGINE_TYPE, &offset);
				FillElement( table, NF9_ENGINE_ID, &offset);
				// unused fill element for 32bit alignment
				break;
		}
		extension_map->size += sizeof(uint16_t);
		extension_map->extension_size += extension_descriptor[map_index].size;

		// found extension in map_index must be the same as in map - otherwise map is dirty
		if ( extension_map->ex_id[next_extension] != map_index ) {
			// dirty map - needs to be refreshed in output stream
			extension_map->ex_id[next_extension] = map_index;
			table->extension_map_changed = 1;

		}
		next_extension++;

	}
	extension_map->ex_id[next_extension++] = 0;

	// make sure map is aligned
	if ( extension_map->size & 0x3 ) {
		extension_map->ex_id[next_extension] = 0;
		extension_map->size = ( extension_map->size + 3 ) &~ 0x3;
	}

	table->output_record_size = offset;
	table->input_record_size  = input_record_size;

	/* ICMP hack for v9  */
	if ( input_template[NF9_ICMP_TYPE].offset != 0 ) {
		if ( input_template[NF9_ICMP_TYPE].length == 2 ) 
			table->ICMP_offset = input_template[NF9_ICMP_TYPE].offset;
		else
			syslog(LOG_ERR, "Process_v9: Unexpected ICMP type field length: %d", 
				input_template[NF9_ICMP_TYPE].length);
	}

	/* Sampler ID */
	if ( input_template[NF9_FLOW_SAMPLER_ID].offset != 0 ) {
		if ( input_template[NF9_FLOW_SAMPLER_ID].length == 1 ) {
			table->sampler_offset = input_template[NF9_FLOW_SAMPLER_ID].offset;
			table->sampler_size = 1;
			dbg_printf("1 byte Sampling ID included at offset %u\n", table->sampler_offset);
		} else if ( input_template[NF9_FLOW_SAMPLER_ID].length == 2 ) {
			table->sampler_offset = input_template[NF9_FLOW_SAMPLER_ID].offset;
			table->sampler_size = 2;
			dbg_printf("2 byte Sampling ID included at offset %u\n", table->sampler_offset);
		}  else {
			syslog(LOG_ERR, "Process_v9: Unexpected SAMPLER ID field length: %d", 
				input_template[NF9_FLOW_SAMPLER_ID].length);
			dbg_printf("Unexpected SAMPLER ID field length: %d", 
				input_template[NF9_FLOW_SAMPLER_ID].length);

		}
	} else {
		dbg_printf("No Sampling ID found\n");
	}

#ifdef DEVEL
	if ( table->extension_map_changed ) {
		printf("Extension Map id=%u changed!\n", extension_map->map_id);
	} else {
		printf("[%u] template %u unchanged\n", exporter->exporter_id, id);
	}

	printf("Table %u Flags: %u, index: %u, Zero: %u input_size: %u, output_size: %u\n", 
		table->id, table->flags, table->input_index, table->zero_index, table->input_record_size, table->output_record_size);

	printf("Process_v9: Check extension map: id: %d, size: %u, extension_size: %u\n", 
		extension_map->map_id, extension_map->size, extension_map->extension_size);
#endif

	return table;

} // End of setup_translation_table

static inline void Process_v9_templates(exporter_domain_t *exporter, void *template_flowset, FlowSource_t *fs) {
void				*template;
input_translation_t *translation_table;
uint16_t	id, count, field_type, field_length, offset;
uint32_t	size_left, template_size, num_extensions, num_v9tags;
int			i;

	size_left = GET_FLOWSET_LENGTH(template_flowset) - 4; // -4 for flowset header -> id and length
	template  = template_flowset + 4;					  // the template description begins at offset 4

	// process all templates in flowset, as long as any bytes are left
	template_size = 0;
	while (size_left) {
		void *p;
		template = template + template_size;

		id 	  = GET_TEMPLATE_ID(template);
		count = GET_TEMPLATE_COUNT(template);
		template_size = 4 + 4 * count;	// id + count = 4 bytes, and 2 x 2 bytes for each entry

		dbg_printf("\n[%u] Template ID: %u\n", exporter->exporter_id, id);
		dbg_printf("template size: %u buffersize: %u\n", template_size, size_left);

		if ( size_left < template_size ) {
			syslog(LOG_ERR, "Process_v9: [%u] buffer size error: expected %u available %u", 
				exporter->exporter_id, template_size, size_left);
			size_left = 0;
			continue;
		}

		offset = 0;
		num_extensions = 0;		// number of extensions
		num_v9tags = 0;			// number of optional v9 tags 
		memset((void *)&input_template, 0, sizeof(input_template));
		memset((void *)map_table, 0, (Max_num_extensions+1) * sizeof(uint32_t));

		p = template + 4;		// type/length pairs start at template offset 4
		for(i=0; i<count; i++ ) {
			uint32_t ext_id;
			field_type   = Get_val16(p); p = p + 2;
			field_length = Get_val16(p); p = p + 2;


			// make sure field < 128
			if ( field_type > 127 ) {
				offset += field_length;
				syslog(LOG_ERR, "Process_v9: [%u] field ID > 128 - field ignored. ", exporter->exporter_id );
				dbg_printf("Type: %u, Length %u => Skipped.\n", field_type, field_length);
				continue; 
			}

			input_template[field_type].offset = offset;
			input_template[field_type].length = field_length;
			num_v9tags++;

			// map v9 tag to extension id - if != 0 then when we support it.
			ext_id = element_info[field_type].extension;

			// do we store this extension? enabled != 0
			// more than 1 v9 tag may map to an extension - so count this extension once only
			if ( ext_id && extension_descriptor[ext_id].enabled ) {
				dbg_printf("Type: %u, Length %u => Extension: %u\n", field_type, field_length, ext_id);
				if ( map_table[ext_id] == 0 ) {
					map_table[ext_id] = 1;
					num_extensions++;
				}
			} else {
				dbg_printf("Type: %u, Length %u\n", field_type, field_length);
			}
			offset += field_length;
		}

		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_IP_v4].enabled ) {
			if ( map_table[EX_ROUTER_IP_v4] == 0 ) {
				map_table[EX_ROUTER_IP_v4] = 1;
				num_extensions++;
			}
			dbg_printf("Add sending router IP address (%s) => Extension: %u\n", 
				fs->sa_family == PF_INET6 ? "ipv6" : "ipv4", EX_ROUTER_IP_v4);
		}
	
		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_ID].enabled ) {
			if ( map_table[EX_ROUTER_ID] == 0 ) {
				map_table[EX_ROUTER_ID] = 1;
				num_extensions++;
			}
			dbg_printf("Force add router ID (engine type/ID), Extension: %u\n", EX_ROUTER_ID);
		}
	
		dbg_printf("Parsed %u v9 tags, total %u extensions\n", num_v9tags, num_extensions);

		translation_table = setup_translation_table(exporter, id, offset);
		if (translation_table->extension_map_changed ) {
			translation_table->extension_map_changed = 0;
			// refresh he map in the ouput buffer
			dbg_printf("Translation Table changed! Add extension map ID: %i\n", translation_table->extension_info.map->map_id);
			AddExtensionMap(fs, translation_table->extension_info.map);
			dbg_printf("Translation Table added! map ID: %i\n", translation_table->extension_info.map->map_id);
		}
		size_left -= template_size;
		processed_records++;

		dbg_printf("\n");

	} // End of while size_left

} // End of Process_v9_templates

static inline void Process_v9_option_templates(exporter_domain_t *exporter, void *option_template_flowset, FlowSource_t *fs) {
void		*option_template, *p;
uint32_t	size_left, nr_scopes, nr_options, i;
uint16_t	id, scope_length, option_length, offset, sampler_id_length;
uint16_t	offset_sampler_id, offset_sampler_mode, offset_sampler_interval, found_sampler;
uint16_t	offset_std_sampler_interval, offset_std_sampler_algorithm, found_std_sampling;

	i = 0;	// keep compiler happy
	size_left 		= GET_FLOWSET_LENGTH(option_template_flowset) - 4; // -4 for flowset header -> id and length
	option_template = option_template_flowset + 4;
	id 	  			= GET_OPTION_TEMPLATE_ID(option_template); 
	scope_length 	= GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(option_template);
	option_length 	= GET_OPTION_TEMPLATE_OPTION_LENGTH(option_template);

	if ( scope_length & 0x3 ) {
		syslog(LOG_ERR, "Process_v9: [%u] scope length error: length %u not multiple of 4", 
			exporter->exporter_id, scope_length);
		return;
	}

	if ( option_length & 0x3 ) {
		syslog(LOG_ERR, "Process_v9: [%u] option length error: length %u not multiple of 4", 
			exporter->exporter_id, option_length);
		return;
	}

	if ( (scope_length + option_length) > size_left ) {
		syslog(LOG_ERR, "Process_v9: [%u] option template length error: size left %u too small for %u scopes length and %u options length", 
			exporter->exporter_id, size_left, scope_length, option_length);
		return;
	}

	nr_scopes  = scope_length >> 2;
	nr_options = option_length >> 2;

	dbg_printf("\n[%u] Option Template ID: %u\n", exporter->exporter_id, id);
	dbg_printf("Scope length: %u Option length: %u\n", scope_length, option_length);

	sampler_id_length			 = 0;
	offset_sampler_id 			 = 0;
	offset_sampler_mode 		 = 0;
	offset_sampler_interval 	 = 0;
	offset_std_sampler_interval  = 0;
	offset_std_sampler_algorithm = 0;
	found_sampler				 = 0;
	found_std_sampling			 = 0;
	offset = 0;

	p = option_template + 6;	// start of length/type data
	for ( i=0; i<nr_scopes; i++ ) {
#ifdef DEVEL
		uint16_t type 	= Get_val16(p);
#endif
		p = p + 2;

		uint16_t length = Get_val16(p); p = p + 2;
		offset += length;
		dbg_printf("Scope field Type: %u, length %u\n", type, length);
	}

	for ( ; i<(nr_scopes+nr_options); i++ ) {
		uint16_t type 	= Get_val16(p); p = p + 2;
		uint16_t length = Get_val16(p); p = p + 2;
		dbg_printf("Option field Type: %u, length %u\n", type, length);
		if ( element_info[type].min && CheckElementLength(type, length) == 0 ) {
			syslog(LOG_ERR,"Process_v9: Option field Type: %u, length %u not supported\n", type, length);
			dbg_printf("Process_v9: Option field Type: %u, length %u not supported\n", type, length);
			continue;
		}
		switch (type) {
			// general sampling
			case NF9_SAMPLING_INTERVAL:
				offset_std_sampler_interval = offset;
				found_std_sampling++;
				break;
			case NF9_SAMPLING_ALGORITHM:
				offset_std_sampler_algorithm = offset;
				found_std_sampling++;
				break;

			// individual samplers
			case NF9_FLOW_SAMPLER_ID:
				offset_sampler_id = offset;
				sampler_id_length = length;
				found_sampler++;
				break;
			case FLOW_SAMPLER_MODE:
				offset_sampler_mode = offset;
				found_sampler++;
				break;
			case NF9_FLOW_SAMPLER_RANDOM_INTERVAL:
				offset_sampler_interval = offset;
				found_sampler++;
				break;
		}
		offset += length;
	}

	if ( found_sampler == 3 ) { // need all three tags
		dbg_printf("[%u] Sampling information found\n", exporter->exporter_id);
		InsertSamplerOffset(fs, id, offset_sampler_id, sampler_id_length, offset_sampler_mode, offset_sampler_interval);
	} else if ( found_std_sampling == 2 ) { // need all two tags
		dbg_printf("[%u] Std sampling information found\n", exporter->exporter_id);
		InsertStdSamplerOffset(fs, id, offset_std_sampler_interval, offset_std_sampler_algorithm);
	} else {
		dbg_printf("[%u] No Sampling information found\n", exporter->exporter_id);
	}
	dbg_printf("\n");
	processed_records++;

} // End of Process_v9_option_templates


static inline void Process_v9_data(exporter_domain_t *exporter, void *data_flowset, FlowSource_t *fs, input_translation_t *table ){
uint64_t			start_time, end_time, packets, bytes, sampling_rate;
uint32_t			size_left, First, Last;
uint8_t				*in, *out;
int					i;
char				*string;

	size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length

	// map input buffer as a byte array
	in  	  = (uint8_t *)(data_flowset + 4);	// skip flowset header

	dbg_printf("[%u] Process data flowset size: %u\n", exporter->exporter_id, size_left);

	// Check if sampling is announced
	if ( table->sampler_offset && fs->sampler  ) {
		uint32_t sampler_id;
		if ( table->sampler_size == 2 ) {
			sampler_id = Get_val16((void *)&in[table->sampler_offset]);
		} else {
			sampler_id = in[table->sampler_offset];
		}
		if ( fs->sampler[sampler_id] ) {
			sampling_rate = fs->sampler[sampler_id]->interval;
			dbg_printf("[%u] Sampling ID %u available\n", exporter->exporter_id, sampler_id);
			dbg_printf("[%u] Sampler_offset : %u\n", exporter->exporter_id, table->sampler_offset);
			dbg_printf("[%u] Sampler Data : %s\n", exporter->exporter_id, fs->sampler == NULL ? "not available" : "available");
			dbg_printf("[%u] Sampling rate: %llu\n", exporter->exporter_id, (long long unsigned)sampling_rate);
		} else {
			sampling_rate = default_sampling;
			dbg_printf("[%u] Sampling ID %u not (yet) available\n", exporter->exporter_id, sampler_id);
		}

	} else if ( fs->std_sampling.interval > 0 ) {
		sampling_rate = fs->std_sampling.interval;
		dbg_printf("[%u] Std sampling available for this flow source: Rate: %llu\n", exporter->exporter_id, (long long unsigned)sampling_rate);
	} else {
		sampling_rate = default_sampling;
		dbg_printf("[%u] No Sampling record found\n", exporter->exporter_id);
	}

	if ( overwrite_sampling > 0 )  {
		sampling_rate = overwrite_sampling;
		dbg_printf("[%u] Hard overwrite sampling rate: %llu\n", exporter->exporter_id, (long long unsigned)sampling_rate);
	} 

	if ( sampling_rate != 1 )
		SetFlag(table->flags, FLAG_SAMPLED);

	while (size_left) {
		common_record_t		*data_record;

		if ( (size_left < table->input_record_size) ) {
			if ( size_left > 3 ) {
				syslog(LOG_WARNING,"Process_v9: Corrupt data flowset? Pad bytes: %u", size_left);
				dbg_printf("Process_v9: Corrupt data flowset? Pad bytes: %u, table record_size: %u\n", 
					size_left, table->input_record_size);
			}
			size_left = 0;
			continue;
		}

		// check for enough space in output buffer
		if ( !CheckBufferSpace(fs->nffile, table->output_record_size) ) {
			// this should really never occur, because the buffer gets flushed ealier
			syslog(LOG_ERR,"Process_v9: output buffer size error. Abort v9 record processing");
			dbg_printf("Process_v9: output buffer size error. Abort v9 record processing");
			return;
		}
		processed_records++;

		// map file record to output buffer
		data_record	= (common_record_t *)fs->nffile->buff_ptr;
		// map output buffer as a byte array
		out 	  = (uint8_t *)data_record;

		dbg_printf("[%u] Process data record: %u addr: %llu, in record size: %u, buffer size_left: %u\n", 
			exporter->exporter_id, processed_records, (long long unsigned)((ptrdiff_t)in - (ptrdiff_t)data_flowset), 
			table->input_record_size, size_left);

		// fill the data record
		data_record->flags 		  = table->flags;
		data_record->size  		  = table->output_record_size;
		data_record->type  		  = CommonRecordType;
	  	data_record->ext_map	  = table->extension_info.map->map_id;
		data_record->exporter_ref = 0;

		// pop up the table to fill the data record
		for ( i=0; i<table->input_index; i++ ) {
			int input_offset  = table->element[i].input_offset;
			int output_offset = table->element[i].output_offset;
			switch ( table->element[i].length ) {
				case 1:
					out[output_offset] = in[input_offset];
					break;
				case 2:
					*((uint16_t *)&out[output_offset]) = Get_val16((void *)&in[input_offset]);
					break;
				case 3:
					*((uint32_t *)&out[output_offset]) = Get_val24((void *)&in[input_offset]);
					break;
				case 4: {
					if ( output_offset == table->packet_offset || output_offset == table->byte_offset ) {
						// although bayte and packets are 4 bytes only, we store 8 bytes, as sampling
						// may overflow 4 bytes. this is a tmp fix.
						type_mask_t t;
						t.val.val64 = (uint64_t)Get_val32((void *)&in[input_offset]);
						t.val.val64 *= sampling_rate;

						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} else {
						uint32_t p = Get_val32((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) = p;
					}
					} break;
				case 5:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val40((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case 6:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val48((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case 7:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val56((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case 8:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val64 = Get_val64((void *)&in[input_offset]);

						if ( output_offset == table->packet_offset || output_offset == table->byte_offset )
							t.val.val64 *= sampling_rate;


						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case 16:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
					  
						t.val.val64 = Get_val64((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4])  = t.val.val32[1];

						t.val.val64 = Get_val64((void *)&in[input_offset+8]);
						*((uint32_t *)&out[output_offset+8])  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+12]) = t.val.val32[1];
					}
					break;
				default:
					memcpy((void *)&out[output_offset], (void *)&in[input_offset], table->element[i].length);
			}
		} // End for

		// pop down the table to zero unavailable elements
		for ( i = Max_num_v9_tags - 1; i > table->zero_index; i-- ) {
			int output_offset 	= table->element[i].output_offset;
			switch ( table->element[i].length ) {
				case 1:
					out[output_offset] = 0;
					break;
				case 2:
					*((uint16_t *)&out[output_offset]) = 0;
					break;
				case 4:
					*((uint32_t *)&out[output_offset]) = 0;
					break;
				case 8:
					*((uint64_t *)&out[output_offset]) = 0;
					break;
				case 16:
					memset((void *)&out[output_offset], 0, 16);
					break;
				default:
					memset((void *)&out[output_offset], 0, table->element[i].length);
			}
		} // End for


		// Ungly ICMP hack for v9, because some IOS version are lazzy
		// most of them send ICMP in dst port field some don't some have both
		if ( data_record->prot == IPPROTO_ICMP || data_record->prot == IPPROTO_ICMPV6 ) {
			if ( table->ICMP_offset ) {
				data_record->dstport = Get_val16((void *)&in[table->ICMP_offset]);
			}
			if ( data_record->dstport == 0 && data_record->srcport != 0 ) {
				// some IOSes are even lazzier and map ICMP code in src port - ughh
				data_record->dstport = data_record->srcport;
				data_record->srcport = 0;
			}
		}

		First = data_record->first;
		Last  = data_record->last;

		if ( First > Last )
			/* First in msec, in case of msec overflow, between start and end */
			start_time = exporter->boot_time - 0x100000000LL + (uint64_t)First;
		else
			start_time = (uint64_t)First + exporter->boot_time;

		/* end time in msecs */
		end_time = (uint64_t)Last + exporter->boot_time;

		data_record->first 		= start_time/1000;
		data_record->msec_first	= start_time - data_record->first*1000;
	
		data_record->last 		= end_time/1000;
		data_record->msec_last	= end_time - data_record->last*1000;

		if ( data_record->first == 0 && data_record->last == 0 )
			data_record->last = 0;

		// update first_seen, last_seen
		if ( start_time < fs->first_seen )
			fs->first_seen = start_time;
		if ( end_time > fs->last_seen )
			fs->last_seen = end_time;

		// Update stats
		if ( table->packet_offset ) {
			if ( (data_record->flags & FLAG_PKG_64 ) == 0 ) // 32bit packet counter
				packets = *((uint32_t *)&(out[table->packet_offset]));
			else {
				/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
				value64_t	v;
				uint32_t	*ptr = (uint32_t *)&(out[table->packet_offset]);

				v.val.val32[0] = ptr[0];
				v.val.val32[1] = ptr[1];
				packets = v.val.val64;
			}
		} else
			packets = 0;

		if ( table->byte_offset ) {
			if ( (data_record->flags & FLAG_BYTES_64 ) == 0 ) // 32bit byte counter
				bytes = *((uint32_t *)&(out[table->byte_offset]));
			else {
				/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
				value64_t	v;
				uint32_t	*ptr = (uint32_t *)&(out[table->byte_offset]);

				v.val.val32[0] = ptr[0];
				v.val.val32[1] = ptr[1];
				bytes = v.val.val64;
			}
		} else
			bytes = 0;
		
		// check if we need to record the router IP address
		if ( table->router_ip_offset ) {
			int output_offset = table->router_ip_offset;
			if ( exporter->sa_family == PF_INET6 ) {
				/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
				type_mask_t t;
					  
				t.val.val64 = exporter->ip.v6[0];
				*((uint32_t *)&out[output_offset]) 	  = t.val.val32[0];
				*((uint32_t *)&out[output_offset+4])  = t.val.val32[1];

				t.val.val64 = exporter->ip.v6[1];
				*((uint32_t *)&out[output_offset+8])  = t.val.val32[0];
				*((uint32_t *)&out[output_offset+12]) = t.val.val32[1];
			} else {
				*((uint32_t *)&out[output_offset]) = exporter->ip.v4;
			}
		}

		// Ugly hack. CISCO never really implemented #38/#39 tags in the records - so take it from the 
		// header, unless some data is filled in
		if ( table->engine_offset ) {
			if ( *((uint32_t *)&out[table->engine_offset]) == 0 ) {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)&out[table->engine_offset];
				tpl->engine_type = ( exporter->exporter_id >> 8 ) & 0xFF;
				tpl->engine_id	 = exporter->exporter_id & 0xFF;
			}
		}

		switch (data_record->prot ) { // switch protocol of
			case IPPROTO_ICMP:
				fs->nffile->stat_record->numflows_icmp++;
				fs->nffile->stat_record->numpackets_icmp  += packets;
				fs->nffile->stat_record->numbytes_icmp    += bytes;
				break;
			case IPPROTO_TCP:
				fs->nffile->stat_record->numflows_tcp++;
				fs->nffile->stat_record->numpackets_tcp   += packets;
				fs->nffile->stat_record->numbytes_tcp     += bytes;
				break;
			case IPPROTO_UDP:
				fs->nffile->stat_record->numflows_udp++;
				fs->nffile->stat_record->numpackets_udp   += packets;
				fs->nffile->stat_record->numbytes_udp     += bytes;
				break;
			default:
				fs->nffile->stat_record->numflows_other++;
				fs->nffile->stat_record->numpackets_other += packets;
				fs->nffile->stat_record->numbytes_other   += bytes;
		}
		fs->nffile->stat_record->numflows++;
		fs->nffile->stat_record->numpackets	+= packets;
		fs->nffile->stat_record->numbytes	+= bytes;
	
		if ( fs->xstat ) {
			uint32_t bpp = packets ? bytes/packets : 0;
			if ( bpp > MAX_BPP ) 
				bpp = MAX_BPP;
			if ( data_record->prot == IPPROTO_TCP ) {
				fs->xstat->bpp_histogram->tcp.bpp[bpp]++;
				fs->xstat->bpp_histogram->tcp.count++;

				fs->xstat->port_histogram->src_tcp.port[data_record->srcport]++;
				fs->xstat->port_histogram->dst_tcp.port[data_record->dstport]++;
				fs->xstat->port_histogram->src_tcp.count++;
				fs->xstat->port_histogram->dst_tcp.count++;
			} else if ( data_record->prot == IPPROTO_UDP ) {
				fs->xstat->bpp_histogram->udp.bpp[bpp]++;
				fs->xstat->bpp_histogram->udp.count++;

				fs->xstat->port_histogram->src_udp.port[data_record->srcport]++;
				fs->xstat->port_histogram->dst_udp.port[data_record->dstport]++;
				fs->xstat->port_histogram->src_udp.count++;
				fs->xstat->port_histogram->dst_udp.count++;
			}
		}

		if ( verbose ) {
			master_record_t master_record;
			ExpandRecord_v2((common_record_t *)data_record, &(table->extension_info), &master_record);
		 	format_file_block_record(&master_record, &string, 0);
			printf("%s\n", string);
		}

		fs->nffile->block_header->size  += data_record->size;
		fs->nffile->block_header->NumRecords++;
		fs->nffile->buff_ptr	= (common_record_t *)((pointer_addr_t)data_record + data_record->size);

		// advance input
		size_left 		   -= table->input_record_size;
		in  	  		   += table->input_record_size;

		// buffer size sanity check
		if ( fs->nffile->block_header->size  > BUFFSIZE ) {
			// should never happen
			syslog(LOG_ERR,"### Software error ###: %s line %d", __FILE__, __LINE__);
			syslog(LOG_ERR,"Process v9: Output buffer overflow! Flush buffer and skip records.");
			syslog(LOG_ERR,"Buffer size: %u > %u", fs->nffile->block_header->size, BUFFSIZE);

			// reset buffer
			fs->nffile->block_header->size 		= 0;
			fs->nffile->block_header->NumRecords = 0;
			fs->nffile->buff_ptr = (void *)((pointer_addr_t)fs->nffile->block_header + sizeof(data_block_header_t) );
			return;
		}

	}

} // End of Process_v9_data

static inline void 	Process_v9_option_data(exporter_domain_t *exporter, void *data_flowset, FlowSource_t *fs) {
option_offset_t *offset_table;
sampler_t	sampler;
uint32_t	id, sampler_id, size_left;
uint8_t		*in;

	id 	= GET_FLOWSET_ID(data_flowset);

	offset_table = fs->option_offset_table;
	while ( offset_table && offset_table->id != id )
		offset_table = offset_table->next;

	if ( !offset_table ) {
		// should never happen - catch it anyway
		syslog(LOG_ERR, "Process_v9: Panic! - No Offset table found! : %s line %d", __FILE__, __LINE__);
		return;
	}

	size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length
	dbg_printf("[%u] Process option data flowset size: %u\n", exporter->exporter_id, size_left);

	// map input buffer as a byte array
	in	  = (uint8_t *)(data_flowset + 4);	// skip flowset header

	if ( TestFlag(offset_table->flags, HAS_SAMPLER_DATA) ) {
		sampler.table_id = id;
		if (offset_table->sampler_id_length == 2) {
			sampler_id = Get_val16((void *)&in[offset_table->offset_id]);
		} else {
			sampler_id = in[offset_table->offset_id];
		}
		sampler.mode 	 = in[offset_table->offset_mode];
		sampler.interval = Get_val32((void *)&in[offset_table->offset_interval]); 
	
		dbg_printf("Extracted Sampler data:\n");
		dbg_printf("Sampler ID      : %u\n", sampler_id);
		dbg_printf("Sampler mode    : %u\n", sampler.mode);
		dbg_printf("Sampler interval: %u\n", sampler.interval);
	
		InsertSampler(fs, sampler_id, &sampler);
	}

	if ( TestFlag(offset_table->flags, HAS_STD_SAMPLER_DATA) ) {
		fs->std_sampling.table_id = 0;
		fs->std_sampling.interval = Get_val32((void *)&in[offset_table->offset_std_sampler_interval]);
		fs->std_sampling.mode 	  = in[offset_table->offset_std_sampler_algorithm];

		dbg_printf("Extracted Std Sampler data:\n");
		dbg_printf("Sampler algorithm: %u\n", fs->std_sampling.mode);
		dbg_printf("Sampler interval : %u\n", fs->std_sampling.interval);

		syslog(LOG_INFO, "Set std sampler: algorithm: %u, interval: %u\n", 
				fs->std_sampling.mode, fs->std_sampling.interval);
		dbg_printf("Set std sampler: algorithm: %u, interval: %u\n", 
				fs->std_sampling.mode, fs->std_sampling.interval);
	}
	processed_records++;

} // End of Process_v9_option_data

void Process_v9(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
exporter_domain_t	*exporter;
void				*flowset_header;
option_template_flowset_t	*option_flowset;
netflow_v9_header_t	*v9_header;
int64_t 			distance;
uint32_t 			expected_records, flowset_id, flowset_length, exporter_id;
ssize_t				size_left;
static int pkg_num = 0;

	pkg_num++;
	size_left = in_buff_cnt;
	if ( size_left < NETFLOW_V9_HEADER_LENGTH ) {
		syslog(LOG_ERR, "Process_v9: Too little data for v9 packet: '%lli'", (long long)size_left);
		return;
	}

	// map v9 data structure to input buffer
	v9_header 	= (netflow_v9_header_t *)in_buff;
	exporter_id = ntohl(v9_header->source_id);

	exporter	= GetExporter(fs, exporter_id);
	if ( !exporter ) {
		syslog(LOG_ERR,"Process_v9: Exporter NULL: Abort v9 record processing");
		return;
	}

	/* calculate boot time in msec */
  	v9_header->SysUptime 	= ntohl(v9_header->SysUptime);
  	v9_header->unix_secs	= ntohl(v9_header->unix_secs);
	exporter->boot_time  	= (uint64_t)1000 * (uint64_t)(v9_header->unix_secs) - (uint64_t)v9_header->SysUptime;
	
	expected_records 		= ntohs(v9_header->count);
	flowset_header 			= (void *)v9_header + NETFLOW_V9_HEADER_LENGTH;

	size_left -= NETFLOW_V9_HEADER_LENGTH;

	dbg_printf("\n[%u] Next packet: %i %u records, buffer: %li \n", exporter_id, pkg_num, expected_records, size_left);
	// sequence check
	if ( exporter->first ) {
		exporter->last_sequence = ntohl(v9_header->sequence);
		exporter->sequence 	  	= exporter->last_sequence;
		exporter->first			= 0;
	} else {
		exporter->last_sequence = exporter->sequence;
		exporter->sequence 	  = ntohl(v9_header->sequence);
		distance 	  = exporter->sequence - exporter->last_sequence;
		// handle overflow
		if (distance < 0) {
			distance = 0xffffffff + distance  +1;
		}
		if (distance != 1) {
			fs->nffile->stat_record->sequence_failure++;
			dbg_printf("[%u] Sequence error: last seq: %lli, seq %lli dist %lli\n", 
				exporter->exporter_id, (long long)exporter->last_sequence, (long long)exporter->sequence, (long long)distance);
			/*
			if ( report_seq ) 
				syslog(LOG_ERR,"Flow sequence mismatch. Missing: %lli packets", delta(last_count,distance));
			*/
		}
	}

	processed_records = 0;

	// iterate over all flowsets in export packet, while there are bytes left
	flowset_length = 0;
	while (size_left) {
		flowset_header = flowset_header + flowset_length;

		flowset_id 		= GET_FLOWSET_ID(flowset_header);
		flowset_length 	= GET_FLOWSET_LENGTH(flowset_header);
			
		dbg_printf("[%u] Next flowset: %u, length: %u buffersize: %li addr: %llu\n", 
			exporter->exporter_id, flowset_id, flowset_length, size_left, 
			(long long unsigned)(flowset_header - in_buff) );

		if ( flowset_length == 0 ) {
			/* 	this should never happen, as 4 is an empty flowset 
				and smaller is an illegal flowset anyway ...
				if it happends, we can't determine the next flowset, so skip the entire export packet
			 */
			syslog(LOG_ERR,"Process_v9: flowset zero length error.");
			dbg_printf("Process_v9: flowset zero length error.\n");
			return;
		}

		// possible padding
		if ( flowset_length <= 4 ) {
			size_left = 0;
			continue;
		}

		if ( flowset_length > size_left ) {
			syslog(LOG_ERR,"Process_v9: flowset length error. Expected bytes: %u > buffersize: %lli", 
				flowset_length, (long long)size_left);
			size_left = 0;
			continue;
		}

#ifdef DEVEL
		if ( (ptrdiff_t)fs->nffile->buff_ptr & 0x3 ) {
			fprintf(stderr, "PANIC: alignment error!! \n");
			exit(255);
		}
#endif

		switch (flowset_id) {
			case NF9_TEMPLATE_FLOWSET_ID:
				Process_v9_templates(exporter, flowset_header, fs);
				break;
			case NF9_OPTIONS_FLOWSET_ID:
				option_flowset = (option_template_flowset_t *)flowset_header;
				syslog(LOG_DEBUG,"Process_v9: Found options flowset: template %u", ntohs(option_flowset->template_id));
				Process_v9_option_templates(exporter, flowset_header, fs);
				break;
			default: {
				input_translation_t *table;
				if ( flowset_id < NF9_MIN_RECORD_FLOWSET_ID ) {
					dbg_printf("Invalid flowset id: %u\n", flowset_id);
					syslog(LOG_ERR,"Process_v9: Invalid flowset id: %u", flowset_id);
				} else {

					dbg_printf("[%u] ID %u Data flowset\n", exporter->exporter_id, flowset_id);

					table = GetTranslationTable(exporter, flowset_id);
					if ( table ) {
						Process_v9_data(exporter, flowset_header, fs, table);
					} else if ( HasOptionTable(fs, flowset_id) ) {
						Process_v9_option_data(exporter, flowset_header, fs);
					} else {
						// maybe a flowset with option data
						dbg_printf("Process v9: [%u] No table for id %u -> Skip record\n", 
							exporter->exporter_id, flowset_id);
					}
				}
			}
		}

		// next flowset
		size_left -= flowset_length;

	} // End of while 

#ifdef DEVEL
	if ( processed_records != expected_records ) {
		syslog(LOG_ERR, "Process_v9: Processed records %u, expected %u", processed_records, expected_records);
		printf("Process_v9: Processed records %u, expected %u\n", processed_records, expected_records);
	}
#endif

	return;
	
} /* End of Process_v9 */

/*
 * functions for sending netflow v9 records
 */

void Init_v9_output(send_peer_t *peer) {
int i;

	v9_output_header = (netflow_v9_header_t *)peer->send_buffer;
	v9_output_header->version 		= htons(9);
	v9_output_header->SysUptime		= 0;
	v9_output_header->unix_secs		= 0;
	v9_output_header->count 		= 0;
	v9_output_header->source_id 	= htonl(1);
	template_id						= NF9_MIN_RECORD_FLOWSET_ID;
	peer->buff_ptr = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	

	// set the max number of v9 tags, we support.
	Max_num_v9_tags = 0;
	for (i=0; i<128; i++) {
		if ( element_info[i].min )
			Max_num_v9_tags++;
	}

} // End of Init_v9_output

static output_template_t *GetOutputTemplate(uint32_t flags, extension_map_t *extension_map) {
output_template_t **t;
template_record_t	*fields;
uint32_t	i, count, record_length;

	t = &output_templates;
	// search for the template, which corresponds to our flags and extension map
	while ( *t ) {
		if ( (*t)->flags == flags &&  (*t)->extension_map == extension_map ) 
			return *t;
		t = &((*t)->next);
	}

	// nothing found, otherwise we would not get here
	*t = (output_template_t *)malloc(sizeof(output_template_t));
	if ( !(*t)) {
		fprintf(stderr, "Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		exit(255);
	}
	memset((void *)(*t), 0, sizeof(output_template_t));
	(*t)->next	 		 = NULL;
	(*t)->flags	 		 = flags;
	(*t)->extension_map  = extension_map;
	(*t)->time_sent		 = 0;
	(*t)->template_flowset = malloc(sizeof(template_flowset_t) + ((Max_num_v9_tags * 4))); // 4 for 2 x uint16_t: type/length

	count 			= 0;
	record_length 	= 0;
	fields = (*t)->template_flowset->fields;

	// Fill the template flowset in the order of the common_record_t 
	// followed be the available extensions
	fields->record[count].type	 = htons(NF9_FIRST_SWITCHED);
	fields->record[count].length = htons(element_info[NF9_FIRST_SWITCHED].min);
	record_length 				+= element_info[NF9_FIRST_SWITCHED].min;
	count++;

	fields->record[count].type   = htons(NF9_LAST_SWITCHED);
	fields->record[count].length = htons(element_info[NF9_LAST_SWITCHED].min);
	record_length 				+= element_info[NF9_LAST_SWITCHED].min;
	count++;

	fields->record[count].type   = htons(NF9_FORWARDING_STATUS);
	fields->record[count].length = htons(element_info[NF9_FORWARDING_STATUS].min);
	record_length 				+= element_info[NF9_FORWARDING_STATUS].min;
	count++;

	fields->record[count].type   = htons(NF9_TCP_FLAGS);
	fields->record[count].length = htons(element_info[NF9_TCP_FLAGS].min);
	record_length 				+= element_info[NF9_TCP_FLAGS].min;
	count++;

	fields->record[count].type   = htons(NF9_IN_PROTOCOL);
	fields->record[count].length = htons(element_info[NF9_IN_PROTOCOL].min);
	record_length 				+= element_info[NF9_IN_PROTOCOL].min;
	count++;

	fields->record[count].type   = htons(NF9_SRC_TOS);
	fields->record[count].length = htons(element_info[NF9_SRC_TOS].min);
	record_length 				+= element_info[NF9_SRC_TOS].min;
	count++;

	fields->record[count].type   = htons(NF9_L4_SRC_PORT);
	fields->record[count].length = htons(element_info[NF9_L4_SRC_PORT].min);
	record_length 				+= element_info[NF9_L4_SRC_PORT].min;
	count++;

	fields->record[count].type   = htons(NF9_L4_DST_PORT);
	fields->record[count].length = htons(element_info[NF9_L4_DST_PORT].min);
	record_length 				+= element_info[NF9_L4_DST_PORT].min;
	count++;

    fields->record[count].type   = htons(NF9_ICMP_TYPE);
    fields->record[count].length = htons(element_info[NF9_ICMP_TYPE].min);
    record_length               += element_info[NF9_ICMP_TYPE].min;
    count++;

	// common record processed

	// fill in IP address tags
	if ( (flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6 addresses
		fields->record[count].type   = htons(NF9_IPV6_SRC_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV6_SRC_ADDR].min);
		record_length 				+= element_info[NF9_IPV6_SRC_ADDR].min;
		count++;
		fields->record[count].type   = htons(NF9_IPV6_DST_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV6_DST_ADDR].min);
		record_length 				+= element_info[NF9_IPV6_DST_ADDR].min;
	} else { // IPv4 addresses
		fields->record[count].type   = htons(NF9_IPV4_SRC_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV4_SRC_ADDR].min);
		record_length 				+= element_info[NF9_IPV4_SRC_ADDR].min;
		count++;
		fields->record[count].type   = htons(NF9_IPV4_DST_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV4_DST_ADDR].min);
		record_length 				+= element_info[NF9_IPV4_DST_ADDR].min;
	}
	count++;

	// packet counter
	fields->record[count].type  = htons(NF9_IN_PACKETS);
	if ( (flags & FLAG_PKG_64) != 0 ) {  // 64bit packet counter
		fields->record[count].length = htons(element_info[NF9_IN_PACKETS].max);
		record_length 				+= element_info[NF9_IN_PACKETS].max;
	} else {
		// fields->record[count].length = htons(element_info[NF9_IN_PACKETS].min);
		fields->record[count].length = htons(4);
		// record_length 				+= element_info[NF9_IN_PACKETS].min;
		record_length 				+= 4;
	}
	count++;

	// bytes counter
	fields->record[count].type  = htons(NF9_IN_BYTES);
	if ( (flags & FLAG_BYTES_64) != 0 ) { // 64bit byte counter
		fields->record[count].length = htons(element_info[NF9_IN_BYTES].max);
		record_length 				+= element_info[NF9_IN_BYTES].max;
	} else {
		// fields->record[count].length = htons(element_info[NF9_IN_BYTES].min);
		fields->record[count].length = htons(4);
		// record_length 				+= element_info[NF9_IN_BYTES].min;
		record_length 				+= 4;
	}
	count++;
	// process extension map 
	i = 0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2:
				fields->record[count].type   = htons(NF9_INPUT_SNMP);
				fields->record[count].length = htons(element_info[NF9_INPUT_SNMP].min);
				record_length 				+= element_info[NF9_INPUT_SNMP].min;
				count++;

				fields->record[count].type   = htons(NF9_OUTPUT_SNMP);
				fields->record[count].length = htons(element_info[NF9_OUTPUT_SNMP].min);
				record_length 				+= element_info[NF9_OUTPUT_SNMP].min;
				count++;
				break;
			case EX_IO_SNMP_4:	// input/output SNMP 4 byte
				fields->record[count].type   = htons(NF9_INPUT_SNMP);
				fields->record[count].length = htons(element_info[NF9_INPUT_SNMP].max);
				record_length 				+= element_info[NF9_INPUT_SNMP].max;
				count++;

				fields->record[count].type   = htons(NF9_OUTPUT_SNMP);
				fields->record[count].length = htons(element_info[NF9_OUTPUT_SNMP].max);
				record_length 				+= element_info[NF9_OUTPUT_SNMP].max;
				count++;
				break;
			case EX_AS_2:	// srcas/dstas 2 byte
				fields->record[count].type   = htons(NF9_SRC_AS);
				fields->record[count].length = htons(element_info[NF9_SRC_AS].min);
				record_length 				+= element_info[NF9_SRC_AS].min;
				count++;

				fields->record[count].type   = htons(NF9_DST_AS);
				fields->record[count].length = htons(element_info[NF9_DST_AS].min);
				record_length 				+= element_info[NF9_DST_AS].min;
				count++;
				break;
			case EX_AS_4:	// srcas/dstas 4 byte
				fields->record[count].type   = htons(NF9_SRC_AS);
				fields->record[count].length = htons(element_info[NF9_SRC_AS].max);
				record_length 				+= element_info[NF9_SRC_AS].max;
				count++;

				fields->record[count].type   = htons(NF9_DST_AS);
				fields->record[count].length = htons(element_info[NF9_DST_AS].max);
				record_length 				+= element_info[NF9_DST_AS].max;
				count++;
				break;
			case EX_MULIPLE: {
				uint16_t src_mask, dst_mask;
				fields->record[count].type   = htons(NF9_DST_TOS);
				fields->record[count].length = htons(element_info[NF9_DST_TOS].min);
				record_length 				+= element_info[NF9_DST_TOS].min;
				count++;

				fields->record[count].type   = htons(NF9_DIRECTION);
				fields->record[count].length = htons(element_info[NF9_DIRECTION].min);
				record_length 				+= element_info[NF9_DIRECTION].min;
				count++;

				if ( (flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6 addresses
					src_mask = NF9_IPV6_SRC_MASK;
					dst_mask = NF9_IPV6_DST_MASK;
				} else { // IPv4 addresses
					src_mask = NF9_SRC_MASK;
					dst_mask = NF9_DST_MASK;
				}

				fields->record[count].type   = htons(src_mask);
				fields->record[count].length = htons(element_info[src_mask].min);
				record_length 				+= element_info[src_mask].min;
				count++;

				fields->record[count].type   = htons(dst_mask);
				fields->record[count].length = htons(element_info[dst_mask].min);
				record_length 				+= element_info[dst_mask].min;
				count++;
				} break;
			case EX_NEXT_HOP_v4:
				fields->record[count].type   = htons(NF9_V4_NEXT_HOP);
				fields->record[count].length = htons(element_info[NF9_V4_NEXT_HOP].min);
				record_length 				+= element_info[NF9_V4_NEXT_HOP].min;
				count++;
				break;
			case EX_NEXT_HOP_v6:
				fields->record[count].type   = htons(NF9_V6_NEXT_HOP);
				fields->record[count].length = htons(element_info[NF9_V6_NEXT_HOP].min);
				record_length 				+= element_info[NF9_V6_NEXT_HOP].min;
				count++;
				break;
			case EX_NEXT_HOP_BGP_v4:
				fields->record[count].type   = htons(NF9_BGP_V4_NEXT_HOP);
				fields->record[count].length = htons(element_info[NF9_BGP_V4_NEXT_HOP].min);
				record_length 				+= element_info[NF9_BGP_V4_NEXT_HOP].min;
				count++;
				break;
			case EX_NEXT_HOP_BGP_v6:
				fields->record[count].type   = htons(NF9_BPG_V6_NEXT_HOP);
				fields->record[count].length = htons(element_info[NF9_BPG_V6_NEXT_HOP].min);
				record_length 				+= element_info[NF9_BPG_V6_NEXT_HOP].min;
				count++;
				break;
			case EX_VLAN:
				fields->record[count].type   = htons(NF9_SRC_VLAN);
				fields->record[count].length = htons(element_info[NF9_SRC_VLAN].min);
				record_length 				+= element_info[NF9_SRC_VLAN].min;
				count++;

				fields->record[count].type   = htons(NF9_DST_VLAN);
				fields->record[count].length = htons(element_info[NF9_DST_VLAN].min);
				record_length 				+= element_info[NF9_DST_VLAN].min;
				count++;
				break;
			case EX_OUT_PKG_4:
				fields->record[count].type   = htons(NF9_OUT_PKTS);
				fields->record[count].length = htons(element_info[NF9_OUT_PKTS].min);
				record_length 				+= element_info[NF9_OUT_PKTS].min;
				count++;
				break;
			case EX_OUT_PKG_8:
				fields->record[count].type   = htons(NF9_OUT_PKTS);
				fields->record[count].length = htons(element_info[NF9_OUT_PKTS].max);
				record_length 				+= element_info[NF9_OUT_PKTS].max;
				count++;
				break;
			case EX_OUT_BYTES_4:
				fields->record[count].type   = htons(NF9_OUT_BYTES);
				fields->record[count].length = htons(element_info[NF9_OUT_BYTES].min);
				record_length 				+= element_info[NF9_OUT_BYTES].min;
				count++;
				break;
			case EX_OUT_BYTES_8:
				fields->record[count].type   = htons(NF9_OUT_BYTES);
				fields->record[count].length = htons(element_info[NF9_OUT_BYTES].max);
				record_length 				+= element_info[NF9_OUT_BYTES].max;
				count++;
				break;
			case EX_AGGR_FLOWS_4:
				fields->record[count].type   = htons(NF9_FLOWS_AGGR);
				fields->record[count].length = htons(element_info[NF9_FLOWS_AGGR].min);
				record_length 				+= element_info[NF9_FLOWS_AGGR].min;
				count++;
				break;
			case EX_AGGR_FLOWS_8:
				fields->record[count].type   = htons(NF9_FLOWS_AGGR);
				fields->record[count].length = htons(element_info[NF9_FLOWS_AGGR].max);
				record_length 				+= element_info[NF9_FLOWS_AGGR].max;
				count++;
				break;
			case EX_MAC_1:
				fields->record[count].type   = htons(NF9_IN_SRC_MAC);
				fields->record[count].length = htons(6);
				// fields->record[count].length = htons(element_info[NF9_IN_SRC_MAC].min);
				// record_length 				+= element_info[NF9_IN_SRC_MAC].min;
				record_length 				+= 6;
				count++;

				fields->record[count].type   = htons(NF9_OUT_DST_MAC);
				fields->record[count].length = htons(6);
				// fields->record[count].length = htons(element_info[NF9_OUT_DST_MAC].min);
				// record_length 				+= element_info[NF9_OUT_DST_MAC].min;
				record_length 				+= 6;
				count++;
				break;
			case EX_MAC_2:
				fields->record[count].type   = htons(NF9_IN_DST_MAC);
				// fields->record[count].length = htons(element_info[NF9_IN_DST_MAC].min);
				// record_length 				+= element_info[NF9_IN_DST_MAC].min;
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;

				fields->record[count].type   = htons(NF9_OUT_SRC_MAC);
				// fields->record[count].length = htons(element_info[NF9_OUT_SRC_MAC].min);
				// record_length 				+= element_info[NF9_OUT_SRC_MAC].min;
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;
				break;
			case EX_MPLS:
				fields->record[count].type   = htons(NF9_MPLS_LABEL_1);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_2);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_3);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_4);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_5);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_6);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_7);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_8);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_9);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_10);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				break;
			case EX_ROUTER_ID:
				fields->record[count].type   = htons(NF9_ENGINE_TYPE);
				fields->record[count].length = htons(1);
				record_length 				+= element_info[NF9_ENGINE_TYPE].min;
				count++;

				fields->record[count].type   = htons(NF9_ENGINE_ID);
				fields->record[count].length = htons(1);
				record_length 				+= element_info[NF9_ENGINE_ID].min;
				count++;
				break;

			// default: other extensions are not (yet) recognised
		}
	}

	(*t)->template_flowset->flowset_id   = htons(NF9_TEMPLATE_FLOWSET_ID);
	(*t)->flowset_length				 = 4 * (2+count); // + 2 for the header

	// add proper padding for 32bit boundary
	if ( ((*t)->flowset_length & 0x3 ) != 0 ) 
		(*t)->flowset_length += (4 - ((*t)->flowset_length & 0x3 ));
	(*t)->template_flowset->length  	 = htons((*t)->flowset_length);

	(*t)->record_length		= record_length;

	fields->template_id		= htons(template_id++);
	fields->count			= htons(count);

	return *t;

} // End of GetOutputTemplate

static void Append_Record(send_peer_t *peer, master_record_t *master_record) {
extension_map_t *extension_map = master_record->map_ref;
uint32_t	i, t1, t2;
uint16_t	icmp;

	t1 	= (uint32_t)(1000LL * (uint64_t)master_record->first + master_record->msec_first - boot_time);
	t2	= (uint32_t)(1000LL * (uint64_t)master_record->last  + master_record->msec_last - boot_time);
  	master_record->first	= htonl(t1);
  	master_record->last		= htonl(t2);

  	master_record->srcport	= htons(master_record->srcport);
  	master_record->dstport	= htons(master_record->dstport);

	// if it's an ICMP send it in the appropriate v9 tag
	if ( master_record->prot == IPPROTO_ICMP || master_record->prot == IPPROTO_ICMPV6  ) { // it's an ICMP
		icmp = master_record->dstport;
		master_record->dstport = 0;
	} else {
		icmp = 0;
	}
	// write the first 16 bytes of the master_record starting with first up to and including dst port
	memcpy(peer->buff_ptr, (void *)&master_record->first, 16);
	peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 16);

	// write ICMP type/code
	memcpy(peer->buff_ptr, (void *)&icmp,2);
	peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 2);

	// IP address info
	if ((master_record->flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6
		master_record->v6.srcaddr[0] = htonll(master_record->v6.srcaddr[0]);
		master_record->v6.srcaddr[1] = htonll(master_record->v6.srcaddr[1]);
		master_record->v6.dstaddr[0] = htonll(master_record->v6.dstaddr[0]);
		master_record->v6.dstaddr[1] = htonll(master_record->v6.dstaddr[1]);
		memcpy(peer->buff_ptr, master_record->v6.srcaddr, 4 * sizeof(uint64_t));
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 4 * sizeof(uint64_t));
	} else {
		Put_val32(htonl(master_record->v4.srcaddr), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
		Put_val32(htonl(master_record->v4.dstaddr), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// packet counter
	if ((master_record->flags & FLAG_PKG_64) != 0 ) { // 64bit counters
		Put_val64(htonll(master_record->dPkts), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
	} else {
		Put_val32(htonl((uint32_t)master_record->dPkts), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// bytes counter
	if ((master_record->flags & FLAG_BYTES_64) != 0 ) { // 64bit counters
		Put_val64(htonll(master_record->dOctets),peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
	} else {
		Put_val32(htonl((uint32_t)master_record->dOctets),peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// send now optional extensions according the extension map
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: {
				uint16_t in, out;

				in  = htons(master_record->input);
				Put_val16(in, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));

				out = htons(master_record->output);
				Put_val16(out, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				} break;
			case EX_IO_SNMP_4:
				Put_val32(htonl(master_record->input), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->output), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_AS_2: { // srcas/dstas 2 byte
				uint16_t src, dst;

				src = htons(master_record->srcas);
				Put_val16(src, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));

				dst = htons(master_record->dstas);
				Put_val16(dst, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				} break;
			case EX_AS_4:  // srcas/dstas 4 byte
				Put_val32(htonl(master_record->srcas), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->dstas), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)peer->buff_ptr;
				tpl->dst_tos  = master_record->dst_tos;
				tpl->dir 	  = master_record->dir;
				tpl->src_mask = master_record->src_mask;
				tpl->dst_mask = master_record->dst_mask;
				peer->buff_ptr = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v4:
				Put_val32(htonl(master_record->ip_nexthop.v4), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_NEXT_HOP_v6: 
				Put_val64(htonll(master_record->ip_nexthop.v6[0]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				Put_val64(htonll(master_record->ip_nexthop.v6[1]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_NEXT_HOP_BGP_v4: 
				Put_val32(htonl(master_record->bgp_nexthop.v4), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_NEXT_HOP_BGP_v6: 
				Put_val64(htonll(master_record->bgp_nexthop.v6[0]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				Put_val64(htonll(master_record->bgp_nexthop.v6[1]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_VLAN: 
				Put_val16(htons(master_record->src_vlan), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				Put_val16(htons(master_record->dst_vlan), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				break;
			case EX_OUT_PKG_4: 
				Put_val32(htonl(master_record->out_pkts), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_OUT_PKG_8:
				Put_val64(htonll(master_record->out_pkts), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_OUT_BYTES_4:
				Put_val32(htonl(master_record->out_bytes), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_OUT_BYTES_8:
				Put_val64(htonll(master_record->out_bytes), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_AGGR_FLOWS_4:
				Put_val32(htonl(master_record->aggr_flows), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_AGGR_FLOWS_8:
				Put_val64(htonll(master_record->aggr_flows), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_MAC_1: {
				uint64_t	val64;
				val64 = htonll(master_record->in_src_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				val64 = htonll(master_record->out_dst_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				} break;
			case EX_MAC_2: {
				uint64_t	val64;
				val64 = htonll(master_record->in_dst_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				val64 = htonll(master_record->out_src_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				} break;
			case EX_MPLS: {
				uint32_t val32, i;
				for ( i=0; i<10; i++ ) {
					val32 = htonl(master_record->mpls_label[i]);
					Put_val24(val32, peer->buff_ptr);
					peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 3);	// 24 bits
				}
				} break;
			case EX_ROUTER_ID: {
				uint8_t *u = (uint8_t *)peer->buff_ptr;
				*u++ = master_record->engine_type;
				*u++ = master_record->engine_id;
				peer->buff_ptr = (void *)u;
				} break;

			// default: ignore all other extension, as we do not understand them
		}
	}

} // End of Append_Record

int Add_v9_output_record(master_record_t *master_record, send_peer_t *peer) {
static data_flowset_t		*data_flowset;
static output_template_t	*template;
static uint32_t	last_flags = 0;
static extension_map_t *last_map = NULL;
static int	record_count, template_count, flowset_count, packet_count;
uint32_t	required_size;
void		*endwrite;
time_t		now = time(NULL);

#ifdef DEVEL
//	char		*string;
//	format_file_block_record(master_record, 1, &string, 0);
//	dbg_printf("%s\n", string);
#endif

	if ( !v9_output_header->unix_secs ) {	// first time a record is added
		// boot time is set one day back - assuming that the start time of every flow does not start ealier
		boot_time	   = (uint64_t)(master_record->first - 86400)*1000;
		v9_output_header->unix_secs = htonl(master_record->first - 86400);
		v9_output_header->sequence  = 0;
		peer->buff_ptr  = (void *)((pointer_addr_t)peer->send_buffer + NETFLOW_V9_HEADER_LENGTH);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		packet_count   = 0;
		data_flowset   = NULL;

		// write common blocksize from frst up to including dstas for one write (memcpy)
//		common_block_size = (pointer_addr_t)&master_record->fill - (pointer_addr_t)&master_record->first;

	} else if ( flowset_count == 0 ) {	// after a buffer flush
		packet_count++;
		v9_output_header->sequence = htonl(packet_count);
	}

	if ( data_flowset ) {
		// output buffer contains already a data flowset
		if ( last_flags == master_record->flags && last_map == master_record->map_ref ) {
			// same id as last record
			// if ( now - template->time_sent > MAX_LIFETIME )
			if ( (record_count & 0xFFF) == 0 ) {	// every 4096 flow records
				uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;
				uint8_t	align   = length & 0x3;
				if ( align != 0 ) {
					length += ( 4 - align );
					data_flowset->length = htons(length);
					peer->buff_ptr += align;
				}
				// template refresh is needed
				// terminate the current data flowset
				data_flowset = NULL;
				if ( (pointer_addr_t)peer->buff_ptr + template->flowset_length > (pointer_addr_t)peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush buffer
				}
				memcpy(peer->buff_ptr, (void *)template->template_flowset, template->flowset_length);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length);
				template->time_sent = now;
				flowset_count++;
				template_count++;

				// open a new data flow set at this point in the output buffer
				data_flowset = (data_flowset_t *)peer->buff_ptr;
				data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
				peer->buff_ptr = (void *)data_flowset->data;
				flowset_count++;
			} // else Add record

		} else {
			// record with different template id
			// terminate the current data flowset
			uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;
			uint8_t	align   = length & 0x3;
			if ( align != 0 ) {
				length += ( 4 - align );
				data_flowset->length = htons(length);
				peer->buff_ptr += align;
			}
			data_flowset = NULL;

			last_flags 	= master_record->flags;
			last_map	= master_record->map_ref;
			template 	= GetOutputTemplate(last_flags, master_record->map_ref);
			if ( now - template->time_sent > MAX_LIFETIME ) {
				// refresh template is needed
				endwrite= (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length + sizeof(data_flowset_t));
				if ( endwrite > peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush the buffer
				}
				memcpy(peer->buff_ptr, (void *)template->template_flowset, template->flowset_length);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length);
				template->time_sent = now;
				flowset_count++;
				template_count++;
			}
			// open a new data flow set at this point in the output buffer
			data_flowset = (data_flowset_t *)peer->buff_ptr;
			data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
			peer->buff_ptr = (void *)data_flowset->data;
			flowset_count++;
		}
	} else {
		// output buffer does not contain a data flowset
		peer->buff_ptr = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	
		last_flags = master_record->flags;
		last_map	= master_record->map_ref;
		template = GetOutputTemplate(last_flags, master_record->map_ref);
		if ( now - template->time_sent > MAX_LIFETIME ) {
			// refresh template
			endwrite= (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length + sizeof(data_flowset_t));
			if ( endwrite > peer->endp ) {
				// this must never happen!
				fprintf(stderr, "Panic: Software error in %s line %d\n", __FILE__, __LINE__);
				fprintf(stderr, "buffer %p, buff_ptr %p template length %x, endbuff %p\n", 
					peer->send_buffer, peer->buff_ptr, template->flowset_length + (uint32_t)sizeof(data_flowset_t), peer->endp );
				exit(255);
			}
			memcpy(peer->buff_ptr, (void *)template->template_flowset, template->flowset_length);
			peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + template->flowset_length);
			template->time_sent = now;
			flowset_count++;
			template_count++;
		}
		// open a new data flow set at this point in the output buffer
		data_flowset = (data_flowset_t *)peer->buff_ptr;
		data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
		peer->buff_ptr = (void *)data_flowset->data;
		flowset_count++;
	}
	// now add the record

	required_size = template->record_length;

	endwrite = (void *)((pointer_addr_t)peer->buff_ptr + required_size);
	if ( endwrite > peer->endp ) {
		uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;
		if ( (length & 0x3) != 0 ) 
			length += ( 4 - (length & 0x3));

		// flush the buffer
		data_flowset->length = htons(length);
		if ( length == 4 ) {	// empty flowset
			peer->buff_ptr = (void *)data_flowset;
		} 
		data_flowset = NULL;
		v9_output_header->count = htons(record_count+template_count);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		peer->flush    = 1;
		return 1;	// return to flush buffer
	}

	// this was a long way up to here, now we can add the data
	Append_Record(peer, master_record);

	data_flowset->length = htons((pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset);
	record_count++;
	v9_output_header->count = htons(record_count+template_count);

	return 0;

} // End of Add_v9_output_record


