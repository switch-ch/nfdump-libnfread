/*
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
 *  $Id: collector.h 51 2010-01-29 09:01:54Z haag $
 *
 *  $LastChangedRevision: 51 $
 *	
 */

#ifndef _COLLECTOR_H
#define _COLLECTOR_H 1

#define FNAME_SIZE  256
#define IDENT_SIZE  32

typedef struct srecord_s {
    char    fname[FNAME_SIZE];      // file name
    char    subdir[FNAME_SIZE];     // subdir name
    char    tstring[16];            // actually 12 needed e.g. 200411011230
    time_t  tstamp;                 // UNIX time stamp
	int		failed;					// in case of an error
} srecord_t;

// common_record_t defines ext_map as uint_8, so max 256 extension maps allowed.
// should be enough anyway

typedef struct sampler_s {
	uint32_t	interval;
	uint16_t	table_id;
	uint8_t		mode;
} sampler_t;

typedef struct option_offset_s {
	struct option_offset_s *next;
	uint32_t	id;					// table id
	uint32_t	flags;				// info about this map

	// sampling offsets
#define HAS_SAMPLER_DATA	1
	uint16_t	offset_id;
	uint16_t    sampler_id_length;
	uint16_t	offset_mode;
	uint16_t	offset_interval;

#define HAS_STD_SAMPLER_DATA 2
	uint16_t	offset_std_sampler_interval;
	uint16_t	offset_std_sampler_algorithm;

} option_offset_t;

typedef struct FlowSource_s {
	// link
	struct FlowSource_s *next;

	// exporter identifiers
	char 				Ident[IDENTLEN];
	ip_addr_t			ip;
	uint32_t			sa_family;

	int					any_source;
	bookkeeper_t 		*bookkeeper;

	// all about data storage
	char				*datadir;		// where to store data for this source
	char				*current;		// current file name - typically nfcad.current.pid
	nffile_t			*nffile;		// the writing file handle

	// statistical data per source
	uint32_t			bad_packets;
	uint64_t			first_seen;		// in msec 
	uint64_t			last_seen;		// in msec

	// port histogram data
	xstat_t				*xstat;

	// Any exporter specific data
	void				*exporter_data;

	// extension map list
	struct {
#define MAP_BLOCKSIZE	16
		int	next_free;
		int	max_maps;
		extension_map_t	**maps;
	} extension_map_list;

	// Netflow v9 only:
	// sampling information: 
	// each flow source may have several sampler applied
	// tags #48, #49, #50
	sampler_t 		 **sampler;

	// global sampling information #34 #35
	sampler_t		std_sampling;

	option_offset_t *option_offset_table;

} FlowSource_t;

/* input buffer size, to read data from the network */
#define NETWORK_INPUT_BUFF_SIZE 65535	// Maximum UDP message size

// prototypes
int AddFlowSource(FlowSource_t **FlowSource, char *ident);

int AddDefaultFlowSource(FlowSource_t **FlowSource, char *ident, char *path);

int InitExtensionMapList(FlowSource_t *fs);

int AddExtensionMap(FlowSource_t *fs, extension_map_t *map);

void FlushExtensionMaps(FlowSource_t *fs);

void InsertSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_sampler_id, uint16_t sampler_id_length, 
	uint16_t offset_sampler_mode, uint16_t offset_sampler_interval);

void InsertStdSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_std_sampler_interval, 
	uint16_t offset_std_sampler_algorithm);

void InsertSampler( FlowSource_t *fs, uint8_t sampler_id, sampler_t *sampler);

int HasOptionTable(FlowSource_t *fs, uint16_t id );

void launcher (char *commbuff, FlowSource_t *FlowSource, char *process, int expire);

/* Default time window in seconds to rotate files */
#define TIME_WINDOW	  	300

/* overdue time: 
 * if nfcapd does not get any data, wake up the receive system call
 * at least after OVERDUE_TIME seconds after the time window
 */
#define OVERDUE_TIME	10

// time nfcapd will wait for launcher to terminate
#define LAUNCHER_TIMEOUT 60

#define SYSLOG_FACILITY "daemon"

#endif //_COLLECTOR_H
