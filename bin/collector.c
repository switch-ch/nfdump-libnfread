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
 *  $Id: collector.c 69 2010-09-09 07:17:43Z haag $
 *
 *  $LastChangedRevision: 69 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

#include <time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#include "util.h"
#include "nf_common.h"
#include "nffile.h"
#include "nfxstat.h"
#include "bookkeeper.h"
#include "collector.h"
#include "nfx.h"

#include "nffile_inline.c"

/* globals */
uint32_t default_sampling   = 1;
uint32_t overwrite_sampling = 0;

int AddFlowSource(FlowSource_t **FlowSource, char *ident) {
FlowSource_t	**source;
struct 	stat 	fstat;
char *p, *q, s[MAXPATHLEN];
int	 has_any_source = 0;
int ok;

	source = FlowSource;
	while ( *source ) {
		has_any_source |= (*source)->any_source;
		source = &((*source)->next);
	}
	if ( has_any_source ) {
		fprintf(stderr, "Ambiguous idents not allowed\n");
		return 0;
	}

	*source = (FlowSource_t *)calloc(1, sizeof(FlowSource_t));
	if ( !*source ) {
		fprintf(stderr, "malloc() allocation error: %s\n", strerror(errno));
		return 0;
	} 
	(*source)->next 	  	  = NULL;
	(*source)->bookkeeper 	  = NULL;
	(*source)->any_source 	  = 0;
	(*source)->exporter_data  = NULL;
	(*source)->sampler  	  = NULL;
	(*source)->xstat 		  = NULL;

	memset((void *)&((*source)->std_sampling), 0, sizeof(sampler_t));

	// separate IP address from ident
	if ( ( p = strchr(ident, ',')) == NULL  ) {
		fprintf(stderr, "Syntax error for netflow source definition. Expect -n ident,IP,path\n");
		return 0;
	}
	*p++ = '\0';

	// separate path from IP
	if ( ( q = strchr(p, ',')) == NULL  ) {
		fprintf(stderr, "Syntax error for netflow source definition. Expect -n ident,IP,path\n");
		return 0;
	}
	*q++ = '\0';

	if ( strchr(p, ':') != NULL ) {
		uint64_t _ip[2];
		ok = inet_pton(PF_INET6, p, _ip);
		(*source)->ip.v6[0] = ntohll(_ip[0]);
		(*source)->ip.v6[1] = ntohll(_ip[1]);
	} else {
		uint32_t _ip;
		ok = inet_pton(PF_INET, p, &_ip);
		(*source)->ip.v6[0] = 0;
		(*source)->ip.v6[1] = 0;
		(*source)->ip.v4 = ntohl(_ip);
	}
	switch (ok) {
		case 0:
			fprintf(stderr, "Unparsable IP address: %s\n", p);
			return 0;
		case 1:
			// success
			break;
		case -1:
			fprintf(stderr, "Error while parsing IP address: %s\n", strerror(errno));
			return 0;
			break;
	}

	// fill in ident
	if ( strlen(ident) >= IDENTLEN ) {
		fprintf(stderr, "Source identifier too long: %s\n", ident);
		return 0;
	}
	if ( strchr(ident, ' ') ) {
		fprintf(stderr,"Illegal characters in ident %s\n", ident);
		exit(255);
	}
	strncpy((*source)->Ident, ident, IDENTLEN-1 );
	(*source)->Ident[IDENTLEN-1] = '\0';

	if ( strlen(q) >= MAXPATHLEN ) {
		fprintf(stderr,"Path too long: %s\n", q);
		exit(255);
	}

	// check for existing path
	if ( stat(q, &fstat) ) {
		fprintf(stderr, "stat() error %s: %s\n", q, strerror(errno));
		return 0;
	}
	if ( !(fstat.st_mode & S_IFDIR) ) {
		fprintf(stderr, "No such directory: %s\n", q);
		return 0;
	}

	// remember path
	(*source)->datadir = strdup(q);
	if ( !(*source)->datadir ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	// cache current collector file
	if ( snprintf(s, MAXPATHLEN-1, "%s/%s.%lu", (*source)->datadir , NF_DUMPFILE, (unsigned long)getpid() ) >= (MAXPATHLEN-1)) {
		fprintf(stderr, "Path too long: %s\n", q);
		return 0;
	}
	(*source)->current = strdup(s);
	if ( !(*source)->current ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	return 1;

} // End of AddFlowSource

int AddDefaultFlowSource(FlowSource_t **FlowSource, char *ident, char *path) {
struct 	stat 	fstat;
char s[MAXPATHLEN];

	*FlowSource = (FlowSource_t *)calloc(1,sizeof(FlowSource_t));
	if ( !*FlowSource ) {
		fprintf(stderr, "calloc() allocation error: %s\n", strerror(errno));
		return 0;
	} 
	(*FlowSource)->next 	  = NULL;
	(*FlowSource)->bookkeeper = NULL;
	(*FlowSource)->any_source = 1;
	(*FlowSource)->exporter_data  = NULL;
	(*FlowSource)->xstat 	  = NULL;

	// fill in ident
	if ( strlen(ident) >= IDENTLEN ) {
		fprintf(stderr, "Source identifier too long: %s\n", ident);
		return 0;
	}
	if ( strchr(ident, ' ') ) {
		fprintf(stderr,"Illegal characters in ident %s\n", ident);
		return 0;
	}
	strncpy((*FlowSource)->Ident, ident, IDENTLEN-1 );
	(*FlowSource)->Ident[IDENTLEN-1] = '\0';

	if ( strlen(path) >= MAXPATHLEN ) {
		fprintf(stderr,"Path too long: %s\n",path);
		return 0;
	}

	// check for existing path
	if ( stat(path, &fstat) ) {
		fprintf(stderr, "stat() error %s: %s\n", path, strerror(errno));
		return 0;
	}
	if ( !(fstat.st_mode & S_IFDIR) ) {
		fprintf(stderr, "No such directory: %s\n", path);
		return 0;
	}

	// remember path
	(*FlowSource)->datadir = strdup(path);
	if ( !(*FlowSource)->datadir ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	// cache current collector file
	if ( snprintf(s, MAXPATHLEN-1, "%s/%s", (*FlowSource)->datadir, NF_DUMPFILE ) >= (MAXPATHLEN-1) ) {
		fprintf(stderr, "Path too long: %s\n", path);
		return 0;
	}
	(*FlowSource)->current = strdup(s);
	if ( !(*FlowSource)->current ) {
		fprintf(stderr, "strdup() error: %s\n", strerror(errno));
		return 0;
	}

	return 1;

} // End of AddDefaultFlowSource

int InitExtensionMapList(FlowSource_t *fs) {

	fs->extension_map_list.maps = (extension_map_t **)calloc(MAP_BLOCKSIZE, sizeof(extension_map_t *));
	if ( !fs->extension_map_list.maps ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	fs->extension_map_list.max_maps  = MAP_BLOCKSIZE;
	fs->extension_map_list.next_free = 0;

	return 1;

} // End of InitExtensionMapList

int AddExtensionMap(FlowSource_t *fs, extension_map_t *map) {
pointer_addr_t 		bsize;
int next_slot = fs->extension_map_list.next_free;

	// is it a new map, we have not yet in the list
	if ( map->map_id == INIT_ID ) {
		if ( next_slot >= fs->extension_map_list.max_maps ) {
			// extend map list
			extension_map_t **p = realloc((void *)fs->extension_map_list.maps, 
				(fs->extension_map_list.max_maps + MAP_BLOCKSIZE ) * sizeof(extension_map_t *));
			if ( !p ) {
				syslog(LOG_ERR, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
				return 0;
			}
			fs->extension_map_list.maps 	= p;
			fs->extension_map_list.max_maps += MAP_BLOCKSIZE;
		}
	
		fs->extension_map_list.maps[next_slot] = map;
	
		map->map_id = next_slot;
		fs->extension_map_list.next_free++;
	}

	// sanity check for buffer size
	bsize = (pointer_addr_t)fs->nffile->buff_ptr - (pointer_addr_t)fs->nffile->block_header;
	// at least space for the map size is required
	if ( bsize >= (BUFFSIZE - map->size )  ) {
		syslog(LOG_WARNING,"AddExtensionMap: Outputbuffer full. Flush buffer but have to skip records.");
		return 0;
	}

	if ( !CheckBufferSpace(fs->nffile, map->size) ) {
		// fishy! - should never happen. maybe disk full?
		syslog(LOG_ERR,"AddExtensionMap: output buffer size error. Abort record processing");
		return 0;
	}

	memcpy(fs->nffile->buff_ptr, (void *)map, map->size);
	fs->nffile->buff_ptr += map->size;

	fs->nffile->block_header->size += map->size;
	fs->nffile->block_header->NumRecords++;

	return 1;

} // End of AddExtensionMap

void FlushExtensionMaps(FlowSource_t *fs) {
int i;

    for ( i=0; i<fs->extension_map_list.next_free; i++ ) {
        extension_map_t *map = fs->extension_map_list.maps[i];

        if ( !CheckBufferSpace(fs->nffile, map->size) ) {
            // fishy! - should never happen. maybe disk full?
            syslog(LOG_ERR,"FlushExtensionMaps: output buffer size error. Abort record processing");
            return;
        }

        memcpy(fs->nffile->buff_ptr, (void *)map, map->size);

        fs->nffile->buff_ptr += map->size;
        fs->nffile->block_header->NumRecords++;
        fs->nffile->block_header->size += map->size;
    }

} // End of FlushExtensionMaps

void InsertSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_sampler_id, uint16_t sampler_id_length,
	uint16_t offset_sampler_mode, uint16_t offset_sampler_interval) {
option_offset_t	**t;

	t = &(fs->option_offset_table);
	while ( *t ) {
		if ( (*t)->id == id ) { // table already known to us - update data
			dbg_printf("Found existing sampling info in template %i\n", id);
			break;
		}
	
		t = &((*t)->next);
	}

	if ( *t == NULL ) {	// new table
		dbg_printf("Allocate new sampling info from template %i\n", id);
		*t = (option_offset_t *)calloc(1, sizeof(option_offset_t));
		if ( !*t ) {
			fprintf(stderr, "malloc() allocation error: %s\n", strerror(errno));
			return ;
		} 
		dbg_printf("Process_v9: New sampler at offsets: ID %i, mode: %i, interval: %i\n", 
			offset_sampler_id, offset_sampler_mode, offset_sampler_interval);
	}	// else existing table

	dbg_printf("Insert/Update sampling info from template %i\n", id);
	SetFlag((*t)->flags, HAS_SAMPLER_DATA);
	(*t)->id 				= id;
	(*t)->offset_id			= offset_sampler_id;
	(*t)->sampler_id_length = sampler_id_length;
	(*t)->offset_mode		= offset_sampler_mode;
	(*t)->offset_interval	= offset_sampler_interval;
	(*t)->offset_std_sampler_interval	= 0;
	(*t)->offset_std_sampler_algorithm	= 0;

} // End of InsertSamplerOffset

void InsertStdSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_std_sampler_interval, uint16_t offset_std_sampler_algorithm) {
option_offset_t	**t;

	t = &(fs->option_offset_table);
	while ( *t ) {
		if ( (*t)->id == id ) { // table already known to us - update data
			dbg_printf("Found existing std sampling info in template %i\n", id);
			break;
		}
	
		t = &((*t)->next);
	}

	if ( *t == NULL ) {	// new table
		dbg_printf("Allocate new std sampling info from template %i\n", id);
		*t = (option_offset_t *)calloc(1, sizeof(option_offset_t));
		if ( !*t ) {
			fprintf(stderr, "malloc() allocation error: %s\n", strerror(errno));
			return ;
		} 
		syslog(LOG_ERR, "Process_v9: New std sampler: interval: %i, algorithm: %i", 
			offset_std_sampler_interval, offset_std_sampler_algorithm);
	}	// else existing table

	dbg_printf("Insert/Update sampling info from template %i\n", id);
	SetFlag((*t)->flags, HAS_STD_SAMPLER_DATA);
	(*t)->id 				= id;
	(*t)->offset_id			= 0;
	(*t)->offset_mode		= 0;
	(*t)->offset_interval	= 0;
	(*t)->offset_std_sampler_interval	= offset_std_sampler_interval;
	(*t)->offset_std_sampler_algorithm	= offset_std_sampler_algorithm;
	
} // End of InsertStdSamplerOffset


void InsertSampler( FlowSource_t *fs, uint8_t sampler_id, sampler_t *sampler) {

	if ( !fs->sampler ) {
		fs->sampler = (sampler_t **)calloc(256, sizeof(sampler_t *));
		if ( !fs->sampler ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return;
		}
	} 
	
	if ( !fs->sampler[sampler_id] ) {
		fs->sampler[sampler_id] = (sampler_t *)malloc(sizeof(sampler_t));
		if ( !fs->sampler[sampler_id] ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return;
		}
		syslog(LOG_INFO, "Add new sampler: ID: %u, mode: %u, interval: %u\n", sampler_id, sampler->mode, sampler->interval);
		dbg_printf("Add new sampler: ID: %u, mode: %u, interval: %u\n", sampler_id, sampler->mode, sampler->interval);
	}

	memcpy((void *)(fs->sampler[sampler_id]), (void *)sampler, sizeof(sampler_t));

} // End of InsertSampler

int HasOptionTable(FlowSource_t *fs, uint16_t id ) {
option_offset_t *t;

	t = fs->option_offset_table;
	while ( t && t->id != id )
		t = t->next;

	dbg_printf("Has option table: %s\n", t == NULL ? "not found" : "found");

	return t != NULL;

} // End of HasOptionTable
