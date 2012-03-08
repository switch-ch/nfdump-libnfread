/*
 *  Copyright (c) 2012, Daniel Roethlisberger
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
 *  $Author$
 *
 *  $Id$
 *
 *  $LastChangedRevision$
 *
 *
 */

/*
 * Simple library stub for reading netflow files.
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "util.h"
#include "flist.h"

#define NFREAD_C
#include "nfread.h"

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

/* module limited globals */
extension_map_list_t extension_map_list;

#include "nffile_inline.c"

static int
nfread_iterate_flowrecord(nfread_iterate_cb_t iteratecb,
                          common_record_t *flow_record)
{
	master_record_t master_record;

	if (flow_record->type == ExtensionMapType) {
		extension_map_t *map = (extension_map_t *)flow_record;
		if (Insert_Extension_Map(&extension_map_list, map)) {
			/* flush new map */
		} /* else map already known and flushed */
		return NFREAD_LOOP_NEXT;
	}

	if (flow_record->type != CommonRecordType) {
		/* unknown flow_record->type */
		return iteratecb(NULL, NFREAD_ERECTYPE, GetCurrentFilename());
	}

	if (!extension_map_list.slot[flow_record->ext_map]) {
		/* unknown flow_record->ext_map */
		return iteratecb(NULL, NFREAD_ECORRUPT, GetCurrentFilename());
	}

	ExpandRecord_v2(flow_record,
	                extension_map_list.slot[flow_record->ext_map],
	                &master_record);
	/* update number of flows matching a given map */
	extension_map_list.slot[flow_record->ext_map]->ref_count++;
	return iteratecb(&master_record, NFREAD_SUCCESS, NULL);
}

__attribute__((visibility("default")))
int
nfread_iterate(nfread_iterate_cb_t iteratecb)
{
	common_record_t *flow_record;
	nffile_t *nffile;
	int i, done, ret, rv;

	/* Get the first file handle */
	nffile = GetNextFile(NULL, 0, 0);
	if (!nffile) {
		LogError("GetNextFile() error in %s line %d: %s\n",
		         __FILE__, __LINE__, strerror(errno));
		return -1;
	}

	done = 0;
	while (!done) {
		/* get next data block from file */
		ret = ReadBlock(nffile);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				rv = iteratecb(NULL, ret == NF_CORRUPT ?
				               NFREAD_ECORRUPT : NFREAD_ERROR,
				               GetCurrentFilename());
				if (rv == NFREAD_LOOP_EXIT) {
					done = 1;
					continue;
				}
				/* fall through */
			case NF_EOF:
			{
				nffile_t *next = GetNextFile(nffile, 0, 0);
				if (next == EMPTY_LIST) {
					done = 1;
				} else if (next == NULL) {
					done = 1;
					iteratecb(NULL, NFREAD_ERROR,
					          "unexpected end of list");
				}
				continue;
			}
		}

		if (nffile->block_header->id == Large_BLOCK_Type) {
			/* skip */
			continue;
		}

		if (nffile->block_header->id != DATA_BLOCK_TYPE_2) {
			/* nffile->block_header->id */
			rv = iteratecb(NULL, NFREAD_EBLKTYPE,
			               GetCurrentFilename());
			if (rv == NFREAD_LOOP_EXIT)
				done = 1;
			continue;
		}

		flow_record = nffile->buff_ptr;
		for (i = 0; i < nffile->block_header->NumRecords; i++) {

			rv = nfread_iterate_flowrecord(iteratecb, flow_record);
			if (rv == NFREAD_LOOP_EXIT) {
				done = 1;
				continue;
			}
			flow_record = (common_record_t *)((pointer_addr_t)
			              flow_record + flow_record->size);
		}
	}

	CloseFile(nffile);
	DisposeFile(nffile);
	PackExtensionMapList(&extension_map_list);
	return 0;
}

__attribute__((visibility("default")))
int
nfread_init(char *rfile, char *Rfile, char *Mdirs)
{
	if (rfile && Rfile) {
		fprintf(stderr, "-r and -R are mutually exclusive. "
		                "Please specify either -r or -R\n");
		exit(255);
	}

	if (Mdirs && !(rfile || Rfile)) {
		fprintf(stderr, "-M needs either -r or -R to specify "
		                "the file or file list. Add '-R .' for "
		                "all files in the directories.\n");
		exit(255);
	}

	InitExtensionMaps(&extension_map_list);
	SetupInputFileSequence(Mdirs, rfile, Rfile);

	return 0;
}

__attribute__((visibility("default")))
void
nfread_fini(void)
{
}

