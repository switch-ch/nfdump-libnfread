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
#include "rbtree.h"
#include "nftree.h"

#define NFREAD_C
#include "nfread.h"

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif


#include "nffile_inline.c"

static int
nfread_iterate_flowrecord(nfread_iterate_cb_t itercb,
                          common_record_t *flow_record,
                          FilterEngine_data_t *fltengine,
                          extension_map_list_t *extmap_list)
{
	master_record_t master_record;

	if (flow_record->type == ExtensionMapType) {
		extension_map_t *map = (extension_map_t *)flow_record;
		if (Insert_Extension_Map(extmap_list, map)) {
			/* flush new map */
		} /* else map already known and flushed */
		return NFREAD_LOOP_NEXT;
	}

	if (flow_record->type != CommonRecordType) {
		/* unknown flow_record->type */
		return itercb(NULL, NFREAD_ERECTYPE, GetCurrentFilename());
	}

	if (!extmap_list->slot[flow_record->ext_map]) {
		/* unknown flow_record->ext_map */
		return itercb(NULL, NFREAD_ECORRUPT, GetCurrentFilename());
	}

	ExpandRecord_v2(flow_record,
	                extmap_list->slot[flow_record->ext_map],
	                &master_record);
	/* update number of flows matching a given map */
	extmap_list->slot[flow_record->ext_map]->ref_count++;
	if (fltengine) {
		fltengine->nfrecord = (uint64_t *)&master_record;
		/* XXX is this really ptr to func ptr? */
		if (!((*fltengine->FilterEngine)(fltengine)))
			return NFREAD_LOOP_NEXT;
	}

	return itercb(&master_record, NFREAD_SUCCESS, NULL);
}

/*
 * Returns NFREAD_LOOP_NEXT if the file was iterated successfully.
 * Returns NFREAD_LOOP_EXIT if the loop was aborted for some reason.
 */
static int
nfread_iterate_file(nfread_iterate_cb_t itercb,
                    nffile_t *nffile,
                    FilterEngine_data_t *fltengine,
                    extension_map_list_t *extmap_list)
{
	common_record_t *flow_record;
	int rv, i;

	for (;;) {
		/* get next data block from file */
		switch ((rv = ReadBlock(nffile))) {
			case NF_CORRUPT:
			case NF_ERROR:
				rv = itercb(NULL, rv == NF_CORRUPT ?
				            NFREAD_ECORRUPT : NFREAD_ERROR,
				            GetCurrentFilename());
				if (rv == NFREAD_LOOP_EXIT)
					return NFREAD_LOOP_EXIT;
				/* fall through */
			case NF_EOF:
				return NFREAD_LOOP_NEXT;
		}

		if (nffile->block_header->id == Large_BLOCK_Type) {
			/* skip */
			continue;
		}

		if (nffile->block_header->id != DATA_BLOCK_TYPE_2) {
			/* nffile->block_header->id */
			rv = itercb(NULL, NFREAD_EBLKTYPE,
			            GetCurrentFilename());
			if (rv == NFREAD_LOOP_EXIT)
				return NFREAD_LOOP_EXIT;
			continue;
		}

		flow_record = nffile->buff_ptr;
		for (i = 0; i < nffile->block_header->NumRecords; i++) {
			rv = nfread_iterate_flowrecord(itercb, flow_record,
			                               fltengine, extmap_list);
			if (rv == NFREAD_LOOP_EXIT)
				return NFREAD_LOOP_EXIT;
			flow_record = (common_record_t *)(
			               ((pointer_addr_t)flow_record)
			               + flow_record->size);
		}
	}

	return NFREAD_LOOP_NEXT;
}

__attribute__((visibility("default")))
int
nfread_iterate_filtered(nfread_iterate_cb_t itercb, const char *fltexpr)
{
	extension_map_list_t extmap_list;
	nffile_t *nffile;
	FilterEngine_data_t *fltengine;

	nffile = GetNextFile(NULL, 0, 0);
	if (!nffile) {
		LogError("GetNextFile() error in %s line %d: %s\n",
		         __FILE__, __LINE__, strerror(errno));
		return -1;
	}

	fltengine = fltexpr ? CompileFilter((char*)fltexpr) : NULL;

	InitExtensionMaps(&extmap_list);

	while (nfread_iterate_file(itercb, nffile, fltengine, &extmap_list)
	       == NFREAD_LOOP_NEXT) {
		nffile_t *next = GetNextFile(nffile, 0, 0);
		if (next == EMPTY_LIST) {
			break;
		} else if (next == NULL) {
			itercb(NULL, NFREAD_ERROR,
			       "unexpected end of list");
			break;
		}
	}

	CloseFile(nffile);
	DisposeFile(nffile);
	PackExtensionMapList(&extmap_list);
	return 0;
}

__attribute__((visibility("default")))
int
nfread_init(const char *rfile, const char *Rfile, const char *Mdirs)
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

	SetupInputFileSequence((char*)Mdirs, (char*)rfile, (char*)Rfile);

	return 0;
}

__attribute__((visibility("default")))
void
nfread_fini(void)
{
}

__attribute__((visibility("default")))
unsigned long
nfread_version(void)
{
	return NFREAD_VERSION;
}

__attribute__((visibility("default")))
nffile_t *
nfread_file_open(const char *filename)
{
	return OpenFile((char*)filename, NULL);
}

__attribute__((visibility("default")))
void
nfread_file_close(nffile_t *nffile)
{
	CloseFile(nffile);
	DisposeFile(nffile);
}

__attribute__((visibility("default")))
int
nfread_file_iterate_filtered(nffile_t *nffile, nfread_iterate_cb_t itercb,
                             const char *fltexpr)
{
	extension_map_list_t extmap_list;
	FilterEngine_data_t *fltengine;
	int rv;

	fltengine = fltexpr ? CompileFilter((char*)fltexpr) : NULL;
	InitExtensionMaps(&extmap_list);
	rv = nfread_iterate_file(itercb, nffile, fltengine, &extmap_list);
	PackExtensionMapList(&extmap_list);
	return (rv == NFREAD_LOOP_NEXT) ? 0 : -1;
}


