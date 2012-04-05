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
 */

#ifndef NFREAD_H
#define NFREAD_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef NFREAD_C
#include "nfread-config.h"
#else /* !NFREAD_C */
#include <nfread/nfread-config.h>
/* useful parts from util.h */
#ifdef NFREAD_WORDS_BIGENDIAN
#       define ntohll(n)        (n)
#       define htonll(n)        (n)
#else /* !NFREAD_WORDS_BIGENDIAN */
#       define ntohll(n)        (((uint64_t)ntohl(n)) << 32) + ntohl((n) >> 32)
#       define htonll(n)        (((uint64_t)htonl(n)) << 32) + htonl((n) >> 32)
#endif /* !NFREAD_WORDS_BIGENDIAN */
#endif /* !NFREAD_C */

/*
 * Version of libnfread.
 * 0xAABBCCDD where AA.BB.CC is nfdump version, DD is libnfread revision.
 * Use NFREAD_VERSION to determine the version at build-time and
 * nfread_version() at run-time.
 */
#define NFREAD_VERSION          0x01060505UL
unsigned long nfread_version(void) __attribute__((const));

/*
 * Error codes passed to nfread_iterate_cb_t's err argument.
 */
#define NFREAD_SUCCESS          0       /* success; nfrec contains record */
#define NFREAD_ERROR            1       /* unspecified error while reading */
#define NFREAD_ECORRUPT         2       /* corrupt data file */
#define NFREAD_EBLKTYPE         3       /* unknown block type */
#define NFREAD_ERECTYPE         4       /* unknown record type */

/*
 * Possible return values from nfread_iterate_cb_t's.
 */
#define NFREAD_LOOP_NEXT        0       /* continue with next record */
#define NFREAD_LOOP_EXIT        1       /* exit the loop and finish */

/*
 * Iterator callback type.
 *
 * On success, err is set to NFREAD_SUCCESS and nfrec is a pointer to a
 * read netflow record, and where is NULL.
 *
 * On errors, err is != NFREAD_SUCCESS and where is a pointer to a string
 * indicating which netflow data file was causing the error, and nfrec is NULL.
 *
 * The callback should return either NFREAD_LOOP_NEXT or NFREAD_LOOP_EXIT to
 * signal libnfread whether to continue reading netflow records.
 *
 * Arg is the pointer passed to the call to one of the iterate() functions
 * and can be NULL.
 */
typedef int (*nfread_iterate_cb_t)(const master_record_t *nfrec,
                                   int err, const char *where,
                                   void *arg);


/*
 * Initialize the global file set using rfile, Rfile and Mdirs configuration.
 * The nfread instance is always global; libnfread cannot be opened multiple
 * times and is not thread-safe.
 *
 * rfile, Rfile and Mdirs are the same as -r -R and -M of the nfdump utility.
 *
 * Returns 0 on success, -1 on failure.
 */
int nfread_init(const char *rfile, const char *Rfile, const char *Mdirs);

/*
 * Deinitialize libnfread after initialization using nfread_init().
 */
void nfread_fini(void);

/*
 * Iterate over all netflow records in the global file set, unpack them,
 * and pass them to the provided callback function.
 *
 * The provided opaque pointer argument arg is passed to the iterator callback
 * and can be used to pass context to the callbacks.  It can be NULL.
 *
 * If fltexpr is non-NULL, filter flows and only pass flows matching the
 * nfdump filterexpression to the callback.  If it is NULL, all flows are
 * passed to the callback.
 *
 * Returns -1 if the loop was aborted for some reason, 0 if not.
 */
int nfread_iterate(nfread_iterate_cb_t itercb, void *arg, const char *fltexpr)
                   __attribute__((nonnull(1)));


/*
 * Open a specific file containing netflow data by name independent of the
 * global file set.
 */
nffile_t * nfread_file_open(const char *filename) __attribute__((malloc));

/*
 * Close a specific file opened previously by nfread_file_open().
 */
void nfread_file_close(nffile_t *nffile) __attribute__((nonnull));

/*
 * Iterate over all netflow records in a file, unpack them, and pass them to
 * the provided callback function.
 *
 * The provided opaque pointer argument arg is passed to the iterator callback
 * and can be used to pass context to the callbacks.  It can be NULL.
 *
 * If fltexpr is non-NULL, filter flows and only pass flows matching the
 * nfdump filterexpression to the callback.  If it is NULL, all flows are
 * passed to the callback.
 *
 * Returns -1 if the loop was aborted for some reason, 0 if not.
 */
int nfread_file_iterate(nffile_t *nffile, nfread_iterate_cb_t itercb,
                        void *arg, const char *fltexpr)
                        __attribute__((nonnull(1,2)));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NFREAD_H */

