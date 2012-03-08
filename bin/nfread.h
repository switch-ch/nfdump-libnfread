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

#ifndef NFREAD_C
#include <nfread/config.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#else /* !HAVE_STDINT_H */
typedef unsigned long long      uint64_t;
typedef unsigned long           uint32_t;
typedef unsigned short          uint16_t;
typedef unsigned char           uint8_t;
#endif /* !HAVE_STDINT_H */
#include <nfread/nffile.h>
/* from util.h */
#ifdef WORDS_BIGENDIAN
#       define ntohll(n)        (n)
#       define htonll(n)        (n)
#else
#       define ntohll(n)        (((uint64_t)ntohl(n)) << 32) + ntohl((n) >> 32)
#       define htonll(n)        (((uint64_t)htonl(n)) << 32) + htonl((n) >> 32)
#endif
#endif /* !NFREAD_C */

/*
 * Initialize libnfread using rfile, Rfile and Mdirs configuration.
 * The nfread instance is always global; libnfread cannot be opened multiple
 * times and is not thread-safe.
 *
 * rfile, Rfile and Mdirs are the same as -r -R and -M of the nfdump utility.
 *
 * Returns 0 on success, -1 on failure.
 */
int nfread_init(char *rfile, char *Rfile, char *Mdirs);

/*
 * Deinitialize libnfread.
 */
void nfread_fini(void);

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
 * On success, err is set to NFREAD_SUCCESS and nfrec is a pointer to a
 * read netflow record, and where is NULL.
 * On errors, err is != NFREAD_SUCCESS and where is a pointer to a string
 * indicating which netflow data file was causing the error, and nfrec is NULL.
 * The callback should return either NFREAD_LOOP_NEXT or NFREAD_LOOP_EXIT to
 * signal libnfread whether to continue reading netflow records.
 */
typedef int (*nfread_iterate_cb_t)(const master_record_t *nfrec,
                                   int err, const char *where);

/*
 * Iterate over all netflow records, unpack them, and pass them to
 * nfread_iterate_cb_t.  The _filtered variant additionally filters the
 * flows using an nfdump filter expression.
 */
#define nfread_iterate(cb) nfread_iterate_filtered((cb), NULL)
int nfread_iterate_filtered(nfread_iterate_cb_t itercb, const char *fltexpr);

#endif /* NFREAD_H */

