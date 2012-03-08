/*
 * gcc -I/usr/local/include -L/usr/local/lib -o nfreadex nfreadex.c -lnfread
 */

#include <nfread/nfread.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int
dumper(const master_record_t *nfrec_ro, int error, const char *where)
{
	char as[40], ds[40], datestr1[64], datestr2[64];
	time_t when;
	struct tm *ts;
	master_record_t *nfrec = (master_record_t*)nfrec_ro;

	if (error != NFREAD_SUCCESS) {
		fprintf(stderr, "Error in data file '%s'\n", where);
		return NFREAD_LOOP_EXIT;
	}

	if ((nfrec->flags & FLAG_IPV6_ADDR) != 0) {
		nfrec->v6.srcaddr[0] = htonll(nfrec->v6.srcaddr[0]);
		nfrec->v6.srcaddr[1] = htonll(nfrec->v6.srcaddr[1]);
		nfrec->v6.dstaddr[0] = htonll(nfrec->v6.dstaddr[0]);
		nfrec->v6.dstaddr[1] = htonll(nfrec->v6.dstaddr[1]);
		inet_ntop(AF_INET6, nfrec->v6.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET6, nfrec->v6.dstaddr, ds, sizeof(ds));
	} else {
		nfrec->v4.srcaddr = htonl(nfrec->v4.srcaddr);
		nfrec->v4.dstaddr = htonl(nfrec->v4.dstaddr);
		inet_ntop(AF_INET, &nfrec->v4.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET, &nfrec->v4.dstaddr, ds, sizeof(ds));
	}
	as[40-1] = 0;
	ds[40-1] = 0;

	when = nfrec->first;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = nfrec->last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	fprintf(stdout, "Flow Record:\n"
	                "  srcaddr     = %16s\n"
	                "  dstaddr     = %16s\n"
	                "  first       =       %10u [%s]\n"
	                "  last        =       %10u [%s]\n"
	                "  msec_first  =            %5u\n"
	                "  msec_last   =            %5u\n"
	                "  prot        =              %3u\n"
	                "  srcport     =            %5u\n"
	                "  dstport     =            %5u\n"
	                "  dPkts       =       %10llu\n"
	                "  dOctets     =       %10llu\n",
	                as, ds, nfrec->first, datestr1, nfrec->last, datestr2,
	                nfrec->msec_first, nfrec->msec_last, nfrec->prot,
	                nfrec->srcport, nfrec->dstport,
	                (unsigned long long)nfrec->dPkts,
	                (unsigned long long)nfrec->dOctets);

	return NFREAD_LOOP_NEXT;
}

int
main(int argc, char *argv[])
{
	if (!argv[1]) {
		fprintf(stderr, "Usage: %s basedir\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	nfread_init(NULL, ".", argv[1]); /* -M basedir -R . */
	nfread_iterate(dumper);
	nfread_fini();

	return EXIT_SUCCESS;
}


