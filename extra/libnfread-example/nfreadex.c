/*
 * gcc -I/usr/local/include -L/usr/local/lib -o nfreadex nfreadex.c -lnfread
 */

#include <nfread/nfread.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int
dumper(const master_record_t *nfrec, int error, const char *where)
{
	char srcaddrstr[40], dstaddrstr[40], firstdatestr[64], lastdatestr[64];
	uint64_t srcaddr6[2], dstaddr6[2];
	uint32_t srcaddr, dstaddr;
	time_t when;
	struct tm *ts;
	int rv;

	if (error != NFREAD_SUCCESS) {
		fprintf(stderr, "Error in data file '%s'\n", where);
		return NFREAD_LOOP_EXIT;
	}

	if ((nfrec->flags & FLAG_IPV6_ADDR) != 0) {
		srcaddr6[0] = htonll(nfrec->v6.srcaddr[0]);
		srcaddr6[1] = htonll(nfrec->v6.srcaddr[1]);
		dstaddr6[0] = htonll(nfrec->v6.dstaddr[0]);
		dstaddr6[1] = htonll(nfrec->v6.dstaddr[1]);
		inet_ntop(AF_INET6, srcaddr6, srcaddrstr, sizeof(srcaddrstr));
		inet_ntop(AF_INET6, dstaddr6, dstaddrstr, sizeof(dstaddrstr));
	} else {
		srcaddr = htonl(nfrec->v4.srcaddr);
		dstaddr = htonl(nfrec->v4.dstaddr);
		inet_ntop(AF_INET, &srcaddr, srcaddrstr, sizeof(srcaddrstr));
		inet_ntop(AF_INET, &dstaddr, dstaddrstr, sizeof(dstaddrstr));
	}

	when = nfrec->first;
	ts = localtime(&when);
	rv = strftime(firstdatestr, sizeof(firstdatestr),
	              "%Y-%m-%d %H:%M:%S", ts);
	assert(rv);

	when = nfrec->last;
	ts = localtime(&when);
	rv = strftime(lastdatestr, sizeof(lastdatestr),
	              "%Y-%m-%d %H:%M:%S", ts);
	assert(rv);

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
	                srcaddrstr, dstaddrstr,
	                nfrec->first, firstdatestr, nfrec->last, lastdatestr,
	                nfrec->msec_first, nfrec->msec_last,
	                nfrec->prot,
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

	printf("compiled against libnfread 0x%08lx\n", NFREAD_VERSION);
	printf("rtlinked against libnfread 0x%08lx\n", nfread_version());

	nfread_init(NULL, ".", argv[1]); /* -M basedir -R . */

	printf("All flows:\n");
	nfread_iterate(dumper);

	printf("Flows with src or dst port 53:\n");
	nfread_iterate_filtered(dumper, "port 53");

	nfread_fini();
	return EXIT_SUCCESS;
}


