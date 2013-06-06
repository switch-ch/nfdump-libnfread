/*
 *  Copyright (c) 2011, Peter Haag
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>

#include "rbtree.h"
#include "util.h"
#include "nffile.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "flowtree.h"
#include "netflow_pcap.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

static int FlowNodeCMP(struct FlowNode *e1, struct FlowNode *e2);

// Insert the IP RB tree code here
RB_GENERATE(FlowTree, FlowNode, entry, FlowNodeCMP);

// Flow Cache to store all nodes
#define FLOWELEMENTNUM 1024 * 1024
//#define FLOWELEMENTNUM 128
static struct FlowNode *FlowElementCache;

// free list 
static struct FlowNode *FlowNode_FreeList;
static pthread_mutex_t m_FreeList = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  c_FreeList = PTHREAD_COND_INITIALIZER;
static uint32_t	CacheOverflow;
static uint32_t	Allocated;

// Flow tree
static FlowTree_t *FlowTree;
static int NumFlows;

// Simple unprotected list
typedef struct FlowNode_list_s {
	struct FlowNode *list;
	struct FlowNode *tail;
	uint32_t	size;
} Linked_list_t;

static Linked_list_t UDP_list;

/* static prototypes */
static void AppendFlowNode(Linked_list_t *LinkedList, struct FlowNode *node);

static void DisconnectFlowNode(Linked_list_t *LinkedList, struct FlowNode *node);

static void TouchFlowNode(Linked_list_t *LinkedList, struct FlowNode *node);

/* Free list handling functions */
// Get next free node from free list
struct FlowNode *New_Node(void) {
struct FlowNode *node;

/*
	node = calloc(1, sizeof(struct FlowNode));
	return node;
*/

	pthread_mutex_lock(&m_FreeList);
    while ( FlowNode_FreeList == NULL ) {
		CacheOverflow++;
		dbg_printf("Free list exhausted: %u, Flows: %u - sleep\n", Allocated, NumFlows);
        pthread_cond_wait(&c_FreeList, &m_FreeList);
	}

	node = FlowNode_FreeList;
	if ( node == NULL ) {
		// should never happen , as we were waiting for a free node
		LogError("*** Software ERROR *** New_Node() unexpected error in %s line %d: %s: %u\n", 
			__FILE__, __LINE__, "Node list exhausted", NumFlows);
		pthread_mutex_unlock(&m_FreeList);
		return NULL;
	}
	if ( node->memflag != NODE_FREE ) {
		LogError("*** Software ERROR *** New_Node() unexpected error in %s line %d: %s\n", 
			__FILE__, __LINE__, "Tried to allocate a non free Node");
		abort();
	}

	FlowNode_FreeList = node->right;
	Allocated++;
	pthread_mutex_unlock(&m_FreeList);

	node->left = NULL;
	node->right = NULL;
	node->memflag = NODE_IN_USE;

	return node;

} // End of New_node

// return node into free list
void Free_Node(struct FlowNode *node) {

	if ( node->memflag == NODE_FREE ) {
		LogError("Free_Node() Fatal: Tried to free an already freed Node");
		abort();
	}

	if ( node->memflag != NODE_IN_USE ) {
		LogError("Free_Node() Fatal: Tried to free a Node not in use");
		abort();
	}

	if ( node->data )
		free(node->data);

/*
	free(node);
	return;
*/
	memset((void *)node, 0, sizeof(struct FlowNode));

	pthread_mutex_lock(&m_FreeList);
	node->right = FlowNode_FreeList;
	node->left  = NULL;
	node->memflag = NODE_FREE;
	FlowNode_FreeList = node;
	Allocated--;
	pthread_mutex_unlock(&m_FreeList);
	pthread_cond_signal(&c_FreeList);

} // End of Free_Node

/* safety check - this must never become 0 - otherwise the cache is too small */
uint32_t CacheCheck(void) {
	return FLOWELEMENTNUM - NumFlows;
} // End of CacheCheck

/* flow tree functions */
int Init_FlowTree(uint32_t CacheSize) {
int i;

	FlowTree = malloc(sizeof(FlowTree_t));
	if ( !FlowTree ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	RB_INIT(FlowTree);

	if ( CacheSize == 0 )
		CacheSize = FLOWELEMENTNUM;
	FlowElementCache = calloc(CacheSize, sizeof(struct FlowNode));
	if ( !FlowElementCache ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		free(FlowTree);
		FlowTree = NULL;
		return 0;
	}

	// init free list
	FlowNode_FreeList 		   = FlowElementCache;
	FlowNode_FreeList->left    = NULL;
	FlowNode_FreeList->right   = &FlowElementCache[1];
	FlowNode_FreeList->memflag = NODE_FREE;
	for (i=1; i < (CacheSize-1); i++ ) {
		FlowElementCache[i].memflag = NODE_FREE;
		FlowElementCache[i].left  = &FlowElementCache[i-1];
		FlowElementCache[i].right = &FlowElementCache[i+1];
	}
	FlowElementCache[i].left  	= &FlowElementCache[i-1];
	FlowElementCache[i].right 	= NULL;
	FlowElementCache[i].memflag = NODE_FREE;

	CacheOverflow = 0;
	Allocated 	  = 0;
	NumFlows 	  = 0;

	UDP_list.list	= NULL;
	UDP_list.tail	= NULL;
	UDP_list.size	= 0;

	return 1;
} // End of Init_FlowTree

void Dispose_FlowTree(void) {
struct FlowNode *node, *nxt;

	// Dump all incomplete flows to the file
	for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
		nxt = RB_NEXT(FlowTree, FlowTree, node);
		RB_REMOVE(FlowTree, FlowTree, node);
		if ( node->data ) 
			free(node->data);
	}
	free(FlowElementCache);
	FlowElementCache 	 = NULL;
	FlowNode_FreeList 	 = NULL;
	CacheOverflow = 0;

} // End of Dispose_FlowTree

static int FlowNodeCMP(struct FlowNode *e1, struct FlowNode *e2) {
uint64_t    *a = e1->src_addr.v6;
uint64_t    *b = e2->src_addr.v6;
int i;
   
	// 2 x sizeof(ip_addr_t) (32) + proto, ports (6)
	i = memcmp((void *)a, (void *)b, 38 );
	return i; 
 
} // End of FlowNodeCMP

struct FlowNode *Lookup_Node(struct FlowNode *node) {
	return RB_FIND(FlowTree, FlowTree, node);
} // End of Lookup_FlowTree

struct FlowNode *Insert_Node(struct FlowNode *node) {
struct FlowNode *n;

	// return RB_INSERT(FlowTree, FlowTree, node);
	n = RB_INSERT(FlowTree, FlowTree, node);
	if ( n ) { // existing node
		return n;
	} else {
		NumFlows++;
		return NULL;
	}
} // End of Lookup_FlowTree

void Remove_Node(struct FlowNode *node) {

#ifdef DEVEL
	if ( NumFlows == 0 ) {
		LogError("Remove_Node() Fatal Tried to remove a Node from empty tree");
		return;
	}
#endif

	RB_REMOVE(FlowTree, FlowTree, node);
	Free_Node(node);
	NumFlows--;

} // End of Lookup_FlowTree

uint32_t Flush_FlowTree(FlowSource_t *fs) {
struct FlowNode *node, *nxt;
uint32_t n = NumFlows;

	// Dump all incomplete flows to the file
	for (node = RB_MIN(FlowTree, FlowTree); node != NULL; node = nxt) {
		StorePcapFlow(fs, node);
		nxt = RB_NEXT(FlowTree, FlowTree, node);
		Remove_Node(node);
	}

#ifdef DEVEL
	if ( NumFlows != 0 )
		LogError("### Flush_FlowTree() remaining flows: %u\n", NumFlows);
#endif

	UDP_list.list	= NULL;
	UDP_list.tail	= NULL;
	UDP_list.size	= 0;

	return n;

} // End of Flush_FlowTree

void UDPexpire(FlowSource_t *fs, time_t t_expire) {
struct FlowNode  *node;
uint32_t num = 0;

	node = UDP_list.list;
	while ( node && (node->t_last.tv_sec < t_expire) ) {
		struct FlowNode  *n = node;
		node = node->right;
		DisconnectFlowNode(&UDP_list, n);
		StorePcapFlow(fs, n);
		Remove_Node(n);
		num++;
	}
	dbg_printf("UDP expired %u flows - left %u\n", num, UDP_list.size);

} // End of UDPexpire

void AppendUDPNode(struct FlowNode *node) {
	AppendFlowNode(&UDP_list, node);
} // End of AppendUDPNode

static void AppendFlowNode(Linked_list_t *LinkedList, struct FlowNode *node) {
	
	if ( LinkedList->list == NULL ) {
		dbg_printf("AppendFlowNode(): First node\n");
		node->left  = NULL;
		node->right = NULL;
		LinkedList->list = node;
		LinkedList->tail = node;
		LinkedList->size++;
	} else {
		// new node 
		LinkedList->tail->right = node;
		node->left = LinkedList->tail;
		node->right = NULL;
		LinkedList->tail = node;
		LinkedList->size++;
	} // else 

} // End of AppendFlowNode


static void DisconnectFlowNode(Linked_list_t *LinkedList, struct FlowNode *node) {
	
	if ( node == NULL ) 
		return;

	else {
		// disconnect node 
		struct FlowNode *prev = node->left;
		struct FlowNode *next = node->right;
		if ( prev )
			prev->right = next;
		else
			LinkedList->list = next;

		if ( next ) 
			next->left  = prev;

		if ( LinkedList->tail == node )
			LinkedList->tail = node->left;

		LinkedList->size--;

	}

} // End of DisconnectFlowNode

void TouchUDPNode(struct FlowNode *node) {
	TouchFlowNode(&UDP_list, node);
} // End of AppendUDPNode

static void TouchFlowNode(Linked_list_t *LinkedList, struct FlowNode *node) {
	
	dbg_printf("In TochFlowNode()\n");
	if ( LinkedList->list == NULL ) {
		// should never happen
		LogError("TouchFlowNode() error in %s line %d: %s\n", __FILE__, __LINE__, "Tried to touch node in empty list" );
		return;
	}

	if ( LinkedList->tail == node ) {
		// nothing to do
		dbg_printf("TochFlowNode() - last node - nothing to do\n");
		return;
	}

	if ( node->left == NULL ) {
		// first node - disconnect node
		dbg_printf("TochFlowNode() - touch first node\n");
		LinkedList->list = node->right;
		LinkedList->list->left = NULL;
	} else {
		dbg_printf("TochFlowNode() - touch middle node\n");
		(node->right)->left = node->left;
		(node->left)->right = node->right;
	}

	// append node
	LinkedList->tail->right = node;
	node->left = LinkedList->tail;
	node->right = NULL;
	LinkedList->tail = node;

} // End of TouchFlowNode

int AddNodeData(struct FlowNode *node, uint32_t seq, void *payload, uint32_t size) {

	return 0;
} // End of AddNodeData

/* Node list functions */
NodeList_t *NewNodeList(void) {
NodeList_t *NodeList;

	NodeList = (NodeList_t *)malloc(sizeof(NodeList_t));
	if ( !NodeList ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	NodeList->list 		= NULL;
	NodeList->last 		= NULL;
	NodeList->length	= 0;
	pthread_mutex_init(&NodeList->m_list, NULL);
	pthread_cond_init(&NodeList->c_list, NULL);

	return NodeList;

} // End of NewNodeList

void DisposeNodeList(NodeList_t *NodeList) {

	if ( !NodeList )
		return;

	if ( NodeList->length ) {
		LogError("Try to free non empty NodeList");
		return;
	}
 	free(NodeList);

} // End of DisposeNodeList

void Push_Node(NodeList_t *NodeList, struct FlowNode *node) {

	pthread_mutex_lock(&NodeList->m_list);
	if ( NodeList->length == 0 ) {
		// empty list
		NodeList->list = node;
		node->left = NULL;
		node->right = NULL;
	} else {
		NodeList->last->right = node;
		node->left = NodeList->last;
	}
	NodeList->last = node;
	NodeList->length++;
	dbg_printf("pushed node 0x%llx %u left\n", (unsigned long long)node, NodeList->length);
 	pthread_mutex_unlock(&NodeList->m_list);
	pthread_cond_signal(&NodeList->c_list);

} // End of Push_Node

struct FlowNode *Pop_Node(NodeList_t *NodeList, int *done) {
struct FlowNode *node;

	pthread_mutex_lock(&NodeList->m_list);
    while ( NodeList->length == 0 && !*done ) 
        pthread_cond_wait(&NodeList->c_list, &NodeList->m_list);

	if ( NodeList->length == 0 && *done ) {
 		pthread_mutex_unlock(&NodeList->m_list);
		dbg_printf("Pop_Node done\n");
		return NULL;
	}

	if ( NodeList->list == NULL ) { 
		// should never happen - list is supposed to have at least one item
 		pthread_mutex_unlock(&NodeList->m_list);
		LogError("Unexpected empty FlowNode_ProcessList");
		return NULL;
	}

	node = NodeList->list;
	NodeList->list = node->right;
	if ( NodeList->list ) 
		NodeList->list->left = NULL;
	else 
		NodeList->last = NULL;

	NodeList->length--;
	dbg_printf("Poped node 0x%llx %u left\n", (unsigned long long)node, NodeList->length);
 	pthread_mutex_unlock(&NodeList->m_list);

	return node;
} // End of Pop_Node

void DumpList(NodeList_t *NodeList) {
struct FlowNode *node;

	printf("FlowNode_ProcessList: 0x%llx\n", (unsigned long long)NodeList->list);
	node = NodeList->list;
	while ( node ) {
		printf("node: 0x%llx\n", (unsigned long long)node);
		printf("  ->left: 0x%llx\n", (unsigned long long)node->left);
		printf("  ->right: 0x%llx\n", (unsigned long long)node->right);
		node = node->right;
	}
	printf("tail: 0x%llx\n\n", (unsigned long long)NodeList->last);
} // End of DumpList

void DumpNodeStat(void) {
	LogInfo("Nodes in use: %u, Flows: %u CacheOverflow: %u", Allocated, NumFlows, CacheOverflow);
} // End of NodesAllocated

/*
int main(int argc, char **argv) {

	
	return 0;
} // End of main
*/
