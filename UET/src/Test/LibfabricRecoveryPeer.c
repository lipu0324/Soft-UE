/* Two public-API processes: late receives, ordered generation recovery and a
 * bounded failure, followed by RMA through an independent resource index space.
 */
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr,"FAIL recovery line %d: %s\n",__LINE__,#condition); return 1; } } while (0)
#define SUCCESS(call) CHECK((call)==0)
#define LARGE_BYTES (512*1024)

static double monotonic_seconds(void) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC,&now);
    return (double)now.tv_sec+(double)now.tv_nsec/1e9;
}

int main(int argc,char** argv) {
    CHECK(argc==2); const int server=!strcmp(argv[1],"server");
    const char* ordering_setting=getenv("SOFTUE_RECOVERY_ORDERED");
    const int ordered=!ordering_setting || strcmp(ordering_setting,"0");
    const char* rendezvous_setting=getenv("SOFTUE_RECOVERY_RENDEZVOUS");
    const int rendezvous=rendezvous_setting && strcmp(rendezvous_setting,"0");
    const int expected_provider_error=rendezvous?0:(ordered?4:5);
    struct fi_info *hints=fi_allocinfo(),*info=NULL; CHECK(hints);
    hints->fabric_attr->prov_name=strdup("softue"); hints->ep_attr->type=FI_EP_RDM;
    hints->caps=FI_MSG|FI_RMA; hints->addr_format=FI_SOCKADDR_IN;
    hints->tx_attr->msg_order=hints->rx_attr->msg_order=ordered?FI_ORDER_SAS:FI_ORDER_NONE;
    SUCCESS(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,hints,&info));
    CHECK(info->tx_attr->msg_order==hints->tx_attr->msg_order);
    struct fid_fabric *fabric; struct fid_domain *domain; struct fid_ep *endpoint;
    struct fid_cq *queue; struct fid_av *addresses; struct fid_mr *control_region;
    SUCCESS(fi_fabric(info->fabric_attr,&fabric,NULL)); SUCCESS(fi_domain(fabric,info,&domain,NULL));
    struct fi_cq_attr queue_attributes={0}; queue_attributes.format=FI_CQ_FORMAT_DATA; queue_attributes.wait_obj=FI_WAIT_NONE;
    SUCCESS(fi_cq_open(domain,&queue_attributes,&queue,NULL));
    struct fi_av_attr address_attributes={0}; address_attributes.type=FI_AV_TABLE;
    SUCCESS(fi_av_open(domain,&address_attributes,&addresses,NULL));
    char control_buffer[8]={0},small_buffer[16]={0},reply_buffer[16]={0};
    uint8_t *large_buffer=calloc(1,LARGE_BYTES); CHECK(large_buffer);
    SUCCESS(fi_mr_reg(domain,control_buffer,sizeof(control_buffer),FI_REMOTE_WRITE,0,0,0,&control_region,NULL));
    SUCCESS(fi_endpoint(domain,info,&endpoint,NULL));
    SUCCESS(fi_ep_bind(endpoint,&queue->fid,FI_TRANSMIT|FI_RECV));
    SUCCESS(fi_ep_bind(endpoint,&addresses->fid,0)); SUCCESS(fi_enable(endpoint));
    if (!server) SUCCESS(fi_recv(endpoint,reply_buffer,sizeof(reply_buffer),NULL,FI_ADDR_UNSPEC,(void*)20));
    struct sockaddr_in local={0}; size_t local_size=sizeof(local);
    SUCCESS(fi_getname(&endpoint->fid,&local,&local_size));
    fprintf(stderr,"READY %u %llu\n",ntohs(local.sin_port),(unsigned long long)fi_mr_key(control_region)); fflush(stderr);
    unsigned int peer_port=0; unsigned long long peer_key=0;
    CHECK(scanf("%u %llu",&peer_port,&peer_key)==2);
    struct sockaddr_in remote={0}; remote.sin_family=AF_INET; remote.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    remote.sin_port=htons((uint16_t)peer_port); fi_addr_t peer;
    CHECK(fi_av_insert(addresses,&remote,1,&peer,0,NULL)==1);
    if (!server) {
        for (size_t byte=0;byte<LARGE_BYTES;++byte) large_buffer[byte]=(uint8_t)(byte*7+1);
        memset(small_buffer,0x66,sizeof(small_buffer));
        SUCCESS(fi_send(endpoint,large_buffer,LARGE_BYTES,NULL,peer,(void*)1));
        SUCCESS(fi_send(endpoint,small_buffer,sizeof(small_buffer),NULL,peer,(void*)2));
    }
    size_t sends=0,receives=0,errors=0;
    int posted=0,replied=0,failure_started=0,done_started=0,done_received=0;
    const double started=monotonic_seconds();
    int finished=0;
    while (!finished && monotonic_seconds()-started<12) {
        // Ordinary ROD exceeds the payload budget; ordinary RUD has NO_MATCH.
        // Rendezvous instead captures a header until this late posting.
        if (server && !posted && monotonic_seconds()-started>0.080) {
            SUCCESS(fi_recv(endpoint,large_buffer,LARGE_BYTES,NULL,FI_ADDR_UNSPEC,(void*)11));
            SUCCESS(fi_recv(endpoint,small_buffer,sizeof(small_buffer),NULL,FI_ADDR_UNSPEC,(void*)12));
            posted=1;
        }
        struct fi_cq_data_entry entries[8]; const ssize_t count=fi_cq_read(queue,entries,8);
        if (count==-FI_EAVAIL) {
            struct fi_cq_err_entry error={0}; CHECK(fi_cq_readerr(queue,&error,0)==1);
            // Preserve the first protocol/application failure before CHECK's
            // early exit can produce a much longer sanitizer cleanup report.
            if (server || !failure_started || error.op_context!=(void*)3 ||
                error.prov_errno!=expected_provider_error || errors)
                fprintf(stderr,"unexpected recovery CQ error server=%d context=%llu err=%d provider=%d "
                    "flags=%llu sends=%zu receives=%zu errors=%zu failure_started=%d elapsed=%.6f\n",
                    server,(unsigned long long)(uintptr_t)error.op_context,error.err,error.prov_errno,
                    (unsigned long long)error.flags,sends,receives,errors,failure_started,monotonic_seconds()-started);
            CHECK(!server && failure_started && error.op_context==(void*)3 && error.prov_errno==expected_provider_error && !errors);
            if (rendezvous) CHECK(error.err==FI_ETIMEDOUT);
            ++errors;
        } else if (count>0) for (ssize_t index=0;index<count;++index) {
            const struct fi_cq_data_entry *entry=&entries[index];
            if (entry->flags&FI_REMOTE_CQ_DATA) {
                CHECK(server && entry->data==99 && entry->len==4 && (entry->flags&FI_REMOTE_WRITE));
                CHECK(!memcmp(control_buffer,"done",4)); done_received=1;
            } else if (entry->flags&FI_RECV) {
                if (server) {
                    CHECK(entry->op_context==(receives?(void*)12:(void*)11));
                    CHECK(entry->len==(receives?sizeof(small_buffer):LARGE_BYTES));
                } else CHECK(entry->op_context==(void*)20 && entry->len==5 && !memcmp(reply_buffer,"reply",5));
                ++receives;
            } else ++sends;
        } else CHECK(count==-FI_EAGAIN);
        if (server && receives==2 && !replied) {
            for (size_t byte=0;byte<LARGE_BYTES;++byte) CHECK(large_buffer[byte]==(uint8_t)(byte*7+1));
            for (size_t byte=0;byte<sizeof(small_buffer);++byte) CHECK((uint8_t)small_buffer[byte]==0x66);
            SUCCESS(fi_send(endpoint,"reply",5,NULL,peer,(void*)30)); replied=1;
        }
        if (!server && sends==2 && receives==1 && !failure_started) {
            // No further receive is posted. Ordinary SEND exhausts its retry
            // policy; rendezvous reaches its single transaction deadline.
            // Each policy returns exactly one final application error.
            SUCCESS(fi_send(endpoint,large_buffer,LARGE_BYTES,NULL,peer,(void*)3)); failure_started=1;
        }
        if (!server && errors==1 && !done_started) {
            free(large_buffer); large_buffer=NULL; // Final error permits buffer reuse while cached protocol cleanup drains.
            // SEND exhaustion must not disable the independent RMA space.
            SUCCESS(fi_writedata(endpoint,"done",4,NULL,99,peer,0,peer_key,(void*)4)); done_started=1;
        }
        finished=server?(replied && sends==1 && done_received):(done_started && sends==3 && receives==1 && errors==1);
        if (!finished) poll(NULL,0,1); // Application wait, outside the protocol kernel.
    }
    if (!finished) fprintf(stderr,"recovery incomplete server=%d sends=%zu receives=%zu errors=%zu posted=%d\n",server,sends,receives,errors,posted);
    CHECK(finished);
    SUCCESS(fi_close(&endpoint->fid)); SUCCESS(fi_close(&control_region->fid));
    SUCCESS(fi_close(&addresses->fid)); SUCCESS(fi_close(&queue->fid)); SUCCESS(fi_close(&domain->fid)); SUCCESS(fi_close(&fabric->fid));
    fi_freeinfo(info); fi_freeinfo(hints); free(large_buffer);
    printf("PASS libfabric %s recovery %s: late receives, bounded failure and independent RMA\n",ordered?"ROD":"RUD",server?"server":"client");
    return 0;
}
