/* This app includes only public libfabric headers. Loading the softue plugin,
 * registering application memory, progress and completions all use fi_* APIs.
 */
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_atomic.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#condition); return 1; } } while (0)
#define SUCCESS(call) do { int result=(int)(call); if (result) { fprintf(stderr,"FAIL line %d: %s: %d %s\n",__LINE__,#call,result,fi_strerror(-result)); return 1; } } while (0)

int main(int argc,char** argv) {
    CHECK(argc==2);
    const int server=!strcmp(argv[1],"server");
    struct fi_info *hints=fi_allocinfo(),*info=NULL;
    CHECK(hints!=NULL);
    hints->fabric_attr->prov_name=strdup("softue"); hints->ep_attr->type=FI_EP_RDM;
    hints->caps=FI_MSG|FI_RMA|FI_REMOTE_CQ_DATA; hints->addr_format=FI_SOCKADDR_IN;
    hints->domain_attr->mr_mode=~3; // fi_info's supported-mode mask, not required modes.
    SUCCESS(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,hints,&info));
    CHECK(info && !strcmp(info->fabric_attr->prov_name,"softue"));
    CHECK(!(info->caps&(FI_READ|FI_REMOTE_READ|FI_TAGGED)) && (info->caps&FI_ATOMIC));
    CHECK(info->domain_attr->data_progress==FI_PROGRESS_MANUAL);
    CHECK(info->domain_attr->mr_mode==FI_MR_PROV_KEY);
    CHECK(info->domain_attr->mr_key_size==6); // RKEY bytes; fi_mr_key still returns all 64 metadata/key bits.
    struct fi_info *transmit_information=NULL,*unsupported_completion=NULL;
    hints->tx_attr->op_flags=FI_TRANSMIT_COMPLETE;
    SUCCESS(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,hints,&transmit_information));
    CHECK(transmit_information->tx_attr->op_flags==FI_TRANSMIT_COMPLETE); fi_freeinfo(transmit_information);
    hints->tx_attr->op_flags=FI_COMMIT_COMPLETE;
    CHECK(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,hints,&unsupported_completion)==-FI_ENODATA);
    CHECK(!unsupported_completion); hints->tx_attr->op_flags=0;
    CHECK(info->ep_attr->max_msg_size==UINT32_MAX);
    struct fid_fabric *fabric=NULL; struct fid_domain *domain=NULL;
    struct fid_av *addresses=NULL; struct fid_cq *completions=NULL;
    struct fid_ep *endpoint=NULL; struct fid_mr *region=NULL,*local_only=NULL,*atomic_region=NULL;
    SUCCESS(fi_fabric(info->fabric_attr,&fabric,NULL));
    SUCCESS(fi_domain(fabric,info,&domain,NULL));
    CHECK(fi_close(&fabric->fid)==-FI_EBUSY);
    uint8_t buffer[8192]={0},protected_buffer[8]={0};
    uint64_t counters[512]={0},increments[512];
    for (size_t element=0;element<512;++element) increments[element]=1;
    // Register before the endpoint exists: the provider's domain MR registry
    // must be the authority used by the eventual SES endpoint.
    SUCCESS(fi_mr_reg(domain,buffer,sizeof(buffer),FI_SEND|FI_RECV|FI_READ|FI_WRITE|FI_REMOTE_WRITE,0,0,0,&region,NULL));
    SUCCESS(fi_mr_reg(domain,protected_buffer,sizeof(protected_buffer),FI_WRITE,0,0,0,&local_only,NULL));
    SUCCESS(fi_mr_reg(domain,counters,sizeof(counters),FI_ATOMIC|FI_REMOTE_READ|FI_REMOTE_WRITE,
        0,(1ULL<<63)|(1ULL<<62),0,&atomic_region,NULL));
    CHECK((fi_mr_key(atomic_region)&(1ULL<<63)) && !(fi_mr_key(atomic_region)&(1ULL<<62)));
    struct fi_atomic_attr atomic_limits;
    SUCCESS(fi_query_atomic(domain,FI_UINT64,FI_SUM,&atomic_limits,0));
    CHECK(atomic_limits.size==8 && atomic_limits.count>=512);
    CHECK(fi_query_atomic(domain,FI_UINT64,FI_SUM,&atomic_limits,FI_FETCH_ATOMIC)==-FI_EOPNOTSUPP);
    CHECK(fi_mr_key(region)!=fi_mr_key(local_only));
    CHECK(fi_mr_key(region)&(1ULL<<48));
    struct fi_cq_attr queue_attributes={0}; queue_attributes.format=FI_CQ_FORMAT_DATA;
    queue_attributes.size=64; queue_attributes.wait_obj=FI_WAIT_NONE;
    SUCCESS(fi_cq_open(domain,&queue_attributes,&completions,NULL));
    struct fi_av_attr address_attributes={0}; address_attributes.type=FI_AV_TABLE;
    SUCCESS(fi_av_open(domain,&address_attributes,&addresses,NULL));
    SUCCESS(fi_endpoint(domain,info,&endpoint,NULL));
    SUCCESS(fi_ep_bind(endpoint,&addresses->fid,0));
    SUCCESS(fi_ep_bind(endpoint,&completions->fid,FI_TRANSMIT|FI_RECV));
    SUCCESS(fi_enable(endpoint));
    size_t atomic_count=0;
    SUCCESS(fi_atomicvalid(endpoint,FI_UINT64,FI_SUM,&atomic_count)); CHECK(atomic_count>=512);
    CHECK(fi_atomicvalid(endpoint,FI_FLOAT,FI_SUM,&atomic_count)==-FI_EOPNOTSUPP && atomic_count==0);
    CHECK(fi_fetch_atomicvalid(endpoint,FI_UINT64,FI_SUM,&atomic_count)==-FI_EOPNOTSUPP && atomic_count==0);
    CHECK(fi_close(&addresses->fid)==-FI_EBUSY && fi_close(&completions->fid)==-FI_EBUSY);
    struct sockaddr_in local={0}; size_t local_size=sizeof(local);
    SUCCESS(fi_getname(&endpoint->fid,&local,&local_size));
    CHECK(local.sin_family==AF_INET && local.sin_port);
    SUCCESS(fi_recv(endpoint,buffer+(server?5000:0),32,fi_mr_desc(region),FI_ADDR_UNSPEC,(void*)77));
    if (server) {
        SUCCESS(fi_recv(endpoint,buffer+5200,1,NULL,FI_ADDR_UNSPEC,(void*)79));
        SUCCESS(fi_recv(endpoint,buffer+5100,8,NULL,FI_ADDR_UNSPEC,(void*)78));
    }
    fprintf(stderr,"READY %u %llu %llu %llu\n",ntohs(local.sin_port),(unsigned long long)fi_mr_key(region),
        (unsigned long long)fi_mr_key(local_only),(unsigned long long)fi_mr_key(atomic_region)); fflush(stderr);
    unsigned int peer_port=0; unsigned long long peer_key=0,peer_protected_key=0,peer_atomic_key=0;
    CHECK(scanf("%u %llu %llu %llu",&peer_port,&peer_key,&peer_protected_key,&peer_atomic_key)==4);
    struct sockaddr_in peer_address={0}; peer_address.sin_family=AF_INET;
    peer_address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); peer_address.sin_port=htons((uint16_t)peer_port);
    fi_addr_t peer;
    CHECK(fi_av_insert(addresses,&peer_address,1,&peer,0,NULL)==1);
    struct sockaddr_in looked_up={0}; size_t lookup_size=sizeof(looked_up);
    SUCCESS(fi_av_lookup(addresses,peer,&looked_up,&lookup_size)); CHECK(looked_up.sin_port==peer_address.sin_port);
    CHECK(fi_read(endpoint,buffer,1,NULL,peer,0,peer_key,NULL)==-FI_ENOSYS);
    uint8_t oversized_message[1025]; memset(oversized_message,0xaa,sizeof(oversized_message));
    if (!server) {
        for (size_t byte=0;byte<4097;++byte) buffer[16+byte]=(uint8_t)(byte*7);
        SUCCESS(fi_writedata(endpoint,buffer+16,4097,fi_mr_desc(region),123,peer,16,peer_key,(void*)11));
        SUCCESS(fi_atomic(endpoint,increments,512,NULL,peer,0,peer_atomic_key,FI_UINT64,FI_SUM,(void*)17));
        SUCCESS(fi_senddata(endpoint,"abc",3,NULL,456,peer,(void*)12));
        SUCCESS(fi_send(endpoint,oversized_message,sizeof(oversized_message),NULL,peer,(void*)18));
        SUCCESS(fi_write(endpoint,"x",1,NULL,peer,0,0,(void*)13));
        SUCCESS(fi_write(endpoint,"x",1,NULL,peer,0,peer_protected_key,(void*)16));
    }
    size_t send_completions=0,errors=0,receives=0,remote_writes=0;
    int reply_started=0,done_started=0,done_received=0,finished=0;
    const time_t deadline=time(NULL)+10;
    while (!finished && time(NULL)<deadline) {
        struct fi_cq_data_entry entries[8]; ssize_t count=fi_cq_read(completions,entries,8);
        if (count==-FI_EAVAIL) {
            struct fi_cq_err_entry error={0}; CHECK(fi_cq_readerr(completions,&error,0)==1);
            if (server) {
                CHECK(error.op_context==(void*)79 && error.err==FI_ETRUNC && error.prov_errno==7);
                CHECK((error.flags&FI_RECV) && error.len==0 && error.olen==sizeof(oversized_message));
                CHECK(error.buf==buffer+5200 && buffer[5200]==0);
            } else if (error.op_context==(void*)18) CHECK(error.prov_errno==7);
            else {
                CHECK(error.op_context==(void*)13 || error.op_context==(void*)16);
                CHECK(error.err==FI_EACCES && (error.prov_errno==0x1c || error.prov_errno==0x18));
            }
            ++errors;
        } else if (count>0) {
            for (ssize_t index=0;index<count;++index) {
                struct fi_cq_data_entry *entry=&entries[index];
                if ((entry->flags&FI_REMOTE_CQ_DATA) && (entry->flags&FI_REMOTE_WRITE)) {
                    CHECK(server && entry->data==123 && entry->len==4097 && (entry->flags&FI_REMOTE_WRITE));
                    ++remote_writes;
                } else if (entry->flags&FI_RECV) {
                    CHECK(entry->flags&FI_REMOTE_CQ_DATA);
                    if (server && entry->op_context==(void*)78) { CHECK(entry->data==0); done_received=1; }
                    else { CHECK(entry->op_context==(void*)77 && entry->data==(server?456:789)); ++receives; }
                } else { CHECK(entry->flags&(FI_SEND|FI_WRITE)); ++send_completions; }
            }
        } else CHECK(count==-FI_EAGAIN);
        if (server && receives==1 && remote_writes==1 && errors==1 && !reply_started) {
            CHECK(!memcmp(buffer+5000,"abc",3));
            for (size_t byte=0;byte<4097;++byte) CHECK(buffer[16+byte]==(uint8_t)(byte*7));
            for (size_t element=0;element<512;++element) CHECK(counters[element]==1);
            struct iovec reply_buffer={(void*)"reply",5};
            struct fi_msg reply_message={0}; reply_message.msg_iov=&reply_buffer; reply_message.iov_count=1;
            reply_message.addr=peer; reply_message.context=(void*)14; reply_message.data=789;
            SUCCESS(fi_sendmsg(endpoint,&reply_message,FI_REMOTE_CQ_DATA)); reply_started=1;
        }
        if (!server && send_completions==3 && errors==3 && receives==1 && !done_started) {
            CHECK(!memcmp(buffer,"reply",5));
            SUCCESS(fi_senddata(endpoint,"done",4,NULL,0,peer,(void*)15)); done_started=1;
        }
        finished=server?(reply_started && send_completions==1 && done_received):(done_started && send_completions==4);
        if (!finished) poll(NULL,0,1); // Application wait; fi_cq_read owns manual progress.
    }
    if (!finished) fprintf(stderr,"incomplete server=%d sends=%zu errors=%zu receives=%zu remote_writes=%zu\n",
        server,send_completions,errors,receives,remote_writes);
    CHECK(finished);
    for (size_t byte=0;byte<sizeof(protected_buffer);++byte) CHECK(protected_buffer[byte]==0);
    SUCCESS(fi_close(&endpoint->fid)); SUCCESS(fi_close(&region->fid)); SUCCESS(fi_close(&local_only->fid));
    SUCCESS(fi_close(&atomic_region->fid));
    SUCCESS(fi_close(&addresses->fid)); SUCCESS(fi_close(&completions->fid));
    SUCCESS(fi_close(&domain->fid)); SUCCESS(fi_close(&fabric->fid));
    fi_freeinfo(info); fi_freeinfo(hints);
    printf("PASS libfabric %s: SEND/WRITE IMM, bulk integer atomics, checked host buffers and CQ errors\n",server?"server":"client");
    return 0;
}
