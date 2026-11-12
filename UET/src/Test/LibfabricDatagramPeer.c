/* Public libfabric API test for the distinct, unreliable UUD/DGRAM path. */
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr,"FAIL DGRAM line %d: %s\n",__LINE__,#condition); return 1; } } while (0)
#define SUCCESS(call) CHECK((call)==0)

int main(int argc,char** argv) {
    CHECK(argc==2); const int server=!strcmp(argv[1],"server");
    struct fi_info *hints=fi_allocinfo(),*info=NULL;
    CHECK(hints); hints->fabric_attr->prov_name=strdup("softue"); hints->ep_attr->type=FI_EP_DGRAM;
    hints->caps=FI_MSG; hints->addr_format=FI_SOCKADDR_IN;
    SUCCESS(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,hints,&info));
    CHECK(info && info->ep_attr->type==FI_EP_DGRAM && info->ep_attr->max_msg_size==1024);
    CHECK(!(info->caps&(FI_RMA|FI_ATOMIC)) && info->tx_attr->msg_order==FI_ORDER_NONE);
    CHECK(info->tx_attr->op_flags==FI_TRANSMIT_COMPLETE);
    struct fid_fabric *fabric; struct fid_domain *domain;
    struct fid_cq *queue; struct fid_av *addresses; struct fid_ep *endpoint;
    SUCCESS(fi_fabric(info->fabric_attr,&fabric,NULL)); SUCCESS(fi_domain(fabric,info,&domain,NULL));
    struct fi_cq_attr queue_attributes={0}; queue_attributes.format=FI_CQ_FORMAT_DATA; queue_attributes.wait_obj=FI_WAIT_NONE;
    SUCCESS(fi_cq_open(domain,&queue_attributes,&queue,NULL));
    struct fi_av_attr address_attributes={0}; address_attributes.type=FI_AV_TABLE;
    SUCCESS(fi_av_open(domain,&address_attributes,&addresses,NULL));
    SUCCESS(fi_endpoint(domain,info,&endpoint,NULL));
    SUCCESS(fi_ep_bind(endpoint,&queue->fid,FI_TRANSMIT|FI_RECV));
    SUCCESS(fi_ep_bind(endpoint,&addresses->fid,0)); SUCCESS(fi_enable(endpoint));
    uint8_t receive_buffer[1024]={0},send_buffer[1025];
    for (size_t byte=0;byte<sizeof(send_buffer);++byte) send_buffer[byte]=(uint8_t)(byte*3);
    SUCCESS(fi_recv(endpoint,receive_buffer,sizeof(receive_buffer),NULL,FI_ADDR_UNSPEC,(void*)1));
    struct sockaddr_in local={0}; size_t local_size=sizeof(local);
    SUCCESS(fi_getname(&endpoint->fid,&local,&local_size));
    fprintf(stderr,"READY %u\n",ntohs(local.sin_port)); fflush(stderr);
    unsigned int peer_port=0; CHECK(scanf("%u",&peer_port)==1);
    struct sockaddr_in remote={0}; remote.sin_family=AF_INET; remote.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    remote.sin_port=htons((uint16_t)peer_port); fi_addr_t peer;
    CHECK(fi_av_insert(addresses,&remote,1,&peer,0,NULL)==1);
    CHECK(fi_send(endpoint,send_buffer,1025,NULL,peer,NULL)==-FI_EMSGSIZE);
    if (!server) SUCCESS(fi_send(endpoint,send_buffer,1024,NULL,peer,(void*)2));
    int sent=0,received=0,reply_started=0;
    const time_t deadline=time(NULL)+8;
    while ((!sent || !received) && time(NULL)<deadline) {
        struct fi_cq_data_entry entries[4]; const ssize_t count=fi_cq_read(queue,entries,4);
        if (count>0) for (ssize_t index=0;index<count;++index) {
            const struct fi_cq_data_entry *entry=&entries[index];
            CHECK(entry->len==1024);
            if (entry->flags&FI_RECV) {
                CHECK(entry->op_context==(void*)1 && !received);
                CHECK(!memcmp(receive_buffer,send_buffer,1024)); received=1;
            } else { CHECK((entry->flags&FI_SEND) && entry->op_context==(void*)2 && !sent); sent=1; }
        } else CHECK(count==-FI_EAGAIN);
        if (server && received && !reply_started) {
            SUCCESS(fi_send(endpoint,send_buffer,1024,NULL,peer,(void*)2)); reply_started=1;
        }
        if (!sent || !received) poll(NULL,0,1);
    }
    CHECK(sent && received);
    SUCCESS(fi_close(&endpoint->fid)); SUCCESS(fi_close(&addresses->fid)); SUCCESS(fi_close(&queue->fid));
    SUCCESS(fi_close(&domain->fid)); SUCCESS(fi_close(&fabric->fid));
    fi_freeinfo(info); fi_freeinfo(hints);
    printf("PASS libfabric DGRAM %s: UUD payload, one-MTU boundary and local transmit completion\n",server?"server":"client");
    return 0;
}
