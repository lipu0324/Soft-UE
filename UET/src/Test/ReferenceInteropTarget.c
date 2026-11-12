/* Test-only NIC adapter for the pinned reference provider. The reference
 * SES/PDS/parser/CRC implementation is linked unchanged from its shared library.
 * This executable overrides only its documented NIC initialization boundary.
 * UDP carries unchanged Ethernet frames; this does not test raw-socket drivers.
 */
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "uet_api.h"
#include "uet_nic.h"
#include "uet_pkt_hdr.h"

static int tunnel_socket=-1;
static struct sockaddr_in tunnel_peer;
static uint16_t tunnel_port;
static unsigned int clear_commands_sent;

static int tunnel_getinfo(struct uet_nic *nic,struct uet_nic_info *info) {
    info->ifname=nic->ifname; info->network_type=nic->network_type;
    info->mac_addr_str=nic->mac_addr_str; info->mtu=nic->mtu;
    info->link_state=UET_NIC_LINK_STATE_UP;
    return 0;
}
static int tunnel_next_hop(struct uet_nic *nic,const struct uet_fa *address,bool ipv6,uint8_t *mac) {
    (void)nic; (void)address; (void)ipv6;
    const uint8_t peer_mac[6]={2,0,0,0,0,1}; memcpy(mac,peer_mac,sizeof(peer_mac));
    return 0;
}
static int tunnel_transmit(struct uet_nic *nic,void *frame,void *ip_header,size_t size) {
    (void)nic; (void)ip_header;
    const ssize_t sent=sendto(tunnel_socket,frame,size,MSG_DONTWAIT,
        (const struct sockaddr*)&tunnel_peer,sizeof(tunnel_peer));
    // Observe (without modifying) the reference's own delayed Clear Command.
    // The test keeps progressing until its receive-state retirement exchange
    // has left the NIC, instead of terminating immediately on an app CQ event.
    if (sent==(ssize_t)size && size>=54) {
        const uint8_t *bytes=frame;
        const unsigned int prologue=((unsigned int)bytes[38]<<8)|bytes[39];
        if ((prologue>>11)==11 && ((prologue>>7)&15)==2) ++clear_commands_sent;
    }
    return sent==(ssize_t)size?0:-errno;
}
static int tunnel_receive(struct uet_nic *nic,void *frame,size_t capacity,size_t *size) {
    (void)nic;
    struct sockaddr_in source; socklen_t source_size=sizeof(source);
    const ssize_t received=recvfrom(tunnel_socket,frame,capacity,MSG_DONTWAIT|MSG_TRUNC,
        (struct sockaddr*)&source,&source_size);
    if (received<0) return errno==EAGAIN || errno==EWOULDBLOCK?0:-errno;
    if ((size_t)received>capacity || source.sin_addr.s_addr!=tunnel_peer.sin_addr.s_addr ||
        source.sin_port!=tunnel_peer.sin_port) return 0;
    *size=(size_t)received; return 1;
}
static int tunnel_poll(struct uet_nic *nic) {
    (void)nic;
    struct pollfd readiness={tunnel_socket,POLLIN,0};
    const int ready=poll(&readiness,1,0);
    return ready>0 && (readiness.revents&POLLIN)?1:0;
}
static void tunnel_finalize(struct uet_nic *nic) {
    (void)nic; if (tunnel_socket>=0) close(tunnel_socket); tunnel_socket=-1;
}

int uet_nic_initialize(struct uet_nic *nic) {
    tunnel_socket=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (tunnel_socket<0) return -errno;
    struct sockaddr_in local={0}; local.sin_family=AF_INET; local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(tunnel_socket,(const struct sockaddr*)&local,sizeof(local))<0) return -errno;
    socklen_t local_size=sizeof(local);
    if (getsockname(tunnel_socket,(struct sockaddr*)&local,&local_size)<0) return -errno;
    tunnel_port=ntohs(local.sin_port);
    strcpy(nic->ifname,"softue-test"); strcpy(nic->network_type,"UDP frame tunnel");
    strcpy(nic->mac_addr_str,"02:00:00:00:00:02");
    const uint8_t local_mac[6]={2,0,0,0,0,2}; memcpy(nic->mac_addr,local_mac,sizeof(local_mac));
    nic->ipv4_addr=2; strcpy(nic->ipv4_addr_str,"0.0.0.2"); nic->has_ipv4=true;
    nic->has_ipv6=false; nic->mtu=9000; nic->l2_hdr_size=14;
    nic->min_pkt_size=UET_MIN_PKT_SIZE; nic->min_ip_pkt_size=UET_MIN_PKT_SIZE-14;
    nic->max_pkt_size=9014; nic->sock_fd=tunnel_socket;
    nic->nic_getinfo=tunnel_getinfo; nic->nic_get_nh=tunnel_next_hop;
    nic->nic_tx_pkt=tunnel_transmit; nic->nic_rx_pkt=tunnel_receive;
    nic->nic_rx_poll=tunnel_poll; nic->nic_finalize=tunnel_finalize;
    return 0;
}

#define REQUIRE_SUCCESS(call) do { int result=(call); if (result) { \
    fprintf(stderr,"FAIL %s: %d (%s)\n",#call,result,fi_strerror(-result)); return 1; } } while (0)

int main(void) {
    uet_handle_t instance; uet_domain_handle_t domain; uet_ep_handle_t endpoint;
    uet_mr_handle_t region; uet_cq_handle_t send_cq,receive_cq; uet_addr_handle_t peer;
    struct fid_fabric fabric={0}; struct fid_domain fabric_domain={0};
    struct fid_ep fabric_endpoint={0}; struct fid_cq fabric_cq={0};
    struct fi_info *hints=fi_allocinfo(),*info=NULL;
    uint8_t memory[4096]={0},receive_buffer[32]={0};
    setenv("UET_PDS","pds",1); setenv("UET_PDS_ACK_TYPE","ack",1);
    /* The pinned reference defaults to a 5 ms wall-clock timeout. An ASan
     * process sharing a CPU with stress tests can be descheduled longer than
     * that without any packet loss. Use its public configuration interface,
     * as the reference's impairment tests do, to allow userspace scheduling.
     * The SES/PDS implementation and all transmitted frames remain unchanged. */
    setenv("UET_PDS_TX_TIMEOUT","100",1);
    REQUIRE_SUCCESS(uet_initialize(&instance));
    hints->caps=FI_MSG|FI_RMA|FI_ATOMIC;
    REQUIRE_SUCCESS(uet_getinfo(instance,NULL,hints,&info));
    info->rx_attr->size=16; info->tx_attr->size=16; info->tx_attr->msg_order=FI_ORDER_SAS;
    info->tx_attr->op_flags=FI_DELIVERY_COMPLETE;
    info->domain_attr->mr_mode|=FI_MR_PROV_KEY;
    REQUIRE_SUCCESS(uet_domain(instance,&fabric,info,&fabric_domain,NULL,NULL,NULL,&domain));
    REQUIRE_SUCCESS(uet_mr_reg(domain,memory,sizeof(memory),FI_READ|FI_WRITE|FI_REMOTE_READ|FI_REMOTE_WRITE|FI_ATOMIC,
        UET_MR_KEY_NONE,0,NULL,&region));
    REQUIRE_SUCCESS(uet_endpoint(domain,info,&fabric_endpoint,NULL,&endpoint));
    REQUIRE_SUCCESS(uet_ep_bind_mr(endpoint,region,0));
    struct fi_cq_attr attributes={0}; attributes.format=FI_CQ_FORMAT_DATA; attributes.size=32;
    REQUIRE_SUCCESS(uet_ep_bind_cq(endpoint,&attributes,&fabric_cq,FI_SEND,NULL,&send_cq));
    REQUIRE_SUCCESS(uet_ep_bind_cq(endpoint,&attributes,&fabric_cq,FI_RECV,NULL,&receive_cq));
    REQUIRE_SUCCESS(uet_mr_enable(region)); REQUIRE_SUCCESS(uet_ep_enable(endpoint));
    REQUIRE_SUCCESS(uet_recv(endpoint,UET_JOB_ID_ANY,receive_buffer,sizeof(receive_buffer),NULL,NULL,(void*)1));
    struct uet_addr local_identity={0}; REQUIRE_SUCCESS(uet_getname(endpoint,&local_identity));
    fprintf(stderr,"READY %u %llu %u %u\n",tunnel_port,(unsigned long long)uet_mr_key(region),
        local_identity.pid_on_fep,local_identity.start_index); fflush(stderr);
    unsigned int peer_port=0;
    if (scanf("%u",&peer_port)!=1 || !peer_port || peer_port>65535) return 1;
    tunnel_peer.sin_family=AF_INET; tunnel_peer.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    tunnel_peer.sin_port=htons((uint16_t)peer_port);
    struct uet_addr peer_identity={0}; peer_identity.flags=UET_ADDR_FA_V|UET_ADDR_PID_ON_FEP_V|UET_ADDR_INDEX_V|UET_ADDR_INITIATOR_V;
    peer_identity.fa.v4=1; peer_identity.pid_on_fep=1; peer_identity.start_index=1;
    peer_identity.num_indices=1; peer_identity.initiator_id=1;
    REQUIRE_SUCCESS(uet_av_insert(domain,&peer_identity,&peer));
    const time_t deadline=time(NULL)+8;
    bool receive_complete=false,reply_started=false,reply_complete=false;
    uint8_t reply[3]={6,5,4};
    while (time(NULL)<deadline && (!reply_complete || !clear_commands_sent)) {
        struct fi_cq_data_entry entry;
        ssize_t count=uet_cq_read(receive_cq,&entry,1);
        if (count>0 && entry.op_context==(void*)1) receive_complete=true;
        if (count<0 && count!=-FI_EAGAIN) { fprintf(stderr,"FAIL reference receive CQ: %zd\n",count); return 1; }
        if (receive_complete && !reply_started) {
            for (size_t byte=0;byte<2049;++byte) if (memory[byte]!=(uint8_t)(byte*7)) {
                fprintf(stderr,"FAIL reference target memory at %zu: %u\n",byte,memory[byte]); return 1;
            }
            if (memcmp(receive_buffer,"abc",3)) return 1;
            for (size_t byte=0;byte<8;++byte) if (memory[3072+byte]!=(byte==0?1:0)) {
                fprintf(stderr,"FAIL reference atomic byte %zu: %u\n",byte,memory[3072+byte]); return 1;
            }
            REQUIRE_SUCCESS((int)uet_send(endpoint,1,reply,sizeof(reply),NULL,peer,(void*)2));
            reply_started=true;
        }
        count=uet_cq_read(send_cq,&entry,1);
        if (count>0 && entry.op_context==(void*)2) reply_complete=true;
        if (count<0 && count!=-FI_EAGAIN) { fprintf(stderr,"FAIL reference send CQ: %zd\n",count); return 1; }
        struct pollfd readiness={tunnel_socket,POLLIN,0}; poll(&readiness,1,1);
    }
    if (!reply_complete || !clear_commands_sent) { fprintf(stderr,"FAIL reference timeout received=%d reply=%d clear=%u\n",
        receive_complete,reply_started,clear_commands_sent); return 1; }
    REQUIRE_SUCCESS(uet_ep_close(endpoint)); REQUIRE_SUCCESS(uet_av_remove(peer));
    REQUIRE_SUCCESS(uet_cq_close(send_cq));
    REQUIRE_SUCCESS(uet_cq_close(receive_cq)); REQUIRE_SUCCESS(uet_mr_close(region));
    REQUIRE_SUCCESS(uet_domain_close(domain)); REQUIRE_SUCCESS(uet_finalize(instance));
    fi_freeinfo(info); fi_freeinfo(hints);
    puts("PASS reference: unchanged SES/PDS received WRITE/SEND/AMO and sent a verified reply");
    return 0;
}
