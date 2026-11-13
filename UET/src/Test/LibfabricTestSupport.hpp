#pragma once
// Public libfabric fixture shared by native interoperability regressions.
#include "Check.hpp"
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>

class ProviderFixture {
public:
    explicit ProviderFixture(uint64_t ordering,uint64_t operation_flags=FI_FENCE,bool datagram=false,fi_cq_format format=FI_CQ_FORMAT_DATA) :completion_format(format) {
        hints=fi_allocinfo(); CHECK(hints);
        hints->fabric_attr->prov_name=::strdup("softue"); hints->ep_attr->type=datagram?FI_EP_DGRAM:FI_EP_RDM;
        hints->addr_format=FI_SOCKADDR_IN; hints->caps=datagram?FI_MSG:FI_MSG|FI_RMA|FI_ATOMIC;
        hints->tx_attr->msg_order=hints->rx_attr->msg_order=ordering;
        hints->tx_attr->op_flags=operation_flags;
        const auto result=fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,hints,&info);
        if (result) std::cerr<<"getinfo ordering="<<ordering<<" result="<<result<<" "<<fi_strerror(-result)<<'\n';
        CHECK(result==0);
        CHECK(info->tx_attr->msg_order==ordering && info->rx_attr->msg_order==ordering);
        CHECK(info->ep_attr->max_order_waw_size==(datagram?0:UINT32_MAX));
        CHECK((info->tx_attr->op_flags&operation_flags)==operation_flags);
        CHECK(fi_fabric(info->fabric_attr,&fabric,nullptr)==0);
        CHECK(fi_domain(fabric,info,&domain,nullptr)==0);
        fi_av_attr av_attributes{}; av_attributes.type=FI_AV_UNSPEC;
        CHECK(fi_av_open(domain,&av_attributes,&addresses,nullptr)==0);
        fi_cq_attr cq_attributes{}; cq_attributes.format=format; cq_attributes.wait_obj=FI_WAIT_NONE;
        CHECK(fi_cq_open(domain,&cq_attributes,&completions,nullptr)==0);
        CHECK(fi_endpoint(domain,info,&endpoint,nullptr)==0);
        CHECK(fi_ep_bind(endpoint,&addresses->fid,0)==0);
        CHECK(fi_ep_bind(endpoint,&completions->fid,FI_TRANSMIT|FI_RECV)==0);
        CHECK(fi_enable(endpoint)==0);
        size_t length=sizeof(address); CHECK(fi_getname(&endpoint->fid,&address,&length)==0);
    }
    void close() {
        CHECK(fi_close(&endpoint->fid)==0); endpoint=nullptr;
        CHECK(fi_close(&addresses->fid)==0); addresses=nullptr;
        CHECK(fi_close(&completions->fid)==0); completions=nullptr;
        CHECK(fi_close(&domain->fid)==0); domain=nullptr;
        CHECK(fi_close(&fabric->fid)==0); fabric=nullptr;
        fi_freeinfo(info); info=nullptr; fi_freeinfo(hints); hints=nullptr;
    }
    fi_addr_t add_peer(uint16_t port) {
        sockaddr_in peer{}; peer.sin_family=AF_INET; peer.sin_addr.s_addr=htonl(INADDR_LOOPBACK); peer.sin_port=htons(port);
        fi_addr_t result; CHECK(fi_av_insert(addresses,&peer,1,&result,0,nullptr)==1); return result;
    }
    size_t progress() {
        fi_cq_data_entry entries[8]; fi_cq_tagged_entry tagged_entries[8];
        const auto count=fi_cq_read(completions,completion_format==FI_CQ_FORMAT_TAGGED?static_cast<void*>(tagged_entries):static_cast<void*>(entries),8);
        CHECK(count>=0 || count==-FI_EAGAIN);
        return count>0?static_cast<size_t>(count):0;
    }
    fi_cq_format completion_format;
    fi_info *hints=nullptr,*info=nullptr;
    fid_fabric* fabric=nullptr; fid_domain* domain=nullptr; fid_av* addresses=nullptr;
    fid_cq* completions=nullptr; fid_ep* endpoint=nullptr; sockaddr_in address{};
};

