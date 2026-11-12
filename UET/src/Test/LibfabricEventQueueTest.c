/* EQ control-event regression using only the installed public libfabric API. */
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr,"FAIL EQ line %d: %s\n",__LINE__,#condition); return 1; } } while (0)
#define SUCCESS(call) CHECK((call)==0)
int main(void) {
    struct fi_info *hints=fi_allocinfo(),*info=NULL; CHECK(hints);
    hints->fabric_attr->prov_name=strdup("softue"); hints->ep_attr->type=FI_EP_RDM;
    hints->caps=FI_MSG; hints->addr_format=FI_SOCKADDR_IN;
    SUCCESS(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,hints,&info));
    struct fid_fabric *fabric=NULL,*other_fabric=NULL;
    SUCCESS(fi_fabric(info->fabric_attr,&fabric,NULL)); SUCCESS(fi_fabric(info->fabric_attr,&other_fabric,NULL));
    struct fi_eq_attr attributes={0}; attributes.flags=FI_WRITE; attributes.size=2; attributes.wait_obj=FI_WAIT_NONE;
    struct fid_eq *events=NULL,*other_events=NULL;
    SUCCESS(fi_eq_open(fabric,&attributes,&events,(void*)11)); CHECK(events->fid.context==(void*)11);
    CHECK(fi_close(&fabric->fid)==-FI_EBUSY); // EQ is a direct fabric child.
    SUCCESS(fi_eq_open(other_fabric,NULL,&other_events,NULL));
    struct fi_eq_entry original={0},result={0}; uint32_t event=0;
    CHECK(fi_eq_write(other_events,FI_NOTIFY,&original,sizeof(original),0)==-FI_EOPNOTSUPP);
    struct fid_domain *domain=NULL,*second_domain=NULL; struct fid_ep *endpoint=NULL,*second_endpoint=NULL;
    SUCCESS(fi_domain(fabric,info,&domain,NULL)); SUCCESS(fi_domain(fabric,info,&second_domain,NULL));
    SUCCESS(fi_endpoint(domain,info,&endpoint,NULL)); SUCCESS(fi_endpoint(second_domain,info,&second_endpoint,NULL));
    CHECK(fi_ep_bind(endpoint,&other_events->fid,0)==-FI_EINVAL);
    SUCCESS(fi_close(&other_events->fid)); SUCCESS(fi_close(&other_fabric->fid));
    SUCCESS(fi_ep_bind(endpoint,&events->fid,0)); CHECK(fi_ep_bind(endpoint,&events->fid,0)==-FI_EINVAL);
    SUCCESS(fi_ep_bind(second_endpoint,&events->fid,0)); CHECK(fi_close(&events->fid)==-FI_EBUSY);
    CHECK(fi_eq_read(events,&event,&result,sizeof(result),0)==-FI_EAGAIN);
    struct fi_eq_err_entry error={0}; CHECK(fi_eq_readerr(events,&error,0)==-FI_EAGAIN);
    original.fid=&endpoint->fid; original.context=(void*)123; original.data=17;
    CHECK(fi_eq_write(events,FI_NOTIFY,&original,sizeof(original),0)==sizeof(original)); original.data=99;
    struct extended_event { struct fi_eq_entry base; unsigned char payload[5]; } second={0},received={0};
    second.base.fid=&second_endpoint->fid; second.base.data=23; second.payload[4]=42;
    CHECK(fi_eq_write(events,FI_NOTIFY,&second,sizeof(second),0)==sizeof(second));
    CHECK(fi_eq_write(events,FI_NOTIFY,&original,sizeof(original),0)==-FI_EAGAIN);
    CHECK(fi_eq_read(events,&event,&result,sizeof(result)-1,0)==-FI_ETOOSMALL);
    CHECK(fi_eq_read(events,&event,&result,sizeof(result),FI_PEEK)==sizeof(result));
    CHECK(event==FI_NOTIFY && result.data==17 && result.context==(void*)123 && result.fid==&endpoint->fid);
    CHECK(fi_eq_read(events,&event,&result,sizeof(result),0)==sizeof(result) && result.data==17);
    CHECK(fi_eq_read(events,&event,&result,sizeof(result),0)==-FI_ETOOSMALL);
    CHECK(fi_eq_read(events,&event,&received,sizeof(received),0)==sizeof(received));
    CHECK(event==FI_NOTIFY && received.base.data==23 && received.payload[4]==42);
    CHECK(fi_eq_read(events,&event,&result,sizeof(result),0)==-FI_EAGAIN);
    CHECK(fi_eq_write(events,FI_NOTIFY,NULL,sizeof(original),0)==-FI_EINVAL);
    CHECK(fi_eq_write(events,FI_NOTIFY,&original,1,0)==-FI_EINVAL);
    CHECK(fi_eq_write(events,FI_NOTIFY,&original,sizeof(original),FI_PEEK)==-FI_EINVAL);
    unsigned char oversized[4097]={0}; CHECK(fi_eq_write(events,FI_NOTIFY,oversized,sizeof(oversized),0)==-FI_EMSGSIZE);
    CHECK(fi_eq_read(events,&event,&result,sizeof(result),FI_WRITE)==-FI_EINVAL);
    CHECK(fi_eq_read(events,NULL,&result,sizeof(result),0)==-FI_EINVAL);
    char description[8]; CHECK(fi_eq_strerror(events,FI_EINVAL,NULL,description,sizeof(description))==description && description[7]==0);
    struct fi_eq_attr invalid=attributes; invalid.wait_obj=FI_WAIT_UNSPEC; struct fid_eq* rejected=NULL;
    CHECK(fi_eq_open(fabric,&invalid,&rejected,NULL)==-FI_EOPNOTSUPP && !rejected);
    invalid=attributes; invalid.size=4097; CHECK(fi_eq_open(fabric,&invalid,&rejected,NULL)==-FI_EINVAL && !rejected);
    SUCCESS(fi_close(&endpoint->fid)); SUCCESS(fi_close(&domain->fid)); CHECK(fi_close(&events->fid)==-FI_EBUSY);
    SUCCESS(fi_close(&second_endpoint->fid)); SUCCESS(fi_close(&second_domain->fid));
    CHECK(fi_close(&fabric->fid)==-FI_EBUSY); SUCCESS(fi_close(&events->fid)); SUCCESS(fi_close(&fabric->fid));
    fi_freeinfo(info); fi_freeinfo(hints);
    puts("PASS public EQ FIFO, owned events, peek, backpressure, binding and lifecycle");
    return 0;
}
