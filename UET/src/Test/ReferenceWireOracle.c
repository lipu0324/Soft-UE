/* Independent wire oracle using the pinned UEC reference implementation.
 * This harness calls its parser and CRC implementation without sharing any
 * Soft-UE codec code. It is a parser comparison, not process interoperability.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uet_api_private.h"
#include "uet_util.h"
#include "crc32c.h"

int main(int argument_count, char** arguments)
{
    if (argument_count!=2 && argument_count!=3) return 2;
    unsigned long udp_destination_port=4793; /* UE 1.1 Table 3-35 reference default. */
    if (argument_count==3) {
        char* end=NULL; udp_destination_port=strtoul(arguments[2],&end,10);
        if (!end || !*arguments[2] || *end || udp_destination_port>65535) return 2;
    }
    FILE* input=fopen(arguments[1],"rb");
    if (!input) return 2;
    unsigned char frame[65536];
    const size_t frame_length=fread(frame,1,sizeof(frame),input);
    fclose(input);
    if (frame_length<54 || frame_length>=sizeof(frame)) return 2;
    struct uet_instance reference_context={0};
    reference_context.uet_ipproto=UET_IPPROTO;
    /* The pinned reference's lab default is 49150. Configure its parser for
     * the chosen fabric port without changing the independent parser code. */
    reference_context.uet_udp_port=(uint16_t)udp_destination_port;
    reference_context.max_payload_len=8192;
    struct uet_parsed_pkt parsed={0};
    const int result=uet_parse_pkt(&reference_context,frame,frame_length,&parsed);
    if (result) { fprintf(stderr,"reference parser rejected frame: %d\n",result); return 1; }
    /* CRC includes addresses, entropy/UDP, PDS, SES and payload (§3.5.26).
     * IPv4/IPv6 mutable traffic-class fields are outside this range. */
    const size_t protected_start=14+(parsed.is_ipv6?8:12);
    const uint32_t expected_crc=crc32c(frame+protected_start,frame_length-protected_start-4);
    /* The reference crc32c() returns its integer in network byte order. */
    if (memcmp(&expected_crc,frame+frame_length-4,4)) {
        fprintf(stderr,"reference CRC mismatch\n"); return 1;
    }
    printf("{\"type\":%u,\"psn\":%u,\"clear_psn\":%u,\"cack_psn\":%u,"
           "\"source_pdc\":%u,\"destination_pdc\":%u,\"entropy\":%u,"
           "\"opcode\":%u,\"message_id\":%u,\"payload_length\":%u,\"packet_id\":%u}\n",
           parsed.pds_type,parsed.pds_psn,parsed.pds_clear_psn,parsed.pds_cack_psn,
           parsed.pds_spdcid,parsed.pds_dpdcid,parsed.entropy_val,
           parsed.ses_opcode,parsed.ses_msg_id,parsed.ses_payload_len,parsed.pds_rudi_pkt_id);
    return 0;
}
