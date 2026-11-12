#include "Fabric.hpp"
#include "Pcap.hpp"
#include "../SES/Endpoint.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>

using namespace UET::Runtime;
using namespace UET::SES;
namespace {
struct Flow { uint32_t source,target,job; size_t bytes; uint64_t offset,context; Time at; int kind,expected,mode; };
struct Link { uint32_t from,to; LinkConfig config; };
struct LinkEvent { Time at; uint32_t from,to; bool up; };
std::vector<uint8_t> payload(size_t length,uint64_t context) {
    std::vector<uint8_t> bytes(length);
    for (size_t i=0; i<length; ++i) bytes[i]=static_cast<uint8_t>(i*131+context*17);
    return bytes;
}
struct Redirect {
    std::streambuf* previous;
    explicit Redirect(std::ostream& destination) : previous(std::cout.rdbuf(destination.rdbuf())) {}
    ~Redirect() { std::cout.rdbuf(previous); }
};
}
int main(int argc,char** argv) {
    try {
        if (argc!=3) throw std::invalid_argument("usage: softue_sim <validated-config> <output-directory>");
        const std::string directory=argv[2];
        std::ifstream input(argv[1]);
        if (!input) throw std::runtime_error("cannot open scenario input");
        std::string line;
        if (!std::getline(input,line) || line!="softue-scenario-v2") throw std::invalid_argument("invalid scenario version");
        uint64_t seed=42,memory_bytes=65536,budget=1000000; Time duration=100000000;
        size_t payload_mtu=1024;
        bool enable_nscc=false,enable_trimming=false;
        UET::CMS::NsccConfig congestion;
        UET::NetworkLayer::WireOptions network;
        std::vector<uint32_t> nodes,switches,jobs;
        std::vector<Link> links; std::vector<Flow> flows; std::vector<LinkEvent> link_events;
        while (std::getline(input,line)) {
            if (line.empty()) continue;
            if (line.find('-')!=std::string::npos) throw std::invalid_argument("negative configuration value");
            std::istringstream row(line); std::string key; row>>key;
            if (key=="seed") row>>seed;
            else if (key=="duration") row>>duration;
            else if (key=="memory") row>>memory_bytes;
            else if (key=="budget") row>>budget;
            else if (key=="payload_mtu") row>>payload_mtu;
            else if (key=="trimming") row>>enable_trimming;
            else if (key=="nscc") {
                uint64_t base_rtt=0,sender_rate=0,receiver_rate=0,initial_window=0; uint32_t nominal_mtu=0;
                row>>enable_nscc>>base_rtt>>sender_rate>>receiver_rate>>nominal_mtu>>initial_window;
                if (!row) throw std::invalid_argument("incomplete NSCC configuration");
                congestion=UET::CMS::NsccConfig::for_link(base_rtt,sender_rate,receiver_rate,nominal_mtu,enable_trimming);
                if (initial_window) congestion.initial_maximum_window=initial_window;
                congestion.validate();
            }
            else if (key=="wire") { int ipv6=0,udp=0,crc=0; row>>ipv6>>udp>>crc; network.ipv6=ipv6; network.udp=udp; network.crc=crc; }
            else if (key=="host") { uint32_t id; row>>id; nodes.push_back(id); }
            else if (key=="switch") { uint32_t id; row>>id; switches.push_back(id); }
            else if (key=="job") { uint32_t id; row>>id; jobs.push_back(id); }
            else if (key=="link") {
                Link link{};
                row>>link.from>>link.to>>link.config.rate_bps>>link.config.delay_ns>>link.config.fec_delay_ns
                   >>link.config.mtu>>link.config.buffer_bytes>>link.config.drop_ppm>>link.config.extra_delay_ns;
                links.push_back(link);
            } else if (key=="queue") {
                uint32_t from=0,to=0; bool trim=false; row>>from>>to;
                auto found=std::find_if(links.begin(),links.end(),[&](const Link& link) { return link.from==from && link.to==to; });
                if (found==links.end()) throw std::invalid_argument("queue has no directed link");
                row>>found->config.scheduling_quantum_bytes>>trim;
                if (trim) found->config.trimming=UET::NetworkLayer::TrimmingOptions{};
                for (auto& weight:found->config.traffic_class_weights) row>>weight;
                for (auto& threshold:found->config.ecn_threshold_bytes) {
                    uint64_t value=UINT64_MAX; row>>value;
                    if (value!=UINT64_MAX) threshold=static_cast<size_t>(value);
                }
            } else if (key=="link_event") {
                LinkEvent event{}; row>>event.at>>event.from>>event.to>>event.up; link_events.push_back(event);
            } else if (key=="flow") {
                Flow flow{}; row>>flow.kind>>flow.source>>flow.target>>flow.job>>flow.bytes>>flow.offset>>flow.context>>flow.at>>flow.expected>>flow.mode;
                flows.push_back(flow);
            } else throw std::invalid_argument("unknown scenario record");
            if (!row) throw std::invalid_argument("invalid scenario record: "+key);
            std::string extra; if (row>>extra) throw std::invalid_argument("extra scenario field");
        }
        if (nodes.size()<2 || nodes.size()>64 || !duration || !budget || jobs.empty() || flows.empty())
            throw std::invalid_argument("invalid scenario size");
        std::ofstream protocol(directory+"/protocol.log");
        if (!protocol) throw std::runtime_error("cannot open protocol log");
        Redirect quiet(protocol);
        EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,seed);
        Pcap capture(directory+"/packets.pcap");
        fabric.set_capture([&](Time time,const Frame& frame) { capture.write(time,frame); });
        Pcap link_capture(directory+"/link-packets.pcap");
        std::ofstream link_records(directory+"/link-packets.jsonl");
        if (!link_records) throw std::runtime_error("cannot open per-hop capture index");
        uint64_t capture_record=0,data_attempts=0,retransmitted_data_attempts=0;
        std::map<std::pair<uint32_t,uint32_t>,uint64_t> transmitted_frames;
        fabric.set_link_capture([&](Time time,uint32_t from,uint32_t to,const Frame& frame) {
            // The shared record ordinal joins each actual post-trim/ECN/stamp
            // frame to its directed egress link without inventing wire fields.
            link_capture.write(time,frame); ++transmitted_frames[{from,to}];
            link_records<<"{\"record\":"<<++capture_record<<",\"time_ns\":"<<time<<",\"from\":"<<from
                        <<",\"to\":"<<to<<",\"source\":"<<frame.source<<",\"destination\":"<<frame.destination
                        <<",\"traffic_class\":"<<unsigned(frame.traffic_class)<<",\"bytes\":"<<frame.bytes.size()<<"}\n";
            if (from==frame.source) {
                const auto decoded=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),network.crc,
                    network.native_ip_protocol,enable_trimming?std::make_optional(UET::NetworkLayer::TrimmingOptions{}):std::nullopt);
                if (decoded.packet.PDS_type==RUOD_req_header) {
                    ++data_attempts;
                    if (decoded.packet.PDS_header.RUOD_req_header.flags.retx) ++retransmitted_data_attempts;
                }
            }
        });
        std::map<uint32_t,Fabric::Port*> ports;
        for (auto node:nodes) ports.emplace(node,&fabric.add_host(node));
        for (auto node:switches) fabric.add_switch(node);
        for (const auto& link:links) fabric.add_link(link.from,link.to,link.config);
        std::map<uint32_t,std::unique_ptr<PdsHost>> hosts;
        std::map<uint32_t,std::unique_ptr<Endpoint>> endpoints;
        std::map<std::pair<uint32_t,uint32_t>,Region> regions;
        for (auto node:nodes) {
            hosts[node]=std::make_unique<PdsHost>(node,loop,trace,*ports.at(node),PdsHost::WireFormat::Uet11,network);
            if (enable_nscc) hosts.at(node)->enable_nscc(congestion);
            if (enable_trimming) hosts.at(node)->configure_trimming({});
            endpoints[node]=std::make_unique<Endpoint>(node,*hosts.at(node),loop,trace,payload_mtu,duration);
            for (auto job:jobs) {
                endpoints.at(node)->memory().add_job(job);
                regions.emplace(std::make_pair(node,job),endpoints.at(node)->memory().register_region(job,1,memory_bytes,7));
            }
        }
        for (const auto& event:link_events)
            loop.at(event.at,[&,event] { fabric.set_link_up(event.from,event.to,event.up); });
        std::map<uint64_t,std::pair<uint32_t,uint64_t>> submitted_operations;
        for (const auto& flow:flows) {
            if (!endpoints.count(flow.source) || !endpoints.count(flow.target) || flow.at>=duration || flow.bytes>16*1024*1024)
                throw std::invalid_argument("invalid flow endpoint, time or message size");
            if (flow.kind!=0 && flow.kind!=1 && flow.kind!=5) throw std::invalid_argument("unsupported runner operation");
            if (flow.kind==5) endpoints.at(flow.target)->post_receive(flow.job,1,regions.at({flow.target,flow.job}).key,flow.offset,flow.bytes,flow.context);
            loop.at(flow.at,[&,flow] {
                Operation operation; operation.type=static_cast<OperationType>(flow.kind);
                if (flow.mode!=RUD && flow.mode!=ROD) throw std::invalid_argument("invalid reliable delivery mode");
                operation.delivery_mode=static_cast<pdc_mode>(flow.mode);
                operation.peer=flow.target; operation.job=flow.job; operation.context=flow.context;
                operation.remote_key=regions.at({flow.target,flow.job}).key;
                operation.remote_offset=flow.offset; operation.payload=payload(flow.bytes,flow.context);
                const auto identifier=endpoints.at(flow.source)->submit(std::move(operation));
                submitted_operations.emplace(flow.context,std::make_pair(flow.source,identifier));
            });
        }
        loop.run_until(duration,budget);
        std::map<uint64_t,Completion> completed;
        for (auto& item:endpoints) {
            Completion completion{};
            while (item.second->poll_completion(completion)) {
                if (!completion.receive && !completed.emplace(completion.context,completion).second)
                    throw std::runtime_error("duplicate application completion");
            }
        }
        std::map<std::pair<uint32_t,uint64_t>,Time> completion_times;
        for (const auto& event:trace.events())
            if (event.event=="operation_complete") completion_times.emplace(std::make_pair(event.node,event.value),event.time);
        bool passed=true;
        uint64_t completed_bytes=0; Time first_start=duration,last_completion=0;
        std::vector<double> flow_goodputs;
        bool comparable_flows=true;
        std::optional<std::pair<size_t,Time>> fairness_workload;
        std::ofstream result(directory+"/result.json");
        if (!result) throw std::runtime_error("cannot open result output");
        result<<"{\"schema_version\":1,\"seed\":"<<seed<<",\"host_count\":"<<nodes.size()
              <<",\"duration_ns\":"<<duration<<",\"events\":"<<loop.executed()
              <<",\"profile_conformance\":false,\"nscc_enabled\":"<<(enable_nscc?"true":"false")<<",\"operations\":[";
        for (size_t i=0;i<flows.size();++i) {
            const auto& flow=flows[i]; const auto found=completed.find(flow.context);
            int status=found==completed.end()?-1:static_cast<int>(found->second.status);
            bool verified=found!=completed.end() && status==flow.expected;
            if (status==static_cast<int>(CompletionStatus::Success) && flow.kind!=0) {
                verified=verified && endpoints.at(flow.target)->memory().read(flow.job,1,regions.at({flow.target,flow.job}).key,flow.offset,flow.bytes)==payload(flow.bytes,flow.context);
            }
            passed=passed&&verified;
            const auto submitted=submitted_operations.find(flow.context);
            const auto finished=submitted==submitted_operations.end()?completion_times.end():completion_times.find(submitted->second);
            const bool timed=finished!=completion_times.end() && finished->second>=flow.at;
            const auto elapsed=timed?finished->second-flow.at:0;
            const bool successful=verified && status==static_cast<int>(CompletionStatus::Success);
            if (successful && timed) {
                completed_bytes+=flow.bytes; first_start=std::min(first_start,flow.at); last_completion=std::max(last_completion,finished->second);
            }
            if (flow.bytes) {
                const auto workload=std::make_pair(flow.bytes,flow.at);
                if (fairness_workload && *fairness_workload!=workload) comparable_flows=false;
                fairness_workload=workload;
                flow_goodputs.push_back(successful && elapsed?double(flow.bytes)*8e9/elapsed:0);
            }
            if (i) result<<',';
            result<<"{\"context\":"<<flow.context<<",\"status\":"<<status<<",\"completed\":"<<(found!=completed.end()?"true":"false")
                  <<",\"verified\":"<<(verified?"true":"false")<<",\"completion_time_ns\":";
            if (timed) result<<finished->second; else result<<"null";
            result<<",\"flow_completion_ns\":"; if (timed) result<<elapsed; else result<<"null";
            result<<",\"goodput_bps\":"<<std::setprecision(17)<<(successful && elapsed?double(flow.bytes)*8e9/elapsed:0)<<'}';
        }
        result<<"],\"links\":[";
        for (size_t i=0;i<links.size();++i) {
            const auto& link=links[i]; const auto& stats=fabric.stats(link.from,link.to);
            if (i) result<<',';
            result<<"{\"from\":"<<link.from<<",\"to\":"<<link.to<<",\"packets\":"<<stats.packets
                  <<",\"bytes\":"<<stats.bytes<<",\"drops\":"<<stats.dropped<<",\"peak_queue_bytes\":"<<stats.peak_queue_bytes
                  <<",\"transmitted_frames\":"<<transmitted_frames[{link.from,link.to}]<<",\"delivered\":"<<stats.delivered
                  <<",\"ecn_marked\":"<<stats.ecn_marked<<",\"trimmed\":"<<stats.trimmed<<",\"trimmed_bytes\":"<<stats.trimmed_bytes
                  <<",\"queued_bytes\":"<<stats.queued_bytes<<",\"traffic_classes\":[";
            for (size_t traffic_class=0;traffic_class<8;++traffic_class) {
                if (traffic_class) result<<',';
                result<<"{\"class\":"<<traffic_class<<",\"queued_bytes\":"<<stats.queued_by_class[traffic_class]
                      <<",\"peak_bytes\":"<<stats.peak_by_class[traffic_class]<<'}';
            }
            result<<"]}";
        }
        for (auto& item:endpoints) item.second->close();
        for (auto& item:hosts) item.second->close();
        // In-flight fabric packets may remain after a configured time limit.
        // They are owned/cancelled by Fabric, never by a destroyed host.
        const auto transfer_span=last_completion>first_start?last_completion-first_start:0;
        double sum_goodput=0,sum_squares=0;
        for (const auto goodput:flow_goodputs) { sum_goodput+=goodput; sum_squares+=goodput*goodput; }
        const bool fairness_available=comparable_flows && flow_goodputs.size()>1 && sum_squares>0;
        result<<"],\"completed_bytes\":"<<completed_bytes<<",\"transfer_span_ns\":"<<transfer_span
              <<",\"aggregate_goodput_bps\":"<<(transfer_span?double(completed_bytes)*8e9/transfer_span:0)
              <<",\"source_data_attempts\":"<<data_attempts<<",\"source_data_retransmissions\":"<<retransmitted_data_attempts
              <<",\"fairness\":{\"basis\":\"equal_size_and_start_flow_completion_goodput\",\"flow_count\":"<<flow_goodputs.size()
              <<",\"eligible\":"<<(fairness_available?"true":"false")<<",\"jain_index\":";
        if (fairness_available) result<<sum_goodput*sum_goodput/(flow_goodputs.size()*sum_squares); else result<<"null";
        result<<"},\"passed\":"<<(passed?"true":"false")<<"}\n";
        std::ofstream journal(directory+"/trace.jsonl");
        if (!journal) throw std::runtime_error("cannot open event trace");
        for (const auto& event:trace.events()) journal<<"{\"time_ns\":"<<event.time<<",\"sequence\":"<<event.sequence
            <<",\"node\":"<<event.node<<",\"event\":\""<<event.event<<"\",\"value\":"<<event.value<<"}\n";
        if (!result || !journal || !link_records) throw std::runtime_error("result write failed");
        return passed?0:1;
    } catch (const std::exception& error) { std::cerr<<"simulation failed: "<<error.what()<<'\n'; return 1; }
}
