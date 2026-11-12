#include "Fabric.hpp"
#include "Pcap.hpp"
#include "../SES/Endpoint.hpp"
#include <fstream>
#include <iostream>
#include <sstream>

using namespace UET::Runtime;
using namespace UET::SES;
namespace {
struct Flow { uint32_t source,target,job; size_t bytes; uint64_t offset,context; Time at; int kind,expected; };
struct Link { uint32_t from,to; LinkConfig config; };
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
        if (!std::getline(input,line) || line!="softue-scenario-v1") throw std::invalid_argument("invalid scenario version");
        uint64_t seed=42,memory_bytes=65536,budget=1000000; Time duration=100000000;
        UET::NetworkLayer::WireOptions network;
        std::vector<uint32_t> nodes,switches,jobs;
        std::vector<Link> links; std::vector<Flow> flows;
        while (std::getline(input,line)) {
            if (line.empty()) continue;
            if (line.find('-')!=std::string::npos) throw std::invalid_argument("negative configuration value");
            std::istringstream row(line); std::string key; row>>key;
            if (key=="seed") row>>seed;
            else if (key=="duration") row>>duration;
            else if (key=="memory") row>>memory_bytes;
            else if (key=="budget") row>>budget;
            else if (key=="wire") { int ipv6,udp,crc; row>>ipv6>>udp>>crc; network.ipv6=ipv6; network.udp=udp; network.crc=crc; }
            else if (key=="host") { uint32_t id; row>>id; nodes.push_back(id); }
            else if (key=="switch") { uint32_t id; row>>id; switches.push_back(id); }
            else if (key=="job") { uint32_t id; row>>id; jobs.push_back(id); }
            else if (key=="link") {
                Link link{};
                row>>link.from>>link.to>>link.config.rate_bps>>link.config.delay_ns>>link.config.fec_delay_ns
                   >>link.config.mtu>>link.config.buffer_bytes>>link.config.drop_ppm>>link.config.extra_delay_ns;
                links.push_back(link);
            } else if (key=="flow") {
                Flow flow{}; row>>flow.kind>>flow.source>>flow.target>>flow.job>>flow.bytes>>flow.offset>>flow.context>>flow.at>>flow.expected;
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
        std::map<uint32_t,Fabric::Port*> ports;
        for (auto node:nodes) ports.emplace(node,&fabric.add_host(node));
        for (auto node:switches) fabric.add_switch(node);
        for (const auto& link:links) fabric.add_link(link.from,link.to,link.config);
        std::map<uint32_t,std::unique_ptr<PdsHost>> hosts;
        std::map<uint32_t,std::unique_ptr<Endpoint>> endpoints;
        std::map<std::pair<uint32_t,uint32_t>,Region> regions;
        for (auto node:nodes) {
            hosts[node]=std::make_unique<PdsHost>(node,loop,trace,*ports.at(node),PdsHost::WireFormat::Uet11,network);
            endpoints[node]=std::make_unique<Endpoint>(node,*hosts.at(node),loop,trace,1024,duration);
            for (auto job:jobs) {
                endpoints.at(node)->memory().add_job(job);
                regions.emplace(std::make_pair(node,job),endpoints.at(node)->memory().register_region(job,1,memory_bytes,7));
            }
        }
        for (const auto& flow:flows) {
            if (!endpoints.count(flow.source) || !endpoints.count(flow.target) || flow.at>=duration || flow.bytes>16*1024*1024)
                throw std::invalid_argument("invalid flow endpoint, time or message size");
            if (flow.kind!=0 && flow.kind!=1 && flow.kind!=5) throw std::invalid_argument("unsupported runner operation");
            if (flow.kind==5) endpoints.at(flow.target)->post_receive(flow.job,1,regions.at({flow.target,flow.job}).key,flow.offset,flow.bytes,flow.context);
            loop.at(flow.at,[&,flow] {
                Operation operation; operation.type=static_cast<OperationType>(flow.kind);
                operation.peer=flow.target; operation.job=flow.job; operation.context=flow.context;
                operation.remote_key=regions.at({flow.target,flow.job}).key;
                operation.remote_offset=flow.offset; operation.payload=payload(flow.bytes,flow.context);
                endpoints.at(flow.source)->submit(std::move(operation));
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
        bool passed=true;
        std::ofstream result(directory+"/result.json");
        if (!result) throw std::runtime_error("cannot open result output");
        result<<"{\"schema_version\":1,\"seed\":"<<seed<<",\"host_count\":"<<nodes.size()
              <<",\"duration_ns\":"<<duration<<",\"events\":"<<loop.executed()
              <<",\"profile_conformance\":false,\"operations\":[";
        for (size_t i=0;i<flows.size();++i) {
            const auto& flow=flows[i]; const auto found=completed.find(flow.context);
            int status=found==completed.end()?-1:static_cast<int>(found->second.status);
            bool verified=found!=completed.end() && status==flow.expected;
            if (status==static_cast<int>(CompletionStatus::Success) && flow.kind!=0) {
                verified=verified && endpoints.at(flow.target)->memory().read(flow.job,1,regions.at({flow.target,flow.job}).key,flow.offset,flow.bytes)==payload(flow.bytes,flow.context);
            }
            passed=passed&&verified;
            if (i) result<<',';
            result<<"{\"context\":"<<flow.context<<",\"status\":"<<status<<",\"completed\":"<<(found!=completed.end()?"true":"false")
                  <<",\"verified\":"<<(verified?"true":"false")<<'}';
        }
        result<<"],\"links\":[";
        for (size_t i=0;i<links.size();++i) {
            const auto& link=links[i]; const auto& stats=fabric.stats(link.from,link.to);
            if (i) result<<',';
            result<<"{\"from\":"<<link.from<<",\"to\":"<<link.to<<",\"packets\":"<<stats.packets
                  <<",\"bytes\":"<<stats.bytes<<",\"drops\":"<<stats.dropped<<",\"peak_queue_bytes\":"<<stats.peak_queue_bytes<<'}';
        }
        for (auto& item:endpoints) item.second->close();
        for (auto& item:hosts) item.second->close();
        // In-flight fabric packets may remain after a configured time limit.
        // They are owned/cancelled by Fabric, never by a destroyed host.
        result<<"],\"passed\":"<<(passed?"true":"false")<<"}\n";
        std::ofstream journal(directory+"/trace.jsonl");
        if (!journal) throw std::runtime_error("cannot open event trace");
        for (const auto& event:trace.events()) journal<<"{\"time_ns\":"<<event.time<<",\"sequence\":"<<event.sequence
            <<",\"node\":"<<event.node<<",\"event\":\""<<event.event<<"\",\"value\":"<<event.value<<"}\n";
        if (!result || !journal) throw std::runtime_error("result write failed");
        return passed?0:1;
    } catch (const std::exception& error) { std::cerr<<"simulation failed: "<<error.what()<<'\n'; return 1; }
}
