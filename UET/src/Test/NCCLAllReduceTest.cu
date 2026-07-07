#include <cuda_runtime.h>
#include <nccl.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#define CHECK_CUDA(cmd)                                                          \
    do {                                                                         \
        cudaError_t e_ = (cmd);                                                  \
        if (e_ != cudaSuccess) {                                                 \
            std::cerr << "CUDA error: " << cudaGetErrorString(e_)               \
                      << " @ " << __FILE__ << ":" << __LINE__ << std::endl;    \
            std::exit(1);                                                        \
        }                                                                        \
    } while (0)

#define CHECK_NCCL(cmd)                                                          \
    do {                                                                         \
        ncclResult_t r_ = (cmd);                                                 \
        if (r_ != ncclSuccess) {                                                 \
            std::cerr << "NCCL error: " << ncclGetErrorString(r_)               \
                      << " @ " << __FILE__ << ":" << __LINE__ << std::endl;    \
            std::exit(1);                                                        \
        }                                                                        \
    } while (0)

struct Opts {
    int gpus = 1;
    int warmup = 10;
    int iters = 50;
    size_t min_bytes = 8;
    size_t max_bytes = 64 * 1024 * 1024;
    int factor = 2;
    bool csv = false;
};

static void print_usage(const char* prog)
{
    std::cout
        << "Usage: " << prog << " [options]\n"
        << "Options:\n"
        << "  --gpus N          Number of local GPUs to use (default: 1)\n"
        << "  --warmup N        Warmup iterations per size (default: 10)\n"
        << "  --iters N         Timed iterations per size (default: 50)\n"
        << "  --min-bytes N     Min bytes (default: 8)\n"
        << "  --max-bytes N     Max bytes (default: 67108864)\n"
        << "  --factor N        Size multiply factor (default: 2)\n"
        << "  --csv             Print CSV format\n"
        << "  -h, --help        Show help\n";
}

static bool parse_int(const char* s, int& out)
{
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (!s || *s == '\0' || !end || *end != '\0') return false;
    out = static_cast<int>(v);
    return true;
}

static bool parse_size(const char* s, size_t& out)
{
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 10);
    if (!s || *s == '\0' || !end || *end != '\0') return false;
    out = static_cast<size_t>(v);
    return true;
}

static Opts parse_args(int argc, char** argv)
{
    Opts o;
    for (int i = 1; i < argc; ++i) {
        const std::string a(argv[i]);
        auto need = [&](const char* k) -> const char* {
            if (a == k && i + 1 < argc) return argv[++i];
            return nullptr;
        };
        if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        } else if (const char* v = need("--gpus")) {
            if (!parse_int(v, o.gpus) || o.gpus <= 0) {
                std::cerr << "Invalid --gpus\n";
                std::exit(1);
            }
        } else if (const char* v = need("--warmup")) {
            if (!parse_int(v, o.warmup) || o.warmup < 0) {
                std::cerr << "Invalid --warmup\n";
                std::exit(1);
            }
        } else if (const char* v = need("--iters")) {
            if (!parse_int(v, o.iters) || o.iters <= 0) {
                std::cerr << "Invalid --iters\n";
                std::exit(1);
            }
        } else if (const char* v = need("--min-bytes")) {
            if (!parse_size(v, o.min_bytes) || o.min_bytes == 0) {
                std::cerr << "Invalid --min-bytes\n";
                std::exit(1);
            }
        } else if (const char* v = need("--max-bytes")) {
            if (!parse_size(v, o.max_bytes) || o.max_bytes == 0) {
                std::cerr << "Invalid --max-bytes\n";
                std::exit(1);
            }
        } else if (const char* v = need("--factor")) {
            if (!parse_int(v, o.factor) || o.factor < 2) {
                std::cerr << "Invalid --factor\n";
                std::exit(1);
            }
        } else if (a == "--csv") {
            o.csv = true;
        } else {
            std::cerr << "Unknown arg: " << a << "\n";
            print_usage(argv[0]);
            std::exit(1);
        }
    }
    if (o.min_bytes > o.max_bytes) std::swap(o.min_bytes, o.max_bytes);
    return o;
}

__global__ static void fill_kernel(float* p, float v, size_t n)
{
    size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) p[i] = v;
}

static void print_env(const char* key)
{
    const char* v = std::getenv(key);
    std::cout << key << "=" << (v ? v : "") << "\n";
}

int main(int argc, char** argv)
{
    const Opts o = parse_args(argc, argv);

    int dev_count = 0;
    CHECK_CUDA(cudaGetDeviceCount(&dev_count));
    if (dev_count <= 0) {
        std::cerr << "No CUDA devices found\n";
        return 1;
    }
    if (o.gpus > dev_count) {
        std::cerr << "Requested --gpus " << o.gpus << " but only " << dev_count << " available\n";
        return 1;
    }

    int nccl_ver = 0;
    CHECK_NCCL(ncclGetVersion(&nccl_ver));
    std::cout << "NCCL version: " << nccl_ver << "\n";
    std::cout << "CUDA devices used: " << o.gpus << "\n";
    print_env("NCCL_NET_PLUGIN");
    print_env("FI_PROVIDER");
    print_env("FI_PROVIDER_PATH");
    print_env("OFI_NCCL_PROTOCOL");
    std::cout << std::endl;

    std::vector<int> devs(o.gpus);
    std::vector<cudaStream_t> streams(o.gpus);
    std::vector<ncclComm_t> comms(o.gpus);
    std::vector<float*> d_send(o.gpus, nullptr);
    std::vector<float*> d_recv(o.gpus, nullptr);

    for (int i = 0; i < o.gpus; ++i) devs[i] = i;
    CHECK_NCCL(ncclCommInitAll(comms.data(), o.gpus, devs.data()));

    const size_t max_count = o.max_bytes / sizeof(float);
    for (int i = 0; i < o.gpus; ++i) {
        CHECK_CUDA(cudaSetDevice(devs[i]));
        CHECK_CUDA(cudaStreamCreate(&streams[i]));
        CHECK_CUDA(cudaMalloc(&d_send[i], max_count * sizeof(float)));
        CHECK_CUDA(cudaMalloc(&d_recv[i], max_count * sizeof(float)));
        const size_t blocks = (max_count + 255) / 256;
        fill_kernel<<<blocks, 256, 0, streams[i]>>>(d_send[i], static_cast<float>(i + 1), max_count);
        CHECK_CUDA(cudaGetLastError());
    }
    for (int i = 0; i < o.gpus; ++i) {
        CHECK_CUDA(cudaSetDevice(devs[i]));
        CHECK_CUDA(cudaStreamSynchronize(streams[i]));
    }

    if (!o.csv) {
        std::cout << std::left
                  << std::setw(12) << "size(B)"
                  << std::setw(12) << "count"
                  << std::setw(14) << "time(us)"
                  << std::setw(14) << "algbw(GB/s)"
                  << std::setw(14) << "busbw(GB/s)"
                  << "check\n";
    } else {
        std::cout << "size_bytes,count,time_us,algbw_gbps,busbw_gbps,check\n";
    }

    for (size_t bytes = o.min_bytes; bytes <= o.max_bytes; bytes *= static_cast<size_t>(o.factor)) {
        const size_t count = std::max<size_t>(1, bytes / sizeof(float));
        for (int w = 0; w < o.warmup; ++w) {
            CHECK_NCCL(ncclGroupStart());
            for (int g = 0; g < o.gpus; ++g) {
                CHECK_NCCL(ncclAllReduce(
                    d_send[g], d_recv[g], count, ncclFloat, ncclSum, comms[g], streams[g]));
            }
            CHECK_NCCL(ncclGroupEnd());
        }
        for (int g = 0; g < o.gpus; ++g) {
            CHECK_CUDA(cudaSetDevice(devs[g]));
            CHECK_CUDA(cudaStreamSynchronize(streams[g]));
        }

        const auto t0 = std::chrono::high_resolution_clock::now();
        for (int it = 0; it < o.iters; ++it) {
            CHECK_NCCL(ncclGroupStart());
            for (int g = 0; g < o.gpus; ++g) {
                CHECK_NCCL(ncclAllReduce(
                    d_send[g], d_recv[g], count, ncclFloat, ncclSum, comms[g], streams[g]));
            }
            CHECK_NCCL(ncclGroupEnd());
        }
        for (int g = 0; g < o.gpus; ++g) {
            CHECK_CUDA(cudaSetDevice(devs[g]));
            CHECK_CUDA(cudaStreamSynchronize(streams[g]));
        }
        const auto t1 = std::chrono::high_resolution_clock::now();
        const double us = std::chrono::duration<double, std::micro>(t1 - t0).count() / o.iters;
        const double sec = us / 1e6;
        const double algbw = static_cast<double>(bytes) / sec / 1e9;
        const double busbw = (o.gpus > 1) ? algbw * (2.0 * (o.gpus - 1) / o.gpus) : 0.0;

        float first = 0.0f;
        CHECK_CUDA(cudaSetDevice(devs[0]));
        CHECK_CUDA(cudaMemcpy(&first, d_recv[0], sizeof(float), cudaMemcpyDeviceToHost));
        const float expect = (static_cast<float>(o.gpus) * (o.gpus + 1)) / 2.0f;
        const bool ok = std::fabs(first - expect) < 1e-3f;

        if (!o.csv) {
            std::cout << std::left
                      << std::setw(12) << bytes
                      << std::setw(12) << count
                      << std::setw(14) << std::fixed << std::setprecision(2) << us
                      << std::setw(14) << std::fixed << std::setprecision(2) << algbw
                      << std::setw(14) << std::fixed << std::setprecision(2) << busbw
                      << (ok ? "OK" : "BAD")
                      << "\n";
        } else {
            std::cout << bytes << "," << count << ","
                      << std::fixed << std::setprecision(2) << us << ","
                      << std::fixed << std::setprecision(2) << algbw << ","
                      << std::fixed << std::setprecision(2) << busbw << ","
                      << (ok ? "OK" : "BAD")
                      << "\n";
        }

        if (bytes > (std::numeric_limits<size_t>::max() / static_cast<size_t>(o.factor))) break;
    }

    for (int i = 0; i < o.gpus; ++i) {
        CHECK_CUDA(cudaSetDevice(devs[i]));
        if (d_send[i]) CHECK_CUDA(cudaFree(d_send[i]));
        if (d_recv[i]) CHECK_CUDA(cudaFree(d_recv[i]));
        CHECK_CUDA(cudaStreamDestroy(streams[i]));
        CHECK_NCCL(ncclCommDestroy(comms[i]));
    }
    return 0;
}
