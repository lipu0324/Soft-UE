#include "LibfabricTestCommon.hpp"

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_errno.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

using UET::Test::Libfabric::select_uet_provider_info;

struct FabricCtx {
    fi_info* info = nullptr;
    fid_fabric* fabric = nullptr;
    fid_domain* domain = nullptr;
};

static void cleanup(FabricCtx& ctx)
{
    if (ctx.domain) fi_close(&ctx.domain->fid);
    if (ctx.fabric) fi_close(&ctx.fabric->fid);
    if (ctx.info) fi_freeinfo(ctx.info);
}

static int setup_domain(FabricCtx& ctx)
{
    fi_info* hints = fi_allocinfo();
    if (!hints) {
        std::cerr << "fi_allocinfo failed" << std::endl;
        return -1;
    }
    hints->caps = 0;
    hints->ep_attr->type = FI_EP_DGRAM;

    int ret = fi_getinfo(FI_VERSION(1, 5), nullptr, nullptr, 0, hints, &ctx.info);
    fi_freeinfo(hints);
    if (ret) {
        std::cerr << "fi_getinfo failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }
    ret = select_uet_provider_info(ctx.info);
    if (ret) {
        return ret;
    }

    ret = fi_fabric(ctx.info->fabric_attr, &ctx.fabric, nullptr);
    if (ret) {
        std::cerr << "fi_fabric failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    ret = fi_domain(ctx.fabric, ctx.info, &ctx.domain, nullptr);
    if (ret) {
        std::cerr << "fi_domain failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    return 0;
}

static int expect_soft_success()
{
    FabricCtx ctx{};
    if (setup_domain(ctx) != 0) {
        cleanup(ctx);
        return 1;
    }

    std::vector<uint8_t> buf(4096, 0);
    fid_mr* mr = nullptr;
    int ret = fi_mr_reg(ctx.domain, buf.data(), buf.size(), FI_READ | FI_WRITE, 0, 0, 0, &mr, nullptr);
    if (ret) {
        std::cerr << "fi_mr_reg failed: " << fi_strerror(-ret) << std::endl;
        cleanup(ctx);
        return 1;
    }
    fi_close(&mr->fid);

    iovec iov{};
    iov.iov_base = buf.data();
    iov.iov_len = buf.size();
    ret = fi_mr_regv(ctx.domain, &iov, 1, FI_READ | FI_WRITE, 0, 0, 0, &mr, nullptr);
    if (ret) {
        std::cerr << "fi_mr_regv(count=1) failed: " << fi_strerror(-ret) << std::endl;
        cleanup(ctx);
        return 1;
    }
    fi_close(&mr->fid);

    iovec iov_pair[2]{iov, iov};
    ret = fi_mr_regv(ctx.domain, iov_pair, 2, FI_READ | FI_WRITE, 0, 0, 0, &mr, nullptr);
    if (ret != -FI_ENOSYS) {
        std::cerr << "fi_mr_regv(count=2) expected -FI_ENOSYS, got " << ret << std::endl;
        cleanup(ctx);
        return 1;
    }

    fi_mr_attr attr{};
    attr.mr_iov = &iov;
    attr.iov_count = 1;
    attr.access = FI_READ | FI_WRITE;
    attr.requested_key = 0;
    attr.offset = 0;
    attr.context = nullptr;
    attr.auth_key = nullptr;
    attr.auth_key_size = 0;
    attr.iface = FI_HMEM_SYSTEM;
    attr.device.reserved = 0;
    ret = fi_mr_regattr(ctx.domain, &attr, 0, &mr);
    if (ret) {
        std::cerr << "fi_mr_regattr failed: " << fi_strerror(-ret) << std::endl;
        cleanup(ctx);
        return 1;
    }
    fi_close(&mr->fid);

    cleanup(ctx);
    return 0;
}

static int expect_rdma_unavailable()
{
    FabricCtx ctx{};
    if (setup_domain(ctx) != 0) {
        cleanup(ctx);
        return 1;
    }

    std::vector<uint8_t> buf(1024, 0);
    fid_mr* mr = nullptr;
    const int ret = fi_mr_reg(ctx.domain, buf.data(), buf.size(), FI_READ | FI_WRITE, 0, 0, 0, &mr, nullptr);
    if (ret == 0) {
        fi_close(&mr->fid);
        cleanup(ctx);
        return 0;
    }
    cleanup(ctx);
    if (ret == -FI_EOPNOTSUPP) {
        return 0;
    }

    std::cerr << "expected rdma fi_mr_reg to succeed or return -FI_EOPNOTSUPP, got " << ret << std::endl;
    return 1;
}

} // namespace

int main()
{
    const char* backend = std::getenv("UET_BACKEND");
    if (backend && std::strcmp(backend, "rdma") == 0) {
        const int rc = expect_rdma_unavailable();
        std::cout << (rc == 0 ? "MRRegLibfabricTest rdma PASS" : "MRRegLibfabricTest rdma FAIL") << std::endl;
        return rc;
    }

    const int rc = expect_soft_success();
    std::cout << (rc == 0 ? "MRRegLibfabricTest soft PASS" : "MRRegLibfabricTest soft FAIL") << std::endl;
    return rc;
}
