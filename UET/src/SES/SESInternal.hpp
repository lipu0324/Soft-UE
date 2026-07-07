#ifndef SES_INTERNAL_HPP
#define SES_INTERNAL_HPP

#include <cstdint>
#include "SES.hpp"

struct SESValidationProbe
{
    static bool validateVersion(SESManager &manager, uint8_t version);
    static bool validateJobId(SESManager &manager, uint64_t job_id);
    static bool validateNeedAck(SESManager &manager, uint32_t messages_id, bool delivery_complete);
};

inline bool SESValidationProbe::validateVersion(SESManager &manager, uint8_t version)
{
    return manager.validate_version(version);
}

inline bool SESValidationProbe::validateJobId(SESManager &manager, uint64_t job_id)
{
    return manager.validate_job_id(job_id);
}

inline bool SESValidationProbe::validateNeedAck(SESManager &manager, uint32_t messages_id, bool delivery_complete)
{
    return manager.validate_need_ack(messages_id, delivery_complete);
}

#endif
