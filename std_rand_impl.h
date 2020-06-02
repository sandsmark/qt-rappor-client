#pragma once

#include "rappor_deps.h"

#include <memory>
#include <random>

namespace rappor {

class StdRand : public IrrRandInterface
{
public:
    StdRand();

    // For unit testing (todo make private I guess)
    StdRand(const std::random_device::result_type);
    virtual ~StdRand() = default;

    virtual bool GetMask(float prob, int num_bits, Bits* mask_out) const;

private:

    std::unique_ptr<std::mt19937> m_engine;
};

}  // namespace rappor
