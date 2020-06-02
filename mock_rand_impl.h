#pragma once

#include "rappor_deps.h"

#include <memory>
#include <random>

namespace rappor {

class MockRand : public IrrRandInterface
{
public:
    MockRand();

    void GetMask(float prob, int num_bits, Bits* mask_out) const override;

private:
    std::vector<uint8_t> m_data;
};

}  // namespace rappor
