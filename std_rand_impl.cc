#include "qt-rappor-client/std_rand_impl.h"

#include <cstdint>
#include <memory>

namespace rappor {

StdRand::StdRand()
{
    // This should be a hardware-backed source according to the spec
    std::random_device entropySource;

    m_engine = std::make_unique<std::mt19937>(entropySource());
}

// For unit testing only
StdRand::StdRand(const std::random_device::result_type seed)
{
    m_engine = std::make_unique<std::mt19937>(seed);
}

void StdRand::GetMask(float prob, int num_bits, Bits* mask_out) const
{
    Bits mask = 0;
    std::bernoulli_distribution distribution(prob);

    for (int i = 0; i < num_bits; ++i) {
        uint8_t bit = distribution(*m_engine) ? 1 : 0;
        mask |= (bit << i);
    }
    *mask_out = mask;
}

}  // namespace rappor
