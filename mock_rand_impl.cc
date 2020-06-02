#include "mock_rand_impl.h"

#include <cstdint>

namespace rappor {

MockRand::MockRand()
{
    for (int i = 0; i < 1024; i++) {
        m_data.push_back((i * 17) % 256);
    }
}

void MockRand::GetMask(float prob, int num_bits, Bits* mask_out) const
{
    uint8_t threshold_256 = static_cast<uint8_t>(prob * 256);

    Bits mask = 0;
    for (int i = 0; i < num_bits; ++i) {
        uint8_t bit = (m_data[i] < threshold_256);
        mask |= (bit << i);
    }
    *mask_out = mask;
}

}  // namespace rappor
