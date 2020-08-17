#pragma once

#include "qt-rappor-client/qt_rappor_global.h"

#include "rappor_deps.h"

#include <memory>
#include <random>

namespace rappor {

class QT_RAPPOR_EXPORT StdRand : public IrrRandInterface
{
public:
    StdRand();

    // For unit testing (todo make private I guess)
    StdRand(const std::random_device::result_type);

    void GetMask(float prob, int num_bits, Bits* mask_out) const override;

private:

    std::unique_ptr<std::mt19937> m_engine;
};

}  // namespace rappor
