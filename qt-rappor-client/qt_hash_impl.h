// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Qt implementation of RAPPOR dependencies.

#pragma once

#include "qt_rappor_global.h"

#include "rappor_deps.h"

namespace rappor {

bool QT_RAPPOR_EXPORT HmacSha256(const std::string& key, const std::string& value,
                std::vector<uint8_t>* output);
// Pass output vector of desired length.
bool QT_RAPPOR_EXPORT HmacDrbg(const std::string& key, const std::string& value,
              std::vector<uint8_t>* output);
bool QT_RAPPOR_EXPORT Md5(const std::string& value, std::vector<uint8_t>* output);

}  // namespace rappor

