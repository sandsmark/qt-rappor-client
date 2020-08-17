#pragma once

#include <qglobal.h>

// clang-format off
#ifdef QT_RAPPOR_SHARED
#  if defined(BUILD_QT_RAPPOR_MODULE)
#    define QT_RAPPOR_EXPORT Q_DECL_EXPORT
#  else
#    define QT_RAPPOR_EXPORT Q_DECL_IMPORT
#  endif
#else
#  define QT_RAPPOR_EXPORT
#endif
// clang-format on
