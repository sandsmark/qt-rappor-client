# We'll add this include path so that we can include using "qt-rappor-client"
# prefix on both CMake and qmake build.
INCLUDEPATH += $$PWD/..

SOURCES += \
    $$PWD/encoder.cc \
    $$PWD/qt_hash_impl.cc \
    $$PWD/std_rand_impl.cc \

HEADERS += \
    $$PWD/encoder.h \
    $$PWD/qt_hash_impl.h \
    $$PWD/std_rand_impl.h \
