cmake_minimum_required(VERSION 3.9)
project(qt-rappor-client LANGUAGES CXX C VERSION 1.0.0)

option(QT_RAPPOR_STATIC "Build static library so it can be built into the application")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(GNUInstallDirs)

find_package(Qt5 COMPONENTS Core REQUIRED)

set(QT_RAPPOR_SRC
    qt-rappor-client/encoder.h
    qt-rappor-client/qt_hash_impl.h
    qt-rappor-client/qt_rappor_global.h
    qt-rappor-client/rappor_deps.h
    qt-rappor-client/std_rand_impl.h
    encoder.cc
    qt_hash_impl.cc
    std_rand_impl.cc
)
if(QT_RAPPOR_STATIC)
    add_library(qt-rappor STATIC ${QT_RAPPOR_SRC})
else()
    add_library(qt-rappor SHARED ${QT_RAPPOR_SRC})
    set_target_properties(qt-rappor PROPERTIES
        POSITION_INDEPENDENT_CODE True
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})
endif()
target_link_libraries(qt-rappor Qt5::Core)
target_include_directories(qt-rappor PUBLIC .)
target_compile_definitions(qt-rappor PRIVATE BUILD_QT_RAPPOR_MODULE)
if (BUILD_SHARED_LIBS)
    target_compile_definitions(qt-rappor PUBLIC QT_RAPPOR_SHARED)
endif()

add_executable(encoder_demo encoder_demo.cc)
target_link_libraries(encoder_demo qt-rappor)

add_executable(rappor_sim rappor_sim.cc)
target_link_libraries(rappor_sim qt-rappor)

find_package(GTest)
if (GTEST_FOUND)
    include(CTest)

    # This never passed, as far back in the git history as I could go
    add_executable(encoder_unittest tests/encoder_unittest.cc tests/mock_rand_impl.cc)

    # This passes
    add_executable(qt_hash_impl_unittest tests/qt_hash_impl_unittest.cc)

    target_link_libraries(qt_hash_impl_unittest qt-rappor GTest::GTest)
    add_test(NAME qt_hash_impl_unittest COMMAND qt_hash_impl_unittest)
    target_link_libraries(encoder_unittest qt-rappor GTest::GTest)
    add_test(NAME encoder_unittest COMMAND encoder_unittest)
else()
    message(STATUS "Skipping tests")
endif()

install(TARGETS qt-rappor LIBRARY DESTINATION lib)

install(FILES qt-rappor-client/encoder.h DESTINATION include/qt-rappor-client)
install(FILES qt-rappor-client/rappor_deps.h DESTINATION include/qt-rappor-client)
install(FILES qt-rappor-client/std_rand_impl.h DESTINATION include/qt-rappor-client)
install(FILES qt-rappor-client/qt_hash_impl.h DESTINATION include/qt-rappor-client)
