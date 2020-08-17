cmake_minimum_required(VERSION 3.9)
project(qt-rappor-client LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Qt5 COMPONENTS Core REQUIRED)

add_library(qt-rappor
    encoder.h
    encoder.cc
    qt_hash_impl.h
    qt_hash_impl.cc
    rappor_deps.h
    std_rand_impl.h
    std_rand_impl.cc
    )
target_link_libraries(qt-rappor Qt5::Core)

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

install(TARGETS qt-rappor DESTINATION lib)

install(FILES encoder.h DESTINATION include/qt-rappor)
install(FILES rappor_deps.h DESTINATION include/qt-rappor)
install(FILES std_rand_impl.h DESTINATION include/qt-rappor)
install(FILES qt_hash_impl.h DESTINATION include/qt-rappor)
