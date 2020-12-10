cmake_minimum_required(VERSION 3.9)
project(qt-rappor-client LANGUAGES CXX C VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(GNUInstallDirs)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Core REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core REQUIRED)

set(qt_rappor_headers
    qt-rappor-client/encoder.h
    qt-rappor-client/qt_hash_impl.h
    qt-rappor-client/qt_rappor_global.h
    qt-rappor-client/rappor_deps.h
    qt-rappor-client/std_rand_impl.h
)

set(QT_RAPPOR_SRC
    ${qt_rappor_headers}
    encoder.cc
    qt_hash_impl.cc
    std_rand_impl.cc
)
add_library(qt-rappor ${QT_RAPPOR_SRC})
set_target_properties(qt-rappor PROPERTIES
    POSITION_INDEPENDENT_CODE True
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

target_link_libraries(qt-rappor Qt${QT_VERSION_MAJOR}::Core)
target_include_directories(qt-rappor PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/qt-rappor-client>
)
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

install(TARGETS qt-rappor
    EXPORT QtRapporClient
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${qt_rappor_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qt-rappor-client)

add_library(QtRapporClient::QtRapporClient ALIAS qt-rappor)
set_target_properties(qt-rappor PROPERTIES
    EXPORT_NAME QtRapporClient
)

install(EXPORT QtRapporClient
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/QtRapporClient
    NAMESPACE QtRapporClient::
    FILE QtRapporClientConfig.cmake
)
