find_package(GTest REQUIRED)

include_directories(${GTEST_INCLUDE_DIRS})

# .sh - simple test, .cpp - google test

function(add_google_test TEST_NAME TEST_SRC)
    add_executable(${TEST_NAME} ${TEST_SRC})
    target_include_directories(${TEST_NAME} SYSTEM PUBLIC
        Threads::Threads
        ${GTEST_INCLUDE_DIRS}
        ${GMOCK_INCLUDE_DIRS}
    )
    set_property(TARGET ${TEST_NAME} PROPERTY RUNTIME_OUTPUT_DIRECTORY "")
    target_link_libraries(${TEST_NAME} PUBLIC ${GTEST_LIBRARIES})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endfunction()

function(add_coverage_to_test TEST_NAME)
    if(NOT TARGET ${TEST_NAME})
        message(WARNING "Target ${TEST_NAME} does not exist, skipping coverage")
        return()
    endif()

    get_target_property(TEST_LIBRARIES ${TEST_NAME} LINK_LIBRARIES)
    if(NOT "${TEST_LIBRARIES}" MATCHES "gtest")
        message(WARNING "Target ${TEST_NAME} does not link against Google Test, skipping coverage")
        return()
    endif()

    get_target_property(TEST_SOURCES ${TEST_NAME} SOURCES)
    if(NOT TEST_SOURCES)
        message(WARNING "No sources found for target ${TEST_NAME}, skipping coverage")
        return()
    endif()

    target_compile_options(${TEST_NAME} PRIVATE -fprofile-arcs -ftest-coverage)
    target_link_options(${TEST_NAME} PRIVATE -fprofile-arcs -ftest-coverage)

    set(COVERAGE_DIR "${CMAKE_BINARY_DIR}/coverage/${TEST_NAME}")
    file(MAKE_DIRECTORY ${COVERAGE_DIR})

    set(GCNO_FILES)
    set(GCDA_FILES)
    foreach(SOURCE_FILE ${TEST_SOURCES})
        get_filename_component(SOURCE_BASE ${SOURCE_FILE} NAME_WE)
        set(GCNO_FILE "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${TEST_NAME}.dir/${SOURCE_BASE}.cpp.gcno")
        set(GCDA_FILE "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${TEST_NAME}.dir/${SOURCE_BASE}.cpp.gcda")
        list(APPEND GCNO_FILES ${GCNO_FILE})
        list(APPEND GCDA_FILES ${GCDA_FILE})
    endforeach()

    add_custom_target(${TEST_NAME}_coverage
        COMMAND ${CMAKE_COMMAND} -E remove ${GCDA_FILES}
        COMMAND $<TARGET_FILE:${TEST_NAME}>
        COMMAND ${CMAKE_COMMAND} -E echo "=== Generating coverage for ${TEST_NAME} ==="
        COMMAND ${CMAKE_COMMAND} -E make_directory ${COVERAGE_DIR}
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}
                gcov -r -b -s ${CMAKE_SOURCE_DIR} ${GCNO_FILES}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/*.gcov ${COVERAGE_DIR}/
        COMMAND ${CMAKE_COMMAND} -E echo "=== Coverage files generated in ${COVERAGE_DIR} ==="
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${TEST_NAME}
        COMMENT "Running coverage analysis for ${TEST_NAME}"
    )

    if(NOT TARGET coverage)
        add_custom_target(coverage
            COMMENT "Aggregating coverage results"
        )
    endif()

    add_dependencies(coverage ${TEST_NAME}_coverage)
endfunction()

function(add_simple_test TEST_NAME TEST_SRC)
    add_executable(${TEST_NAME} ${TEST_SRC})
    set_property(TARGET ${TEST_NAME} PROPERTY RUNTIME_OUTPUT_DIRECTORY "")
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endfunction()

function(copy_dlls_target target)
    if(WIN32)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:${target}>
            $<TARGET_FILE_DIR:${target}>
            COMMAND_EXPAND_LISTS
        )
    endif()
endfunction()
