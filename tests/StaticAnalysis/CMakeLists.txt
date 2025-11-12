find_program(BASH_EXECUTABLE bash REQUIRED)
# Adding format test
set(CLANG_FORMAT_SCRIPT ${PROJECT_SOURCE_DIR}/tests/StaticAnalysis/clang_format_tests.sh)

file(GLOB_RECURSE SRCS_FOR_FORMAT
  "${PROJECT_SOURCE_DIR}/app/*.cpp"
  "${PROJECT_SOURCE_DIR}/include/*.hpp"
  "${PROJECT_SOURCE_DIR}/tests//Helpers/*.hpp"
)

add_test(
    NAME FormatCheck
    COMMAND ${BASH_EXECUTABLE} ${CLANG_FORMAT_SCRIPT} ${SRCS_FOR_FORMAT}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# Adding tidy test
set(CLANG_TIDY_SCRIPT ${PROJECT_SOURCE_DIR}/tests/StaticAnalysis/clang_tidy_tests.sh)
set(SRCS_FOR_TIDY ${SRCS_FOR_FORMAT})

add_test(
    NAME TidyCheck
    COMMAND ${BASH_EXECUTABLE} ${CLANG_TIDY_SCRIPT} ${SRCS_FOR_TIDY}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
