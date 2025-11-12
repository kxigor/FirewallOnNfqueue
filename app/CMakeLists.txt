find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNFQ REQUIRED libnetfilter_queue)

add_executable(app app.cpp)
target_link_libraries(app ${LIBNFQ_LIBRARIES})
target_include_directories(app PRIVATE ${LIBNFQ_INCLUDE_DIRS})