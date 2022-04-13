include_directories(.)

add_executable(Hello_World Hello_World.cpp)
target_link_libraries(Hello_World snark gtest gtest_main)
target_include_directories(
 Hello_World
 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/gtest
)

add_executable(RunAllTests RunAllTests.cpp)
target_link_libraries(RunAllTests snark gtest gtest_main)
target_include_directories(
  RunAllTests
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/gtest/googletest/include
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/gtest
)
