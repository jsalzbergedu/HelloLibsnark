include_directories(.)

add_executable(Hello_World Hello_World.cpp)
target_link_libraries(Hello_World snark)
target_include_directories(
 Hello_World
 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(TestAndGate TestAndGate.cpp)
target_link_libraries(TestAndGate snark)
target_link_libraries(TestAndGate gtest_main)
target_include_directories(
  TestAndGate
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(TestOrGate TestOrGate.cpp)
target_link_libraries(TestOrGate snark)
target_link_libraries(TestOrGate gtest_main)
target_include_directories(
  TestOrGate
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(TestRangeCheck TestRangeCheck.cpp)
target_link_libraries(TestRangeCheck snark)
target_link_libraries(TestRangeCheck gtest_main)
target_include_directories(
  TestRangeCheck
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(TestGraphColoring TestGraphColoring.cpp)
target_link_libraries(TestGraphColoring snark)
target_link_libraries(TestGraphColoring gtest_main)
target_include_directories(
  TestGraphColoring
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
