#include <gtest/gtest.h>
#include "RangeCheck.tcc"
#include "OrGate.tcc"
#include "GraphColoring.tcc"
#include "AndGate.tcc"

typedef libff::Fr<libsnark::default_r1cs_ppzksnark_pp> F; // FieldT other places

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
