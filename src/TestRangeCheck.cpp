#include <gtest/gtest.h>
#include "RangeCheck.tcc"
#include <iostream>

typedef libff::Fr<libsnark::default_r1cs_ppzksnark_pp> F; // FieldT other places

namespace {

class RangeCheckTests : public ::testing::Test {
 protected:
  libsnark::protoboard<F> pb;
  libsnark::pb_variable<F> x;

  RangeCheckTests() {}
  ~RangeCheckTests() override {}
  void SetUp() override {
    libff::inhibit_profiling_info = true;
    libsnark::default_r1cs_ppzksnark_pp::init_public_params();

    // allocate variables (public first)
    x.allocate(pb, "x"); // private

    // set the number of public variables
    // First 1 variables are public
    pb.set_input_sizes(1);
  }

  void TearDown() override {
  }

  bool verify_constraints() {
    // produce keypair from full constraint system
    const libsnark::r1cs_constraint_system<F> constraint_system = pb.get_constraint_system();
    const libsnark::r1cs_ppzksnark_keypair<libsnark::default_r1cs_ppzksnark_pp> keypair = libsnark::r1cs_ppzksnark_generator<libsnark::default_r1cs_ppzksnark_pp>(constraint_system);

    // generate proof
    const libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> proof = libsnark::r1cs_ppzksnark_prover<libsnark::default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // verify proof
    bool verified = libsnark::r1cs_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    return verified;
  }
};

TEST_F(RangeCheckTests, OneVariable) {
  pb.clear_values();
  // call gadgets
  std::vector<F> to_be = {1};
  RangeCheck<F> g(pb, x, to_be);
  // generate constraints
  g.generate_r1cs_constraints();
  g.generate_r1cs_witness();
  pb.val(x) = 1;
  ASSERT_TRUE(verify_constraints());
  ASSERT_EQ(pb.val(x), 1);
};

TEST_F(RangeCheckTests, OneVariableDeathTest) {
  pb.clear_values();
  // call gadgets
  pb.val(x) = -1;
  std::vector<F> to_be = {1};
  RangeCheck<F> g(pb, x, to_be);
  // generate constraints
  g.generate_r1cs_constraints();
  g.generate_r1cs_witness();
  ASSERT_DEATH(verify_constraints(), ".*");
};

TEST_F(RangeCheckTests, TwoVariableTestFirst) {
  pb.clear_values();
  // call gadgets
  pb.val(x) = 10;
  std::vector<F> to_be = {10, 20};
  RangeCheck<F> g(pb, x, to_be);
  // generate constraints
  g.generate_r1cs_constraints();
  g.generate_r1cs_witness();
  ASSERT_TRUE(verify_constraints());
};

TEST_F(RangeCheckTests, TwoVariableTestSecond) {
  pb.clear_values();
  // call gadgets
  pb.val(x) = 20;
  std::vector<F> to_be = {10, 20};
  RangeCheck<F> g(pb, x, to_be);
  // generate constraints
  g.generate_r1cs_constraints();
  g.generate_r1cs_witness();
  ASSERT_TRUE(verify_constraints());
};

TEST_F(RangeCheckTests, TwoVariableDeathTest) {
  pb.clear_values();
  // call gadgets
  pb.val(x) = -5;
  std::vector<F> to_be = {10, 20};
  RangeCheck<F> g(pb, x, to_be);
  // generate constraints
  g.generate_r1cs_constraints();
  g.generate_r1cs_witness();
  ASSERT_DEATH(verify_constraints(), ".*");
};

TEST_F(RangeCheckTests, ThreeVariableTest) {
  pb.clear_values();
  // call gadgets
  pb.val(x) = 20;
  std::vector<F> to_be = {10, 20, 30};
  RangeCheck<F> g(pb, x, to_be);
  // generate constraints
  g.generate_r1cs_constraints();
  g.generate_r1cs_witness();
  ASSERT_TRUE(verify_constraints());
};


TEST_F(RangeCheckTests, ThreeVariableDeathTest) {
  pb.clear_values();
  // call gadgets
  pb.val(x) = -5;
  std::vector<F> to_be = {10, 20, 30};
  RangeCheck<F> g(pb, x, to_be);
  // generate constraints
  g.generate_r1cs_constraints();
  g.generate_r1cs_witness();
  ASSERT_DEATH(verify_constraints(), ".*");
};

} // namespace

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
