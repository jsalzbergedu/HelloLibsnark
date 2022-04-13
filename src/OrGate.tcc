#ifndef OR_GATE_H
#define OR_GATE_H 1
#include <iostream>
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <gtest/gtest.h>

template<typename F>
class OrGate : public libsnark::gadget<F> {
private:
public:
  const libsnark::pb_variable<F> x, y, z;

  OrGate(libsnark::protoboard<F> &pb,
           const libsnark::pb_variable<F> &x,
           const libsnark::pb_variable<F> &y,
           const libsnark::pb_variable<F> &z) :
      libsnark::gadget<F>(pb, "OrGate"), x(x), y(y), z(z) {}

  // Perhaps this is just adding them to the circuit?
  void generate_r1cs_constraints() {
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(x - 1, x, 0));
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(y - 1, y, 0));
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(x, y, x + y - z));
  }

  void generate_r1cs_witness() {
    this->pb.val(z) = (this->pb.val(x) == 0 && this->pb.val(y) == 0) ? 0 : 1;
  }
};

namespace {

typedef libff::Fr<libsnark::default_r1cs_ppzksnark_pp> F; // FieldT other places
class OrGateTests : public ::testing::Test {
 protected:
  libsnark::protoboard<F> pb;
  libsnark::pb_variable<F> z;
  libsnark::pb_variable<F> x;
  libsnark::pb_variable<F> y;

  OrGateTests() {}
  ~OrGateTests() override {}
  void SetUp() override {
    libff::inhibit_profiling_info = true;
    libsnark::default_r1cs_ppzksnark_pp::init_public_params();


    // allocate variables (public first)
    z.allocate(pb, "z"); // public
    x.allocate(pb, "x"); // private
    y.allocate(pb, "y"); // private

    // set the number of public variables
    // First 1 variables are public
    pb.set_input_sizes(3);
  }

  void TearDown() override {
  }

  void verify_constraints() {
    // produce keypair from full constraint system
    const libsnark::r1cs_constraint_system<F> constraint_system = pb.get_constraint_system();
    const libsnark::r1cs_ppzksnark_keypair<libsnark::default_r1cs_ppzksnark_pp> keypair = libsnark::r1cs_ppzksnark_generator<libsnark::default_r1cs_ppzksnark_pp>(constraint_system);

    // generate proof
    const libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> proof = libsnark::r1cs_ppzksnark_prover<libsnark::default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // verify proof
    bool verified = libsnark::r1cs_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    ASSERT_TRUE(verified);
  }
};

TEST_F(OrGateTests, XX) {
  pb.clear_values();
  pb.val(z) = 0;
  pb.val(x) = 1;
  pb.val(y) = 1;

  // call gadgets
  OrGate<F> g(pb, x, y, z);
  // generate constraints
  g.generate_r1cs_constraints();
  // generate witness values
  g.generate_r1cs_witness();

  verify_constraints();

  ASSERT_EQ(pb.val(z), 1);
};

TEST_F(OrGateTests, XO) {
  pb.clear_values();
  pb.val(z) = 0;
  pb.val(x) = 0;
  pb.val(y) = 1;

  // call gadgets
  OrGate<F> g(pb, x, y, z);
  // generate constraints
  g.generate_r1cs_constraints();
  // generate witness values
  g.generate_r1cs_witness();

  verify_constraints();

  ASSERT_EQ(pb.val(z), 1);
};

TEST_F(OrGateTests, OO) {
  pb.clear_values();
  pb.val(z) = 0;
  pb.val(x) = 0;
  pb.val(y) = 0;

  // call gadgets
  OrGate<F> g(pb, x, y, z);
  // generate constraints
  g.generate_r1cs_constraints();
  // generate witness values
  g.generate_r1cs_witness();

  verify_constraints();

  ASSERT_EQ(pb.val(z), 0);
};
} // namespace
#endif
