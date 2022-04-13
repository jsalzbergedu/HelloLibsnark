#ifndef RANGE_CHECK_H
#define RANGE_CHECK_H 1
#include <iostream>
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <vector>
#include <assert.h>
#include <gtest/gtest.h>

template<typename F>
class RangeCheck : public libsnark::gadget<F> {
private:
public:
  const libsnark::linear_combination<F> x;
  const std::vector<F> &to_be;
  std::vector<libsnark::r1cs_constraint<F>> deferred_poly_constraint;
  std::vector<libsnark::pb_variable<F>> deferred_polys;

  RangeCheck(libsnark::protoboard<F> &pb, const libsnark::pb_variable<F> &x, const std::vector<F> &to_be) :
      libsnark::gadget<F>(pb, "RangeCheck"), x(x), to_be(to_be) {}

  void generate_r1cs_constraints() {
    // Cases:
    // {}: nothing needs to be constrained
    // {c0}: x = c0
    // {c0, c1}: (x - c0)(x - c1) = 0
    // {c0, c1, c2, ...}: (x - c0)(x - c1) = p0, p0(x - c2) = p1, ...
    if (to_be.size() == 0) {
      return;
    }
    if (to_be.size() == 1) {
      this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(x, 1, to_be[0]));
    }
    if (to_be.size() == 2) {
      this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(x - to_be[0], x - to_be[1], 0));
    }
    // In these 3 cases nothing has to be generated.
    // otherwise the value of poly accum depends on x:
    // (x - c0)(x - c1) = p0 so you just run that arithmetically
    libsnark::pb_variable<F> poly_accum;

    for (int i = 0; i < to_be.size(); i++) {
      if (i == 0) {
        if (i + 1 < to_be.size()) {
          poly_accum.allocate(this->pb, "range_check_polynomial");
          auto dp = libsnark::r1cs_constraint<F>(x - to_be[i], x - to_be[i + 1], poly_accum);
          deferred_poly_constraint.push_back(dp);
          deferred_polys.push_back(poly_accum);
          this->pb.add_r1cs_constraint(dp);
          i += 1;
        } else {
          this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(x, 1, to_be[i]));
        }
      } else {
        libsnark::pb_variable<F> poly;
        poly.allocate(this->pb, "range_check_polynomial");
        auto dp = libsnark::r1cs_constraint<F>(x - to_be[i], poly_accum, poly);
        deferred_poly_constraint.push_back(dp);
          deferred_polys.push_back(poly);
        this->pb.add_r1cs_constraint(dp);
        poly_accum = poly;
      }
    }
    if (to_be.size() > 1) {
      this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(poly_accum, 1, 0));
    }
  }

  void generate_r1cs_witness() {
    assert(deferred_polys.size() == deferred_poly_constraint.size());
    for (int i = 0; i < deferred_polys.size(); i++) {
      this->pb.val(deferred_polys[i]) = deferred_poly_constraint[i].a.evaluate(this->pb.full_variable_assignment()) * deferred_poly_constraint[i].b.evaluate(this->pb.full_variable_assignment());
    }
  }
};

namespace {

typedef libff::Fr<libsnark::default_r1cs_ppzksnark_pp> F; // FieldT other places

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

#endif
