#include <gtest/gtest.h>
#include "GraphColoring.tcc"
#include <unordered_map>
#include <unordered_set>
#include <iostream>

typedef libff::Fr<libsnark::default_r1cs_ppzksnark_pp> F; // FieldT other places

namespace {

class TestGraphColoring : public ::testing::Test {
 protected:
  libsnark::protoboard<F> pb;

  TestGraphColoring() {}
  ~TestGraphColoring() override {}
  void SetUp() override {
    libff::inhibit_profiling_info = true;
    libsnark::default_r1cs_ppzksnark_pp::init_public_params();


    // set the number of public variables
    // Here lets just make them all private
    pb.set_input_sizes(0);
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

TEST_F(TestGraphColoring, Basic) {
  pb.clear_values();

  libsnark::pb_variable<F> x;
  libsnark::pb_variable<F> y;
  libsnark::pb_variable<F> z;
  x.allocate(pb, "x");
  y.allocate(pb, "y");
  z.allocate(pb, "z");
  std::map<int, libsnark::pb_variable<F>> id_to_variable;
  id_to_variable.insert({{1, x}, {2, y}, {3, z}});
  std::map<int, std::vector<int>> adjacencies;
  adjacencies.insert({{1, {2, 3}}, {2, {1, 3}}, {3, {1, 2}}});
  std::set<int> ids;
  ids.insert(1);
  ids.insert(2);
  ids.insert(3);
  GraphColoring<F> gc(pb, adjacencies, id_to_variable, ids);
  gc.generate_r1cs_constraints();
  gc.generate_r1cs_witness();
  std::cout << "done" << std::endl;
  ASSERT_TRUE(verify_constraints());
};

} // namespace

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
