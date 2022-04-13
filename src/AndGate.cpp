
// Example code that runs the full pipeline

#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "AndGate.tcc"

int main() {
  // Initialize curve parameters
  libsnark::default_r1cs_ppzksnark_pp::init_public_params();
  typedef libff::Fr<libsnark::default_r1cs_ppzksnark_pp> F; // FieldT other places

  // create libsnark::protoboard
  libsnark::protoboard<F> pb;

  libsnark::pb_variable<F> z;
  libsnark::pb_variable<F> w;
  libsnark::pb_variable<F> x;
  libsnark::pb_variable<F> y;

  // allocate variables (public first)
  z.allocate(pb, "w"); // public
  z.allocate(pb, "z"); // public
  x.allocate(pb, "x"); // private
  y.allocate(pb, "y"); // private

  // set the number of public variables
  // First 1 variables are public
  pb.set_input_sizes(2);

  pb.val(z) = 0;
  pb.val(w) = 0;
  pb.val(x) = 1;
  pb.val(y) = 1;

  // call gadgets
  AND_Gate<F> g(pb, x, y, z);
  AND_Gate<F> o(pb, z, x, w);

  std::cout << "Constraint system: " << pb.get_constraint_system() << std::endl;

  // generate constraints
  g.generate_r1cs_constraints();

  std::cout << "Dumping variables: " << std::endl;
  pb.dump_variables();
  std::cout << pb.val(x) << std::endl;
  std::cout << pb.val(y) << std::endl;
  std::cout << pb.val(z) << std::endl;
  std::cout << pb.val(w) << std::endl;

  // produce keypair from full constraint system
  const libsnark::r1cs_constraint_system<F> constraint_system = pb.get_constraint_system();
  const libsnark::r1cs_ppzksnark_keypair<libsnark::default_r1cs_ppzksnark_pp> keypair = libsnark::r1cs_ppzksnark_generator<libsnark::default_r1cs_ppzksnark_pp>(constraint_system);

  // generate witness values
  g.generate_r1cs_witness();

  // generate proof
  std::cout << "Primary input looks like: " << pb.primary_input();
  const libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> proof = libsnark::r1cs_ppzksnark_prover<libsnark::default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  // verify proof
  bool verified = libsnark::r1cs_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);


  // print result
  std::cout << "The proof " << (verified ? "is" : "isn't") << " valid\n" << std::endl;

  std::cout << "Dumping variables: " << std::endl;
  pb.dump_variables();
  std::cout << pb.full_variable_assignment() << std::endl;
  std::cout << pb.val(x) << std::endl;
  std::cout << pb.val(y) << std::endl;
  std::cout << pb.val(z) << std::endl;
  std::cout << pb.val(w) << std::endl;

  return 0;
}
