
// Example code that runs the full pipeline

#include <iostream>

#include "AndGate.tcc"

// TODO thread together and and or gate
// TODO setup tests :-)
// TODO: Implement OR gate
// TODO: Implement XOR gate
// TODO: Implement NOT gate
// TODO: Implement NAND gate

// TODO Begin implementing kruskall like thing
/*
 * Notes:
 * How do you pass it input? (Public witnesses? protoboard?)
 * * Public and private inputs, _along with_ parameters
 * How do you take its output? Only one bit? (Oh, public witnesses (?))
 * * Public witness values yea
 * What get's produced in proving?
 * * 1 bit = proved + public witnesses
 * What's pb primary input, pb auxillary input?
 * * Primary input = public witnesses
 * * Auxilary input = ???
 * How do you hook together two circuits?
 * * I believe you can just reuse variables.
 * How do you incorporate benes networks/clos networks?
 * * TODO
 * Why did he put x and y as private?
 * * Because they're also input (?) because the verf doesnt have to know them
 * * And MOREOVER the and gate just publicly ACTS as an and gate, in in fact
 * * is not CONSTRAINED to be an and gate
 * How is it constrained to binary?
 * * You have to add it as a constraint, not as witness gen!
 * Ok time to build a testable project
 */

int main() {
  // Initialize curve parameters
  libsnark::default_r1cs_ppzksnark_pp::init_public_params();
  typedef libff::Fr<libsnark::default_r1cs_ppzksnark_pp> F; // FieldT other places

  // create libsnark::protoboard
  libsnark::protoboard<F> pb;

  libsnark::pb_variable<F> z;
  // libsnark::pb_variable<F> w;
  libsnark::pb_variable<F> x;
  libsnark::pb_variable<F> y;

  // allocate variables (public first)
  // z.allocate(pb, "w"); // public
  z.allocate(pb, "z"); // public
  x.allocate(pb, "x"); // private
  y.allocate(pb, "y"); // private

  // set the number of public variables
  // First 1 variables are public
  pb.set_input_sizes(3);

  // pb.val(w) = 0;
  pb.val(z) = 0;
  pb.val(x) = 1;
  pb.val(y) = 1;

  // call gadgets
  AndGate<F> g(pb, x, y, z);

  std::cout << "Constraint system: " << pb.get_constraint_system() << std::endl;

  // generate constraints
  g.generate_r1cs_constraints();

  std::cout << "Dumping variables: " << std::endl;
  pb.dump_variables();
  std::cout << pb.val(x) << std::endl;
  std::cout << pb.val(y) << std::endl;
  std::cout << pb.val(z) << std::endl;
  // std::cout << pb.val(w) << std::endl;

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
  // std::cout << pb.val(w) << std::endl;

  return 0;
}
