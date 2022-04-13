#include <iostream>
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"

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
    std::cout << "Setting z: " << this->pb.val(z) << std::endl;
    this->pb.val(z) = (this->pb.val(x) == 0 && this->pb.val(y) == 0) ? 0 : 1;
    std::cout << "z set: " << this->pb.val(z) << std::endl;
    std::cout << "x * y = x + y - z" << std::endl << this->pb.val(x) << " * " << this->pb.val(y) << " = " << this->pb.val(x) << " + " << this->pb.val(y) << "-" << this->pb.val(z) << std::endl;
    std::cout << "x * y = x + y - z" << std::endl << this->pb.val(x) * this->pb.val(y) << " = " << this->pb.val(x) + this->pb.val(y) - this->pb.val(z) << std::endl;
  }
};