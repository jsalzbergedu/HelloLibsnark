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


