#include <iostream>
#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "RangeCheck.tcc"
#include <vector>
#include <tuple>
#include <map>
#include <set>

  static int countat = 0;
// TODO Fix vrb gen

// template<typename F>
// struct ComparePBV {
//   bool operator()(const libsnark::pb_variable<F> &fst, const libsnark::pb_variable<F> &snd) {
//     return fst.index < snd.index;
//   }
// };
enum class Color { Red = 0, Blue = 1, Green = 2 };

std::ostream& operator<<(std::ostream& out, const Color& color) {
  return out << ((color == Color::Red) ? "red" : (color == Color::Blue) ? "blue" : "green");
}

template<typename F>
class GraphColoring : public libsnark::gadget<F> {
private:
public:
  const std::map<int, std::vector<int>> adjacencies;
  const std::map<int, libsnark::pb_variable<F>> id_to_variable;
  std::map<int, std::map<int, libsnark::pb_variable<F>>> edge_to_difference_range;
  const std::set<int> ids;
  std::vector<RangeCheck<F>> range_checks;

  GraphColoring(libsnark::protoboard<F> &pb,
                std::map<int, std::vector<int>> &id_adjacencies,
                std::map<int, libsnark::pb_variable<F>> &id_to_variable,
                std::set<int> &ids) :
      libsnark::gadget<F>(pb, "GraphColoring"), adjacencies(id_adjacencies), id_to_variable(id_to_variable), ids(ids) {
  }

  // Perhaps this is just adding them to the circuit?
  void generate_r1cs_constraints() {

    for (auto vertex_adj : adjacencies) {
      libsnark::pb_variable<F> e0 = id_to_variable.at(vertex_adj.first);

      // Constrain e0 to be w/in the colors
      RangeCheck<F> is_color = RangeCheck<F>(this->pb, e0, {0, 1, 2});
      range_checks.push_back(is_color);

      for (auto e1_id : vertex_adj.second) {
        libsnark::pb_variable<F> e1 = id_to_variable.at(e1_id);

        // Constrain the difference
        libsnark::pb_variable<F> allowed_difference_values;
        allowed_difference_values.allocate(this->pb);
        RangeCheck<F> is_difference = RangeCheck<F>(this->pb, allowed_difference_values, {2, 1, -1, -2});
        range_checks.push_back(is_difference);
        if (edge_to_difference_range.find(vertex_adj.first) == edge_to_difference_range.end()) {
          edge_to_difference_range.insert({{vertex_adj.first, {}}});
        }
        edge_to_difference_range.at(vertex_adj.first).insert({{e1_id, allowed_difference_values}});

        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<F>(e0 - e1, 1, allowed_difference_values));
      }
    }
  }

  std::map<int, Color> color_variables(std::set<int> uncolored, std::map<int, Color> vertex_colors) {
    if (uncolored.empty()) {
    return vertex_colors;
    } else {
      int picked;
      for (auto id : uncolored) {
        picked = id;
        break;
      }
      uncolored.erase(picked);
      bool red_possible, blue_possible, green_possible = true;
      for (auto adj : adjacencies.at(picked)) {
        red_possible = red_possible && ((vertex_colors.find(adj) == vertex_colors.end()) || (vertex_colors.at(adj) != Color::Red));
        blue_possible = blue_possible && ((vertex_colors.find(adj) == vertex_colors.end()) || (vertex_colors.at(adj) != Color::Blue));
        green_possible = green_possible && ((vertex_colors.find(adj) == vertex_colors.end()) || (vertex_colors.at(adj) != Color::Green));
      }
      std::map<int, Color> restore(vertex_colors);
      if (red_possible) {
        try {
          vertex_colors.insert({{picked, Color::Red}});
          vertex_colors = color_variables(uncolored, vertex_colors);
        } catch (const std::nested_exception &e) {
          vertex_colors = restore;
          if (blue_possible) {
            goto blue_case;
          }
          if (green_possible) {
            goto green_case;
          }
        }
      } else if (blue_possible) {
     blue_case:
        try {
          vertex_colors.insert({{picked, Color::Blue}});
          vertex_colors = color_variables(uncolored, vertex_colors);
        } catch (const std::nested_exception &e) {
          vertex_colors = restore;
          if (green_possible) {
            goto green_case;
          }
        }
      } else if (green_possible) {
     green_case:
        vertex_colors.insert({{picked, Color::Green}});
        vertex_colors = color_variables(uncolored, vertex_colors);
      } else {
        std::throw_with_nested(std::nested_exception());
      }
      return vertex_colors;
    }
  }

  void generate_r1cs_witness() {
    try {
      std::map<int, Color> out;
      auto coloring = color_variables(ids, out);
      for (auto id_color : coloring) {
        int color = static_cast<int>(id_color.second);

        this->pb.val(id_to_variable.at(id_color.first)) = color;
        for (auto adj : adjacencies.at(id_color.first)) {
          this->pb.val(edge_to_difference_range.at(id_color.first).at(adj)) = static_cast<int>(id_color.second) - static_cast<int>(coloring.at(adj));
        }
      }
    } catch (std::nested_exception &e) {
      // Fallthrough, no coloring is possible
    }
    for (auto range_check : range_checks) {
      range_check.generate_r1cs_witness();
    }
  }
};
