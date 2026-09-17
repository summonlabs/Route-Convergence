#include "rc/upstream.hpp"

#include "rc/limits.hpp"

namespace rc {
namespace {

[[nodiscard]] std::string id_or_dash(bool present, const auto& id) {
  return present ? id.to_text() : std::string("-");
}

}  // namespace

bool RouteBinding::is_well_formed() const noexcept {
  if (route.is_nil() || path.is_nil()) {
    return false;
  }
  if (generation.value() == 0 || path_authority_generation.value() == 0) {
    return false;
  }
  // A multipath set, an ECMP group and a weighted path set are optional: a route
  // may be a plain single-path binding.  When one is present its generations must
  // be present as well, so a partially specified binding can never be planned.
  const bool has_multipath = !multipath_set.is_nil();
  const bool has_ecmp = !ecmp_group.is_nil();
  const bool has_weighted = !weighted_set.is_nil();
  if (has_multipath && multipath_generation.value() == 0) {
    return false;
  }
  if (has_ecmp && (ecmp_generation.value() == 0 || assignment_generation.value() == 0)) {
    return false;
  }
  if (has_weighted && weight_policy_generation.value() == 0) {
    return false;
  }
  return true;
}

std::string RouteBinding::render() const {
  std::string out = "route=";
  out += route.to_text();
  out += " generation=" + std::to_string(generation.value());
  out += " path=";
  out += path.to_text();
  out += " path_authority_generation=" + std::to_string(path_authority_generation.value());
  out += " multipath_set=";
  out += id_or_dash(!multipath_set.is_nil(), multipath_set);
  out += " multipath_generation=" + std::to_string(multipath_generation.value());
  out += " ecmp_group=";
  out += id_or_dash(!ecmp_group.is_nil(), ecmp_group);
  out += " ecmp_generation=" + std::to_string(ecmp_generation.value());
  out += " assignment_generation=" + std::to_string(assignment_generation.value());
  out += " weighted_set=";
  out += id_or_dash(!weighted_set.is_nil(), weighted_set);
  out += " weight_policy_generation=" + std::to_string(weight_policy_generation.value());
  out += " current=" + std::to_string(current ? 1 : 0);
  out += " legal=" + std::to_string(legal ? 1 : 0);
  return out;
}

std::string PathLegality::render() const {
  std::string out = "path=";
  out += path.to_text();
  out += " generation=" + std::to_string(generation.value());
  out += " legal=" + std::to_string(legal ? 1 : 0);
  return out;
}

}  // namespace rc
