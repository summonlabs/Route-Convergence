#include "rc/version.hpp"

#include <string>

namespace rc {

std::string version_report() {
  std::string out;
  out += "product: ";
  out += kProductName;
  out += '\n';
  out += "vendor: ";
  out += kVendorName;
  out += '\n';
  out += "version: ";
  out += kVersionString;
  out += '\n';
  out += "wire_version: " + std::to_string(kWireVersion) + '\n';
  out += "persistence_format_version: " + std::to_string(kPersistenceFormatVersion) + '\n';
  out += "digest_encoding_version: " + std::to_string(kDigestEncodingVersion) + '\n';
  out += "plan_encoding_version: " + std::to_string(kPlanEncodingVersion) + '\n';
  out += "step_semantics_version: " + std::to_string(kStepSemanticsVersion) + '\n';
  out += "license: ";
  out += kLicenseNotice;
  out += '\n';
  return out;
}

std::string version_line() {
  std::string out = "route-convergence ";
  out += kVersionString;
  return out;
}

}  // namespace rc
