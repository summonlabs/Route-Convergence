#include "rc/limits.hpp"

namespace rc {

bool ConvergenceLimits::is_coherent(std::string& reason) const {
  if (max_steps_per_plan == 0 || max_steps_per_plan > kAbsoluteMaxStepsPerPlan) {
    reason = "max_steps_per_plan must be in [1, kAbsoluteMaxStepsPerPlan]";
    return false;
  }
  if (max_dependencies_per_step > kAbsoluteMaxDependenciesPerStep) {
    reason = "max_dependencies_per_step exceeds kAbsoluteMaxDependenciesPerStep";
    return false;
  }
  if (max_parallel_steps == 0 || max_parallel_steps > kAbsoluteMaxParallelSteps) {
    reason = "max_parallel_steps must be in [1, kAbsoluteMaxParallelSteps]";
    return false;
  }
  if (max_parallel_steps > max_steps_per_plan) {
    reason = "max_parallel_steps cannot exceed max_steps_per_plan";
    return false;
  }
  if (max_retries_per_step > kAbsoluteMaxRetriesPerStep) {
    reason = "max_retries_per_step exceeds kAbsoluteMaxRetriesPerStep";
    return false;
  }
  if (max_total_dependencies < max_dependencies_per_step) {
    reason = "max_total_dependencies cannot be smaller than max_dependencies_per_step";
    return false;
  }
  if (max_persistence_record_bytes == 0) {
    reason = "max_persistence_record_bytes must be positive";
    return false;
  }
  if (max_frame_bytes < kMinimumFrameBytes) {
    reason = "max_frame_bytes must be able to hold one empty frame";
    return false;
  }
  if (max_explanation_entries == 0) {
    reason = "max_explanation_entries must be positive";
    return false;
  }
  if (max_history_per_plan == 0) {
    reason = "max_history_per_plan must be positive";
    return false;
  }
  reason.clear();
  return true;
}

}  // namespace rc
