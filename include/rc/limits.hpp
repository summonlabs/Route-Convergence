#pragma once

#include <cstdint>
#include <string>

namespace rc {

// Absolute hard ceiling for any step count in one convergence plan, independent
// of configuration.  A plan larger than this is malformed, not merely large.
inline constexpr std::uint32_t kAbsoluteMaxStepsPerPlan = 4096;
inline constexpr std::uint32_t kAbsoluteMaxDependenciesPerStep = 1024;
inline constexpr std::uint32_t kAbsoluteMaxParallelSteps = 256;
inline constexpr std::uint32_t kAbsoluteMaxSubjectBytes = 128;
// Minimum frame budget that can still hold one complete empty wire frame
// (84 header bytes plus a 32 byte integrity tag).
inline constexpr std::uint32_t kMinimumFrameBytes = 128;
// Hard ceiling on retries any convergence policy may request.
inline constexpr std::uint32_t kAbsoluteMaxRetriesPerStep = 64;

// Every field below is a live limit: each one is consulted on the path it
// bounds.  A zero value disables the capability it bounds (for example
// max_plans == 0 rejects every plan creation) rather than acting as "unlimited".
struct ConvergenceLimits {
  std::uint32_t max_plans = 200000;
  std::uint32_t max_steps_per_plan = 64;
  std::uint32_t max_dependencies_per_step = 64;
  std::uint32_t max_total_dependencies = 4096;
  std::uint32_t max_parallel_steps = 16;
  std::uint32_t max_history_per_plan = 64;
  std::uint32_t max_retries_per_step = 4;
  std::uint32_t max_frame_bytes = 262144;
  std::uint32_t max_batch_size = 256;
  std::uint32_t max_workers = 64;
  std::uint32_t max_sessions = 64;
  std::uint32_t max_persistence_record_bytes = 67108864;
  std::uint32_t max_explanation_entries = 64;
  std::uint32_t max_attempts_remembered = 512;
  std::uint32_t max_journal_entries = 4096;

  // Returns false and fills reason when the limit set is internally incoherent,
  // so that no impossible configuration can be configured.
  [[nodiscard]] bool is_coherent(std::string& reason) const;
};

}  // namespace rc
