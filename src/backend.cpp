#include "rc/backend.hpp"

#include <algorithm>

#include "rc/digest.hpp"

namespace rc {

JournalBackend::JournalBackend(std::uint32_t max_entries) : max_entries_(max_entries) {}

bool JournalBackend::is_idempotent(StepKind kind) const noexcept {
  // Every Route Convergence step is keyed by (plan, step) identity, so the
  // journal can always answer "already applied" instead of applying twice.  The
  // observation-only steps are trivially idempotent.
  (void)kind;
  return true;
}

BackendOutcome JournalBackend::apply(const StepExecutionRequest& request, std::string& detail) {
  const std::string key = request.plan.to_text() + ':' + request.step.to_text();
  const std::lock_guard<std::mutex> lock(mutex_);

  auto scripted = scripted_.find(key);
  if (scripted == scripted_.end()) {
    scripted = scripted_.find("*:" + request.step.to_text());
  }
  if (scripted != scripted_.end()) {
    const BackendOutcome outcome = scripted->second;
    scripted_.erase(scripted);
    detail = "scripted ";
    detail += to_string(outcome);
    return outcome;
  }

  for (const Entry& entry : entries_) {
    if (entry.plan == request.plan && entry.step == request.step) {
      ++replayed_;
      detail = "already applied";
      return BackendOutcome::IDEMPOTENT;
    }
  }

  if (entries_.size() >= max_entries_) {
    detail = "journal capacity exhausted";
    return BackendOutcome::PERMANENT_FAILURE;
  }

  Entry entry;
  entry.plan = request.plan;
  entry.step = request.step;
  entry.kind = request.spec.kind;
  entry.route_generation = request.target.generation;
  entry.path_generation = request.target.path_authority_generation;
  entries_.push_back(entry);
  ++applied_;
  detail = "applied ";
  detail += to_string(request.spec.kind);
  return BackendOutcome::APPLIED;
}

bool JournalBackend::observes_applied(const StepExecutionRequest& request) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  for (const Entry& entry : entries_) {
    if (entry.plan == request.plan && entry.step == request.step) {
      return true;
    }
  }
  return false;
}

void JournalBackend::script_outcome(const TransitionStepId& step, BackendOutcome outcome) {
  const std::lock_guard<std::mutex> lock(mutex_);
  scripted_["*:" + step.to_text()] = outcome;
}

void JournalBackend::clear_script() {
  const std::lock_guard<std::mutex> lock(mutex_);
  scripted_.clear();
}

bool JournalBackend::has_applied(const ConvergencePlanId& plan, const TransitionStepId& step) const {
  const std::lock_guard<std::mutex> lock(mutex_);
  for (const Entry& entry : entries_) {
    if (entry.plan == plan && entry.step == step) {
      return true;
    }
  }
  return false;
}

std::size_t JournalBackend::applied_count() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  return entries_.size();
}

std::vector<std::string> JournalBackend::journal_lines() const {
  const std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> out;
  out.reserve(entries_.size());
  for (const Entry& entry : entries_) {
    std::string line = "journal plan=";
    line += entry.plan.to_text();
    line += " step=";
    line += entry.step.to_text();
    line += " kind=";
    line += to_string(entry.kind);
    line += " route_generation=" + std::to_string(entry.route_generation.value());
    line += " path_authority_generation=" + std::to_string(entry.path_generation.value());
    out.push_back(std::move(line));
  }
  return out;
}

}  // namespace rc
