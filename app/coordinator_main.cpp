// Route Convergence coordinator service.
//
// Serves exactly one authoritative convergence governor over loopback.  It is not
// a consensus participant: one coordinator owns the durable store at a time and
// stale epochs are fenced by epoch comparison.

#include <atomic>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>

#include "rc/rc.hpp"
#include "rc/server.hpp"
#include "support.hpp"

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true); }

}  // namespace

int main(int argc, char** argv) {
  using namespace rc;
  using namespace rc::app;

  const CommandLine line = CommandLine::parse(argc, argv);
  if (line.has("help")) {
    print_line("usage: rc_coordinator [--port N] [--store PATH] [--epoch N] [--synthetic]");
    print_line("                      [--max-requests N] [--recover] [--no-store]");
    print_line("                      [--fabric HEX] [--namespace HEX]");
    return 0;
  }

  const std::uint64_t epoch_value = line.u64("epoch", 1);
  const bool use_synthetic = !line.has("no-synthetic");
  const std::string store = line.value_or("store", std::string{});

  SyntheticUpstream synthetic(CoordinatorEpoch::from_value(epoch_value));

  GovernorOptions options;
  options.initial_epoch = CoordinatorEpoch::from_value(epoch_value);
  options.store_path = store;
  options.autosave = !store.empty();
  options.fabric = fabric_for(1);
  options.routing_namespace = namespace_for(1);

  std::string reason;
  if (!ConvergenceGovernor::validate_options(options, reason)) {
    print_line("RC_COORDINATOR_ERROR code=INTERNAL_INVARIANT detail=" + reason);
    return 2;
  }

  ConvergenceGovernor governor(synthetic, synthetic, synthetic, options);

  bool recovered = false;
  std::error_code exists_code;
  const bool store_exists = !store.empty() && std::filesystem::exists(store, exists_code);
  if (line.has("recover") && store_exists) {
    const PlanMutationResult loaded = governor.load(store);
    recovered = loaded.accepted();
    if (!recovered) {
      std::string detail;
      for (const Condition& condition : loaded.conditions.entries()) {
        if (!detail.empty()) {
          detail += " | ";
        }
        detail += condition.render();
      }
      print_line(std::string("RC_COORDINATOR_ERROR code=STORE_STRUCTURE detail=") + detail);
      return 3;
    }
  }

  CoordinatorServerOptions server_options;
  server_options.port = static_cast<std::uint16_t>(line.u64("port", 0));
  server_options.store_path = store;
  server_options.autosave = !store.empty();
  server_options.synthetic_upstream = use_synthetic ? &synthetic : nullptr;
  server_options.max_requests = line.u64("max-requests", 0);
  server_options.receive_deadline_ms =
      static_cast<std::uint32_t>(line.u64("receive-deadline-ms", 5000));
  server_options.limits = options.limits;

  CoordinatorServer server(governor, server_options);
  std::string error;
  if (!server.start(error)) {
    print_line("RC_COORDINATOR_ERROR code=TRANSPORT_FAILURE detail=" + error);
    return 4;
  }
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  print_line("RC_COORDINATOR_READY port=" + std::to_string(server.port()) +
             " epoch=" + std::to_string(governor.epoch().value()) +
             " recovered=" + std::to_string(recovered ? 1 : 0) +
             " synthetic=" + std::to_string(use_synthetic ? 1 : 0));

  server.serve();
  server.stop();

  if (!store.empty()) {
    const PlanMutationResult saved = governor.save(store);
    if (!saved.accepted()) {
      print_line("RC_COORDINATOR_ERROR code=STORE_IO detail=final save failed");
      return 5;
    }
  }
  print_line("RC_COORDINATOR_EXIT handled=" + std::to_string(server.handled_requests()) +
             " epoch=" + std::to_string(governor.epoch().value()));
  return 0;
}
