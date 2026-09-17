#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "rc/convergence.hpp"
#include "rc/net.hpp"
#include "rc/synthetic.hpp"

namespace rc {

struct CoordinatorServerOptions {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  // Bounded protocol read budget for one frame.  A peer that stops mid-frame is
  // disconnected with an explicit PEER_TIMEOUT failure instead of pinning a
  // session.
  std::uint32_t receive_deadline_ms = 5000;
  ConvergenceLimits limits;
  std::filesystem::path store_path;  // empty disables durable autosave
  bool autosave = true;
  // When set, ROUTE_CHANGE / PATH_CHANGE / EPOCH_CHANGE notices are applied to
  // this synthetic observation source before the governor re-observes.  When it
  // is null no upstream feed is attached and those messages are refused with
  // BACKEND_UNSUPPORTED rather than silently ignored.
  SyntheticUpstream* synthetic_upstream = nullptr;
  // 0 means "serve until stopped"; a positive value stops the coordinator after
  // that many handled requests, which the scripted examples and proofs use.
  std::uint64_t max_requests = 0;
};

// Single authoritative coordinator.  Route Convergence 1.0.0 is not a consensus
// system: exactly one coordinator owns the durable store at a time and stale
// epochs are fenced by epoch comparison, not by distributed agreement.
class CoordinatorServer {
 public:
  CoordinatorServer(ConvergenceGovernor& governor, CoordinatorServerOptions options);
  ~CoordinatorServer();
  CoordinatorServer(const CoordinatorServer&) = delete;
  CoordinatorServer& operator=(const CoordinatorServer&) = delete;

  [[nodiscard]] bool start(std::string& error);
  [[nodiscard]] std::uint16_t port() const;
  void serve();  // accept loop until stop() is called
  void stop();
  [[nodiscard]] std::uint32_t active_sessions() const;
  [[nodiscard]] std::uint64_t handled_requests() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace rc
