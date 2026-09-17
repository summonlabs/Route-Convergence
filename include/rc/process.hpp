#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace rc {

// Local OS process supervision.  Used by the distributed proofs, the examples and
// the CLI to start real coordinator and worker processes and to observe real
// process death.  There is deliberately no thread-based substitute anywhere in
// Route Convergence: worker death and coordinator restart are proven with real OS
// process termination.
//
// Platform support: 1.0.0 implements this on Windows.  On other platforms the
// factory returns std::nullopt with a clear error string.
class LocalProcess {
 public:
  struct Options {
    std::string executable;
    std::vector<std::string> arguments;
    std::string working_directory;
  };

  LocalProcess();
  ~LocalProcess();
  LocalProcess(LocalProcess&& other) noexcept;
  LocalProcess& operator=(LocalProcess&& other) noexcept;
  LocalProcess(const LocalProcess&) = delete;
  LocalProcess& operator=(const LocalProcess&) = delete;

  // Starts the process with stdout and stderr redirected into one pipe the parent
  // reads.  Returns std::nullopt and fills error when the process could not be
  // started.
  [[nodiscard]] static std::optional<LocalProcess> spawn(const Options& options, std::string& error);

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::uint64_t pid() const noexcept;
  [[nodiscard]] bool running() const;

  // Reads one line from the child's combined output.  Returns false at end of
  // output.  Blocking by design: a child that never produces expected output is a
  // defect, not something to hide behind a timeout.
  [[nodiscard]] bool read_line(std::string& line);

  // Reads until end of output.
  [[nodiscard]] std::string read_until_exit();

  // Waits for natural termination and returns the exit code.
  [[nodiscard]] int wait_for_exit();

  // Terminates the process like an external kill would.  Returns false when the
  // process was already gone.
  [[nodiscard]] bool terminate();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace rc
