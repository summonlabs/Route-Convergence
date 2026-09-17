#include "rc/process.hpp"

#include <mutex>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#error "Route Convergence 1.0.0 implements local process supervision on Windows only."
#endif

namespace rc {
namespace {

[[nodiscard]] std::string quote_argument(const std::string& argument) {
  std::string out = "\"";
  for (const char character : argument) {
    if (character == '"') {
      out += "\\\"";
    } else {
      out += character;
    }
  }
  out += '"';
  return out;
}

}  // namespace

struct LocalProcess::Impl {
  PROCESS_INFORMATION process{};
  HANDLE read_pipe = INVALID_HANDLE_VALUE;
  bool valid = false;
  bool exited = false;
  int exit_code = 0;
  std::string buffer;
  std::mutex mutex;
  std::mutex wait_mutex;

  Impl() = default;
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  // Every handle created by spawn() is owned here, so no path can leak one: the
  // smart pointer that holds this object releases exactly what was created.
  ~Impl() {
    if (process.hProcess != nullptr && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
      TerminateProcess(process.hProcess, 1);
      WaitForSingleObject(process.hProcess, INFINITE);
    }
    valid = false;
    if (read_pipe != INVALID_HANDLE_VALUE) {
      CloseHandle(read_pipe);
      read_pipe = INVALID_HANDLE_VALUE;
    }
    if (process.hThread != nullptr) {
      CloseHandle(process.hThread);
      process.hThread = nullptr;
    }
    if (process.hProcess != nullptr) {
      CloseHandle(process.hProcess);
      process.hProcess = nullptr;
    }
  }
};

LocalProcess::LocalProcess() = default;

LocalProcess::~LocalProcess() = default;

LocalProcess::LocalProcess(LocalProcess&& other) noexcept : impl_(std::move(other.impl_)) {}

LocalProcess& LocalProcess::operator=(LocalProcess&& other) noexcept {
  if (this != &other) {
    // Assigning releases the previous child, whose handles the Impl destructor
    // closes after terminating it.
    impl_ = std::move(other.impl_);
  }
  return *this;
}

std::optional<LocalProcess> LocalProcess::spawn(const Options& options, std::string& error) {
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  HANDLE read_pipe = INVALID_HANDLE_VALUE;
  HANDLE write_pipe = INVALID_HANDLE_VALUE;
  if (!CreatePipe(&read_pipe, &write_pipe, &attributes, 0)) {
    error = "output pipe could not be created";
    return std::nullopt;
  }
  SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

  std::string command_line = quote_argument(options.executable);
  for (const std::string& argument : options.arguments) {
    command_line += ' ';
    command_line += quote_argument(argument);
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_pipe;
  startup.hStdError = write_pipe;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  std::vector<char> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back('\0');

  // The process handles are written straight into the object that owns them, so
  // there is no path on which a created handle is not owned by a destructor.
  auto impl = std::make_unique<LocalProcess::Impl>();
  const BOOL created =
      CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW, nullptr,
                     options.working_directory.empty() ? nullptr
                                                       : options.working_directory.c_str(),
                     &startup, &impl->process);
  CloseHandle(write_pipe);
  impl->read_pipe = read_pipe;
  if (!created) {
    error = "child process could not be created";
    return std::nullopt;
  }
  impl->valid = true;

  LocalProcess process;
  process.impl_ = std::move(impl);
  error.clear();
  return process;
}

bool LocalProcess::valid() const noexcept { return impl_ != nullptr && impl_->valid; }

std::uint64_t LocalProcess::pid() const noexcept {
  if (impl_ == nullptr) {
    return 0;
  }
  return static_cast<std::uint64_t>(impl_->process.dwProcessId);
}

bool LocalProcess::running() const {
  if (!valid()) {
    return false;
  }
  return WaitForSingleObject(impl_->process.hProcess, 0) == WAIT_TIMEOUT;
}

bool LocalProcess::read_line(std::string& line) {
  if (impl_ == nullptr) {
    return false;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  for (;;) {
    const std::size_t position = impl_->buffer.find('\n');
    if (position != std::string::npos) {
      line = impl_->buffer.substr(0, position);
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      impl_->buffer.erase(0, position + 1);
      return true;
    }
    char chunk[512];
    DWORD read = 0;
    if (!ReadFile(impl_->read_pipe, chunk, sizeof(chunk), &read, nullptr) || read == 0) {
      if (!impl_->buffer.empty()) {
        line = impl_->buffer;
        impl_->buffer.clear();
        if (!line.empty() && line.back() == '\r') {
          line.pop_back();
        }
        return true;
      }
      return false;
    }
    impl_->buffer.append(chunk, read);
  }
}

std::string LocalProcess::read_until_exit() {
  std::string out;
  std::string line;
  while (read_line(line)) {
    if (!out.empty()) {
      out += '\n';
    }
    out += line;
  }
  return out;
}

int LocalProcess::wait_for_exit() {
  if (!valid()) {
    return -1;
  }
  const std::lock_guard<std::mutex> lock(impl_->wait_mutex);
  if (!impl_->exited) {
    WaitForSingleObject(impl_->process.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(impl_->process.hProcess, &code);
    impl_->exit_code = static_cast<int>(code);
    impl_->exited = true;
    impl_->valid = false;
  }
  return impl_->exit_code;
}

bool LocalProcess::terminate() {
  if (!valid()) {
    return false;
  }
  if (WaitForSingleObject(impl_->process.hProcess, 0) != WAIT_TIMEOUT) {
    return false;
  }
  const BOOL killed = TerminateProcess(impl_->process.hProcess, 1);
  WaitForSingleObject(impl_->process.hProcess, INFINITE);
  const std::lock_guard<std::mutex> lock(impl_->wait_mutex);
  impl_->exited = true;
  impl_->exit_code = 1;
  impl_->valid = false;
  return killed == TRUE;
}

}  // namespace rc
