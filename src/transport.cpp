#include "rc/net.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#else
#error "Route Convergence 1.0.0 implements its loopback transport on Windows only."
#endif

namespace rc {
namespace {

void ensure_winsock() {
  static std::once_flag flag;
  std::call_once(flag, []() {
    WSADATA data{};
    (void)WSAStartup(MAKEWORD(2, 2), &data);
  });
}

}  // namespace

std::string_view to_string(ReceiveStatus status) noexcept {
  switch (status) {
    case ReceiveStatus::OK: return "OK";
    case ReceiveStatus::TIMEOUT: return "TIMEOUT";
    case ReceiveStatus::CLOSED: return "CLOSED";
    case ReceiveStatus::FAILURE: return "FAILURE";
  }
  return "FAILURE";
}

struct TcpConnection::Impl {
  SOCKET socket = INVALID_SOCKET;
  std::mutex mutex;
  bool closed = false;
};

TcpConnection::TcpConnection() : impl_(std::make_shared<Impl>()) { ensure_winsock(); }

TcpConnection::~TcpConnection() { close(); }

TcpConnection::TcpConnection(TcpConnection&& other) noexcept : impl_(std::move(other.impl_)) {}

TcpConnection& TcpConnection::operator=(TcpConnection&& other) noexcept {
  if (this != &other) {
    close();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

bool TcpConnection::valid() const noexcept {
  return impl_ != nullptr && impl_->socket != INVALID_SOCKET;
}

std::uint16_t TcpConnection::local_port() const {
  if (!valid()) {
    return 0;
  }
  sockaddr_in address{};
  int length = sizeof(address);
  if (getsockname(impl_->socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return 0;
  }
  return ntohs(address.sin_port);
}

std::uint16_t TcpConnection::remote_port() const {
  if (!valid()) {
    return 0;
  }
  sockaddr_in address{};
  int length = sizeof(address);
  if (getpeername(impl_->socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return 0;
  }
  return ntohs(address.sin_port);
}

bool TcpConnection::send_all(std::span<const std::uint8_t> bytes, std::string& error) {
  if (!valid()) {
    error = "connection is not open";
    return false;
  }
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const int chunk = static_cast<int>(
        std::min<std::size_t>(bytes.size() - sent, static_cast<std::size_t>(1u << 20)));
    const int result =
        send(impl_->socket, reinterpret_cast<const char*>(bytes.data() + sent), chunk, 0);
    if (result <= 0) {
      error = "send failed";
      return false;
    }
    sent += static_cast<std::size_t>(result);
  }
  return true;
}

ReceiveStatus TcpConnection::receive_exactly(std::span<std::uint8_t> out,
                                             std::uint32_t deadline_ms, std::string& error) {
  if (!valid()) {
    error = "connection is not open";
    return ReceiveStatus::CLOSED;
  }
  std::size_t received = 0;
  const ULONGLONG start = GetTickCount64();
  while (received < out.size()) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(impl_->socket, &set);
    timeval timeout{};
    const ULONGLONG elapsed = GetTickCount64() - start;
    if (elapsed >= deadline_ms) {
      error = "peer did not deliver a complete frame within the read budget";
      return ReceiveStatus::TIMEOUT;
    }
    const std::uint32_t remaining = deadline_ms - static_cast<std::uint32_t>(elapsed);
    timeout.tv_sec = static_cast<long>(remaining / 1000u);
    timeout.tv_usec = static_cast<long>((remaining % 1000u) * 1000u);
    const int ready = select(0, &set, nullptr, nullptr, &timeout);
    if (ready == 0) {
      error = "peer did not deliver a complete frame within the read budget";
      return ReceiveStatus::TIMEOUT;
    }
    if (ready < 0) {
      error = "select failed";
      return ReceiveStatus::FAILURE;
    }
    const int chunk = static_cast<int>(
        std::min<std::size_t>(out.size() - received, static_cast<std::size_t>(1u << 20)));
    const int result =
        recv(impl_->socket, reinterpret_cast<char*>(out.data() + received), chunk, 0);
    if (result == 0) {
      error = "peer closed the connection";
      return ReceiveStatus::CLOSED;
    }
    if (result < 0) {
      error = "recv failed";
      return ReceiveStatus::FAILURE;
    }
    received += static_cast<std::size_t>(result);
  }
  return ReceiveStatus::OK;
}

void TcpConnection::shutdown() {
  if (impl_ == nullptr) {
    return;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket != INVALID_SOCKET) {
    ::shutdown(impl_->socket, SD_BOTH);
  }
}

void TcpConnection::close() {
  if (impl_ == nullptr) {
    return;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket != INVALID_SOCKET) {
    closesocket(impl_->socket);
    impl_->socket = INVALID_SOCKET;
  }
  impl_->closed = true;
}

struct TcpListener::Impl {
  SOCKET socket = INVALID_SOCKET;
  std::mutex mutex;
};

TcpListener::TcpListener() : impl_(std::make_shared<Impl>()) { ensure_winsock(); }

TcpListener::~TcpListener() { close(); }

TcpListener::TcpListener(TcpListener&& other) noexcept : impl_(std::move(other.impl_)) {}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    close();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

std::optional<TcpListener> TcpListener::bind_loopback(std::uint16_t port, std::string& error) {
  ensure_winsock();
  SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == INVALID_SOCKET) {
    error = "socket creation failed";
    return std::nullopt;
  }
  BOOL exclusive = TRUE;
  setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
             sizeof(exclusive));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    closesocket(socket);
    error = "loopback bind failed";
    return std::nullopt;
  }
  if (listen(socket, SOMAXCONN) != 0) {
    closesocket(socket);
    error = "listen failed";
    return std::nullopt;
  }
  TcpListener listener;
  listener.impl_->socket = socket;
  error.clear();
  return listener;
}

bool TcpListener::valid() const noexcept {
  return impl_ != nullptr && impl_->socket != INVALID_SOCKET;
}

std::uint16_t TcpListener::port() const {
  if (!valid()) {
    return 0;
  }
  sockaddr_in address{};
  int length = sizeof(address);
  if (getsockname(impl_->socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return 0;
  }
  return ntohs(address.sin_port);
}

std::optional<TcpConnection> TcpListener::accept(std::string& error, std::uint32_t deadline_ms) {
  if (!valid()) {
    error = "listener is closed";
    return std::nullopt;
  }
  fd_set set;
  FD_ZERO(&set);
  FD_SET(impl_->socket, &set);
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(deadline_ms / 1000u);
  timeout.tv_usec = static_cast<long>((deadline_ms % 1000u) * 1000u);
  const int ready = select(0, &set, nullptr, nullptr, &timeout);
  if (ready == 0) {
    error = "no connection arrived within the accept budget";
    return std::nullopt;
  }
  if (ready < 0) {
    error = "accept select failed";
    return std::nullopt;
  }
  SOCKET accepted = ::accept(impl_->socket, nullptr, nullptr);
  if (accepted == INVALID_SOCKET) {
    error = "accept failed";
    return std::nullopt;
  }
  TcpConnection connection;
  connection.impl_->socket = accepted;
  error.clear();
  return connection;
}

void TcpListener::close() {
  if (impl_ == nullptr) {
    return;
  }
  const std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->socket != INVALID_SOCKET) {
    closesocket(impl_->socket);
    impl_->socket = INVALID_SOCKET;
  }
}

std::optional<TcpConnection> connect_loopback(std::uint16_t port, std::string& error) {
  ensure_winsock();
  SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket == INVALID_SOCKET) {
    error = "socket creation failed";
    return std::nullopt;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    closesocket(socket);
    error = "loopback connect failed";
    return std::nullopt;
  }
  TcpConnection connection;
  connection.impl_->socket = socket;
  error.clear();
  return connection;
}

WireDefect read_frame(TcpConnection& connection, const ConvergenceLimits& limits,
                      std::uint32_t deadline_ms, Envelope& out, std::string& error) {
  std::vector<std::uint8_t> header(kWireHeaderBytes, 0);
  const ReceiveStatus header_status =
      connection.receive_exactly(header, deadline_ms, error);
  if (header_status != ReceiveStatus::OK) {
    return header_status == ReceiveStatus::TIMEOUT ? WireDefect::PEER_TIMEOUT
                                                   : WireDefect::PEER_CLOSED;
  }
  // The declared payload length is validated before anything is allocated.
  const std::uint32_t payload_bytes =
      static_cast<std::uint32_t>(header[kWireHeaderBytes - 8]) |
      (static_cast<std::uint32_t>(header[kWireHeaderBytes - 7]) << 8) |
      (static_cast<std::uint32_t>(header[kWireHeaderBytes - 6]) << 16) |
      (static_cast<std::uint32_t>(header[kWireHeaderBytes - 5]) << 24);
  if (payload_bytes > limits.max_frame_bytes) {
    error = "declared frame length exceeds the configured frame limit";
    return WireDefect::FRAME_TOO_LARGE;
  }
  std::vector<std::uint8_t> body = header;
  body.resize(kWireHeaderBytes + payload_bytes + kWireTagBytes, 0);
  const ReceiveStatus body_status = connection.receive_exactly(
      std::span<std::uint8_t>(body.data() + kWireHeaderBytes, payload_bytes + kWireTagBytes),
      deadline_ms, error);
  if (body_status != ReceiveStatus::OK) {
    return body_status == ReceiveStatus::TIMEOUT ? WireDefect::PEER_TIMEOUT
                                                 : WireDefect::PEER_CLOSED;
  }
  return decode_frame(body, limits, out);
}

bool write_frame(TcpConnection& connection, const Envelope& envelope,
                 const ConvergenceLimits& limits, std::string& error) {
  const std::vector<std::uint8_t> frame = encode_frame(envelope, limits);
  if (frame.empty()) {
    error = "frame exceeds the configured frame limit";
    return false;
  }
  return connection.send_all(frame, error);
}

}  // namespace rc
