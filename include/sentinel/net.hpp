// A loopback TCP harness, the smallest one that lets the admission layer be
// measured end to end.
//
// The platform difference is confined to this pair of files: Winsock on Windows,
// Berkeley sockets everywhere else. Nothing above this header knows which one it
// is running on, and no platform header is pulled into the rest of the project.
//
// The listener binds to the loopback address only. That is not a default, it is
// the boundary of the experiment: the load generator in this repository can
// reach nothing but this process.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace sentinel::net {

using native_socket = std::uintptr_t;
inline constexpr native_socket invalid_socket = static_cast<native_socket>(-1);

// Winsock needs a process wide startup call. Safe to call more than once.
void initialise();
std::string last_error();

class connection {
public:
    connection() = default;
    explicit connection(native_socket s) : sock_(s) {}
    ~connection() { close(); }

    connection(connection&& other) noexcept : sock_(other.sock_), peer_(other.peer_) {
        other.sock_ = invalid_socket;
    }
    connection& operator=(connection&& other) noexcept;
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    bool valid() const { return sock_ != invalid_socket; }
    void close();

    bool send_all(const void* data, std::size_t n);
    bool recv_exact(void* data, std::size_t n);
    // Reads until the peer closes. Used to observe the end of the exchange.
    void drain();

    // Peer address and port folded into one value, which is what the admission
    // layer uses to tell sources apart.
    std::uint64_t peer_id() const { return peer_; }
    void set_peer_id(std::uint64_t v) { peer_ = v; }

private:
    native_socket sock_ = invalid_socket;
    std::uint64_t peer_ = 0;
};

class listener {
public:
    listener() = default;
    ~listener() { close(); }
    listener(const listener&) = delete;
    listener& operator=(const listener&) = delete;

    // Binds 127.0.0.1 on the given port, or an ephemeral one when port is zero.
    bool open(std::uint16_t port = 0, int backlog = 512);
    std::uint16_t port() const { return port_; }
    bool valid() const { return sock_ != invalid_socket; }
    std::optional<connection> accept();
    void close();

private:
    native_socket sock_ = invalid_socket;
    std::uint16_t port_ = 0;
};

std::optional<connection> connect_loopback(std::uint16_t port);

}  // namespace sentinel::net
