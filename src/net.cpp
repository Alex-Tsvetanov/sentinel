#include "sentinel/net.hpp"

#include <cstring>

#if defined(_WIN32)
// winsock2.h has to come before anything that pulls in windows.h, or the older
// winsock.h wins and the two disagree about the same symbols.
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_type = int;
using recv_size = int;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
using socklen_type = socklen_t;
using recv_size = std::size_t;
#endif

namespace sentinel::net {
namespace {

#if defined(_WIN32)
int close_socket(native_socket s) { return ::closesocket(static_cast<SOCKET>(s)); }
SOCKET raw(native_socket s) { return static_cast<SOCKET>(s); }
int last_errno() { return ::WSAGetLastError(); }
#else
int close_socket(native_socket s) { return ::close(static_cast<int>(s)); }
int raw(native_socket s) { return static_cast<int>(s); }
int last_errno() { return errno; }
#endif

void disable_nagle(native_socket s) {
    // Every message in this harness is a single small write followed by a wait
    // for the answer, which is the case Nagle's algorithm delays.
    int on = 1;
    ::setsockopt(raw(s), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&on), sizeof on);
}

}  // namespace

void initialise() {
#if defined(_WIN32)
    static bool done = false;
    if (!done) {
        WSADATA data;
        ::WSAStartup(MAKEWORD(2, 2), &data);
        done = true;
    }
#endif
}

std::string last_error() { return std::to_string(last_errno()); }

connection& connection::operator=(connection&& other) noexcept {
    if (this != &other) {
        close();
        sock_ = other.sock_;
        peer_ = other.peer_;
        other.sock_ = invalid_socket;
    }
    return *this;
}

void connection::close() {
    if (sock_ != invalid_socket) {
        close_socket(sock_);
        sock_ = invalid_socket;
    }
}

bool connection::send_all(const void* data, std::size_t n) {
    const char* p = static_cast<const char*>(data);
    std::size_t sent = 0;
    while (sent < n) {
        const auto k = ::send(raw(sock_), p + sent, static_cast<recv_size>(n - sent), 0);
        if (k <= 0) return false;
        sent += static_cast<std::size_t>(k);
    }
    return true;
}

bool connection::recv_exact(void* data, std::size_t n) {
    char* p = static_cast<char*>(data);
    std::size_t got = 0;
    while (got < n) {
        const auto k = ::recv(raw(sock_), p + got, static_cast<recv_size>(n - got), 0);
        if (k <= 0) return false;  // zero means the peer closed, which is short here
        got += static_cast<std::size_t>(k);
    }
    return true;
}

void connection::drain() {
    char buf[256];
    while (::recv(raw(sock_), buf, static_cast<recv_size>(sizeof buf), 0) > 0) {
    }
}

bool listener::open(std::uint16_t port, int backlog) {
    initialise();
    sock_ = static_cast<native_socket>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (sock_ == invalid_socket) return false;

    int on = 1;
    ::setsockopt(raw(sock_), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&on),
                 sizeof on);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // loopback only, by design
    if (::bind(raw(sock_), reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        close();
        return false;
    }
    if (::listen(raw(sock_), backlog) != 0) {
        close();
        return false;
    }
    socklen_type len = sizeof addr;
    if (::getsockname(raw(sock_), reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        close();
        return false;
    }
    port_ = ntohs(addr.sin_port);
    return true;
}

std::optional<connection> listener::accept() {
    sockaddr_in peer{};
    socklen_type len = sizeof peer;
    const auto s = ::accept(raw(sock_), reinterpret_cast<sockaddr*>(&peer), &len);
#if defined(_WIN32)
    if (s == INVALID_SOCKET) return std::nullopt;
#else
    if (s < 0) return std::nullopt;
#endif
    connection c{static_cast<native_socket>(s)};
    disable_nagle(static_cast<native_socket>(s));
    // Address in the upper half, port in the lower, so a single value identifies
    // the source the way the admission layer expects.
    c.set_peer_id((static_cast<std::uint64_t>(ntohl(peer.sin_addr.s_addr)) << 32) |
                  ntohs(peer.sin_port));
    return c;
}

void listener::close() {
    if (sock_ != invalid_socket) {
        close_socket(sock_);
        sock_ = invalid_socket;
    }
}

std::optional<connection> connect_loopback(std::uint16_t port) {
    initialise();
    const auto s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#if defined(_WIN32)
    if (s == INVALID_SOCKET) return std::nullopt;
#else
    if (s < 0) return std::nullopt;
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(static_cast<decltype(raw(0))>(s), reinterpret_cast<sockaddr*>(&addr),
                  sizeof addr) != 0) {
        close_socket(static_cast<native_socket>(s));
        return std::nullopt;
    }
    disable_nagle(static_cast<native_socket>(s));
    return connection{static_cast<native_socket>(s)};
}

}  // namespace sentinel::net
