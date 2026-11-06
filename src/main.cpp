#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr std::size_t kKeySize = 32;
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;
constexpr std::size_t kPskSize = 32;
constexpr std::uint16_t kDefaultControlPort = 9000;
constexpr std::uint32_t kMaxPacketSize = 65535;
constexpr char kHandshakeMagic[] = "SIC1";

using Key = std::array<unsigned char, kKeySize>;
using Psk = std::array<unsigned char, kPskSize>;
using Nonce = std::array<unsigned char, kNonceSize>;
using Tag = std::array<unsigned char, kTagSize>;

struct Config {
    std::string role;
    std::string peer;
    std::string listen_address = "0.0.0.0";
    std::string psk_file;
    std::string source_ip;
    std::string destination_ip;
    std::uint16_t destination_port = 5001;
    std::uint16_t control_port = kDefaultControlPort;
    std::uint16_t queue_num = 0;
};

struct AppContext {
    Key key{};
    bool encrypt = false;
    std::uint32_t source_ip = 0;      // network byte order
    std::uint32_t destination_ip = 0; // network byte order
    std::uint16_t destination_port = 0; // host byte order
    std::uint32_t nonce_prefix = 0;
    std::uint64_t nonce_counter = 0;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

void check_ssl(int ok, const char* what) {
    if (ok != 1) fail(std::string(what) + " failed");
}

std::uint16_t read_be16(const unsigned char* p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8U) | p[1]);
}

void write_be16(unsigned char* p, std::uint16_t value) {
    p[0] = static_cast<unsigned char>((value >> 8U) & 0xffU);
    p[1] = static_cast<unsigned char>(value & 0xffU);
}

void write_be32(unsigned char* p, std::uint32_t value) {
    p[0] = static_cast<unsigned char>((value >> 24U) & 0xffU);
    p[1] = static_cast<unsigned char>((value >> 16U) & 0xffU);
    p[2] = static_cast<unsigned char>((value >> 8U) & 0xffU);
    p[3] = static_cast<unsigned char>(value & 0xffU);
}

void write_be64(unsigned char* p, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<unsigned char>(value & 0xffU);
        value >>= 8U;
    }
}

std::uint32_t parse_ipv4(const std::string& value) {
    in_addr addr{};
    if (inet_pton(AF_INET, value.c_str(), &addr) != 1) {
        fail("Invalid IPv4 address: " + value);
    }
    return addr.s_addr;
}

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

Psk load_psk(const std::string& path) {
    std::ifstream in(path);
    if (!in) fail("Cannot open PSK file: " + path);
    std::string hex((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    hex = trim(hex);
    if (hex.size() != kPskSize * 2) {
        fail("PSK file must contain exactly 64 hexadecimal characters (32 bytes)");
    }
    Psk psk{};
    for (std::size_t i = 0; i < kPskSize; ++i) {
        const std::string byte = hex.substr(i * 2, 2);
        char* end = nullptr;
        const long parsed = std::strtol(byte.c_str(), &end, 16);
        if (end == nullptr || *end != '\0' || parsed < 0 || parsed > 255) {
            fail("PSK file contains invalid hexadecimal data");
        }
        psk[i] = static_cast<unsigned char>(parsed);
    }
    return psk;
}

void send_all(int fd, const unsigned char* data, std::size_t length) {
    std::size_t sent = 0;
    while (sent < length) {
        const ssize_t n = send(fd, data + sent, length - sent, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("Handshake socket send failed");
        sent += static_cast<std::size_t>(n);
    }
}

void recv_all(int fd, unsigned char* data, std::size_t length) {
    std::size_t received = 0;
    while (received < length) {
        const ssize_t n = recv(fd, data + received, length - received, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("Handshake socket closed unexpectedly");
        received += static_cast<std::size_t>(n);
    }
}

struct X25519Pair {
    EVP_PKEY* private_key = nullptr;
    std::array<unsigned char, 32> public_key{};
    ~X25519Pair() { EVP_PKEY_free(private_key); }
    X25519Pair() = default;
    X25519Pair(const X25519Pair&) = delete;
    X25519Pair& operator=(const X25519Pair&) = delete;
    X25519Pair(X25519Pair&& other) noexcept
        : private_key(other.private_key), public_key(other.public_key) {
        other.private_key = nullptr;
    }
    X25519Pair& operator=(X25519Pair&& other) noexcept {
        if (this != &other) {
            EVP_PKEY_free(private_key);
            private_key = other.private_key;
            public_key = other.public_key;
            other.private_key = nullptr;
        }
        return *this;
    }
};

X25519Pair make_x25519_pair() {
    X25519Pair pair;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) fail("EVP_PKEY_CTX_new_id(X25519) failed");
    check_ssl(EVP_PKEY_keygen_init(ctx), "X25519 keygen init");
    check_ssl(EVP_PKEY_keygen(ctx, &pair.private_key), "X25519 keygen");
    EVP_PKEY_CTX_free(ctx);
    std::size_t public_len = pair.public_key.size();
    check_ssl(EVP_PKEY_get_raw_public_key(pair.private_key, pair.public_key.data(), &public_len),
              "Reading X25519 public key");
    if (public_len != pair.public_key.size()) fail("Unexpected X25519 public key size");
    return pair;
}

Key x25519_shared_secret(EVP_PKEY* private_key, const unsigned char* peer_public) {
    Key shared{};
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public, 32);
    if (!peer) fail("Creating peer X25519 key failed");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer);
        fail("Creating X25519 derive context failed");
    }
    check_ssl(EVP_PKEY_derive_init(ctx), "X25519 derive init");
    check_ssl(EVP_PKEY_derive_set_peer(ctx, peer), "X25519 set peer");
    std::size_t shared_len = shared.size();
    check_ssl(EVP_PKEY_derive(ctx, shared.data(), &shared_len), "X25519 shared secret derivation");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    if (shared_len != shared.size()) fail("Unexpected X25519 shared-secret size");
    return shared;
}

std::array<unsigned char, 32> hmac_sha256(const Psk& psk, const std::vector<unsigned char>& data) {
    std::array<unsigned char, 32> out{};
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), psk.data(), static_cast<int>(psk.size()), data.data(), data.size(),
              out.data(), &out_len) || out_len != out.size()) {
        fail("HMAC-SHA256 failed");
    }
    return out;
}

Key derive_session_key(const Key& shared, const std::array<unsigned char, 32>& salt,
                       const std::vector<unsigned char>& transcript) {
    Key key{};
    static constexpr unsigned char info[] = "secure-inline-channel/aes-256-gcm/v1";
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) fail("HKDF context creation failed");
    check_ssl(EVP_PKEY_derive_init(ctx), "HKDF derive init");
    check_ssl(EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()), "HKDF set digest");
    check_ssl(EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size())), "HKDF set salt");
    check_ssl(EVP_PKEY_CTX_set1_hkdf_key(ctx, shared.data(), static_cast<int>(shared.size())), "HKDF set key");
    check_ssl(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info) - 1), "HKDF set info");
    check_ssl(EVP_PKEY_CTX_add1_hkdf_info(ctx, transcript.data(), static_cast<int>(transcript.size())),
              "HKDF bind transcript");
    std::size_t key_len = key.size();
    check_ssl(EVP_PKEY_derive(ctx, key.data(), &key_len), "HKDF derive key");
    EVP_PKEY_CTX_free(ctx);
    if (key_len != key.size()) fail("Unexpected HKDF output size");
    return key;
}

std::vector<unsigned char> labelled_transcript(const char* label,
        const std::array<unsigned char, 32>& client_pub,
        const std::array<unsigned char, 32>& server_pub,
        const std::array<unsigned char, 32>& salt) {
    std::vector<unsigned char> data(label, label + std::strlen(label));
    data.insert(data.end(), client_pub.begin(), client_pub.end());
    data.insert(data.end(), server_pub.begin(), server_pub.end());
    data.insert(data.end(), salt.begin(), salt.end());
    return data;
}

Key client_handshake(const Config& cfg, const Psk& psk) {
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(cfg.control_port);
    peer.sin_addr.s_addr = parse_ipv4(cfg.peer);
    int fd = -1;
    for (int attempt = 0; attempt < 20; ++attempt) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) fail("Cannot create handshake socket");
        if (connect(fd, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) == 0) break;
        const int connect_error = errno;
        close(fd);
        fd = -1;
        if (connect_error != ECONNREFUSED && connect_error != ETIMEDOUT && connect_error != EINTR) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    if (fd < 0) {
        fail("Could not connect to Device2 handshake service at " + cfg.peer + ":" + std::to_string(cfg.control_port));
    }

    auto pair = make_x25519_pair();
    std::array<unsigned char, 36> hello{};
    std::memcpy(hello.data(), kHandshakeMagic, 4);
    std::memcpy(hello.data() + 4, pair.public_key.data(), 32);
    send_all(fd, hello.data(), hello.size());

    std::array<unsigned char, 100> response{};
    recv_all(fd, response.data(), response.size());
    if (std::memcmp(response.data(), kHandshakeMagic, 4) != 0) {
        close(fd);
        fail("Invalid handshake response magic");
    }
    std::array<unsigned char, 32> server_pub{};
    std::array<unsigned char, 32> salt{};
    std::memcpy(server_pub.data(), response.data() + 4, 32);
    std::memcpy(salt.data(), response.data() + 36, 32);
    std::array<unsigned char, 32> server_mac{};
    std::memcpy(server_mac.data(), response.data() + 68, 32);

    const auto server_auth_data = labelled_transcript("server", pair.public_key, server_pub, salt);
    const auto expected_server_mac = hmac_sha256(psk, server_auth_data);
    if (CRYPTO_memcmp(server_mac.data(), expected_server_mac.data(), server_mac.size()) != 0) {
        close(fd);
        fail("Device2 authentication failed (wrong PSK or possible MITM)");
    }
    const auto client_auth_data = labelled_transcript("client", pair.public_key, server_pub, salt);
    const auto client_mac = hmac_sha256(psk, client_auth_data);
    send_all(fd, client_mac.data(), client_mac.size());

    const Key shared = x25519_shared_secret(pair.private_key, server_pub.data());
    const auto transcript = labelled_transcript("transcript", pair.public_key, server_pub, salt);
    Key session_key = derive_session_key(shared, salt, transcript);
    close(fd);
    return session_key;
}

Key server_handshake(const Config& cfg, const Psk& psk) {
    const int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) fail("Cannot create handshake listening socket");
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(cfg.control_port);
    address.sin_addr.s_addr = parse_ipv4(cfg.listen_address);
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        close(listen_fd);
        fail("Cannot bind handshake address " + cfg.listen_address + ":" + std::to_string(cfg.control_port));
    }
    if (listen(listen_fd, 1) != 0) {
        close(listen_fd);
        fail("Handshake listen() failed");
    }
    std::cout << "[Device2] Waiting for authenticated DH handshake on "
              << cfg.listen_address << ':' << cfg.control_port << std::endl;
    const int fd = accept(listen_fd, nullptr, nullptr);
    close(listen_fd);
    if (fd < 0) fail("Handshake accept() failed");

    std::array<unsigned char, 36> hello{};
    recv_all(fd, hello.data(), hello.size());
    if (std::memcmp(hello.data(), kHandshakeMagic, 4) != 0) {
        close(fd);
        fail("Invalid handshake request magic");
    }
    std::array<unsigned char, 32> client_pub{};
    std::memcpy(client_pub.data(), hello.data() + 4, 32);
    auto pair = make_x25519_pair();
    std::array<unsigned char, 32> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        close(fd);
        fail("Could not generate handshake salt");
    }
    const auto server_auth_data = labelled_transcript("server", client_pub, pair.public_key, salt);
    const auto server_mac = hmac_sha256(psk, server_auth_data);
    std::array<unsigned char, 100> response{};
    std::memcpy(response.data(), kHandshakeMagic, 4);
    std::memcpy(response.data() + 4, pair.public_key.data(), 32);
    std::memcpy(response.data() + 36, salt.data(), 32);
    std::memcpy(response.data() + 68, server_mac.data(), 32);
    send_all(fd, response.data(), response.size());

    std::array<unsigned char, 32> client_mac{};
    recv_all(fd, client_mac.data(), client_mac.size());
    const auto client_auth_data = labelled_transcript("client", client_pub, pair.public_key, salt);
    const auto expected_client_mac = hmac_sha256(psk, client_auth_data);
    if (CRYPTO_memcmp(client_mac.data(), expected_client_mac.data(), client_mac.size()) != 0) {
        close(fd);
        fail("Device1 authentication failed (wrong PSK or possible MITM)");
    }
    const Key shared = x25519_shared_secret(pair.private_key, client_pub.data());
    const auto transcript = labelled_transcript("transcript", client_pub, pair.public_key, salt);
    Key session_key = derive_session_key(shared, salt, transcript);
    close(fd);
    return session_key;
}

std::uint16_t internet_checksum(const unsigned char* data, std::size_t length) {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    for (; i + 1 < length; i += 2) {
        sum += (static_cast<std::uint32_t>(data[i]) << 8U) | data[i + 1];
    }
    if (i < length) sum += static_cast<std::uint32_t>(data[i]) << 8U;
    while (sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum & 0xffffU);
}

void recompute_checksums(std::vector<unsigned char>& packet, std::size_t ip_header_len,
                         std::size_t tcp_header_offset) {
    if (packet.size() > std::numeric_limits<std::uint16_t>::max()) fail("IPv4 packet too large");
    write_be16(packet.data() + 2, static_cast<std::uint16_t>(packet.size()));
    packet[10] = packet[11] = 0;
    write_be16(packet.data() + 10, internet_checksum(packet.data(), ip_header_len));

    const std::size_t tcp_len = packet.size() - tcp_header_offset;
    packet[tcp_header_offset + 16] = 0;
    packet[tcp_header_offset + 17] = 0;
    std::uint32_t sum = 0;
    // IPv4 pseudo-header: source + destination + zero + protocol + TCP length.
    for (std::size_t i = 12; i < 20; i += 2) {
        sum += (static_cast<std::uint32_t>(packet[i]) << 8U) | packet[i + 1];
    }
    sum += packet[9];
    sum += static_cast<std::uint32_t>(tcp_len);
    for (std::size_t i = tcp_header_offset; i + 1 < packet.size(); i += 2) {
        sum += (static_cast<std::uint32_t>(packet[i]) << 8U) | packet[i + 1];
    }
    if ((tcp_len & 1U) != 0U) sum += static_cast<std::uint32_t>(packet.back()) << 8U;
    while (sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
    write_be16(packet.data() + tcp_header_offset + 16, static_cast<std::uint16_t>(~sum & 0xffffU));
}

std::vector<unsigned char> make_aad(const std::vector<unsigned char>& packet,
                                     std::size_t header_length,
                                     std::size_t tcp_offset) {
    std::vector<unsigned char> aad(packet.begin(), packet.begin() + static_cast<std::ptrdiff_t>(header_length));
    // These fields necessarily change when the nonce/tag are added or removed.
    aad[2] = aad[3] = 0;                 // IPv4 total length
    aad[8] = 0;                          // TTL changes at each routed hop
    aad[10] = aad[11] = 0;               // IPv4 checksum
    aad[tcp_offset + 16] = 0;            // TCP checksum
    aad[tcp_offset + 17] = 0;
    return aad;
}

Nonce next_nonce(AppContext& ctx) {
    if (ctx.nonce_counter == std::numeric_limits<std::uint64_t>::max()) {
        fail("Nonce counter exhausted; establish a new session before encrypting more packets");
    }
    ++ctx.nonce_counter;
    Nonce nonce{};
    write_be32(nonce.data(), ctx.nonce_prefix);
    write_be64(nonce.data() + 4, ctx.nonce_counter);
    return nonce;
}

std::vector<unsigned char> aes_gcm_encrypt(const Key& key, const Nonce& nonce,
        const std::vector<unsigned char>& aad, const unsigned char* plaintext, std::size_t plaintext_len,
        Tag& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) fail("AES-GCM context allocation failed");
    check_ssl(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "AES-GCM init");
    check_ssl(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr), "AES-GCM nonce length");
    check_ssl(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()), "AES-GCM key/nonce setup");
    int out_len = 0;
    if (!aad.empty()) check_ssl(EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())), "AES-GCM AAD");
    std::vector<unsigned char> ciphertext(plaintext_len + 16);
    int ciphertext_len = 0;
    if (plaintext_len > 0) {
        check_ssl(EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext, static_cast<int>(plaintext_len)), "AES-GCM encrypt");
        ciphertext_len += out_len;
    }
    check_ssl(EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &out_len), "AES-GCM final");
    ciphertext_len += out_len;
    check_ssl(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()), "AES-GCM get tag");
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(static_cast<std::size_t>(ciphertext_len));
    return ciphertext;
}

bool aes_gcm_decrypt(const Key& key, const Nonce& nonce, const Tag& tag,
        const std::vector<unsigned char>& aad, const unsigned char* ciphertext, std::size_t ciphertext_len,
        std::vector<unsigned char>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
    int out_len = 0;
    if (ok && !aad.empty()) ok = EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) == 1;
    plaintext.assign(ciphertext_len + 16, 0);
    int plaintext_len = 0;
    if (ok && ciphertext_len > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext, static_cast<int>(ciphertext_len)) == 1;
        plaintext_len += out_len;
    }
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                     const_cast<unsigned char*>(tag.data())) == 1;
    if (ok) {
        const int final_ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &out_len);
        ok = final_ok == 1;
        if (ok) plaintext_len += out_len;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (ok) plaintext.resize(static_cast<std::size_t>(plaintext_len));
    else plaintext.clear();
    return ok;
}

bool process_packet(AppContext& ctx, const unsigned char* input, std::size_t input_len,
                    std::vector<unsigned char>& output, std::string& error) {
    if (input_len < 20 || (input[0] >> 4U) != 4U) return false;
    const std::size_t ip_header_len = static_cast<std::size_t>(input[0] & 0x0fU) * 4U;
    if (ip_header_len < 20 || input_len < ip_header_len || input[9] != IPPROTO_TCP) return false;
    const std::size_t total_len = read_be16(input + 2);
    if (total_len < ip_header_len || total_len > input_len) return false;
    // Non-initial fragments and fragmented packets are not processed by this prototype.
    const std::uint16_t frag = read_be16(input + 6);
    if ((frag & 0x3fffU) != 0U) {
        error = "Fragmented IPv4 packet encountered; this prototype drops it";
        return true;
    }
    if (input_len != total_len) {
        // NFQUEUE normally supplies exactly the IPv4 packet. Ignore trailing bytes if present.
        input_len = total_len;
    }
    if (input_len < ip_header_len + 20) return false;
    const std::size_t tcp_offset = ip_header_len;
    const std::size_t tcp_header_len = static_cast<std::size_t>(input[tcp_offset + 12] >> 4U) * 4U;
    if (tcp_header_len < 20 || tcp_offset + tcp_header_len > input_len) return false;

    std::uint32_t src_ip = 0, dst_ip = 0;
    std::memcpy(&src_ip, input + 12, 4);
    std::memcpy(&dst_ip, input + 16, 4);
    const std::uint16_t dst_port = read_be16(input + tcp_offset + 2);
    if (src_ip != ctx.source_ip || dst_ip != ctx.destination_ip || dst_port != ctx.destination_port) return false;

    const std::size_t payload_offset = tcp_offset + tcp_header_len;
    const std::size_t payload_len = input_len - payload_offset;
    if (payload_len == 0) return false; // SYN/ACK/FIN-only packets are not encrypted.

    std::vector<unsigned char> packet(input, input + input_len);
    const auto aad = make_aad(packet, payload_offset, tcp_offset);

    try {
        if (ctx.encrypt) {
            const Nonce nonce = next_nonce(ctx);
            Tag tag{};
            const auto ciphertext = aes_gcm_encrypt(ctx.key, nonce, aad,
                packet.data() + payload_offset, payload_len, tag);
            output.assign(packet.begin(), packet.begin() + static_cast<std::ptrdiff_t>(payload_offset));
            output.insert(output.end(), nonce.begin(), nonce.end());
            output.insert(output.end(), ciphertext.begin(), ciphertext.end());
            output.insert(output.end(), tag.begin(), tag.end());
            recompute_checksums(output, ip_header_len, tcp_offset);
            return true;
        }

        if (payload_len < kNonceSize + kTagSize) {
            error = "Protected packet is too short to contain nonce and GCM tag";
            return true;
        }
        Nonce nonce{};
        std::memcpy(nonce.data(), packet.data() + payload_offset, nonce.size());
        const std::size_t ciphertext_len = payload_len - kNonceSize - kTagSize;
        Tag tag{};
        std::memcpy(tag.data(), packet.data() + payload_offset + kNonceSize + ciphertext_len, tag.size());
        std::vector<unsigned char> plaintext;
        const bool verified = aes_gcm_decrypt(ctx.key, nonce, tag, aad,
            packet.data() + payload_offset + kNonceSize, ciphertext_len, plaintext);
        if (!verified) {
            error = "AES-GCM authentication failed; packet rejected";
            return true;
        }
        output.assign(packet.begin(), packet.begin() + static_cast<std::ptrdiff_t>(payload_offset));
        output.insert(output.end(), plaintext.begin(), plaintext.end());
        recompute_checksums(output, ip_header_len, tcp_offset);
        return true;
    } catch (const std::exception& ex) {
        error = ex.what();
        return true;
    }
}

int queue_callback(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfa, void* user_data) {
    auto* ctx = static_cast<AppContext*>(user_data);
    nfqnl_msg_packet_hdr* header = nfq_get_msg_packet_hdr(nfa);
    if (!header) return 0;
    const std::uint32_t id = ntohl(header->packet_id);
    unsigned char* payload = nullptr;
    const int len = nfq_get_payload(nfa, &payload);
    if (len <= 0 || payload == nullptr) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    std::vector<unsigned char> modified;
    std::string error;
    const bool selected = process_packet(*ctx, payload, static_cast<std::size_t>(len), modified, error);
    if (!error.empty()) {
        std::cerr << (ctx->encrypt ? "[Device1] " : "[Device2] ") << error << std::endl;
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    }
    if (selected && !modified.empty()) {
        return nfq_set_verdict2(qh, id, NF_ACCEPT, 0,
                                static_cast<std::uint32_t>(modified.size()), modified.data());
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

void run_queue(const Config& cfg, AppContext& ctx) {
    nfq_handle* handle = nfq_open();
    if (!handle) fail("nfq_open() failed; run as root and check NFQUEUE kernel support");
    (void)nfq_unbind_pf(handle, AF_INET);
    if (nfq_bind_pf(handle, AF_INET) < 0) {
        nfq_close(handle);
        fail("nfq_bind_pf(AF_INET) failed");
    }
    nfq_q_handle* queue = nfq_create_queue(handle, cfg.queue_num, &queue_callback, &ctx);
    if (!queue) {
        nfq_close(handle);
        fail("nfq_create_queue() failed; is another process using this queue?");
    }
    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        nfq_destroy_queue(queue);
        nfq_close(handle);
        fail("nfq_set_mode() failed");
    }
    int fd = nfq_fd(handle);
    std::vector<char> buffer(1024 * 1024);
    std::cout << (ctx.encrypt ? "[Device1]" : "[Device2]")
              << " READY: NFQUEUE " << cfg.queue_num
              << (ctx.encrypt ? " encrypting" : " decrypting")
              << " TCP payloads for " << cfg.source_ip << " -> " << cfg.destination_ip
              << ':' << cfg.destination_port << std::endl;
    while (true) {
        const int rv = static_cast<int>(recv(fd, buffer.data(), buffer.size(), 0));
        if (rv >= 0) {
            nfq_handle_packet(handle, buffer.data(), rv);
        } else if (errno == EINTR) {
            continue;
        } else {
            std::cerr << "NFQUEUE recv error: " << std::strerror(errno) << std::endl;
            break;
        }
    }
    nfq_destroy_queue(queue);
    nfq_close(handle);
}

void usage(const char* program) {
    std::cerr <<
      "Usage:\n"
      "  " << program << " --role receiver --psk psk.hex --src 10.0.1.2 --dst 10.0.3.2 [options]\n"
      "  " << program << " --role sender --peer 10.0.2.2 --psk psk.hex --src 10.0.1.2 --dst 10.0.3.2 [options]\n\n"
      "Options:\n"
      "  --role sender|receiver       Device1 encrypts / Device2 decrypts\n"
      "  --peer IPv4                  Device2 control-plane address (sender only)\n"
      "  --listen IPv4                Control-plane bind address (receiver; default 0.0.0.0)\n"
      "  --psk FILE                   32-byte PSK as 64 hex characters\n"
      "  --src IPv4                   Protected TCP source address\n"
      "  --dst IPv4                   Protected TCP destination address\n"
      "  --dport PORT                 Protected TCP destination port (default 5001)\n"
      "  --control-port PORT          DH handshake TCP port (default 9000)\n"
      "  --queue NUMBER               NFQUEUE number (default 0)\n"
      "  --help                       Show this help\n";
}

std::uint16_t parse_port(const char* value, const char* option_name) {
    char* end = nullptr;
    const long parsed = std::strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 1 || parsed > 65535)
        fail(std::string(option_name) + " must be between 1 and 65535");
    return static_cast<std::uint16_t>(parsed);
}

std::uint16_t parse_queue(const char* value) {
    char* end = nullptr;
    const long parsed = std::strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 0 || parsed > 65535)
        fail("--queue must be between 0 and 65535");
    return static_cast<std::uint16_t>(parsed);
}

Config parse_args(int argc, char** argv) {
    Config cfg;
    static option options[] = {
        {"role", required_argument, nullptr, 'r'},
        {"peer", required_argument, nullptr, 'p'},
        {"listen", required_argument, nullptr, 'l'},
        {"psk", required_argument, nullptr, 'k'},
        {"src", required_argument, nullptr, 's'},
        {"dst", required_argument, nullptr, 'd'},
        {"dport", required_argument, nullptr, 'P'},
        {"control-port", required_argument, nullptr, 'c'},
        {"queue", required_argument, nullptr, 'q'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };
    while (true) {
        const int c = getopt_long(argc, argv, "", options, nullptr);
        if (c == -1) break;
        switch (c) {
            case 'r': cfg.role = optarg; break;
            case 'p': cfg.peer = optarg; break;
            case 'l': cfg.listen_address = optarg; break;
            case 'k': cfg.psk_file = optarg; break;
            case 's': cfg.source_ip = optarg; break;
            case 'd': cfg.destination_ip = optarg; break;
            case 'P': cfg.destination_port = parse_port(optarg, "--dport"); break;
            case 'c': cfg.control_port = parse_port(optarg, "--control-port"); break;
            case 'q': cfg.queue_num = parse_queue(optarg); break;
            case 'h': usage(argv[0]); std::exit(0);
            default: usage(argv[0]); std::exit(2);
        }
    }
    if (cfg.role != "sender" && cfg.role != "receiver") fail("--role must be sender or receiver");
    if (cfg.psk_file.empty() || cfg.source_ip.empty() || cfg.destination_ip.empty()) {
        fail("--psk, --src and --dst are required");
    }
    if (cfg.role == "sender" && cfg.peer.empty()) fail("--peer is required for sender role");
    return cfg;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const Config cfg = parse_args(argc, argv);
        const Psk psk = load_psk(cfg.psk_file);
        std::cout << (cfg.role == "sender" ? "[Device1]" : "[Device2]")
                  << " Starting authenticated X25519 handshake..." << std::endl;
        const Key session_key = (cfg.role == "sender")
            ? client_handshake(cfg, psk)
            : server_handshake(cfg, psk);
        std::cout << "[" << (cfg.role == "sender" ? "Device1" : "Device2")
                  << "] Authenticated session established; AES-256-GCM key derived." << std::endl;

        AppContext ctx;
        ctx.key = session_key;
        ctx.encrypt = cfg.role == "sender";
        ctx.source_ip = parse_ipv4(cfg.source_ip);
        ctx.destination_ip = parse_ipv4(cfg.destination_ip);
        ctx.destination_port = cfg.destination_port;
        if (ctx.encrypt) {
            std::array<unsigned char, 4> prefix{};
            if (RAND_bytes(prefix.data(), static_cast<int>(prefix.size())) != 1) fail("Nonce prefix generation failed");
            std::memcpy(&ctx.nonce_prefix, prefix.data(), prefix.size());
        }
        run_queue(cfg, ctx);
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
