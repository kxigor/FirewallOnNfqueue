#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <sys/select.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>
#include <vector>

namespace nfq {

class FirewallFactory {
 public:
  struct QueueConfig {
    std::uint16_t number{0};
    std::uint8_t mode{NFQNL_COPY_PACKET};
    std::uint32_t range{0xffff};
    nfq_callback *handler{nullptr};
    void *user_data{nullptr};
  };

  struct FirewallConfig {
    std::uint16_t protocol_family{AF_INET};
    std::vector<QueueConfig> queues;
  };

  static uint32_t get_packet_id(struct nfq_data *nfad) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    if (!ph) return 0;

    uint32_t packet_id = ph->packet_id;
    return ((packet_id & 0xFF000000) >> 24) | ((packet_id & 0x00FF0000) >> 8) |
           ((packet_id & 0x0000FF00) << 8) | ((packet_id & 0x000000FF) << 24);
  }

  static int accept_packet(struct nfq_q_handle *qh, struct nfq_data *nfad) {
    return nfq_set_verdict(qh, get_packet_id(nfad), NF_ACCEPT, 0, NULL);
  }

  static int drop_packet(struct nfq_q_handle *qh, struct nfq_data *nfad) {
    return nfq_set_verdict(qh, get_packet_id(nfad), NF_DROP, 0, NULL);
  }

  static int banned_words_handler(struct nfq_q_handle *qh,
                                  struct nfgenmsg *nfmsg, struct nfq_data *nfad,
                                  void *data) {
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfad, &packet_data);

    if (packet_len <= 0) {
      return accept_packet(qh, nfad);
    }

    struct iphdr *iph = (struct iphdr *)packet_data;

    if (packet_len < sizeof(struct iphdr) || iph->version != 4) {
      return accept_packet(qh, nfad);
    }

    if (iph->protocol != IPPROTO_TCP) {
      return accept_packet(qh, nfad);
    }

    int ip_header_len = iph->ihl * 4;

    if (packet_len < ip_header_len + sizeof(struct tcphdr)) {
      return accept_packet(qh, nfad);
    }

    struct tcphdr *tcph = (struct tcphdr *)(packet_data + ip_header_len);

    int tcp_header_len = tcph->doff * 4;

    int total_headers_len = ip_header_len + tcp_header_len;

    if (packet_len <= total_headers_len) {
      return accept_packet(qh, nfad);
    }

    unsigned char *app_data = packet_data + total_headers_len;
    int app_data_len = packet_len - total_headers_len;

    std::vector<std::string> banned_words = *((std::vector<std::string> *)data);

    std::string packet_content((char *)app_data, app_data_len);

    for (const auto &word : banned_words) {
      if (packet_content.find(word) != std::string::npos) {
        std::cout << "BLOCKED: Found banned word '" << word << "'" << std::endl;
        return drop_packet(qh, nfad);
      }
    }

    return accept_packet(qh, nfad);
  }
};

class Firewall {
 public:
  using FirewallConfig = FirewallFactory::FirewallConfig;
  using ErrorHandler = std::function<void(std::string_view func_name,
                                          std::string_view message, int errid)>;

  void set_config(FirewallConfig config) noexcept {
    config_ = std::move(config);
  }

  void start(ErrorHandler error_handler) noexcept {
    if (running_.exchange(true)) {
      std::invoke(error_handler, "Firewall::start", "already running", 0);
      return;
    }

    worker_thread_ =
        std::jthread([&, error_handler]() { runner(error_handler); });
  }

  void stop() noexcept { running_.store(false); }

 private:
  void runner(ErrorHandler error_handler) {
    nfq_handle *handle = nfq_open();
    std::vector<nfq_q_handle *> queue_handles;
    int netlink_fd{};

    queue_handles.reserve(config_.queues.size());

    if (handle == nullptr) {
      std::invoke(error_handler, "runner::nfq_open", "can't nfq_open()", errno);
      stop();
      return;
    }

    if (nfq_bind_pf(handle, config_.protocol_family) < 0) {
      std::invoke(error_handler, "runner::nfq_bind_pf",
                  std::format("can't nfq_bind_pf({}, {})", (void *)handle,
                              config_.protocol_family),
                  errno);
      stop();
      return;
    }

    for (const auto &[number, mode, range, handler, user_data] :
         config_.queues) {
      nfq_q_handle *queue_handle =
          nfq_create_queue(handle, number, handler, user_data);
      if (queue_handle == nullptr) {
        std::invoke(
            error_handler, "runner::nfq_create_queue",
            std::format("can't nfq_create_queue({}, {}, {}, {})",
                        (void *)handle, number, (void *)handler, user_data),
            errno);
      }

      if (nfq_set_mode(queue_handle, mode, range) < 0) {
        std::invoke(error_handler, "runner::nfq_set_mode",
                    std::format("can't nfq_set_mode({}, {}, {})",
                                (void *)queue_handle, mode, range),
                    errno);
        stop();
        return;
      }

      queue_handles.emplace_back(queue_handle);
    }

    netlink_fd = nfq_fd(handle);
    char buf[4096] __attribute__((aligned)){};

    ssize_t rv;
    fd_set read_fds;
    struct timeval timeout;

    while (running_.load()) {
      FD_ZERO(&read_fds);
      FD_SET(netlink_fd, &read_fds);

      timeout.tv_sec = 0;
      timeout.tv_usec = 100000;

      int ready = select(netlink_fd + 1, &read_fds, NULL, NULL, &timeout);

      if (ready < 0) {
        if (errno == EINTR) continue;
        perror("select");
        break;
      } else if (ready == 0) {
        continue;
      }

      if (FD_ISSET(netlink_fd, &read_fds)) {
        ssize_t rv = recv(netlink_fd, buf, sizeof(buf), 0);
        if (rv > 0) {
          nfq_handle_packet(handle, buf, (int)rv);
        } else if (rv == 0) {
          break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
          perror("recv");
          break;
        }
      }
    }

    for (auto &queue_handle : queue_handles) {
      nfq_destroy_queue(queue_handle);
    }

    nfq_close(handle);
  }

  std::atomic<bool> running_{false};
  std::jthread worker_thread_;

  FirewallConfig config_{};
};
};  // namespace nfq