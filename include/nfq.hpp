#pragma once

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <sstream>
#include <thread>
#include <vector>

namespace nfq {

struct PacketFilter {
  enum Action { ACCEPT, DROP };
  Action action{DROP};

  uint32_t src_ip{0};
  uint32_t dst_ip{0};

  uint16_t src_port{0};
  uint16_t dst_port{0};

  uint8_t tcp_flags_mask{0};
  uint8_t tcp_flags_expected{0};

  std::vector<std::string> banned_words;

  uint8_t protocol{0};
};

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

  static int generic_packet_handler(struct nfq_q_handle *qh,
                                    struct nfgenmsg *nfmsg,
                                    struct nfq_data *nfad, void *data) {
    std::vector<PacketFilter> *filters =
        static_cast<std::vector<PacketFilter> *>(data);

    if (!filters || filters->empty()) {
      return accept_packet(qh, nfad);
    }

    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfad, &packet_data);

    if (packet_len <= 0) {
      return accept_packet(qh, nfad);
    }

    struct iphdr *iph = (struct iphdr *)packet_data;

    if (packet_len < sizeof(struct iphdr) || iph->version != 4) {
      return accept_packet(qh, nfad);
    }

    int ip_header_len = iph->ihl * 4;

    struct tcphdr *tcph = nullptr;
    unsigned char *app_data = nullptr;
    int app_data_len = 0;

    if (iph->protocol == IPPROTO_TCP) {
      if (packet_len >= ip_header_len + sizeof(struct tcphdr)) {
        tcph = (struct tcphdr *)(packet_data + ip_header_len);
        int tcp_header_len = tcph->doff * 4;
        int total_headers_len = ip_header_len + tcp_header_len;

        if (packet_len > total_headers_len) {
          app_data = packet_data + total_headers_len;
          app_data_len = packet_len - total_headers_len;
        }
      }
    }

    for (const auto &filter : *filters) {
      bool match = true;

      if (filter.protocol != 0 && filter.protocol != iph->protocol) {
        match = false;
      }

      if (match && filter.src_ip != 0 && filter.src_ip != iph->saddr) {
        match = false;
      }

      if (match && filter.dst_ip != 0 && filter.dst_ip != iph->daddr) {
        match = false;
      }

      if (match && iph->protocol == IPPROTO_TCP && tcph) {
        if (filter.src_port != 0 && filter.src_port != ntohs(tcph->source)) {
          match = false;
        }
        if (match && filter.dst_port != 0 &&
            filter.dst_port != ntohs(tcph->dest)) {
          match = false;
        }
        uint8_t actual_flags =
            ((tcph->fin ? TH_FIN : 0) | (tcph->syn ? TH_SYN : 0) |
             (tcph->rst ? TH_RST : 0) | (tcph->psh ? TH_PUSH : 0) |
             (tcph->ack ? TH_ACK : 0) | (tcph->urg ? TH_URG : 0));

        if (match && filter.tcp_flags_mask != 0) {
          if ((actual_flags & filter.tcp_flags_mask) !=
              filter.tcp_flags_expected) {
            match = false;
          }
        }
      }

      if (match && !filter.banned_words.empty() && app_data) {
        std::string packet_content((char *)app_data, app_data_len);
        bool found_banned_word = false;
        for (const auto &word : filter.banned_words) {
          if (packet_content.find(word) != std::string::npos) {
            found_banned_word = true;
            break;
          }
        }
        if (!found_banned_word) {
          match = false;
        }
      } else if (match && !filter.banned_words.empty() && !app_data) {
        match = false;
      }

      if (match) {
        struct in_addr src_ip_addr;
        src_ip_addr.s_addr = iph->saddr;
        std::cout << "MATCH: Filter applied. Src: " << inet_ntoa(src_ip_addr)
                  << " Protocol: " << (int)iph->protocol << ". Action: "
                  << (filter.action == PacketFilter::DROP ? "DROP" : "ACCEPT")
                  << std::endl;

        if (filter.action == PacketFilter::DROP) {
          return drop_packet(qh, nfad);
        } else {
          return accept_packet(qh, nfad);
        }
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
      std::ostringstream ss;
      ss << "can't nfq_bind_pf(" << (void *)handle << ", "
         << config_.protocol_family << ")";
      std::invoke(error_handler, "runner::nfq_bind_pf", ss.str(), errno);
      stop();
      return;
    }

    for (const auto &[number, mode, range, handler, user_data] :
         config_.queues) {
      nfq_q_handle *queue_handle =
          nfq_create_queue(handle, number, handler, user_data);
      if (queue_handle == nullptr) {
        std::ostringstream ss;
        ss << "can't nfq_create_queue(" << (void *)handle << ", " << number
           << ", " << (void *)handler << ", " << user_data << ")";
        std::invoke(error_handler, "runner::nfq_create_queue", ss.str(), errno);
      }

      if (nfq_set_mode(queue_handle, mode, range) < 0) {
        std::ostringstream ss;
        ss << "can't nfq_set_mode(" << (void *)queue_handle << ", " << (int)mode
           << ", " << range << ")";
        std::invoke(error_handler, "runner::nfq_set_mode", ss.str(), errno);
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