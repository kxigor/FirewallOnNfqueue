#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
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

      // Таймаут 100ms
      timeout.tv_sec = 0;
      timeout.tv_usec = 100000;

      int ready = select(netlink_fd + 1, &read_fds, NULL, NULL, &timeout);

      if (ready < 0) {
        if (errno == EINTR) continue;  // Сигнал прервал
        perror("select");
        break;
      } else if (ready == 0) {
        // Таймаут - проверяем флаг и продолжаем
        continue;
      }

      // Есть данные для чтения
      if (FD_ISSET(netlink_fd, &read_fds)) {
        ssize_t rv = recv(netlink_fd, buf, sizeof(buf), 0);
        if (rv > 0) {
          nfq_handle_packet(handle, buf, (int)rv);
        } else if (rv == 0) {
          break;  // Соединение закрыто
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