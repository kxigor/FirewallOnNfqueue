#include <cstring>
#include <iostream>

#include "../include/nfq.hpp"

void error_handler(const std::string_view &func_name,
                   const std::string_view &message, int errid) {
  std::cout << "FUNC_NAME: " << func_name << ", MESSAGE:" << message
            << ", ERROR: {}" << std::strerror(errid) << '\n';
}

int main() {
  std::vector<nfq::PacketFilter> filters;

  // Пример блокировки по banned_words
  nfq::PacketFilter banned_words_filter;
  banned_words_filter.action = nfq::PacketFilter::DROP;
  banned_words_filter.protocol = IPPROTO_TCP;
  banned_words_filter.banned_words = {"C++", "blockme", "virus"};
  filters.emplace_back(std::move(banned_words_filter));

  // Пример блокировки HTTP порт 1337
  nfq::PacketFilter block_http_filter;
  block_http_filter.action = nfq::PacketFilter::DROP;
  block_http_filter.protocol = IPPROTO_TCP;
  block_http_filter.dst_port = 1337;
  filters.emplace_back(std::move(block_http_filter));

  // Пример блокировки SYN с определенного IP
  nfq::PacketFilter block_syn_flood_filter;
  block_syn_flood_filter.action = nfq::PacketFilter::DROP;
  block_syn_flood_filter.protocol = IPPROTO_TCP;
  block_syn_flood_filter.src_ip = inet_addr("192.168.1.100");
  block_syn_flood_filter.tcp_flags_mask = TH_SYN;
  block_syn_flood_filter.tcp_flags_expected = TH_SYN;
  filters.emplace_back(std::move(block_syn_flood_filter));

  nfq::FirewallFactory::QueueConfig queue_config{
      .handler = &nfq::FirewallFactory::generic_packet_handler,
      .user_data = (void *)&filters};

  nfq::FirewallFactory::FirewallConfig config;
  config.queues.emplace_back(queue_config);

  nfq::Firewall firewall;
  firewall.set_config(std::move(config));
  firewall.start(error_handler);

  std::cout << "Firewall started with " << filters.size() << " filters.\n";
  std::cout << "Press Q to exit\n";
  while (getchar() != (int)'Q');

  firewall.stop();
}