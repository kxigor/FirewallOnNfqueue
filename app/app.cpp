#include <cstring>
#include <iostream>
#include <print>

#include "../include/nfq.hpp"

void error_handler(const std::string_view &func_name,
                   const std::string_view &message, int errid) {
  std::println("FUNC_NAME: {}, MESSAGE: {}, error: {}", func_name, message,
               std::strerror(errid));
}

static int banned_words_handler(struct nfq_q_handle *gh, struct nfgenmsg *nfmsg,
                                struct nfq_data *nfad, void *data) {
  std::vector<std::string> banned_words = *((std::vector<std::string> *)data);
}

int main() {
  std::vector<std::string> banned_words = {"C++"};
  nfq::FirewallFactory::QueueConfig queue_config{
      .handler = banned_words_handler, .user_data = (void *)&banned_words};

  nfq::FirewallFactory::FirewallConfig config;
  config.queues.emplace_back(queue_config);

  nfq::Firewall firewall;
  firewall.set_config(std::move(config));
  firewall.start(error_handler);

  std::println("Press Q to exit");
  while (getchar() != (int)'Q') { std::print("1");}

  firewall.stop();
  std::cout << "GERRE\n";
}