# Межсетевой экран на nfqueue

### Замечание
Это набросок структуры, проект ещё будет дописываться

## Быстрый старт
```shell
./runbuild.sh
sudo env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" ./build/bin/app
```

## Требования
+ `C++20`
+ `g++ (GCC) 14.2.0`
+ `cmake 3.16`
+ `libnetfilter_queue`

## Пример работы

### Терминал 1
```shell
└─[$]> sudo hping3 -c 1 -S -p 80 -a 192.168.1.100 8.8.8.8
HPING 8.8.8.8 (enp4s0 8.8.8.8): S set, 40 headers + 0 data bytes

--- 8.8.8.8 hping statistic ---
1 packets transmitted, 0 packets received, 100% packet loss
round-trip min/avg/max = 0.0/0.0/0.0 ms

└─[$]> nc -z 127.0.0.1 1337
^C

└─[$]> curl -A "blockme" http://example.com 
^C
```

### Терминал 2
```shell
sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 0
```

### Терминал 3
```shell
└─[$]> sudo env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" ./build/bin/app
Firewall started with 3 filters.
Press Q to exit
MATCH: Filter applied. Src: 192.168.1.100 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 127.0.0.1 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 127.0.0.1 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 127.0.0.1 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP
MATCH: Filter applied. Src: 192.168.31.5 Protocol: 6. Action: DROP

```
