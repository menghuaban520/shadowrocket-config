# 安全区块预览

> 自动生成；疑似密码、私钥、Token、UUID 或带秘密查询参数的内容只会显示 `<REDACTED>`。

## [General]

```ini
hijack-dns = 8.8.8.8:53,8.8.4.4:53,1.1.1.1:53,1.0.0.1:53,223.5.5.5:53,119.29.29.29:53
direct-dns-server = https://dns.alidns.com/dns-query#no-h3,https://doh.pub/dns-query#no-h3
dns-server = https://1.1.1.1/dns-query#proxy&no-h3
fallback-dns-server = https://1.0.0.1/dns-query#proxy&no-h3
proxy-dns-server = https://dns.alidns.com/dns-query#no-h3,https://doh.pub/dns-query#no-h3
dns-direct-system = false
dns-fallback-system = false
dns-direct-fallback-proxy = false
always-ip-address = false
ipv6 = false
prefer-ipv6 = false
udp-policy-not-supported-behaviour = REJECT
close-if-proxy-chain-missing = true
block-quic = all-proxy

```

## [Host]

```ini
bwg.091329.xyz = 95.169.18.212
localhost = 127.0.0.1
dns.alidns.com = 223.5.5.5
doh.pub = 1.12.12.12
```

