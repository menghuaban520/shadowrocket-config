# 规则分类与复核

> 这是只读分析，不会改变 `花花最终版.conf` 的顺序或内容。

## 策略 × 类型矩阵

| 策略 | `DOMAIN` | `DOMAIN-SUFFIX` | `FINAL` | `GEOIP` | `IP-CIDR` | `IP-CIDR6` | 合计 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `DIRECT` | 277 | 111,204 | 0 | 1 | 11 | 3 | 111,496 |
| `REJECT` | 23,758 | 13,939 | 0 | 0 | 0 | 0 | 37,697 |
| `PROXY` | 0 | 63 | 1 | 0 | 0 | 0 | 64 |

## 顺序特征

- 有效规则：149,257
- 按连续策略计算的策略区块：8
- Shadowrocket 按顺序匹配；如果把所有 DIRECT / REJECT / PROXY 直接物理重排，可能改变先匹配到哪条规则。

## 完全重复规则（前 30）

- ×3: `DOMAIN-SUFFIX,byteimg.com,DIRECT`
- ×3: `DOMAIN-SUFFIX,servicewechat.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,10010.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,12306.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,126.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,126.net,DIRECT`
- ×2: `DOMAIN-SUFFIX,127.net,DIRECT`
- ×2: `DOMAIN-SUFFIX,163.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,163yun.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,1688.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,360buy.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,360buyimg.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,36kr.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,51job.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,58.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,95516.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,abchina.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,alibaba.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,alicdn.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,alipan.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,alipay.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,alipayobjects.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,aliyun.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,aliyuncdn.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,aliyundrive.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,amap.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,amemv.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,autonavi.com,DIRECT`
- ×2: `DOMAIN-SUFFIX,b23.tv,DIRECT`
- ×2: `DOMAIN-SUFFIX,baidu.com,DIRECT`

## 候选策略冲突

> “候选”不等于一定是错误；这里把同一种简单匹配条件指向多个策略的情况列出来，需结合原始顺序判断。

- `DOMAIN-SUFFIX,amd.com` → `DIRECT`, `PROXY`
- `DOMAIN-SUFFIX,baidustatic.com` → `DIRECT`, `REJECT`
- `DOMAIN-SUFFIX,browserleaks.com` → `DIRECT`, `PROXY`
- `DOMAIN-SUFFIX,koowo.com` → `DIRECT`, `REJECT`
- `DOMAIN-SUFFIX,sony.com` → `DIRECT`, `PROXY`

