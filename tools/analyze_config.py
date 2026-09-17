#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import re

CONFIG = Path('花花最终版.conf')
OUT = Path('classified')
OUT.mkdir(exist_ok=True)

raw = CONFIG.read_bytes()
text = raw.decode('utf-8-sig', errors='replace')
lines = text.splitlines()

section_re = re.compile(r'^\s*\[([^\]]+)\]\s*$')
sections: dict[str, list[str]] = defaultdict(list)
section_order: list[str] = ['(preamble)']
current = '(preamble)'

for line in lines:
    m = section_re.match(line)
    if m:
        current = m.group(1).strip()
        if current not in section_order:
            section_order.append(current)
        continue
    sections[current].append(line)

rule_section_name = next((s for s in section_order if s.lower() in {'rule', 'rules'}), None)
rule_lines: list[str] = []
if rule_section_name:
    rule_lines = [
        line.strip() for line in sections[rule_section_name]
        if line.strip() and not line.lstrip().startswith(('#', ';'))
    ]

rule_type_counts = Counter()
policy_counts = Counter()
exact_rule_counts = Counter(rule_lines)
semantic_policies: dict[tuple[str, tuple[str, ...]], set[str]] = defaultdict(set)

simple_types = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-SET',
    'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'USER-AGENT', 'PROCESS-NAME',
    'DST-PORT', 'SRC-PORT', 'SRC-IP', 'URL-REGEX', 'RULE-SET',
    'SCRIPT', 'FINAL'
}

for line in rule_lines:
    parts = [p.strip() for p in line.split(',')]
    if not parts:
        continue
    rule_type = parts[0].upper()
    rule_type_counts[rule_type] += 1
    if len(parts) >= 2:
        policy_index = -2 if parts[-1].lower() == 'no-resolve' and len(parts) >= 3 else -1
        policy = parts[policy_index]
        if policy:
            policy_counts[policy] += 1
        if rule_type in simple_types:
            body = parts[1:policy_index]
            semantic_policies[(rule_type, tuple(body))].add(policy)

exact_duplicate_instances = sum(c - 1 for c in exact_rule_counts.values() if c > 1)
exact_duplicate_unique = sum(1 for c in exact_rule_counts.values() if c > 1)
conflicting_keys = sum(1 for policies in semantic_policies.values() if len(policies) > 1)

sensitive_patterns = {
    'proxy URI (ss/vmess/vless/trojan/hysteria/tuic)': re.compile(r'(?i)\b(?:ss|vmess|vless|trojan|hysteria2?|tuic)://'),
    'password field': re.compile(r'(?i)(?:^|[,;\s])password\s*='),
    'private key field': re.compile(r'(?i)(?:private[-_ ]?key|privatekey|wg[-_ ]?private)\s*='),
    'token/API key field': re.compile(r'(?i)(?:^|[,?&;\s])(?:token|api[-_ ]?key|authorization)\s*='),
    'UUID field': re.compile(r'(?i)(?:^|[,;\s])uuid\s*='),
}

sensitive_counts = Counter()
for line in lines:
    if not line.strip() or line.lstrip().startswith(('#', ';')):
        continue
    for label, pattern in sensitive_patterns.items():
        if pattern.search(line):
            sensitive_counts[label] += 1

section_stats = []
for name in section_order:
    body = sections[name]
    nonblank = sum(1 for x in body if x.strip())
    comments = sum(1 for x in body if x.lstrip().startswith(('#', ';')))
    section_stats.append((name, len(body), nonblank, comments))

sha256 = hashlib.sha256(raw).hexdigest()

index: list[str] = []
index.append('# 配置分类索引\n')
index.append('> 自动生成。原始 `花花最终版.conf` 不会被修改。\n')
index.append('## 文件概况\n')
index.append(f'- 大小：{len(raw):,} bytes ({len(raw)/1024/1024:.2f} MiB)')
index.append(f'- 总行数：{len(lines):,}')
index.append(f'- SHA-256：`{sha256}`')
index.append(f'- 检测到区块：{len(section_order) - (1 if section_order and section_order[0] == "(preamble)" else 0)}\n')
index.append('## 区块分布\n')
index.append('| 区块 | 总行数 | 非空行 | 注释行 |')
index.append('|---|---:|---:|---:|')
for name, total, nonblank, comments in section_stats:
    if name == '(preamble)' and total == 0:
        continue
    index.append(f'| `{name}` | {total:,} | {nonblank:,} | {comments:,} |')
index.append('')

if rule_section_name:
    index.append('## Rule 概况\n')
    index.append(f'- 有效规则行：{len(rule_lines):,}')
    index.append(f'- 完全重复规则：{exact_duplicate_instances:,} 条额外副本，涉及 {exact_duplicate_unique:,} 种规则')
    index.append(f'- 简单规则中“同一匹配条件指向多个策略”的候选冲突：{conflicting_keys:,} 组')
    index.append('')
    index.append('### 按规则类型\n')
    index.append('| 类型 | 数量 |')
    index.append('|---|---:|')
    for name, count in rule_type_counts.most_common():
        index.append(f'| `{name}` | {count:,} |')
    index.append('')
    index.append('### 按策略目标（前 30）\n')
    index.append('| 策略 | 数量 |')
    index.append('|---|---:|')
    for name, count in policy_counts.most_common(30):
        safe_name = name.replace('|', '\\|')
        index.append(f'| `{safe_name}` | {count:,} |')
    index.append('')

index.append('## 敏感信息启发式检查\n')
if sensitive_counts:
    index.append('> ⚠️ 只显示命中数量，不回显具体内容。仓库是 Public 时应人工复核。\n')
    index.append('| 类型 | 命中行数 |')
    index.append('|---|---:|')
    for label, count in sensitive_counts.items():
        index.append(f'| {label} | {count:,} |')
else:
    index.append('未命中脚本内置的常见敏感字段模式。**这不等于绝对不存在秘密，只代表启发式扫描没有发现。**')
index.append('')
index.append('## 怎么用这个目录\n')
index.append('- `花花最终版.conf`：继续作为当前实际使用版本。')
index.append('- `classified/CONFIG-INDEX.md`：先看结构、规则规模、重复和风险。')
index.append('- 这个阶段只做“地图”，不改变规则顺序，不自动重写配置，避免分流行为被悄悄改变。')

(OUT / 'CONFIG-INDEX.md').write_text('\n'.join(index) + '\n', encoding='utf-8')

readme = '''# classified\n\n这里是对 `花花最终版.conf` 的自动分类/体检结果。\n\n- 原配置保持不动。\n- 报告不会回显密码、私钥或 token 的具体值。\n- 先根据报告确认结构，再决定是否真的拆成 `rules/`、`stable.conf` 等运行文件。\n\n> 规则顺序会影响 Shadowrocket 的匹配结果，所以在没有看清原配置前，不做“为了整齐而整齐”的自动重排。\n'''
(OUT / 'README.md').write_text(readme, encoding='utf-8')

print(f'Analyzed {CONFIG}: {len(raw):,} bytes, {len(lines):,} lines')
print(f'Sections: {len(section_order)}; rules: {len(rule_lines):,}; duplicate extras: {exact_duplicate_instances:,}')
print(f'Sensitive-pattern hit lines: {sum(sensitive_counts.values()):,}')
