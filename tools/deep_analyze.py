#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
import re

CONFIG = Path('花花最终版.conf')
OUT = Path('classified')
OUT.mkdir(exist_ok=True)

text = CONFIG.read_text(encoding='utf-8-sig', errors='replace')
lines = text.splitlines()

section_re = re.compile(r'^\s*\[([^\]]+)\]\s*$')
sections: dict[str, list[str]] = defaultdict(list)
current = '(preamble)'
for line in lines:
    m = section_re.match(line)
    if m:
        current = m.group(1).strip()
    else:
        sections[current].append(line)

sensitive = re.compile(
    r'(?i)(?:\b(?:ss|vmess|vless|trojan|hysteria2?|tuic)://|'
    r'(?:password|private[-_ ]?key|privatekey|wg[-_ ]?private|token|api[-_ ]?key|authorization|uuid)\s*=)'
)
secret_query = re.compile(r'(?i)[?&](?:token|key|api_key|apikey|auth|authorization|secret|password)=')

def safe_line(line: str) -> str:
    if sensitive.search(line) or secret_query.search(line):
        key = line.split('=', 1)[0].strip() if '=' in line else '(redacted)'
        return f'{key} = <REDACTED>'
    return line

safe_sections = ['General', 'Host']
out = ['# 安全区块预览', '', '> 自动生成；疑似密码、私钥、Token、UUID 或带秘密查询参数的内容只会显示 `<REDACTED>`。', '']
for sec in safe_sections:
    if sec not in sections:
        continue
    out += [f'## [{sec}]', '', '```ini']
    out.extend(safe_line(x) for x in sections[sec])
    out += ['```', '']
(OUT / 'SAFE-SECTIONS.md').write_text('\n'.join(out) + '\n', encoding='utf-8')

rule_sec = next((k for k in sections if k.lower() in {'rule', 'rules'}), None)
rule_lines = [] if rule_sec is None else [
    x.strip() for x in sections[rule_sec]
    if x.strip() and not x.lstrip().startswith(('#', ';'))
]

matrix: dict[str, Counter[str]] = defaultdict(Counter)
duplicates = Counter(rule_lines)
semantic: dict[tuple[str, tuple[str, ...]], set[str]] = defaultdict(set)
policy_sequence: list[str] = []

simple_types = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-SET',
    'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'USER-AGENT', 'PROCESS-NAME',
    'DST-PORT', 'SRC-PORT', 'SRC-IP', 'URL-REGEX', 'RULE-SET', 'SCRIPT', 'FINAL'
}

for line in rule_lines:
    parts = [p.strip() for p in line.split(',')]
    if len(parts) < 2:
        continue
    kind = parts[0].upper()
    policy_index = -2 if parts[-1].lower() == 'no-resolve' and len(parts) >= 3 else -1
    policy = parts[policy_index]
    matrix[policy][kind] += 1
    policy_sequence.append(policy)
    if kind in simple_types:
        semantic[(kind, tuple(parts[1:policy_index]))].add(policy)

policy_blocks = 0
last = None
for p in policy_sequence:
    if p != last:
        policy_blocks += 1
        last = p

all_types = sorted({t for c in matrix.values() for t in c})
review = ['# 规则分类与复核', '', '> 这是只读分析，不会改变 `花花最终版.conf` 的顺序或内容。', '']
review += ['## 策略 × 类型矩阵', '']
review.append('| 策略 | ' + ' | '.join(f'`{t}`' for t in all_types) + ' | 合计 |')
review.append('|---|' + '|'.join(['---:'] * (len(all_types) + 1)) + '|')
for policy, counts in sorted(matrix.items(), key=lambda kv: -sum(kv[1].values())):
    vals = [counts[t] for t in all_types]
    review.append('| `' + policy.replace('|', '\\|') + '` | ' + ' | '.join(f'{v:,}' for v in vals) + f' | {sum(vals):,} |')
review += ['', '## 顺序特征', '', f'- 有效规则：{len(rule_lines):,}', f'- 按连续策略计算的策略区块：{policy_blocks:,}', '- Shadowrocket 按顺序匹配；如果把所有 DIRECT / REJECT / PROXY 直接物理重排，可能改变先匹配到哪条规则。', '']

dup_items = [(line, count) for line, count in duplicates.items() if count > 1]
dup_items.sort(key=lambda x: (-x[1], x[0]))
review += ['## 完全重复规则（前 30）', '']
if not dup_items:
    review.append('未发现完全重复。')
else:
    for line, count in dup_items[:30]:
        shown = line if len(line) <= 220 else line[:217] + '...'
        shown = shown.replace('`', '\\`')
        review.append(f'- ×{count}: `{shown}`')
review.append('')

conflicts = [(key, policies) for key, policies in semantic.items() if len(policies) > 1]
conflicts.sort(key=lambda x: (x[0][0], x[0][1]))
review += ['## 候选策略冲突', '']
if not conflicts:
    review.append('未发现简单规则的同条件多策略候选冲突。')
else:
    review.append('> “候选”不等于一定是错误；这里把同一种简单匹配条件指向多个策略的情况列出来，需结合原始顺序判断。')
    review.append('')
    for (kind, body), policies in conflicts:
        key_text = ','.join((kind, *body)).replace('`', '\\`')
        pol_text = ', '.join(f'`{p}`' for p in sorted(policies))
        review.append(f'- `{key_text}` → {pol_text}')
review.append('')

(OUT / 'RULES-REVIEW.md').write_text('\n'.join(review) + '\n', encoding='utf-8')
print(f'Wrote deep review: {len(rule_lines):,} rules, {len(dup_items)} duplicate keys, {len(conflicts)} conflict candidates, {policy_blocks} policy blocks')
