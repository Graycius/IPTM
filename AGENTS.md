# IPTM — Agent context (5.30.12)

DietPi/Debian firewall, DNS and QoS manager written in PHP, Python, Bash and JavaScript. IPTM prioritizes iptables and Linux `tc`. Squid / transparent proxy functionality was removed in 5.30.12. Never reintroduce it without an explicit user request.

- Preserve active SSH and LAN connectivity during changes, with tested rollback.
- Never widen `FORWARD DROP` or remove IoT or DNS/DoT rules implicitly.
- DNS redirection and DoT policies are preserved when editing drafts; removal requires explicit user choice.
- Only add `-i` interfaces and anti-spoofing when the topology is verified; do not infer WAN from bond0 or wg0.
- No privileged effects in offline tests.
- Do not turn empty interface, malformed CIDR, or invalid state into wildcard firewall rules.
- Keep HTTP native updates with independently trusted SHA-256 and strict package/manifest verification.
- Prefer lightweight CAKE/fq_codel and measured DNS improvements over new proxies.
