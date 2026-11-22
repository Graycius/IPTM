# IPTM — Agent context

IPTM 5.30.1 is a DietPi/Debian network management app written in PHP 8+, Python 3, Bash and JavaScript, built around iptables and Linux `tc`.

**Non-negotiable constraints**

- Protect existing SSH sessions; do not rate-limit `ESTABLISHED` TCP traffic. Evaluate `NEW` SYN only for SSH brute-force rules.
- Preserve trusted-management access and a working path to restore the previous rules. Never flush live rules or overwrite third-party chains in a test.
- Treat shell/iptables/tc commands as privileged actions requiring strict argument validation, file-ownership checks and exception handling.
- Never turn a missing port alias, empty network, malformed CIDR, missing interface, or parse error into a wildcard `ACCEPT`, `DROP` or NAT rule.
- Do not pretend a user-facing dry-run validates performance or traffic on a production kernel.
- Calibrating CAKE while shaping is active must not trigger large speedtests or rewrite confirmed rates automatically.
- HTTP update is a user requirement; require independently trusted SHA-256 for HTTP and prevent redirect-based SSRF.
- Distinguish features that are implemented from those that depend on a verified qdisc/IFB; Layer7 and process attribution are unimplemented.

**Review priority**: remote lockout > root privilege safety > allowed legitimate traffic > change rollback > performance > UI polish. Review `modules/03_rule_generation.php`, `modules/11_firewall_transaction.php`, `extensions/ssh_continuity.py`, `extensions/qos_engine.py`, `runtime/iptm-helper`, and update/backup code especially carefully.
