# Honeypot Analysis

## Summary of Observed Attacks

The SSH honeypot observed multiple unauthorized access attempts originating from the same source IP during the testing period. Attackers attempted to authenticate using common and default usernames such as `root`, `admin`, and `test`, often paired with weak or minimal passwords. Several sessions were short in duration, indicating automated or scripted login attempts, while one longer session demonstrated interactive attacker behavior after successful authentication.

The honeypot successfully recorded all authentication attempts, session durations, and attacker interactions, including executed commands and disconnect events.

## Notable Patterns

Several common attack behaviors were identified during analysis: (simulated by me lol)

- **Credential Guessing / Brute Force:** Repeated login attempts using common usernames and weak passwords triggered a brute-force alert, indicating suspicious authentication behavior from the same source IP.
- **Post-Login Reconnaissance:** After gaining access, the attacker executed typical system enumeration commands such as `whoami`, `pwd`, `uname -a`, `id`, and `ls` to gather information about the system.
- **Sensitive File Access Attempts:** The attacker attempted to read sensitive files and directories including `/etc/passwd`, `/etc/shadow`, `/root`, and `/home`, suggesting credential harvesting and data discovery efforts.
- **Privilege Escalation Attempts:** Commands such as `sudo su`, `sudo -l`, and attempts to modify `/etc/passwd` indicate efforts to escalate privileges or establish persistent access.
- **Automated Command Execution:** The use of chained commands suggests automated scanning or scripted attack behavior.

## Recommendations

Based on the observed activity, the following security improvements are recommended:

- Disable password-based SSH authentication in favor of key-based authentication to reduce the risk of brute-force attacks.
- Implement rate limiting or automated blocking for IP addresses exhibiting repeated failed authentication attempts.
- Monitor and alert on post-login commands targeting sensitive files or privilege escalation mechanisms.
- Use honeypots as an early-warning system to detect reconnaissance and intrusion attempts without exposing production services.
- Correlate honeypot logs with centralized monitoring or SIEM systems to improve visibility and incident response.

Check logs for more info. 