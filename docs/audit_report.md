# Passive OSINT Suite - Network Audit (quick)

Date: 2025-09-14

Summary
-------
This audit scans the `modules/` directory for code paths that perform raw sockets, dnspython lookups, or other network calls that do not flow through `OSINTUtils`'s Tor-configured `requests.Session`. Such code can bypass Tor and weaken OPSEC. The report lists findings and recommended remediations.

Findings
--------
- `modules/domain_recon.py`
  - Uses `dns.resolver` (dnspython) in `get_dns_records`, `get_greynoise_info`, and other places.
    - dnspython uses system DNS by default and does not route through the Tor HTTP/SOCKS proxy.
    - Risk: DNS queries leak to the system resolver (non-Tor). Active DNS queries are also an active footprint.
  - Uses `socket.create_connection` + `ssl` in `get_certificate_info` to open a TLS connection and fetch the cert.
    - Risk: This performs a direct TCP connection to the target (bypasses Tor if sockets are not proxied) and is an active operation.

- `modules/ip_intel.py`
  - Uses `socket.gethostbyaddr()` in at least one code path to reverse-resolve an IP.
    - Risk: This is an active DNS call via system resolver.

- `Sublist3r/` (third-party folder)
  - Contains code that performs DNS resolution and raw socket operations. This tool is active by design and has been made opt-in in `install.sh`.

- Other modules
  - Most modules use `OSINTUtils` and route HTTP calls via the Tor-configured `requests.Session`. Those are OK (and many were updated to use `request_with_fallback`).

Recommendations
---------------
1. Treat `domain_recon` and `ip_intel` active features as "opt-in active checks". For OPSEC-sensitive runs, skip or disable functions that use raw DNS/socket calls.

2. Replace dnspython calls with DNS-over-HTTPS (DoH) via `OSINTUtils.request_with_fallback` where passive DNS is acceptable. Example DoH providers (Cloudflare, Google) can be queried via HTTP and will route through Tor when using the session. Note: DoH endpoints may also block Tor; fallback semantics still apply.

3. For certificate info, prefer passive Certificate Transparency (crt.sh) and other CT logs (already used elsewhere). Opening direct TLS connections is active; only enable `get_certificate_info` when operator explicitly allows active checks.

4. Keep third-party active tools (Sublist3r, direct-scanners) opt-in and document the OPSEC implications in README (done).

5. If you need some DNS capability but must keep it over Tor, implement DNS-over-HTTPS in `utils/osint_utils.py` (helper) and call it from modules instead of dnspython. Or, require that fallback/VPN be enabled for active DNS lookups and mark those functions accordingly.

Actionable next steps
---------------------
- Mark `domain_recon.get_dns_records`, `get_certificate_info`, and related functions as active/opt-in in the UI and docs.
- Implement a `utils/osint_utils.py` helper `doh_query(name, type='A')` that calls a DoH endpoint through the Tor session.
- Add warnings in the CLI when the user enables active scans or fallback globally.

If you want, I can now:
- Implement the DoH helper and switch `domain_recon` to use it for passive-friendly DNS (requires careful testing).
- Add UI flags to disable active functions by default and prompt for explicit enable.

---
Audit produced automatically by the suite's code scan.
