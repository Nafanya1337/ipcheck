# ipcheck

[English](README.md) | [Русский](README.ru.md)

A terminal script that scores an IPv4 address before you buy a VPS or dedicated server. Paste an IP and get a packet path map, a comparison of GeoIP databases and DNS resolvers, a block check, and a total score from 0 to 100.

Built for the task of picking a European location with the lowest latency from Russia, but it works for evaluating any IP.

The script output is in Russian.

## What it checks

| Metric | What is measured | Weight |
|---|---|---|
| Latency | average RTT from mtr (30 packets) | 18 |
| Packet loss | loss on the last hop | 12 |
| Jitter | StDev from mtr | 6 |
| TCP | connect time to ports 443, 80, 22 | 6 |
| Route | number of hops to the target | 5 |
| PTR | reverse DNS from 5 resolvers (system, Cloudflare, Google, Quad9, Yandex) | 5 |
| Location / AS | country and AS by majority of GeoIP databases | 8 |
| GeoIP agreement | country match across 5 services | 10 |
| Spam lists | Spamhaus, SpamCop, Barracuda, UCEPROTECT | 5 |
| Blocks (Roskomnadzor) | cheburcheck.ru, antifilter, CDN lists | 25 |

If the IP is found in block lists, the total score is capped at 40.

The report has four parts: a packet path map with the ASN of every hop and AS boundaries, a table of answers from five GeoIP services (ip-api, ipinfo, ipwho.is, ipapi.co, geojs), a PTR table by resolver, and a final table with scores.

## Requirements

Python 3.8+ and root privileges. No third-party Python libraries. The script asks for sudo by itself and installs mtr via apt, dnf, yum, apk, pacman, zypper or brew.

## Usage

```bash
git clone https://github.com/Nafanya1337/ipcheck.git
cd ipcheck
python3 check.py
```

Then paste an IP. You can also pass several addresses as arguments, and a ranking will be printed at the end:

```bash
python3 check.py ip1 ip2 ip3
```

The `--debug` flag prints the text returned by cheburcheck.ru. Use it to adjust page parsing if the service changes its layout.

For a fair result, run the script from the machine that will actually send the traffic, for example your Russian relay node, not from a home connection. It is better to measure from several points and at different times of day.

## Configuration

Metric weights are in the `W` dictionary at the top of the file, latency, loss and jitter thresholds are in `LAT`, `LOSS`, `JIT`. The score cap for blocked addresses is `BLOCKED_CAP`.

## How the block check works

cheburcheck.ru has no JSON API, so the script requests the `/check?target=IP` page and parses the visible text for key phrases. In parallel the IP is checked against the open lists from antifilter.download and cdn-ip-ranges, cached for 6 hours in `/tmp/ipcheck-cache`. If the sources disagree, the metric gets 50 points and a "discrepancy" note.

## Privacy

The checked IP is sent to external services: ip-api.com, ipinfo.io, ipwho.is, ipapi.co, geojs.io and cheburcheck.ru (which stores queries). Your public IP and the IPs of route hops are sent to ip-api.com. Public DNS resolvers receive PTR queries. Keep this in mind if you check addresses you do not want to expose.

## Limitations

IPv4 only. Free APIs have rate limits, so with frequent runs some ASN or GeoIP data may be missing. Metrics that could not be measured are marked n/a and excluded from the total. The score is an estimate, not a guarantee, so confirm the final choice with a trial plan.

## License

MIT
