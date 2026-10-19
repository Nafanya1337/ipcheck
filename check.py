#!/usr/bin/env python3
import os, sys, re, socket, struct, random, subprocess, shutil, json
import statistics, time, ipaddress
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

os.environ["PATH"] += ":/usr/sbin:/sbin:/usr/local/sbin:/opt/homebrew/sbin:/opt/homebrew/bin"

DEBUG = "--debug" in sys.argv

# Веса метрик (в сумме 100). Меняйте под свои приоритеты.
W = {"latency": 18, "loss": 12, "jitter": 6, "tcp": 6, "route": 5, "rdns": 5,
     "geo": 8, "agree": 10, "dnsbl": 5, "block": 25}

NAMES = {"latency": "Пинг (mtr, avg)", "loss": "Потери пакетов", "jitter": "Джиттер (StDev)",
         "tcp": "TCP 443/80/22", "route": "Маршрут (хопы)", "rdns": "PTR у резолверов",
         "geo": "Локация / AS", "agree": "Согласие гео-баз", "dnsbl": "Спам-списки",
         "block": "Блокировки РКН"}

EUROPE = {"NL", "DE", "FI", "SE", "PL", "FR", "AT", "CH", "GB", "LV", "LT", "EE",
          "CZ", "NO", "DK", "BE", "LU", "IE", "ES", "IT", "RO", "BG", "HU", "SK"}

# Пороги: (лучшее значение, худшее значение). Между ними балл линейный.
LAT = (15, 120)   # мс
LOSS = (0, 5)     # %
JIT = (0.5, 15)   # мс

BLOCKED_CAP = 40  # максимум итогового балла, если блокировка подтверждена

RESOLVERS = [("Система", None), ("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"),
             ("Quad9", "9.9.9.9"), ("Yandex", "77.88.8.8")]

CACHE = "/tmp/ipcheck-cache"
BLOCK_LISTS = [
    ("antifilter ip", "https://antifilter.download/list/ip.lst"),
    ("antifilter subnet", "https://antifilter.download/list/subnet.lst"),
    ("CDN-списки", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/all/all_plain.lst"),
]


# ---------- root и зависимости ----------

def ensure_root():
    if os.name != "posix" or os.geteuid() == 0:
        return
    if shutil.which("sudo"):
        print("Нужен root для установки mtr и ICMP-замеров, запрашиваю sudo...")
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
    print("Запустите скрипт от root: sudo не найден")


def ensure_deps():
    if shutil.which("mtr"):
        return True
    print("mtr не найден, устанавливаю...")
    managers = [
        ("apt-get", [["apt-get", "update", "-qq"], ["apt-get", "install", "-y", "mtr-tiny"]]),
        ("dnf", [["dnf", "install", "-y", "mtr"]]),
        ("yum", [["yum", "install", "-y", "mtr"]]),
        ("apk", [["apk", "add", "mtr"]]),
        ("pacman", [["pacman", "-Sy", "--noconfirm", "mtr"]]),
        ("zypper", [["zypper", "--non-interactive", "install", "mtr"]]),
        ("brew", [["brew", "install", "mtr"]]),
    ]
    for name, cmds in managers:
        if not shutil.which(name):
            continue
        prefix = []
        # brew нельзя запускать от root, поэтому идём от имени обычного пользователя
        if name == "brew" and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
            prefix = ["sudo", "-u", os.environ["SUDO_USER"]]
        for c in cmds:
            subprocess.run(prefix + c)
        break
    ok = bool(shutil.which("mtr"))
    print("mtr установлен" if ok else "Не удалось установить mtr автоматически")
    return ok


# ---------- утилиты ----------

def lin(v, best, worst):
    return max(0.0, min(100.0, 100 * (worst - v) / (worst - best)))


def run(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout + p.stderr
    except Exception as e:
        return str(e)


def http_json(url, data=None, timeout=6):
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "Mozilla/5.0", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def fetch_text(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------- mtr: пинг, потери, джиттер, маршрут ----------

def mtr_run(ip, tcp=False):
    cmd = ["mtr", "-r", "-w", "-n", "-c", "30"]
    cmd += (["-T", "-P", "443"] if tcp else []) + [ip]
    out = run(cmd, 120)
    hops = []
    pat = (r"\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%?\s+(\d+)\s+"
           r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)")
    for line in out.splitlines():
        m = re.match(pat, line)
        if m:
            # хост, потери %, avg, stdev
            hops.append((m.group(2), float(m.group(3)),
                         float(m.group(6)), float(m.group(9))))
    return out, hops


def check_mtr(ip):
    na = ("нет данных", None)
    if not shutil.which("mtr"):
        return ("mtr не найден", None), na, na, na, None, []
    out, hops = mtr_run(ip)
    mode = ""
    if not hops or hops[-1][0] != ip or hops[-1][1] >= 100:
        _, hops2 = mtr_run(ip, tcp=True)
        if hops2 and hops2[-1][0] == ip and hops2[-1][1] < 100:
            hops, mode = hops2, " (TCP)"
    if not hops:
        return (out.strip()[:40] or "mtr не дал результата", None), na, na, na, None, []
    host, loss, avg, stdev = hops[-1]
    n = len(hops)
    if host != ip or loss >= 100:
        return (("нет ответа", None), ("100%", None), na,
                (f"{n} хопов, цель молчит", 50), None, hops)
    return ((f"{avg:.1f} мс{mode}", lin(avg, *LAT)),
            (f"{loss:.0f}%{mode}", lin(loss, *LOSS)),
            (f"{stdev:.1f} мс", lin(stdev, *JIT)),
            (f"{n} хопов", max(20, lin(n, 8, 20))),
            avg, hops)


# ---------- TCP ----------

def check_tcp(ip):
    def probe(port):
        times = []
        for _ in range(5):
            t = time.perf_counter()
            try:
                with socket.create_connection((ip, port), timeout=2):
                    times.append((time.perf_counter() - t) * 1000)
            except OSError:
                pass
        return port, times

    with ThreadPoolExecutor(3) as ex:
        res = [r for r in ex.map(probe, (443, 80, 22)) if r[1]]
    if not res:
        return ("нет открытых портов", 40, None)
    best_ok = max(len(t) for _, t in res)
    txt = ", ".join(f"{p}: {statistics.median(t):.0f} мс" for p, t in res)
    ms = min(statistics.median(t) for _, t in res)
    return (txt, 100 * best_ok / 5, ms)


# ---------- PTR через разные DNS-резолверы ----------

def _read_name(d, off):
    labels, jumped, end, cnt = [], False, None, 0
    while True:
        l = d[off]
        if l & 0xC0 == 0xC0:
            ptr = ((l & 0x3F) << 8) | d[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            cnt += 1
            if cnt > 20:
                raise ValueError("loop")
            continue
        if l == 0:
            off += 1
            break
        labels.append(d[off + 1:off + 1 + l].decode("ascii", "replace"))
        off += 1 + l
    return ".".join(labels), (end if jumped else off)


def dns_ptr(ip, server, timeout=3):
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for p in qname.split("."):
        q += bytes([len(p)]) + p.encode()
    q += b"\x00" + struct.pack(">HH", 12, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        d, _ = s.recvfrom(2048)
    except OSError:
        return None, "таймаут"
    finally:
        s.close()
    try:
        rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", d[:12])
        if rid != tid:
            return None, "ошибка"
        rcode = flags & 0xF
        off = 12
        for _ in range(qd):
            _, off = _read_name(d, off)
            off += 4
        names = []
        for _ in range(an):
            _, off = _read_name(d, off)
            t, _, _, rl = struct.unpack(">HHIH", d[off:off + 10])
            off += 10
            if t == 12:
                n, _ = _read_name(d, off)
                names.append(n)
            off += rl
        if names:
            return names[0], "ok"
        return None, "нет PTR" if rcode in (0, 3) else f"rcode {rcode}"
    except Exception:
        return None, "ошибка"


def check_ptr(ip):
    def one(item):
        name, server = item
        if server is None:
            try:
                return name, socket.gethostbyaddr(ip)[0], "ok"
            except socket.herror:
                return name, None, "нет PTR"
            except OSError:
                return name, None, "ошибка"
        ptr, st = dns_ptr(ip, server)
        return name, ptr, st

    with ThreadPoolExecutor(5) as ex:
        rows = list(ex.map(one, RESOLVERS))
    valid = [r for r in rows if r[2] in ("ok", "нет PTR")]
    if not valid:
        return rows, ("резолверы не ответили", None)
    names = {r[1].lower() for r in valid if r[1]}
    if not names:
        return rows, ("PTR не задан нигде", 40)
    if len(names) == 1 and all(r[1] for r in valid):
        host = next(iter(names))
        try:
            fwd = ip in socket.gethostbyname_ex(host)[2]
        except OSError:
            fwd = False
        return rows, (f"{len(valid)}/{len(valid)} одинаково" + ("" if fwd else ", forward не совпал"),
                      100 if fwd else 80)
    return rows, ("расхождения между резолверами", 60)


# ---------- гео / AS в разных сервисах ----------

def s_ipapi(ip):
    d = http_json(f"http://ip-api.com/json/{ip}?fields=status,countryCode,city,as")
    if d.get("status") != "success":
        raise ValueError
    return d["countryCode"], d.get("city", ""), d.get("as", "")


def s_ipinfo(ip):
    d = http_json(f"https://ipinfo.io/{ip}/json")
    return d["country"], d.get("city", ""), d.get("org", "")


def s_ipwho(ip):
    d = http_json(f"https://ipwho.is/{ip}")
    if not d.get("success"):
        raise ValueError
    c = d.get("connection", {})
    return d["country_code"], d.get("city", ""), f"AS{c.get('asn', '?')} {c.get('org', '')}"


def s_ipapico(ip):
    d = http_json(f"https://ipapi.co/{ip}/json/")
    if d.get("error"):
        raise ValueError
    return d["country_code"], d.get("city", ""), f"{d.get('asn', '')} {d.get('org', '')}"


def s_geojs(ip):
    d = http_json(f"https://get.geojs.io/v1/ip/geo/{ip}.json")
    return (d["country_code"], d.get("city", ""),
            f"AS{d.get('asn', '?')} {d.get('organization_name', '')}")


SERVICES = [("ip-api.com", s_ipapi), ("ipinfo.io", s_ipinfo), ("ipwho.is", s_ipwho),
            ("ipapi.co", s_ipapico), ("geojs.io", s_geojs)]


def geo_all(ip):
    def one(item):
        name, fn = item
        try:
            return name, fn(ip)
        except Exception:
            return name, None

    with ThreadPoolExecutor(5) as ex:
        return list(ex.map(one, SERVICES))


def geo_summary(rows):
    ok = [(n, r) for n, r in rows if r]
    if not ok:
        return ("нет данных", None), ("нет данных", None), None
    cnt = Counter(r[0] for _, r in ok)
    top, k = cnt.most_common(1)[0]
    org = next(r[2] for _, r in ok if r[0] == top)
    geo = (f"{top}, {org[:30]}", 100 if top in EUROPE else 40)
    if len(ok) < 2:
        agree = (f"только {len(ok)} источник", None)
    else:
        agree = (f"{k}/{len(ok)} сервисов: {top}", 100 * k / len(ok))
    return geo, agree, top


# ---------- ASN для хопов и вашего IP ----------

def asn_lookup(ips):
    res = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            data = http_json("http://ip-api.com/batch?fields=status,query,as,countryCode",
                             data=json.dumps(chunk).encode(), timeout=8)
            for d in data:
                if d.get("status") == "success":
                    res[d["query"]] = d.get("as") or "?"
        except Exception:
            pass
    return res


def my_info():
    try:
        d = http_json("http://ip-api.com/json/?fields=status,query,as,city,countryCode")
        if d.get("status") == "success":
            return d["query"], d.get("as", "?"), d.get("city", "")
    except Exception:
        pass
    return "?", "?", ""


# ---------- DNSBL (спам-списки) ----------

def check_dnsbl(ip):
    rev = ".".join(reversed(ip.split(".")))
    zones = ["zen.spamhaus.org", "bl.spamcop.net",
             "b.barracudacentral.org", "dnsbl-1.uceprotect.net"]
    listed, unknown = [], 0
    for z in zones:
        try:
            r = socket.gethostbyname(f"{rev}.{z}")
            if r.startswith("127.255.255."):
                unknown += 1
            else:
                listed.append(z.split(".")[-2])
        except socket.gaierror:
            pass
    if unknown == len(zones):
        return ("проверка недоступна", None)
    if listed:
        return ("в списках: " + ", ".join(listed), max(0, 100 - 40 * len(listed)))
    return ("чисто", 100)


# ---------- блокировки РКН: cheburcheck + локальные списки ----------

def _snippet(text, m):
    return "..." + text[max(0, m.start() - 40): m.end() + 60] + "..."


def check_cheburcheck(ip):
    try:
        html = fetch_text(f"https://cheburcheck.ru/check?target={ip}")
    except Exception:
        return None, "сайт недоступен"
    text = re.sub(r"<(script|style).*?</\1>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).lower()
    if DEBUG:
        print("\n[debug] текст cheburcheck:\n" + text[:1500] + "\n")
    m = re.search(r"не заблокирован|не найден|не обнаружен|не входит в", text)
    if m:
        return False, _snippet(text, m)
    m = re.search(r"\bзаблокирован", text)
    if m:
        return True, _snippet(text, m)
    return None, "вердикт не распознан (запустите с --debug)"


def load_list(name, url, ttl=6 * 3600):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, re.sub(r"\W", "_", name) + ".txt")
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl
    if not fresh:
        try:
            with open(path, "w") as f:
                f.write(fetch_text(url, 60))
        except Exception:
            if not os.path.exists(path):
                return None
    with open(path) as f:
        tokens = f.read().split()
    ips, nets = set(), []
    for t in tokens:
        try:
            if "/" in t and not t.endswith("/32"):
                nets.append(ipaddress.ip_network(t, strict=False))
            else:
                ips.add(int(ipaddress.IPv4Address(t.split("/")[0])))
        except ValueError:
            pass
    if not ips and not nets:
        return None
    return ips, nets


def list_match(ip, data):
    ips, nets = data
    if int(ipaddress.IPv4Address(ip)) in ips:
        return ip
    addr = ipaddress.ip_address(ip)
    for n in nets:
        if addr in n:
            return str(n)
    return None


def check_block(ip):
    results = []  # (источник, True/False/None, пояснение)
    for name, url in BLOCK_LISTS:
        data = load_list(name, url)
        if data is None:
            results.append((name, None, "список не загрузился"))
            continue
        hit = list_match(ip, data)
        size = len(data[0]) + len(data[1])
        results.append((name, hit is not None,
                        f"совпадение: {hit}" if hit else f"{size} записей, совпадений нет"))
    v, note = check_cheburcheck(ip)
    results.append(("cheburcheck.ru", v, note))

    known = [v for _, v, _ in results if v is not None]
    n_true = sum(known)
    blocked = False
    if not known:
        cell = ("нет данных", None)
    elif n_true == 0:
        cell = (f"чисто ({len(known)} ист.)", 100)
    elif n_true >= 2:
        cell = (f"заблокирован: {n_true}/{len(known)} источников", 0)
        blocked = True
    else:
        cell = (f"возможно: {n_true}/{len(known)}, нужна проверка", 50)
    return cell, blocked, results


# ---------- основная оценка ----------

def evaluate(ip):
    with ThreadPoolExecutor(7) as ex:
        fm = ex.submit(check_mtr, ip)
        ft = ex.submit(check_tcp, ip)
        fp = ex.submit(check_ptr, ip)
        fg = ex.submit(geo_all, ip)
        fb = ex.submit(check_dnsbl, ip)
        fk = ex.submit(check_block, ip)
        fy = ex.submit(my_info)
        lat, loss, jit, route, avg, hops = fm.result()
        tcp_txt, tcp_score, tcp_ms = ft.result()
        ptr_rows, rdns = fp.result()
        geo_rows = fg.result()
        dnsbl = fb.result()
        block, blocked, bdetails = fk.result()
        me = fy.result()
    if avg is None and tcp_ms is not None:
        lat = (f"{tcp_ms:.0f} мс (по TCP-коннекту)", lin(tcp_ms, *LAT))
    geo, agree, _ = geo_summary(geo_rows)
    pub = sorted({h[0] for h in hops if is_public(h[0])})
    asn_map = asn_lookup(pub) if pub else {}
    data = {"latency": lat, "loss": loss, "jitter": jit, "tcp": (tcp_txt, tcp_score),
            "route": route, "rdns": rdns, "geo": geo, "agree": agree,
            "dnsbl": dnsbl, "block": block}
    rows = [(k, NAMES[k], data[k][0], data[k][1]) for k in W]
    avail = [(W[k], s) for k, _, _, s in rows if s is not None]
    total = sum(w * s for w, s in avail) / sum(w for w, _ in avail) if avail else 0
    capped = blocked and total > BLOCKED_CAP
    if capped:
        total = BLOCKED_CAP
    return {"rows": rows, "total": total, "capped": capped, "hops": hops,
            "asn": asn_map, "me": me, "geo_rows": geo_rows, "ptr_rows": ptr_rows,
            "block_details": bdetails}


# ---------- вывод ----------

def paint(text, score):
    if not sys.stdout.isatty() or score is None:
        return text
    c = 32 if score >= 80 else 33 if score >= 55 else 31
    return f"\033[{c}m{text}\033[0m"


def verdict(t):
    return ("отлично" if t >= 85 else "хорошо" if t >= 70
            else "средне" if t >= 50 else "плохо")


def asn_token(s):
    return s.split()[0] if s and s.startswith("AS") else None


def show_path(ip, r):
    my_ip, my_as, my_city = r["me"]
    hops, asn_map = r["hops"], r["asn"]
    line = "-" * 92
    print("\nКарта пути пакета (вы -> цель)")
    print(line)
    print(f"{'#':<4}{'IP':<18}{'ASN / организация':<42}{'Потери':>8}{'Avg мс':>9}")
    print(line)
    if not hops:
        print("нет данных (нужен mtr)")
        print(line)
        return
    print(f"{'0':<4}{my_ip:<18}{my_as[:40]:<42}{'':>8}{'':>9}  <- вы ({my_city})")
    prev = asn_token(my_as)
    for i, (host, loss, avg, _) in enumerate(hops, 1):
        if host == "???":
            asn = "нет ответа (хоп скрыт)"
        elif not is_public(host):
            asn = "частная сеть / CGNAT"
        else:
            asn = asn_map.get(host, "?")
        tok = asn_token(asn)
        if tok and prev and tok != prev:
            print(f"    >> граница AS: {prev} -> {tok}")
        if tok:
            prev = tok
        avg_s = f"{avg:.1f}" if host != "???" else "-"
        mark = "  <- цель" if (i == len(hops) and host == ip) else ""
        print(paint(f"{i:<4}{host:<18}{asn[:40]:<42}{loss:>7.0f}%{avg_s:>9}",
                    lin(loss, *LOSS) if host != "???" else None) + mark)
    print(line)


def show_services(r):
    rows = r["geo_rows"]
    _, _, top = geo_summary(rows)
    line = "-" * 92
    print("\nКак сервисы определяют IP (гео / AS)")
    print(line)
    print(f"{'Сервис':<14}{'Страна':<9}{'Город':<20}{'AS / организация'}")
    print(line)
    for name, res in rows:
        if not res:
            print(f"{name:<14}{'нет ответа'}")
            continue
        cc, city, org = res
        bad = top and cc != top
        txt = f"{name:<14}{cc + (' !' if bad else ''):<9}{city[:18]:<20}{org[:44]}"
        print(paint(txt, 30 if bad else 100))
    print("(! = страна отличается от большинства)")
    print(line)


def show_ptr(r):
    line = "-" * 92
    print("\nКак резолверы видят PTR (reverse DNS)")
    print(line)
    print(f"{'Резолвер':<14}{'Статус':<12}{'PTR'}")
    print(line)
    for name, ptr, st in r["ptr_rows"]:
        print(f"{name:<14}{st:<12}{ptr or '-'}")
    print(line)


def show_block(ip, r):
    line = "-" * 92
    print("\nДетали проверки блокировок")
    print(line)
    word = {True: "в блокировке", False: "чисто", None: "нет данных"}
    for name, v, note in r["block_details"]:
        print(f"{name:<20}{word[v]:<14}{note[:56]}")
    print(f"Проверить вручную: https://cheburcheck.ru/check?target={ip}")
    print(line)


def show_metrics(ip, r):
    line = "-" * 100
    print(f"\nИтоговая оценка для {ip}")
    print(line)
    print(f"{'Метрика':<20}{'Результат':<60}{'Балл':>6}{'Вес':>6}")
    print(line)
    for k, name, disp, s in r["rows"]:
        sc = f"{s:.0f}" if s is not None else "n/a"
        print(paint(f"{name:<20}{disp[:58]:<60}{sc:>6}{W[k]:>6}", s))
    print(line)
    print(paint(f"ИТОГО: {r['total']:.0f}/100 ({verdict(r['total'])})", r["total"]))
    if r["capped"]:
        print(f"Балл ограничен {BLOCKED_CAP}: блокировка подтверждена несколькими источниками")
    print("n/a: метрика не измерена и не входит в итог")


def main():
    ensure_root()
    ensure_deps()
    args = [a for a in sys.argv[1:] if a != "--debug"]
    raw = " ".join(args) or input("Вставьте IP (можно несколько через пробел): ")
    results = []
    for ip in [x for x in re.split(r"[\s,;]+", raw.strip()) if x]:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            print(f"{ip}: нужен корректный IPv4")
            continue
        print(f"\nПроверяю {ip} (до 1-2 минут)...")
        r = evaluate(ip)
        show_path(ip, r)
        show_services(r)
        show_ptr(r)
        show_block(ip, r)
        show_metrics(ip, r)
        results.append((ip, r["total"]))
    if len(results) > 1:
        print("\nСравнение:")
        for ip, t in sorted(results, key=lambda x: -x[1]):
            print(f"{ip:<18}{t:.0f}/100")


if __name__ == "__main__":
    main()
