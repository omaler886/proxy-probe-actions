# -*- coding: utf-8 -*-
"""Multi-source egress geolocation: country / ASN (number + brand) / city.

Root causes this module replaces (all three were visible in production):

  * ``_org_short()`` kept the FIRST word of the org string, so
    "Hong Kong Broadband Network Ltd." became ``Hong`` and, combined with the
    city "Hong Kong", produced ``香港-Hong-Hong``. Organization names are now
    resolved through an ASN table first, and generic words (Hong, Kong,
    Telecom, Network, ...) can never be selected as a brand.
  * ASN numbers never reached the name and the only ASN source was a single
    optional HTTP API. ASN is now authoritative from Team Cymru
    (``origin.asn.cymru.com`` / ``origin6`` TXT over DoH: no API key, no
    per-IP quota, IPv4 **and** IPv6 coverage), with ip-api ``asname`` and
    ipwho as fallbacks.
  * Country is a majority vote over trace(CF) / ip-api / ipwho. Team Cymru
    deliberately does NOT vote on country: its TXT record reports the RIR
    registry country, not where the address is used, so it calls an AWS
    Sydney egress "US" (AS16509 is registered in the United States). Cymru
    supplies the ASN only, which is exactly what its data is good for.

Design rules:
  * Offline by default (``PROBE_GEO_LOOKUP`` unset): no network at all, names
    degrade to ``cc + Unknown`` and unit tests stay deterministic.
  * A failing source degrades that field only; it never blocks renaming.
  * Every lookup is cached per exit IP, so one exit costs one Cymru query.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

COUNTRY_ZH = {
    "HK": "香港", "TW": "台湾", "MO": "澳门", "CN": "中国", "JP": "日本", "KR": "韩国",
    "SG": "新加坡", "MY": "马来西亚", "TH": "泰国", "VN": "越南", "PH": "菲律宾",
    "ID": "印度尼西亚", "IN": "印度", "PK": "巴基斯坦", "BD": "孟加拉", "LK": "斯里兰卡",
    "KH": "柬埔寨", "LA": "老挝", "MM": "缅甸", "NP": "尼泊尔", "MN": "蒙古",
    "KZ": "哈萨克斯坦", "AE": "阿联酋", "SA": "沙特阿拉伯", "IL": "以色列", "TR": "土耳其",
    "QA": "卡塔尔", "KW": "科威特", "BH": "巴林", "OM": "阿曼", "JO": "约旦",
    "IR": "伊朗", "IQ": "伊拉克", "US": "美国", "CA": "加拿大", "MX": "墨西哥",
    "BR": "巴西", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁",
    "VE": "委内瑞拉", "EC": "厄瓜多尔", "UY": "乌拉圭", "PY": "巴拉圭",
    "GB": "英国", "IE": "爱尔兰", "FR": "法国", "DE": "德国", "NL": "荷兰",
    "BE": "比利时", "LU": "卢森堡", "CH": "瑞士", "AT": "奥地利", "IT": "意大利",
    "ES": "西班牙", "PT": "葡萄牙", "SE": "瑞典", "NO": "挪威", "DK": "丹麦",
    "FI": "芬兰", "IS": "冰岛", "PL": "波兰", "CZ": "捷克", "SK": "斯洛伐克",
    "HU": "匈牙利", "RO": "罗马尼亚", "BG": "保加利亚", "GR": "希腊", "HR": "克罗地亚",
    "SI": "斯洛文尼亚", "RS": "塞尔维亚", "UA": "乌克兰", "RU": "俄罗斯",
    "BY": "白俄罗斯", "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚",
    "MD": "摩尔多瓦", "AL": "阿尔巴尼亚", "MT": "马耳他", "CY": "塞浦路斯",
    "AU": "澳大利亚", "NZ": "新西兰", "ZA": "南非", "EG": "埃及", "NG": "尼日利亚",
    "KE": "肯尼亚", "MA": "摩洛哥", "TN": "突尼斯", "DZ": "阿尔及利亚",
    "GH": "加纳", "ET": "埃塞俄比亚", "SC": "塞舌尔", "MU": "毛里求斯",
    "GI": "直布罗陀", "PR": "波多黎各", "PA": "巴拿马", "CR": "哥斯达黎加",
}

# ASN -> brand. A hit here bypasses _org_brand(), so truncation cannot happen.
ASN_SHORT = {
    13335: "Cloudflare", 209242: "Cloudflare", 395747: "Cloudflare",
    2914: "NTT", 4760: "HKT", 3462: "HiNet", 16509: "AWS", 15169: "Google",
    8075: "Microsoft", 6939: "HE", 24940: "Hetzner", 14061: "DigitalOcean",
    16276: "OVH", 12876: "Scaleway", 212238: "Datacamp", 60068: "Datacamp",
    135377: "UCLOUD", 30088: "GTHost", 63023: "GTHost", 47172: "Greenhost",
    49453: "GlobalLayer", 9009: "M247", 51167: "Contabo", 197540: "Netcup",
    20473: "Vultr", 63949: "Linode", 20454: "Kaopu", 62874: "Kaopu",
    45102: "Alibaba", 37963: "Alibaba", 132203: "Tencent", 45090: "Tencent",
    4134: "Chinanet", 4812: "Chinanet", 23724: "Chinanet", 4837: "Unicom",
    4808: "Unicom", 9929: "Unicom", 17816: "Unicom", 9808: "ChinaMobile",
    58466: "ChinaMobile", 56040: "ChinaMobile", 56041: "ChinaMobile",
    24400: "ChinaMobile", 55990: "HuaweiCloud", 136907: "HuaweiCloud",
    131642: "Pittqiao", 215439: "Play2Go", 55933: "Cloudie", 40065: "CNServers",
    53667: "FranTech", 40676: "Psychz", 29802: "Hivelocity", 46844: "Sharktech",
    174: "Cogent", 54600: "Cogent", 7018: "AT&T", 20115: "Charter",
    11426: "Spectrum", 6128: "Altice", 9321: "Vero", 17539: "HKBN",
    9269: "HKBN", 9500: "HKBN", 4515: "PCCW", 3491: "PCCW", 9925: "PCCW",
    9381: "HKBN", 9908: "i-CABLE", 3786: "HGC", 10103: "HKBN",
}

CITY_ZH = {
    "Hong Kong": "香港", "Taipei": "台北", "New Taipei": "新北", "Tokyo": "东京",
    "Osaka": "大阪", "Seoul": "首尔", "Incheon": "仁川", "Busan": "釜山",
    "Singapore": "新加坡", "Bangkok": "曼谷", "Kuala Lumpur": "吉隆坡",
    "Jakarta": "雅加达", "Manila": "马尼拉", "Hanoi": "河内",
    "Ho Chi Minh City": "胡志明市", "Los Angeles": "洛杉矶", "San Jose": "圣何塞",
    "San Francisco": "旧金山", "Seattle": "西雅图", "New York": "纽约",
    "Dallas": "达拉斯", "Chicago": "芝加哥", "Miami": "迈阿密",
    "Toronto": "多伦多", "Vancouver": "温哥华", "London": "伦敦",
    "Frankfurt am Main": "法兰克福", "Paris": "巴黎", "Amsterdam": "阿姆斯特丹",
    "Zurich": "苏黎世", "Sydney": "悉尼", "Melbourne": "墨尔本",
    "Sao Paulo": "圣保罗", "Moscow": "莫斯科", "Istanbul": "伊斯坦布尔",
    "Dubai": "迪拜", "Mumbai": "孟买", "Taipei City": "台北",
}

# Words that are never a brand on their own (they describe geography or a role).
_GENERIC = {
    "korea", "china", "japan", "hong", "kong", "taiwan", "singapore", "asia",
    "pacific", "global", "international", "united", "states", "new", "the",
    "telecom", "telecommunications", "telecommunication", "network", "networks",
    "broadband", "technology", "technologies", "communication",
    "communications", "digital", "internet", "data", "online", "cloud",
    "hosting", "server", "servers", "limited", "company",
}

_LEGAL = re.compile(
    r"(?i)\b(inc|llc|ltd|limited|corp|corporation|co|company|gmbh|sarl|plc|"
    r"group|holdings|enterprises|solutions|services|telecom|telecommunications|"
    r"networks?|technologies|technology)\b")

# RIR / registry handle noise: HKBN-AS-AP, HKBNES-AS-AP, CLOUDFLARENET-...
_RIR_SUF = re.compile(
    r"(?:[-_](?:AS|ASN))?(?:[-_](?:AP|EU|US|ARIN|RIPE|APNIC|LACNIC|AFRINIC))+$"
    r"|[-_](?:NET|COM|ORG|INFO|BIZ)$", re.I)

_CYMRU_DOH = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://doh.opendns.com/dns-query",
)

LOOKUP_ON = os.environ.get("PROBE_GEO_LOOKUP", "0") == "1"
IPWHO_BUDGET = int(os.environ.get("PROBE_IPWHO_BUDGET", "600"))
_TIMEOUT = float(os.environ.get("PROBE_GEO_TIMEOUT", "6"))


def _flag(cc):
    cc = (cc or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


# ip-api/ipwho return Traditional for HK/TW districts. Product names are
# Simplified elsewhere, so these are transliterated. Only characters that
# actually appear in place names are mapped; anything else passes through.
_T2S = str.maketrans({
    "環": "环", "觀": "观", "灣": "湾", "區": "区", "門": "门", "龍": "龙", "馬": "马", "黃": "黄",
    "鑽": "钻", "頭": "头", "藍": "蓝", "將": "将", "軍": "军", "嶺": "岭", "錦": "锦", "羅": "罗",
    "貢": "贡", "離": "离", "島": "岛", "東": "东", "臺": "台", "縣": "县", "鄉": "乡", "鎮": "镇",
    "莊": "庄", "園": "园", "樓": "楼", "圍": "围", "徑": "径", "篤": "笃", "鰂": "鲗", "魚": "鱼",
    "銅": "铜", "鑼": "锣", "紅": "红", "湧": "涌", "硤": "硖", "轆": "辘", "欖": "榄", "蠔": "蚝",
    "貝": "贝", "崗": "岗", "長": "长", "邊": "边", "華": "华", "僑": "侨", "國": "国", "際": "际",
    "電": "电", "訊": "讯", "網": "网", "絡": "络", "數": "数", "據": "据", "雲": "云", "機": "机",
    "廠": "厂", "維": "维", "亞": "亚", "聖": "圣", "爾": "尔", "薩": "萨", "蘭": "兰", "釗": "钊",
    "賓": "宾", "蘇": "苏", "聯": "联", "體": "体", "歐": "欧", "義": "义", "達": "达", "魯": "鲁",
    "賽": "赛", "萬": "万", "圖": "图", "盧": "卢", "茲": "兹", "漢": "汉", "諾": "诺", "麥": "麦",
    "倫": "伦", "納": "纳", "庫": "库", "頁": "页", "熱": "热", "內": "内", "濃": "浓", "紐": "纽",
    "約": "约", "頓": "顿", "喬": "乔", "鳳": "凤",
})


def t2s(text):
    """Traditional -> Simplified for place names (best effort, never raises)."""
    return (text or "").translate(_T2S)


def _doh_json(base, name):
    url = base + "?" + urllib.parse.urlencode({"name": name, "type": "TXT"})
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def cymru_asn_cc(ip):
    """Team Cymru origin ASN lookup over DoH TXT -> (asn, cc). IPv4 and IPv6.

    Reply format: "4760 | 203.198.0.0/20 | HK | apnic | 1999-05-20".
    """
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return 0, ""
    if addr.version == 4:
        name = addr.reverse_pointer.removesuffix(".in-addr.arpa") + ".origin.asn.cymru.com"
    else:
        name = addr.reverse_pointer.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"
    for base in _CYMRU_DOH:
        try:
            doc = _doh_json(base, name)
        except Exception:
            continue
        for answer in doc.get("Answer", []) or []:
            txt = (answer.get("data") or "").strip().strip('"')
            parts = [part.strip() for part in txt.split("|")]
            if len(parts) < 3 or not parts[0].isdigit():
                continue
            cc = parts[2].upper()
            return int(parts[0]), (cc if len(cc) == 2 and cc.isalpha() else "")
    return 0, ""


def _ipapi_batch(ips):
    """ip-api batch (zh-CN) -> {ip: {cc, city, region, asn, asname}}."""
    out = {}
    ips = sorted({ip for ip in ips if ip})
    for start in range(0, len(ips), 100):
        chunk = ips[start:start + 100]
        body = json.dumps([{"query": ip} for ip in chunk]).encode()
        data = None
        for _ in range(2):
            try:
                req = urllib.request.Request(
                    "http://ip-api.com/batch?fields=query,country,countryCode,"
                    "regionName,city,as,asname&lang=zh-CN",
                    data=body, headers={"Content-Type": "application/json"})
                data = json.loads(urllib.request.urlopen(req, timeout=20).read())
                break
            except Exception:
                time.sleep(1)
        for item in data or []:
            query = item.get("query")
            if not query:
                continue
            match = re.match(r"AS(\d+)", item.get("as") or "")
            out[query] = {
                "cc": (item.get("countryCode") or "").upper(),
                "city": item.get("city") or "",
                "region": item.get("regionName") or "",
                "asn": int(match.group(1)) if match else 0,
                "asname": item.get("asname") or "",
            }
    return out


def _ipwho(ip):
    """ipwho.is single IP -> {cc, city, region, country, asn, org} | None."""
    try:
        url = "https://ipwho.is/" + urllib.parse.quote(str(ip), safe="")
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
        if data.get("success") is False:
            return None
        conn = data.get("connection") or {}
        try:
            asn = int(conn.get("asn") or 0)
        except (TypeError, ValueError):
            asn = 0
        return {
            "cc": (data.get("country_code") or "").upper(),
            "city": data.get("city") or "",
            "region": data.get("region") or "",
            "zone": data.get("district") or data.get("zone") or "",
            "country": data.get("country") or "",
            "asn": asn,
            "org": (conn.get("org") or conn.get("isp") or "").strip(),
        }
    except Exception:
        return None


def _org_brand(raw, asn=0):
    """Brand token for an ASN. The ASN table wins; generics are never returned.

    "Hong Kong Broadband Network Ltd." with no table hit yields ``HKBN``-style
    handles only if a real handle word exists; otherwise the second meaningful
    word, and as the last resort the ASN number. ``Hong`` can never come out.
    """
    if asn and asn in ASN_SHORT:
        return ASN_SHORT[asn]
    text = (raw or "").strip()
    if not text:
        return ""
    text = _LEGAL.sub(" ", text)
    text = re.sub(r"[^A-Za-z0-9& -]", " ", text)
    words = [word for word in text.split() if word]
    if not words:
        return ""
    meaningful = [word for word in words
                  if word.lower() not in _GENERIC and len(word) > 1]
    if meaningful:
        brand = _RIR_SUF.sub("", meaningful[0]).strip(" -&") or meaningful[0]
        if brand.lower() not in _GENERIC and len(brand) > 2:
            return brand[:20]
        if brand.lower() not in _GENERIC:
            return brand[:20]
    # Every word was generic ("Hong Kong Broadband Network", "Korea Telecom").
    # Returning "" makes the caller fall back to the AS number, which is honest;
    # emitting "Hong" or "Korea" as if it were a brand is exactly the old bug.
    return ""


def _majority(votes):
    """Majority vote with a fixed authority order: ip-api > ipwho > trace.

    Two votes always beat one, so a stale trace or a blocked ip-api cannot flip
    a country on its own; a full tie falls back to the listed order.
    """
    votes = [(src, cc) for src, cc in votes if cc]
    if not votes:
        return ""
    counts, first = {}, {}
    for index, (_src, cc) in enumerate(votes):
        counts[cc] = counts.get(cc, 0) + 1
        first.setdefault(cc, index)
    return max(counts.items(), key=lambda kv: (kv[1], -first[kv[0]]))[0]


def _blank(cc=""):
    return {"cc": (cc or "").upper(), "asn": 0, "org": "", "city": "",
            "region": "", "zone": "", "country": ""}


# --------------------------------------------------------------- local ASN DB
# A network API is never a complete ASN source: ip-api rate-limits after 45
# requests/min, ipwho drops unusual ranges, and both can be blocked from a
# runner. DB-IP ASN lite ships ~485k IPv4 + ~76k IPv6 ranges as a plain CSV
# (CC-BY, refreshed monthly), so it answers instantly, offline, for both
# families. It only supplies ASN number and organization.
class AsnDb:
    """"start,end,asn,org" CSV (plain or .gz), binary-searched by range."""

    def __init__(self, path):
        self.path = path
        self.v4_starts = None
        self.v4_ends = None
        self.v4_asn = None
        self.v4_org = None
        self.v6 = None
        self.loaded = False
        self.error = ""

    def _open(self):
        if not self.path or not os.path.isfile(self.path):
            self.error = "missing"
            return None
        if self.path.lower().endswith(".gz"):
            import gzip
            return gzip.open(self.path, "rt", encoding="utf-8", errors="replace")
        return open(self.path, encoding="utf-8", errors="replace")

    def load(self):
        if self.loaded or self.error:
            return self
        handle = self._open()
        if handle is None:
            return self
        v4 = []
        v6 = []
        try:
            with handle as stream:
                for line in stream:
                    parts = line.rstrip("\n").split(",", 3)
                    if len(parts) < 3:
                        continue
                    start, end, asn = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    org = parts[3].strip().strip('"') if len(parts) > 3 else ""
                    if not asn.isdigit():
                        continue
                    try:
                        lo = ipaddress.ip_address(start)
                        hi = ipaddress.ip_address(end)
                    except ValueError:
                        continue
                    if lo.version != hi.version:
                        continue
                    row = (int(lo), int(hi), int(asn), org)
                    (v4 if lo.version == 4 else v6).append(row)
        except Exception as exc:                      # corrupt/partial file
            self.error = type(exc).__name__
            return self
        from array import array
        v4.sort()
        self.v4_starts = array("Q", (row[0] for row in v4))
        self.v4_ends = array("Q", (row[1] for row in v4))
        self.v4_asn = array("I", (row[2] for row in v4))
        self.v4_org = [row[3] for row in v4]
        v6.sort()
        self.v6 = v6
        self.loaded = True
        return self

    def lookup(self, ip):
        """-> (asn, org). (0, "") when the address is not in the database."""
        if not self.loaded:
            return 0, ""
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return 0, ""
        value = int(addr)
        if addr.version == 4:
            if self.v4_starts is None or not len(self.v4_starts):
                return 0, ""
            import bisect
            index = bisect.bisect_right(self.v4_starts, value) - 1
            if index >= 0 and value <= self.v4_ends[index]:
                return int(self.v4_asn[index]), self.v4_org[index]
            return 0, ""
        lo, hi = 0, len(self.v6 or []) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, asn, org = self.v6[mid]
            if value < start:
                hi = mid - 1
            elif value > end:
                lo = mid + 1
            else:
                return asn, org
        return 0, ""


ASN_DB_PATH = os.environ.get("PROBE_ASN_CSV", "").strip()
_ASN_DB = AsnDb(ASN_DB_PATH)


def _ASN_DB_PATH_WANTED():
    """The local database is optional: an unset path simply means no offline layer."""
    return bool(_ASN_DB.path)


def asn_db_status():
    """Small diagnostic used by the workflow log (no paths, no secrets)."""
    return {"loaded": _ASN_DB.loaded, "v4": len(_ASN_DB.v4_starts or []),
            "v6": len(_ASN_DB.v6 or []), "error": _ASN_DB.error}


class Resolver:
    """Per-exit-IP geolocation cache. One exit costs one lookup set."""

    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def clear(self):
        with self._lock:
            self._cache.clear()

    def prefetch(self, items):
        """items: [(exit_ip, fallback_cc)]. Missing/failed lookups degrade only."""
        wanted = {}
        for ip, cc in items:
            if ip and ip not in self._cache:
                wanted[ip] = cc
        if not wanted:
            return
        with self._lock:
            for ip, cc in wanted.items():
                self._cache[ip] = _blank(cc)
        if not LOOKUP_ON:
            return
        ips = list(wanted)
        local = {}
        if _ASN_DB_PATH_WANTED():
            _ASN_DB.load()
            for ip in ips:
                hit = _ASN_DB.lookup(ip)
                if hit[0]:
                    local[ip] = hit
        cymru, ipapi, ipwho = {}, {}, {}

        def _cy(ip):
            return ip, cymru_asn_cc(ip)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
            for ip, result in pool.map(_cy, ips):
                if result and (result[0] or result[1]):
                    cymru[ip] = result
        try:
            ipapi = _ipapi_batch(ips)
        except Exception:
            ipapi = {}
        remaining = [min(IPWHO_BUDGET, len(ips))]

        def _who(ip):
            if remaining[0] <= 0:
                return ip, None
            remaining[0] -= 1
            return ip, _ipwho(ip)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(ips))) as pool:
            for ip, result in pool.map(_who, ips):
                if result:
                    ipwho[ip] = result
        with self._lock:
            for ip in ips:
                entry = self._cache.setdefault(ip, _blank())
                fallback = wanted.get(ip, "")
                cy_asn, cy_cc = cymru.get(ip, (0, ""))
                db_asn, db_org = local.get(ip, (0, ""))
                pa, wh = ipapi.get(ip, {}), ipwho.get(ip, {})
                # Cymru is RIR-authoritative; the local monthly dump is the
                # offline fallback and also covers IPv6 that a blocked DoH
                # endpoint would otherwise lose.
                entry["asn"] = (cy_asn or db_asn or pa.get("asn")
                                or wh.get("asn") or 0)
                entry["cc"] = _majority([("trace", (fallback or "").upper()),
                                         ("ipapi", pa.get("cc")),
                                         ("ipwho", wh.get("cc"))])
                entry["org"] = _org_brand(pa.get("asname") or wh.get("org") or "",
                                          entry["asn"])
                entry["city"] = (pa.get("city")
                                 or CITY_ZH.get(wh.get("city", ""), "")
                                 or wh.get("city", ""))
                entry["region"] = pa.get("region") or wh.get("region") or ""
                entry["zone"] = wh.get("zone") or wh.get("district") or ""
                entry["country"] = wh.get("country") or ""

    def entry(self, ip, fallback_cc=""):
        with self._lock:
            value = self._cache.get(ip)
        return dict(value) if value else _blank(fallback_cc)

    def display(self, ip, fallback_cc=""):
        """``flag+country-brand-city``. Never emits Unknown-Unknown chains."""
        return self.display_parts(ip, fallback_cc)[0]

    def display_parts(self, ip, fallback_cc=""):
        """Candidate display names, most specific first.

        The list exists because one country/brand/city triple can cover many
        distinct exits (several AWS regions inside one city, several HK
        districts inside "Hong Kong"). Each extra candidate adds one more
        geographic level, so names stay human readable instead of degrading
        into ``-2``/``-3`` counters.
        """
        geo = self.entry(ip, fallback_cc)
        cc = geo["cc"] or (fallback_cc or "").upper()
        country = COUNTRY_ZH.get(cc) or geo.get("country") or cc or "未知"
        head = _flag(cc) + t2s(country)
        brand = geo["org"] or (("AS" + str(geo["asn"])) if geo["asn"] else "Unknown")
        city = t2s((geo["city"] or "").strip())
        region = t2s((geo["region"] or "").strip())
        zone = t2s((geo.get("zone") or "").strip())
        parts = []
        if city and city != country:
            parts.append(head + "-" + brand + "-" + city[:20])
            if region and region != city and region != country:
                parts.append(head + "-" + brand + "-" + city[:20] + "-" + region[:20])
        # A city alone often covers an entire metro area (Sydney, Ashburn). The
        # next level is the coarse district/zone inside it, which is what
        # separates two exits of the same provider inside one city. It is a
        # BETTER discriminator than the region, so it goes before the region.
        if zone and zone != city and zone != country:
            if city and city != country:
                parts.append(head + "-" + brand + "-" + city[:20] + "-" + zone[:20])
            else:
                parts.append(head + "-" + brand + "-" + zone[:20])
        if region and region != country:
            parts.append(head + "-" + brand + "-" + region[:20])
        parts.append(head + "-" + brand)
        # Deduplicate while preserving order.
        out = []
        for value in parts:
            if value and value not in out:
                out.append(value)
        return out


RESOLVER = Resolver()


def prefetch(items):
    RESOLVER.prefetch(items)


def display_name(ip, fallback_cc=""):
    return RESOLVER.display(ip, fallback_cc)