#!/usr/bin/env python3
"""
MONSTER_REV v3 — Reverse IP Intelligence Engine
Version: 3.0.0 [github.com/officialmonsterz]
License: Proprietary — Authorized Penetration Testing Use Only

Aggregates reverse DNS/IP data from 7 APIs (Shodan, VirusTotal, SecurityTrails,
IPdata, IP2Location, ViewDNS, WhoisXML), performs port scanning, detects
high-value "gold" targets, and generates comprehensive reports.

Usage:
    Interactive mode:  python monster_rev_v3.py
    CLI mode:          python monster_rev_v3.py --ip 8.8.8.8 [--no-interactive]
"""

import asyncio
import json
import logging
import os
import random
import re
import socket
import sqlite3
import sys
import textwrap
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, List, Dict, Set, Tuple

# ─── Windows Event Loop Fix (BEFORE any other imports) ───
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ─── Logging ────────────────────────────────────────────
_log_format = "%(asctime)s [%(levelname)-8s] %(message)s"
_date_format = "%H:%M:%S"

class ColoredLogFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m", "INFO": "\033[34m", "WARNING": "\033[33m",
        "ERROR": "\033[31m", "CRITICAL": "\033[41m",
        "SUCCESS": "\033[32m", "GOLD": "\033[33;1m", "HEADER": "\033[35;1m", "RESET": "\033[0m",
    }
    def format(self, record):
        level = record.levelname
        color = self.COLORS.get(level, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]
        record.msg = f"{color}{record.msg}{reset}"
        return super().format(record)

log = logging.getLogger("monster_rev")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(ColoredLogFormatter(_log_format, datefmt=_date_format))
log.addHandler(ch)
fh = logging.FileHandler("monster_rev.log", mode="a", encoding="utf-8")
fh.setFormatter(logging.Formatter(_log_format, datefmt=_date_format))
fh.setLevel(logging.DEBUG)
log.addHandler(fh)

def cprint(msg: str, level: str = "INFO") -> None:
    level = level.upper()
    if level in ("SUCCESS", "GOLD", "HEADER"): log.info(msg)
    elif level == "WARNING": log.warning(msg)
    elif level == "ERROR": log.error(msg)
    elif level == "DEBUG": log.debug(msg)
    else: log.info(msg)

# ─── Constants ───────────────────────────────────────────
SCRIPT_NAME = "MONSTER_REV v3"
SCRIPT_VERSION = "3.0.0"

GOLD_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 139, 143, 389, 443,
    445, 465, 500, 514, 587, 593, 636, 993, 995, 1080, 1194, 1352, 1433,
    1434, 1521, 1723, 2049, 2375, 2376, 3128, 3268, 3269, 3306, 3389,
    4333, 4444, 4848, 5000, 5001, 5222, 5432, 5631, 5632, 5800, 5900,
    5901, 5984, 6000, 6001, 6379, 6667, 6689, 6697, 7001, 7002, 7071,
    7199, 8000, 8001, 8080, 8081, 8086, 8089, 8090, 8140, 8181, 8332,
    8333, 8443, 8888, 9000, 9001, 9042, 9090, 9100, 9160, 9200, 9300,
    9418, 9999, 10000, 11211, 11214, 11215, 27017, 27018, 27019, 50070,
    50075, 50090,
]

SVC_MAP = {
    21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
    111:"rpcbind",123:"ntp",135:"msrpc",137:"netbios-ns",139:"netbios-ssn",
    143:"imap",389:"ldap",443:"https",445:"smb",465:"smtps",500:"isakmp",
    514:"syslog",587:"smtp-sub",593:"http-rpc-epmap",636:"ldaps",993:"imaps",
    995:"pop3s",1080:"socks",1194:"openvpn",1352:"lotusnotes",1433:"mssql",
    1434:"mssql-mon",1521:"oracle",1723:"pptp",2049:"nfs",2375:"docker",
    2376:"docker-tls",3128:"squid",3268:"ldap-global",3269:"ldap-global-ssl",
    3306:"mysql",3389:"rdp",4333:"ahsp",4444:"metasploit",4848:"glassfish",
    5000:"upnp",5001:"plex",5222:"xmpp",5432:"postgresql",5631:"pcanywhere",
    5632:"pcanywhere-stat",5800:"vnc-http",5900:"vnc",5901:"vnc-1",
    5984:"couchdb",6000:"x11",6001:"x11-1",6379:"redis",6667:"irc",
    6689:"irc-ssl",6697:"ircs",7001:"weblogic",7002:"weblogic-ssl",
    7071:"zookeeper",7199:"cassandra",8000:"http-alt",8001:"http-alt2",
    8080:"http-proxy",8081:"http-proxy2",8086:"influxdb",8089:"http-alt3",
    8090:"http-alt4",8140:"puppet",8181:"http-alt5",8332:"bitcoin-rpc",
    8333:"bitcoin",8443:"https-alt2",8888:"http-alt6",9000:"http-alt7",
    9001:"http-alt8",9042:"cassandra-native",9090:"http-alt54",
    9100:"jetdirect",9160:"cassandra-thrift",9200:"elasticsearch",
    9300:"elasticsearch-cluster",9418:"git",9999:"http-alt9",
    10000:"webmin",11211:"memcached",11214:"memcached-ssl",
    11215:"memcached-ssl2",27017:"mongodb",27018:"mongodb-shard",
    27019:"mongodb-config",50070:"hadoop-nn",50075:"hadoop-dn",50090:"hadoop-sec",
}

def svc(port: int) -> str:
    return SVC_MAP.get(port, "unknown")

# ─── IP Validation ──────────────────────────────────────
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
def valid_ip(s: str) -> bool:
    return bool(IPV4_RE.match(s.strip()))

# ─── Data Classes ────────────────────────────────────────
@dataclass
class PortResult:
    port: int
    state: str = "closed"
    service: str = ""
    banner: str = ""
    response_time_ms: float = 0.0

@dataclass
class ScanTarget:
    ip: str
    domains: List[str] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    api_results: Dict[str, Any] = field(default_factory=dict)
    gold_score: int = 0
    gold_reasons: List[str] = field(default_factory=list)
    scan_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ─── Configuration ───────────────────────────────────────
class Config:
    """Loads/validates config.json."""
    def __init__(self, path: str = "config.json"):
        self.path = path
        self.data: Dict[str, Any] = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self._create_default()
        with open(self.path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self._validate()
        cprint(f"Config loaded from '{self.path}'", "success")

    def _validate(self):
        apis = self.data.get("apis", {})
        required = ["shodan","virustotal","securitytrails","ipdata","ip2location","viewdns","whoisxml"]
        for r in required:
            if r not in apis:
                cprint(f"Config: missing '{r}' section", "warning")

    def _create_default(self):
        cfg = {
            "apis": {
                "shodan": {"key": ""},
                "virustotal": {"key": ""},
                "securitytrails": {"key": ""},
                "ipdata": {"key": ""},
                "ip2location": {"key": ""},
                "viewdns": {"key": ""},
                "whoisxml": {"key": ""}
            },
            "gold_detection": {
                "enabled": True,
                "min_score": 3,
                "categories": {
                    "database": {"ports": GOLD_PORTS[:15], "weight": 3},
                    "marketplace": {"ports": [443,80,8080,8443,3000,5000,8000,8888,9090,4443], "weight": 2},
                    "secret_storage": {"ports": [22,443,993,995,8443,989,990,636,3268,3269], "weight": 4},
                    "blockchain": {"ports": [8333,8332,18332,18333,30303,30304,8545,8546,4444,46657], "weight": 5},
                    "api_multi_source": {"min_sources": 3, "weight": 2},
                    "vulnerable_services": {"ports": [21,23,3389,5900,5901], "weight": 3}
                }
            },
            "output": {"directory": "results", "format": "json", "detailed_report": True,
                        "save_api_status": True, "save_crack_commands": True},
            "caching": {"enabled": True, "database": "monster_rev_cache.db", "ttl_hours": 24},
            "rate_limiting": {"enabled": True, "max_concurrent": 5, "delay_between_requests_ms": 200,
                             "api_specific": {"shodan":1,"virustotal":4,"securitytrails":1,"ip2location":2,"viewdns":2}},
            "port_scanning": {"enabled": True, "timeout_seconds": 2, "max_threads": 100, "rate_limit": 1000},
            "dns_resolution": {"timeout_seconds": 5, "max_retries": 2}
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)
        cprint(f"Default config created at '{self.path}' — edit it with your API keys.", "success")
        self.data = cfg

    def api_key(self, service: str) -> str:
        apis = self.data.get("apis", {})
        entry = apis.get(service, {})
        if isinstance(entry, dict):
            return entry.get("key", "")
        return ""

    def get(self, key: str, default: Any = None) -> Any:
        parts = key.split(".")
        val = self.data
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
                if val is None:
                    return default
            else:
                return default
        return val

# ─── Cache ───────────────────────────────────────────────
class Cache:
    def __init__(self, db: str = "monster_rev_cache.db", ttl_h: int = 24):
        self.db = db
        self.ttl = ttl_h * 3600
        self.conn: Optional[sqlite3.Connection] = None
        self._init()
    def _init(self):
        try:
            self.conn = sqlite3.connect(self.db, timeout=10)
            self.conn.execute("CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT, ts REAL)")
            self.conn.commit()
        except Exception as e:
            log.warning(f"Cache init failed: {e}")
            self.conn = None
    def get(self, k: str) -> Optional[str]:
        if not self.conn: return None
        try:
            cur = self.conn.execute("SELECT v, ts FROM cache WHERE k = ?", (k,))
            row = cur.fetchone()
            if row and time.time() - row[1] < self.ttl:
                return row[0]
            if row:
                self.conn.execute("DELETE FROM cache WHERE k = ?", (k,))
                self.conn.commit()
            return None
        except: return None
    def set(self, k: str, v: str):
        if not self.conn: return
        try:
            self.conn.execute("INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?, ?, ?)", (k, v, time.time()))
            self.conn.commit()
        except: pass
    def close(self):
        if self.conn:
            try: self.conn.close()
            except: pass
            self.conn = None

# ─── Rate Limiter ────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_conc: int = 5, delay_ms: int = 200, api_specific: Optional[Dict[str,int]] = None):
        self.sem = asyncio.Semaphore(max_conc)
        self.delay = delay_ms / 1000.0
        self.api_spec = api_specific or {}
        self._last: Dict[str, float] = {}
        self._lock = asyncio.Lock()
    async def acquire(self, api: str = "default"):
        await self.sem.acquire()
        d = self.api_spec.get(api, self.delay)
        async with self._lock:
            last = self._last.get(api, 0.0)
            elapsed = time.monotonic() - last
            if elapsed < d:
                await asyncio.sleep(d - elapsed)
            self._last[api] = time.monotonic()
    def release(self):
        self.sem.release()

# ─── Base API Connector ──────────────────────────────────
class BaseConnector:
    def __init__(self, config: Config, rl: RateLimiter, cache: Optional[Cache] = None):
        self.config = config
        self.rl = rl
        self.cache = cache
        self.api_key = ""
        self.api_name = "base"
        self._session: Optional[Any] = None

    async def _session_get(self):
        import aiohttp
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _req(self, url: str, headers: Optional[Dict]=None, params: Optional[Dict]=None,
                   timeout: int = 30, cache_key: Optional[str] = None, method: str = "GET") -> Optional[Dict]:
        if cache_key and self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return json.loads(cached)
        await self.rl.acquire(self.api_name)
        try:
            import aiohttp
            session = await self._session_get()
            kwargs: Dict = {"url": url, "headers": headers or {}, "params": params or {},
                            "timeout": aiohttp.ClientTimeout(total=timeout)}
            async with session.request(method, **kwargs) as resp:
                if resp.status == 429:
                    retry = int(resp.headers.get("Retry-After", "5"))
                    log.debug(f"[{self.api_name}] rate limited, waiting {retry}s")
                    await asyncio.sleep(min(retry, 30))
                    return None
                if resp.status in (403, 204):
                    log.debug(f"[{self.api_name}] HTTP {resp.status}")
                    return None
                if resp.status != 200:
                    log.debug(f"[{self.api_name}] HTTP {resp.status}")
                    return None
                text = await resp.text()
                data = json.loads(text)
                if cache_key and self.cache:
                    self.cache.set(cache_key, text)
                return data
        except asyncio.TimeoutError:
            log.debug(f"[{self.api_name}] timeout")
            return None
        except Exception as e:
            log.debug(f"[{self.api_name}] error: {e}")
            return None
        finally:
            self.rl.release()

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

# ─── API Connectors (7 remaining) ────────────────────────

class ShodanConn(BaseConnector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.api_name = "shodan"
        self.api_key = self.config.api_key("shodan")
    async def lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key: return None
        url = f"https://api.shodan.io/shodan/host/{ip}"
        data = await self._req(url, params={"key": self.api_key}, cache_key=f"shodan:{ip}")
        if not data: return None
        return {"source":"shodan","hostnames":data.get("hostnames",[]),"ports":data.get("ports",[]),
                "vulns":data.get("vulns",[]),"org":data.get("org",""),"country":data.get("country_name",""),
                "domains":data.get("domains",[]),"raw":data}

class VTConn(BaseConnector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.api_name = "virustotal"
        self.api_key = self.config.api_key("virustotal")
    async def lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key: return None
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        data = await self._req(url, headers={"x-apikey": self.api_key}, cache_key=f"virustotal:{ip}")
        if not data: return None
        attr = data.get("data",{}).get("attributes",{})
        resolutions = attr.get("resolutions",[])
        domains = [r.get("hostname","") for r in resolutions if isinstance(r,dict) and r.get("hostname")]
        return {"source":"virustotal","domains":domains,
                "malicious":attr.get("last_analysis_stats",{}).get("malicious",0),
                "suspicious":attr.get("last_analysis_stats",{}).get("suspicious",0),
                "country":attr.get("country",""),"asn":attr.get("asn",""),"org":attr.get("as_owner",""),
                "raw":data}

class STrailsConn(BaseConnector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.api_name = "securitytrails"
        self.api_key = self.config.api_key("securitytrails")
    async def lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key: return None
        url = f"https://api.securitytrails.com/v1/domain/ip/{ip}"
        data = await self._req(url, headers={"APIKEY":self.api_key,"Accept":"application/json"},
                               cache_key=f"st:{ip}")
        if not data: return None
        domains = data.get("domains",[])
        return {"source":"securitytrails","domains":domains,"total":data.get("total",len(domains)),"raw":data}

class IPdataConn(BaseConnector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.api_name = "ipdata"
        self.api_key = self.config.api_key("ipdata")
    async def lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key: return None
        url = f"https://api.ipdata.co/{ip}?api-key={self.api_key}"
        data = await self._req(url, cache_key=f"ipdata:{ip}")
        if not data: return None
        return {"source":"ipdata","country":data.get("country_name",""),"city":data.get("city",""),
                "org":data.get("organization",""),"asn":data.get("asn",""),
                "threat_score":data.get("threat",{}).get("score",0) if isinstance(data.get("threat"),dict) else 0,
                "raw":data}

class IP2LocConn(BaseConnector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.api_name = "ip2location"
        self.api_key = self.config.api_key("ip2location")
    async def lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key: return None
        url = "https://domains.ip2whois.com/domains"
        data = await self._req(url, params={"key":self.api_key,"ip":ip,"format":"json"},
                               cache_key=f"ip2l:{ip}")
        if not data: return None
        domains = data.get("domains",[])
        return {"source":"ip2location","domains":domains,"total":data.get("total_domains",len(domains)),"raw":data}

class ViewDNSConn(BaseConnector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.api_name = "viewdns"
        self.api_key = self.config.api_key("viewdns")
    async def lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key: return None
        url = "https://api.viewdns.info/reverseip/"
        data = await self._req(url, params={"host":ip,"apikey":self.api_key,"output":"json"},
                               cache_key=f"vdns:{ip}")
        if not data: return None
        resp = data.get("response",{})
        domains_raw = resp.get("domains",[])
        domains = [d.get("name","") for d in domains_raw if isinstance(d,dict)]
        return {"source":"viewdns","domains":domains,"total":len(domains),"raw":data}

class WhoisXMLConn(BaseConnector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.api_name = "whoisxml"
        self.api_key = self.config.api_key("whoisxml")
    async def lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key: return None
        url = "https://reverse-ip.whoisxmlapi.com/api/v1"
        data = await self._req(url, params={"apiKey":self.api_key,"ip":ip,"format":"JSON"},
                               cache_key=f"wxml:{ip}")
        if not data: return None
        domains: List[str] = []
        for key in ("domains","domainNames","result","records"):
            items = data.get(key,[])
            if isinstance(items,list):
                for item in items:
                    if isinstance(item,str): domains.append(item)
                    elif isinstance(item,dict):
                        for sk in ("domain","name","domainName"):
                            if sk in item and isinstance(item[sk],str): domains.append(item[sk])
        return {"source":"whoisxml","domains":list(set(domains)),"total":len(set(domains)),"raw":data}

# ─── Port Scanner ────────────────────────────────────────
class PortScanner:
    def __init__(self, config: Config):
        self.timeout = config.get("port_scanning.timeout_seconds", 2)
        self.max_t = config.get("port_scanning.max_threads", 100)
        self.enabled = config.get("port_scanning.enabled", True)
        self.sem = asyncio.Semaphore(self.max_t)

    async def scan_one(self, ip: str, port: int) -> PortResult:
        async with self.sem:
            start = time.monotonic()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
                ms = (time.monotonic() - start) * 1000
                banner = ""
                try:
                    b = await asyncio.wait_for(r.read(1024), timeout=1.0)
                    banner = b.decode("utf-8","replace").strip()[:200]
                except: pass
                w.close()
                try: await w.wait_closed()
                except: pass
                return PortResult(port=port, state="open", service=svc(port), banner=banner, response_time_ms=round(ms,1))
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return PortResult(port=port, state="closed", service=svc(port))

    async def scan(self, ip: str, ports: List[int]) -> List[PortResult]:
        if not self.enabled: return []
        tasks = [self.scan_one(ip, p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = [r for r in results if isinstance(r, PortResult) and r.state == "open"]
        return sorted(open_ports, key=lambda x: x.port)

# ─── Gold Detection Engine ───────────────────────────────
class GoldEngine:
    def __init__(self, config: Config):
        self.enabled = config.get("gold_detection.enabled", True)
        self.min_score = config.get("gold_detection.min_score", 3)
        cats = config.get("gold_detection.categories", {})
        self.port_cats: Dict[int, Tuple[str, int]] = {}
        for cn, cc in cats.items():
            if isinstance(cc, dict):
                for p in cc.get("ports", []):
                    self.port_cats[p] = (cn, cc.get("weight", 1))

    async def evaluate(self, target: ScanTarget) -> ScanTarget:
        if not self.enabled: return target
        score = 0
        reasons: List[str] = []
        # port-based
        for pr in target.ports:
            if pr.port in self.port_cats:
                cn, w = self.port_cats[pr.port]
                score += w
                reasons.append(f"Port {pr.port} ({cn}) w={w}")
        # multi-source
        active = [k for k, v in target.api_results.items() if v]
        cats = self.port_cats  # not needed here, use config access
        # We'll just check via config data pattern
        if len(active) >= 3:
            score += 2
            reasons.append(f"Multi-source ({len(active)} sources) w=2")
        # vulns from shodan
        sh = target.api_results.get("shodan", {})
        if isinstance(sh, dict):
            vulns = sh.get("vulns", [])
            if vulns:
                score += len(vulns) * 2
                reasons.append(f"{len(vulns)} vulns w={len(vulns)*2}")
        # threat from ipdata
        ipd = target.api_results.get("ipdata", {})
        if isinstance(ipd, dict):
            ts = ipd.get("threat_score", 0)
            if ts > 50:
                score += 3
                reasons.append(f"Threat score {ts} w=3")
        # domain richness
        all_doms: Set[str] = set()
        for ad in target.api_results.values():
            if isinstance(ad, dict):
                for k in ("domains","hostnames","names"):
                    vals = ad.get(k,[])
                    if isinstance(vals,list):
                        for v in vals:
                            if isinstance(v,str) and v.strip():
                                all_doms.add(v.strip())
        if len(all_doms) >= 10:
            score += 2
            reasons.append(f"Rich domains ({len(all_doms)}) w=2")
        elif len(all_doms) >= 5:
            score += 1
            reasons.append(f"Moderate domains ({len(all_doms)}) w=1")

        target.gold_score = score
        target.gold_reasons = reasons
        return target

# ─── Main Engine ─────────────────────────────────────────
class ReverseIPEngine:
    def __init__(self, config: Config):
        self.config = config
        self.cache: Optional[Cache] = None
        self.rl: Optional[RateLimiter] = None
        self.scanner: Optional[PortScanner] = None
        self.gold: Optional[GoldEngine] = None
        self.connectors: Dict[str, BaseConnector] = {}
        self.results: Dict[str, ScanTarget] = {}
        self.on_progress: Optional[Any] = None

    async def init(self):
        cprint(f"{SCRIPT_NAME} v{SCRIPT_VERSION} initializing...", "info")
        if self.config.get("caching.enabled", True):
            db = self.config.get("caching.database", "monster_rev_cache.db")
            ttl = self.config.get("caching.ttl_hours", 24)
            self.cache = Cache(db, ttl)
            cprint(f"Cache enabled: {db}", "info")
        mc = self.config.get("rate_limiting.max_concurrent", 5)
        dm = self.config.get("rate_limiting.delay_between_requests_ms", 200)
        asp = self.config.get("rate_limiting.api_specific", {})
        self.rl = RateLimiter(mc, dm, asp)
        self.scanner = PortScanner(self.config)
        self.gold = GoldEngine(self.config)
        # Init 7 connectors
        self.connectors["shodan"] = ShodanConn(self.config, self.rl, self.cache)
        self.connectors["virustotal"] = VTConn(self.config, self.rl, self.cache)
        self.connectors["securitytrails"] = STrailsConn(self.config, self.rl, self.cache)
        self.connectors["ipdata"] = IPdataConn(self.config, self.rl, self.cache)
        self.connectors["ip2location"] = IP2LocConn(self.config, self.rl, self.cache)
        self.connectors["viewdns"] = ViewDNSConn(self.config, self.rl, self.cache)
        self.connectors["whoisxml"] = WhoisXMLConn(self.config, self.rl, self.cache)
        # Check which API keys are configured
        for name, conn in self.connectors.items():
            if conn.api_key:
                cprint(f"  [+] {name}: API key configured", "info")
            else:
                cprint(f"  [-] {name}: NO API key — will be skipped", "warning")
        cprint("Ready.", "success")

    async def scan_ip(self, ip: str, do_port_scan: bool = True, ports: Optional[List[int]] = None) -> ScanTarget:
        target = ScanTarget(ip=ip)
        cprint(f"\n{'='*60}", "header")
        cprint(f"  Scanning: {ip}", "header")
        cprint(f"{'='*60}", "header")

        # API lookups (parallel)
        api_tasks: Dict[str, asyncio.Task] = {}
        for name, conn in self.connectors.items():
            if conn.api_key:
                api_tasks[name] = asyncio.create_task(conn.lookup(ip))
            else:
                api_tasks[name] = asyncio.create_task(asyncio.sleep(0, result=None))

        # Port scan (parallel with APIs)
        scan_task = None
        if do_port_scan:
            if ports is None:
                ports = GOLD_PORTS[:50]  # first 50 gold ports by default
            scan_task = asyncio.create_task(self.scanner.scan(ip, ports))

        # Collect API results as they finish
        api_status: Dict[str, str] = {}
        for name, task in api_tasks.items():
            if not self.connectors[name].api_key:
                api_status[name] = "no_key"
                cprint(f"  [~] {name}: no API key configured, skipped", "debug")
                continue
            try:
                result = await task
                if result:
                    target.api_results[name] = result
                    domains = result.get("domains", result.get("hostnames", []))
                    if isinstance(domains, list):
                        target.domains.extend([d for d in domains if isinstance(d, str) and d.strip()])
                    api_status[name] = "OK"
                    cprint(f"  [+] {name}: responded ({len(domains)} results)", "success")
                else:
                    api_status[name] = "no_data"
                    cprint(f"  [-] {name}: no data returned", "warning")
            except Exception as e:
                api_status[name] = f"error: {e}"
                cprint(f"  [!] {name}: error: {e}", "error")

        # Deduplicate domains
        target.domains = list(set(target.domains))

        # Collect port results
        if scan_task:
            try:
                open_ports = await scan_task
                target.ports = open_ports
                if open_ports:
                    cprint(f"  [*] Open ports ({len(open_ports)}):", "info")
                    for p in open_ports[:20]:
                        cprint(f"      {p.port}/{p.service}", "info")
                    if len(open_ports) > 20:
                        cprint(f"      ... and {len(open_ports)-20} more", "info")
                else:
                    cprint(f"  [-] No open ports found (or scan disabled)", "warning")
            except Exception as e:
                cprint(f"  [!] Port scan error: {e}", "error")

        # Gold detection
        target = await self.gold.evaluate(target)
        if target.gold_score >= self.config.get("gold_detection.min_score", 3):
            cprint(f"  [GOLD] Score: {target.gold_score}", "gold")
            for r in target.gold_reasons:
                cprint(f"         {r}", "gold")
        else:
            cprint(f"  [*] Gold score: {target.gold_score}", "info")

        cprint(f"  [*] Total unique domains: {len(target.domains)}", "info")
        if target.domains:
            for d in target.domains[:10]:
                cprint(f"      {d}", "info")
            if len(target.domains) > 10:
                cprint(f"      ... and {len(target.domains)-10} more", "info")

        self.results[ip] = target
        return target

    async def close(self):
        for conn in self.connectors.values():
            await conn.close()
        if self.cache:
            self.cache.close()

# ─── Report Writer ───────────────────────────────────────
def write_reports(results: Dict[str, ScanTarget], config: Config):
    out_dir = config.get("output.directory", "results")
    os.makedirs(out_dir, exist_ok=True)

    # JSON
    jpath = os.path.join(out_dir, "results.json")
    try:
        data = {}
        for ip, t in results.items():
            data[ip] = {
                "ip": t.ip,
                "domains": t.domains,
                "gold_score": t.gold_score,
                "gold_reasons": t.gold_reasons,
                "ports": [{"port":p.port,"state":p.state,"service":p.service,"banner":p.banner} for p in t.ports],
                "api_results": {k: v for k, v in t.api_results.items() if "raw" not in v} if config.get("output.save_api_status",True) else {},
                "scan_time": t.scan_time,
            }
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        cprint(f"JSON report: {jpath}", "success")
    except Exception as e:
        cprint(f"Error writing JSON: {e}", "error")

    # Gold report
    gpath = os.path.join(out_dir, "gold_report.txt")
    gold_items = [(ip, t) for ip, t in results.items() if t.gold_score >= config.get("gold_detection.min_score", 3)]
    gold_items.sort(key=lambda x: x[1].gold_score, reverse=True)
    try:
        with open(gpath, "w", encoding="utf-8") as f:
            f.write(f"MONSTER_REV v3 — Gold Report\n{'='*60}\n")
            f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
            if not gold_items:
                f.write("No gold targets found.\n")
            for ip, t in gold_items:
                f.write(f"\n[GOLD] {ip} (Score: {t.gold_score})\n")
                for r in t.gold_reasons:
                    f.write(f"  -> {r}\n")
                f.write(f"  Domains: {len(t.domains)}\n")
                f.write(f"  Open ports: {len(t.ports)}\n")
        cprint(f"Gold report: {gpath}", "success")
    except Exception as e:
        cprint(f"Error writing gold report: {e}", "error")

    # Port report
    ppath = os.path.join(out_dir, "port_report.txt")
    try:
        with open(ppath, "w", encoding="utf-8") as f:
            f.write(f"MONSTER_REV v3 — Port Scan Report\n{'='*60}\n")
            f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
            for ip, t in results.items():
                f.write(f"\n{ip} — {len(t.ports)} open ports\n")
                for p in t.ports:
                    f.write(f"  {p.port:>5}/tcp  {p.service:<15}  {p.banner[:80] if p.banner else ''}\n")
        cprint(f"Port report: {ppath}", "success")
    except Exception as e:
        cprint(f"Error writing port report: {e}", "error")

    # Hydra commands for brute-forceable services
    if config.get("output.save_crack_commands", True):
        hpath = os.path.join(out_dir, "hydra_commands.txt")
        try:
            with open(hpath, "w", encoding="utf-8") as f:
                f.write(f"MONSTER_REV v3 — Hydra Commands\n{'='*60}\n")
                f.write("# Generated for authorized penetration testing only\n\n")
                brute_services = {21:"ftp",22:"ssh",23:"telnet",1433:"mssql",3306:"mysql",5432:"postgres",
                                  3389:"rdp",5900:"vnc",6379:"redis",27017:"mongodb"}
                for ip, t in results.items():
                    for p in t.ports:
                        if p.port in brute_services:
                            svc_name = brute_services[p.port]
                            f.write(f"hydra -L users.txt -P pass.txt {svc_name}://{ip}:{p.port}\n")
            cprint(f"Hydra commands: {hpath}", "success")
        except Exception as e:
            cprint(f"Error writing hydra commands: {e}", "error")

# ─── Interactive Menu ────────────────────────────────────
def print_banner():
    banner = f"""
{'='*60}
  {SCRIPT_NAME} v{SCRIPT_VERSION}
  Reverse IP Intelligence Engine
  Authorized Penetration Testing Tool
{'='*60}
"""
    cprint(banner, "header")

def prompt_str(prompt: str, default: str = "") -> str:
    try:
        val = input(f"\033[36m[?]\033[0m {prompt} ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return ""

def prompt_yn(prompt: str, default: bool = True) -> bool:
    choices = "Y/n" if default else "y/N"
    val = input(f"\033[36m[?]\033[0m {prompt} [{choices}] ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "true", "1")

def prompt_int(prompt: str, default: int = 0, min_val: int = 0, max_val: int = 99999) -> int:
    val = input(f"\033[36m[?]\033[0m {prompt} [{default}] ").strip()
    if not val:
        return default
    try:
        v = int(val)
        return max(min_val, min(v, max_val))
    except ValueError:
        return default

def prompt_choice(prompt: str, options: List[str], default: int = 0) -> int:
    print(f"\033[36m[?]\033[0m {prompt}")
    for i, opt in enumerate(options):
        marker = ">" if i == default else " "
        print(f"    {marker} [{i+1}] {opt}")
    val = input(f"  Enter choice [1-{len(options)}] (default={default+1}): ").strip()
    if not val:
        return default
    try:
        idx = int(val) - 1
        if 0 <= idx < len(options):
            return idx
    except ValueError: pass
    return default

async def interactive_main_menu(config: Config) -> None:
    """Full interactive step-by-step menu."""
    print_banner()
    cprint("Welcome to MONSTER_REV v3 Interactive Mode!", "header")
    cprint("This tool finds domains associated with IP addresses.\n", "info")

    # Step 1: Input method
    ips: List[str] = []
    cprint("--- Step 1: Choose input method ---", "header")
    input_method = prompt_choice("How would you like to provide IP addresses?", [
        "Enter a single IP address",
        "Enter multiple IPs (comma or space separated)",
        "Load from ips.txt file",
        "Enter a CIDR range (auto-expand to IPs)"
    ], default=0)

    if input_method == 0:
        raw = prompt_str("Enter IP address (e.g., 8.8.8.8):")
        if raw:
            raw = raw.strip()
            if valid_ip(raw):
                ips = [raw]
            else:
                cprint(f"Invalid IP: {raw}", "error")
                return
    elif input_method == 1:
        raw = prompt_str("Enter IPs separated by commas or spaces:")
        candidates = re.split(r"[\s,]+", raw.strip())
        for c in candidates:
            c = c.strip()
            if valid_ip(c):
                ips.append(c)
            else:
                cprint(f"Invalid IP ignored: {c}", "warning")
    elif input_method == 2:
        fpath = prompt_str("Path to ips.txt:", default="ips.txt")
        try:
            with open(fpath, "r") as f:
                for line in f:
                    c = line.strip()
                    if c and valid_ip(c):
                        ips.append(c)
                    elif c:
                        cprint(f"Invalid IP ignored: {c}", "warning")
            cprint(f"Loaded {len(ips)} IPs from {fpath}", "success")
        except FileNotFoundError:
            cprint(f"File not found: {fpath}", "error")
            return
    else:  # CIDR
        cidr = prompt_str("Enter CIDR (e.g., 192.168.1.0/24):")
        try:
            import ipaddress
            net = ipaddress.ip_network(cidr, strict=False)
            ips = [str(ip) for ip in net.hosts()]
            cprint(f"Expanded CIDR {cidr} to {len(ips)} IPs", "success")
        except Exception as e:
            cprint(f"Invalid CIDR: {e}", "error")
            return

    if not ips:
        cprint("No valid IPs provided. Exiting.", "warning")
        return

    # Limit to reasonable count
    max_scan = prompt_int(f"Max IPs to scan (out of {len(ips)} available):", default=min(10, len(ips)), min_val=1, max_val=len(ips))
    ips = ips[:max_scan]
    cprint(f"Will scan {len(ips)} IP(s): {', '.join(ips)}", "success")

    # Step 2: Scan options
    cprint("\n--- Step 2: Configure scan options ---", "header")
    do_ports = prompt_yn("Enable port scanning?", default=True)

    ports_to_scan = GOLD_PORTS[:50]
    if do_ports:
        port_choice = prompt_choice("Port scan type:", [
            "Top 50 gold ports (fast)",
            "Top 100 gold ports (moderate)",
            "All gold ports (~120, slower)",
            "Custom port list"
        ], default=0)
        if port_choice == 0: ports_to_scan = GOLD_PORTS[:50]
        elif port_choice == 1: ports_to_scan = GOLD_PORTS[:100]
        elif port_choice == 2: ports_to_scan = GOLD_PORTS
        else:
            custom = prompt_str("Enter comma-separated ports (e.g., 22,80,443,3389):")
            try:
                ports_to_scan = [int(p.strip()) for p in custom.split(",") if p.strip().isdigit()]
            except: pass

    do_gold = prompt_yn("Enable gold detection?", default=True)
    gold_min = prompt_int("Minimum gold score to report:", default=3, min_val=1, max_val=100)

    # Step 3: Confirm
    cprint("\n--- Step 3: Review & Launch ---", "header")
    cprint(f"Targets: {len(ips)} IP(s)", "info")
    cprint(f"Port scanning: {'YES' if do_ports else 'NO'}", "info")
    if do_ports:
        cprint(f"  Ports to scan: {len(ports_to_scan)}", "info")
    cprint(f"Gold detection: {'YES' if do_ports and do_gold else 'NO'}", "info")
    if do_gold:
        cprint(f"  Min gold score: {gold_min}", "info")

    api_count = sum(1 for api in ["shodan","virustotal","securitytrails","ipdata","ip2location","viewdns","whoisxml"] if config.api_key(api))
    cprint(f"APIs configured: {api_count}/7", "info")
    for api in ["shodan","virustotal","securitytrails","ipdata","ip2location","viewdns","whoisxml"]:
        k = config.api_key(api)
        if k:
            cprint(f"  [+] {api}: key configured ({k[:8]}...{k[-4:]})", "info")
        else:
            cprint(f"  [-] {api}: NO KEY", "warning")

    if not prompt_yn("Launch scan now?", default=True):
        cprint("Scan cancelled.", "warning")
        return

    # Step 4: Execute
    engine = ReverseIPEngine(config)
    await engine.init()

    start_time = time.time()
    for i, ip in enumerate(ips, 1):
        cprint(f"\n--- Target {i}/{len(ips)} ---", "header")
        await engine.scan_ip(ip, do_port_scan=do_ports, ports=ports_to_scan)

    elapsed = time.time() - start_time
    cprint(f"\n{'='*60}", "header")
    cprint(f"  Scan complete! {len(ips)} IP(s) scanned in {elapsed:.1f}s", "success")
    cprint(f"{'='*60}\n", "header")

    # Step 5: Reports
    cprint("--- Step 5: Generate Reports ---", "header")
    if prompt_yn("Write reports to 'results/' directory?", default=True):
        write_reports(engine.results, config)

    # Step 6: Summary
    gold_count = sum(1 for t in engine.results.values() if t.gold_score >= gold_min)
    total_domains = sum(len(t.domains) for t in engine.results.values())
    total_ports = sum(len(t.ports) for t in engine.results.values())

    cprint("\n--- Scan Summary ---", "header")
    cprint(f"  IPs scanned:  {len(ips)}", "info")
    cprint(f"  APIs OK:      {api_count}/7", "info")
    cprint(f"  Gold targets: {gold_count}", "info" if gold_count == 0 else "gold")
    cprint(f"  Total domains:{total_domains}", "info")
    cprint(f"  Total ports:  {total_ports}", "info")

    # Show gold targets in detail
    if gold_count > 0:
        cprint("\n  HIGH-VALUE TARGETS:", "gold")
        for ip, t in engine.results.items():
            if t.gold_score >= gold_min:
                cprint(f"    {ip} (Score: {t.gold_score}) — {', '.join(t.gold_reasons[:3])}", "gold")

    await engine.close()

# ─── CLI Mode (simple, non-interactive) ──────────────────
async def cli_mode(config: Config, ip: str) -> None:
    engine = ReverseIPEngine(config)
    await engine.init()
    target = await engine.scan_ip(ip, do_port_scan=True, ports=GOLD_PORTS[:50])
    write_reports({ip: target}, config)

    gold_min = config.get("gold_detection.min_score", 3)
    if target.gold_score >= gold_min:
        cprint(f"\n[GOLD] HIGH-VALUE TARGET: {ip} (Score: {target.gold_score})", "gold")
    cprint(f"\nTotal domains: {len(target.domains)}", "info")
    cprint(f"Open ports: {len(target.ports)}", "info")
    await engine.close()

# ─── Entry Point ─────────────────────────────────────────
def main():
    """Entry point with Windows event loop fix already applied above."""
    parser = None
    try:
        import argparse
        parser = argparse.ArgumentParser(description=f"{SCRIPT_NAME} v{SCRIPT_VERSION}")
        parser.add_argument("--ip", help="Single IP to scan (CLI mode, skips interactive menu)")
        parser.add_argument("--no-interactive", action="store_true", help="Force non-interactive mode")
        parser.add_argument("--config", default="config.json", help="Path to config file")
        args, _ = parser.parse_known_args()
    except ImportError:
        args = None

    config = Config(args.config if args else "config.json")

    # Check if we have at least one API key
    has_keys = any(config.api_key(a) for a in ["shodan","virustotal","securitytrails","ipdata","ip2location","viewdns","whoisxml"])
    if not has_keys:
        cprint("WARNING: No API keys configured! Edit config.json before running.", "warning")
        cprint("You need at least one API key for domain lookups.", "warning")
        if not prompt_yn("Continue anyway (only port scanning will work)?", default=False):
            sys.exit(1)

    if args and args.ip and (args.no_interactive or True):
        # CLI mode
        asyncio.run(cli_mode(config, args.ip))
    elif args and args.ip:
        # IP provided but interactive mode
        import ipaddress
        ips = [args.ip]
        asyncio.run(interactive_main_menu(config))
    else:
        # Full interactive mode
        asyncio.run(interactive_main_menu(config))

if __name__ == "__main__":
    main()
