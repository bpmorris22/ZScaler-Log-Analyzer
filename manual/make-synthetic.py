# make-synthetic.py - synthetic ZIA web-log export for the manual and the screenshots.
# Fictional tenant "Acme Retail": example.* domains, RFC 5737 documentation IPs, invented users. Deterministic (seeded).
# Writes the CSV exactly as the ZIA portal exports it: BOM, preamble lines, 26-column Web Insights header, Event Time in
# the exporting admin's zone (PDT), CRLF. The users work on UTC+10 (Brisbane). The export is cut at 100,000 rows to show
# the row-cap warning, like a real capped export.
# Planted scenario (for the manual's worked example):
#   Wed 16 Sep 10:12 +10  c.diaz downloads a password-protected ZIP (unscannable) from files-transfer.example
#   from 10:31            c.diaz's workstation ACME-WS07 beacons to 203.0.113.77 every ~30 s (/api/hello?h=..&u=..,
#                         /api/cmd/.., /api/out/..), 24x7
#   Thu 17 Sep            the same implant appears for d.patel (ACME-WS12) and k.berg (ACME-FIN03)
#   Thu 17 Sep 14:05      k.berg uploads to file.io (temp file host)
#   plus: phishing + malware blocks, one allowed 'Suspicious' threat, TeamViewer (IT), blocked AnyDesk, DNS over HTTPS,
#   adware retrying while blocked, games blocked, GenAI use, SSL handshake noise.
# Usage: py -I make-synthetic.py <out.csv>
import csv, random, sys, datetime as dt

random.seed(20260914)
OUT = sys.argv[1]
UTC = dt.timezone.utc
PDT = dt.timedelta(hours=-7)
LOCAL = dt.timedelta(hours=10)
START_LOCAL = dt.datetime(2026, 9, 14, 0, 0, 0)          # Monday, users' clock
DAYS = 7
ROWCAP = 100000

USERS = {  # user: (department, location, workstation)
  "a.chen@acme-retail.example": ("Head Office", "Brisbane HQ", "ACME-WS01"),
  "b.okafor@acme-retail.example": ("Head Office", "Brisbane HQ", "ACME-WS02"),
  "c.diaz@acme-retail.example": ("Head Office", "Brisbane HQ", "ACME-WS07"),
  "d.patel@acme-retail.example": ("IT", "Brisbane HQ", "ACME-WS12"),
  "e.novak@acme-retail.example": ("Stores", "Road Warrior", "ACME-ST04"),
  "f.haddad@acme-retail.example": ("Stores", "Road Warrior", "ACME-ST05"),
  "g.silva@acme-retail.example": ("Stores", "Road Warrior", "ACME-ST09"),
  "h.kim@acme-retail.example": ("Finance", "Brisbane HQ", "ACME-FIN01"),
  "i.murphy@acme-retail.example": ("Finance", "Brisbane HQ", "ACME-FIN02"),
  "j.tanaka@acme-retail.example": ("IT", "Brisbane HQ", "ACME-WS15"),
  "k.berg@acme-retail.example": ("Finance", "Brisbane HQ", "ACME-FIN03"),
  "l.osei@acme-retail.example": ("Stores", "Road Warrior", "ACME-ST11"),
}
FILTER_EXTRA = ["m.rossi@acme-retail.example", "n.ali@acme-retail.example"]   # in the export filter, no traffic

# (weight, host, paths, appclass, app, urlclass, supercat, cat, alpn)
SITES = [
  (60, "www.google.com", ["/search?q=stock+levels", "/search?q=freight+rates", "/complete/search?q=acme", "/"], "Web Search", "Google Search", "Business Use", "Information Technology", "Web Search", "HTTP/2 over TLS"),
  (40, "www.google-analytics.com", ["/g/collect?v=2", "/collect"], "General Browsing", "None", "Business Use", "Business and Economy", "Professional Services", "HTTP/2 over TLS"),
  (45, "login.microsoftonline.com", ["/common/oauth2/v2.0/token", "/common/login"], "Productivity and CRM Tools", "Microsoft Login Services", "Business Use", "Business and Economy", "Professional Services", "HTTP/2 over TLS"),
  (55, "outlook.office.com", ["/mail/inbox", "/owa/service.svc", "/mail/sentitems"], "Productivity and CRM Tools", "Outlook (Office 365)", "Business Use", "Internet Communication", "Internet Services", "HTTP/2 over TLS"),
  (40, "teams.microsoft.com", ["/api/chatsvc/messages", "/_#/conversations"], "Collaboration and Online Meetings", "Microsoft Teams", "Business Use", "Internet Communication", "Online Chat", "HTTP/2 over TLS"),
  (35, "acmeretail.sharepoint.com", ["/sites/stores/Shared%20Documents/Rosters.xlsx", "/sites/finance/_api/web"], "File Sharing", "Sharepoint Online", "Business Use", "Information Technology", "Professional Services", "HTTP/2 over TLS"),
  (30, "portal.acme-retail.example", ["/pos/sync", "/inventory/api/v2/items", "/reports/daily"], "General Browsing", "None", "Business Use", "User-Defined", "Custom_Acme_Apps", "HTTP/2 over TLS"),
  (20, "www.youtube.com", ["/watch?v=training01", "/youtubei/v1/player"], "Streaming Media", "YouTube", "Bandwidth Loss", "Entertainment/Recreation", "Video Streaming", "HTTP/2 over TLS"),
  (18, "web.whatsapp.com", ["/", "/ws/chat"], "Instant Messaging", "Whatsapp Web", "Business Use", "Internet Communication", "Online Chat", "HTTP/2 over TLS"),
  (12, "chatgpt.com", ["/backend-api/conversation", "/c/new"], "AI & ML Applications", "ChatGPT", "Business Use", "Information Technology", "Generative AI and ML Applications", "HTTP/2 over TLS"),
  (15, "www.bing.com", ["/search?q=weather+brisbane", "/fd/ls/l"], "Web Search", "Bing", "Business Use", "Information Technology", "Web Search", "HTTP/2 over TLS"),
  (14, "freight.partner.example", ["/tracking/AU", "/api/shipments"], "General Browsing", "None", "Business Use", "Business and Economy", "Corporate Marketing", "HTTP/2 over TLS"),
  (10, "news.example", ["/business", "/world"], "General Browsing", "None", "General Surfing", "News and Media", "News and Media", "HTTP/2 over TLS"),
  (10, "shop.example", ["/deals", "/cart"], "Consumer", "None", "General Surfing", "Shopping and Auctions", "Online Shopping", "HTTP/2 over TLS"),
  (8, "v10.events.data.microsoft.com", ["/OneCollector/1.0/"], "General Browsing", "None", "Business Use", "Business and Economy", "Corporate Marketing", "N/A"),
  (6, "198.51.100.20", ["/printer/status", "/ipp/print"], "General Browsing", "None", "Business Use", "Internet Communication", "Internet Services", "N/A"),
]
SITE_W = [s[0] for s in SITES]

rows = []
def add(ts_utc, user, url, action="Allowed", appclass="General Browsing", app="None", urlclass="Business Use", supercat="Information Technology",
        cat="Internet Services", threatcat="None", threat="None", blocktype="None", cert="Pass", unscan="None", alpn="HTTP/2 over TLS", dlpmd5="None", dlpid="None"):
    dept, loc, _ = USERS[user]
    rows.append([ts_utc, user, url, action, appclass, app, urlclass, supercat, cat, threatcat, threat, loc, dept, blocktype, cert, "No" if cert == "Pass" else "None",
                 dlpmd5, dlpid, alpn, unscan, "None", "None", "None", "None", "None"])

def local(day, h, m, s=0):
    return START_LOCAL + dt.timedelta(days=day, hours=h, minutes=m, seconds=s) - LOCAL   # -> UTC naive

# ---- ordinary working days: browsing within business hours (weekends light)
for day in range(DAYS):
    weekend = (START_LOCAL + dt.timedelta(days=day)).weekday() >= 5
    for user in USERS:
        if weekend and random.random() < 0.75: continue
        n = random.randint(90, 160) if weekend else random.randint(1100, 1700)
        start_h = 8 if not weekend else 10
        for _ in range(n):
            t = local(day, start_h, 0) + dt.timedelta(seconds=random.randint(0, (9 if not weekend else 3) * 3600))
            s = random.choices(SITES, weights=SITE_W)[0]
            url = s[1] + random.choice(s[2])
            if random.random() < 0.006:
                add(t, user, s[1], "Dropped due to failed client SSL handshake", s[3], s[4], s[5], s[6], s[7], cert="None", alpn="N/A")
            else:
                add(t, user, url, "Allowed", s[3], s[4], s[5], s[6], s[7], alpn=s[8])

# ---- channels and policy events
for day in range(5):
    for k in range(random.randint(80, 140)):   # IT uses TeamViewer (sanctioned?)
        add(local(day, 9, 0) + dt.timedelta(seconds=random.randint(0, 28000)), "j.tanaka@acme-retail.example", "router12.teamviewer.com/din.aspx?s=0001", appclass="IT Services", app="TeamViewer", supercat="Information Technology", cat="Remote Access Tools")
    for k in range(random.randint(400, 700)):  # DNS over HTTPS from d.patel's browser
        add(local(day, 8, 30) + dt.timedelta(seconds=random.randint(0, 30000)), "d.patel@acme-retail.example", "dns.google/dns-query?dns=AAABAAAB", appclass="DNS Over HTTPS Services", app="Google DNS", cat="DNS Over HTTPS Services")
    for k in range(random.randint(15, 30)):    # store user tries games (blocked)
        add(local(day, 12, 0) + dt.timedelta(seconds=random.randint(0, 3600)), "l.osei@acme-retail.example", "games.example/play", "Not allowed to browse this category", urlclass="Productivity Loss", supercat="Games", cat="Online and Other Games", blocktype="URL Filtering")
# AnyDesk attempt (blocked) - Tue
for k in range(40):
    add(local(1, 15, 2, k * 7), "e.novak@acme-retail.example", "relay-4a1b.net.anydesk.com", "Not allowed to browse this category", appclass="IT Services", app="AnyDesk", supercat="Information Technology", cat="Remote Access Tools", blocktype="URL Filtering")
# adware: polls every 5 minutes, all week, blocked
t = local(0, 0, 3)
while t < local(DAYS, 0, 0):
    add(t, "g.silva@acme-retail.example", "api.toolbar-updates.example/engine.php?a=config&v=3.2", "Not allowed to browse this category", urlclass="Privacy Risk", supercat="Security", cat="Spyware/Adware", blocktype="URL Filtering")
    t += dt.timedelta(seconds=300 + random.randint(-4, 4))
# phishing (blocked) - Tue 11:41
add(local(1, 11, 41, 9), "f.haddad@acme-retail.example", "invoice-portal.example/acme/login.php", "Not allowed to browse this Malicious URL", urlclass="Adv. Security Risk", supercat="Advanced Security", cat="Phishing", threatcat="Phishing", threat="HTML.Phishing.Gen", blocktype="Advanced Threat Protection")
add(local(1, 11, 41, 12), "f.haddad@acme-retail.example", "invoice-portal.example/acme/login.php", "Not allowed to browse this Malicious URL", urlclass="Adv. Security Risk", supercat="Advanced Security", cat="Phishing", threatcat="Phishing", threat="HTML.Phishing.Gen", blocktype="Advanced Threat Protection")
# malware download (blocked) - Mon 14:20
add(local(0, 14, 20, 33), "i.murphy@acme-retail.example", "cdn-files.example/update/flashplayer_update.exe", "Malicious file Blocked", appclass="General Browsing", urlclass="Adv. Security Risk", supercat="Advanced Security", cat="Malicious Content", threatcat="Trojan", threat="Win32.Trojan.Agent", blocktype="Malware Protection")
# one suspicious file allowed - Fri 09:05
add(local(4, 9, 5, 2), "a.chen@acme-retail.example", "docs-share.example/viewer/Q3_report.html", "Allowed", cat="Miscellaneous or Unknown", supercat="Miscellaneous", urlclass="General Surfing", threatcat="Suspicious", threat="HTML.Suspicious.Redirect")

# ---- the planted intrusion
c, d, kb = "c.diaz@acme-retail.example", "d.patel@acme-retail.example", "k.berg@acme-retail.example"
add(local(2, 10, 12, 4), c, "files-transfer.example/dl/Invoice_4471.zip", "Allowed", cat="Miscellaneous or Unknown", supercat="Miscellaneous", urlclass="General Surfing", unscan="Unscannable File")
add(local(2, 10, 12, 5), c, "files-transfer.example/dl/Invoice_4471.zip", "Allowed", cat="Miscellaneous or Unknown", supercat="Miscellaneous", urlclass="General Surfing", unscan="Unscannable File")
def implant(user, host, start):
    add(start, user, "203.0.113.77/api/register/" + host, cat="Miscellaneous or Unknown", supercat="Miscellaneous", urlclass="General Surfing", alpn="N/A")
    t = start + dt.timedelta(seconds=20); n = 0
    while t < local(DAYS, 0, 0):
        add(t, user, "203.0.113.77/api/hello?h=%s&u=%s" % (host, user.split("@")[0]), cat="Miscellaneous or Unknown", supercat="Miscellaneous", urlclass="General Surfing", alpn="N/A")
        if n % 10 == 0: add(t + dt.timedelta(seconds=1), user, "203.0.113.77/api/cmd/" + host, cat="Miscellaneous or Unknown", supercat="Miscellaneous", urlclass="General Surfing", alpn="N/A")
        if n % 120 == 7: add(t + dt.timedelta(seconds=2), user, "203.0.113.77/api/out/" + host, cat="Miscellaneous or Unknown", supercat="Miscellaneous", urlclass="General Surfing", alpn="N/A")
        t += dt.timedelta(seconds=30 + random.randint(-3, 3)); n += 1
implant(c, "ACME-WS07", local(2, 10, 31, 40))
implant(d, "ACME-WS12", local(3, 2, 14, 10))     # 02:14 local - off-hours spread
implant(kb, "ACME-FIN03", local(3, 2, 19, 55))
for k in range(6):   # Thu 14:05 upload to a temp file host
    add(local(3, 14, 5, k * 9), kb, "file.io/upload", appclass="File Sharing", app="File.io", supercat="Information Technology", cat="FileHost")

# ---- write: time order, cut at the row cap, Event Time in PDT
rows.sort(key=lambda r: r[0])
rows = rows[:ROWCAP]
def ev(t):
    p = (t + PDT)
    return p.strftime("%B ") + str(p.day) + p.strftime(", %Y ") + str(int(p.strftime("%I"))) + p.strftime(":%M:%S %p") + " PDT"
HDR = ["No.", "Event Time", "User", "URL", "Policy Action", "Cloud Application Class", "Cloud Application", "URL Class", "URL Super Category", "URL Category",
       "Threat Category", "Threat Name", "Location", "Department", "Blocked Policy Type", "Certificate Chain Validity", "Server Certificate Self Signed",
       "DLP MD5", "DLP Identifier", "ALPN Protocol", "Unscannable Type", "Forwarding Rule", "Forwarding Method", "Application Segment", "Gateway IP", "Gateway Name"]
with open(OUT, "w", encoding="utf-8-sig", newline="") as fh:
    w = csv.writer(fh, lineterminator="\r\n")
    pad = [""] * 24
    w.writerow(["Administrator", "zscaler.admin@acme-retail.zslogin.example"] + pad)
    w.writerow(["Report Created", "Sep 21, 2026 9:15:02 AM UTC"] + pad)
    w.writerow(["Users", "Include - [" + ",".join(list(USERS) + FILTER_EXTRA) + "]"] + pad)
    w.writerow(HDR)
    for i, r in enumerate(rows, 1):
        w.writerow([i, ev(r[0])] + r[1:])
print("%d rows, %s .. %s UTC" % (len(rows), rows[0][0], rows[-1][0]))
