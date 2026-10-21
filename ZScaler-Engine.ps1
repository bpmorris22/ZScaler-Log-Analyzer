# ZScaler-Engine.ps1 - streaming aggregator for Zscaler Internet Access (ZIA) web-log CSV exports (ZScaler Log Analyzer).
# Reads the CSV exactly as the ZIA admin portal exports it (Analytics > Web Insights > Logs > Export CSV): an optional
# preamble (Administrator / Report Created / filter lines), then a header row starting "No.,Event Time,User,URL,...".
# One pass, and writes:
#   <OutDir>\<Host>-ZScaler-<Stamp>.json   every table as a bounded PREVIEW (<= 6000 rows) for the HTA viewer,
#                                          with true totals, priority rows always kept, and full-data stats
#   <OutDir>\<Stamp>_<table>.csv           every table in FULL (event lists stream straight to disk while parsing)
# Columns are mapped by header NAME, so an export with the admin's own column choice still reads; unknown columns are
# listed on Sources > Files, never guessed. Every event row carries SourceFile + SourceLine (the physical line the record
# begins on, header counted) so a finding can cite it.
# Times: ZIA writes "Event Time" in the exporting admin's portal timezone, as an abbreviation ("PDT"). The abbreviation
# is mapped to its UTC offset per row; ambiguous ones (IST, CST, BST, AST, GST) are flagged; an unknown or absent zone
# stops the run unless -TzOverride (+HH:MM) is given. Everything written is UTC.
# NB this file is embedded verbatim in ZScaler-Log-Analyzer.hta - it must never contain a closing script tag.
param(
  [Parameter(Mandatory=$true)][string]$InputPath,     # file or folder; several separated by |
  [Parameter(Mandatory=$true)][string]$OutDir,
  [Parameter(Mandatory=$true)][string]$TargetHost,    # tenant / case label - names the output
  [string]$From = "",                                 # yyyy-MM-dd (UTC, inclusive) - records outside are skipped
  [string]$To = "",
  [string]$TzOverride = "",                           # +HH:MM / -HH:MM - replaces the abbreviation mapping for every row
  [string]$IocFile = "",
  [string]$AppVersion = "0.1.0-dev",
  [string]$Stamp = "",
  [string]$ProgressFile = ""
)
$ErrorActionPreference = 'Stop'

$cs = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Globalization;

public class ZsAgg {
  public int Cap = 500;
  public long N, First = long.MaxValue, Last = long.MinValue;
  public long[] C = new long[16];
  public Dictionary<string,long>[] T = new Dictionary<string,long>[10];
  public bool[] Over = new bool[10];
  public string S0 = "", S1 = "", S2 = "", S3 = "", S4 = "", S5 = "";
  public HashSet<long> Days;
  public List<string> Samples, Hits;
  public void HitPath(string s, int max){ if(Hits == null) Hits = new List<string>(); if(Hits.Count < max) Hits.Add(s); }
  public void Seen(long ms){ N++; if(ms > 0){ if(ms < First) First = ms; if(ms > Last) Last = ms; } }
  public void Add(int slot, string v){ Add(slot, v, 1); }
  public void Add(int slot, string v, long w){
    if(string.IsNullOrEmpty(v)) return;
    Dictionary<string,long> d = T[slot];
    if(d == null){ d = new Dictionary<string,long>(StringComparer.OrdinalIgnoreCase); T[slot] = d; }
    long c;
    if(d.TryGetValue(v, out c)) d[v] = c + w;
    else if(d.Count < Cap) d[v] = w;
    else Over[slot] = true;
  }
  public void Day(long ms){ if(ms <= 0) return; if(Days == null) Days = new HashSet<long>(); Days.Add(ms / 86400000L); }
  public void Sample(string s, int max){ if(string.IsNullOrEmpty(s)) return; if(Samples == null) Samples = new List<string>(); if(Samples.Count < max && !Samples.Contains(s)) Samples.Add(s); }
  public long Distinct(int slot){ return T[slot] == null ? 0 : T[slot].Count; }
  public string Most(int slot){
    Dictionary<string,long> d = T[slot]; if(d == null) return "";
    string best = ""; long bc = -1;
    foreach(KeyValuePair<string,long> kv in d){ if(kv.Value > bc || (kv.Value == bc && string.CompareOrdinal(kv.Key, best) < 0)){ best = kv.Key; bc = kv.Value; } }
    return best;
  }
  public string Top(int slot, int k){
    Dictionary<string,long> d = T[slot];
    if(d == null || d.Count == 0) return "";
    List<KeyValuePair<string,long>> l = new List<KeyValuePair<string,long>>(d);
    l.Sort(delegate(KeyValuePair<string,long> a, KeyValuePair<string,long> b){ int r = b.Value.CompareTo(a.Value); return r != 0 ? r : string.CompareOrdinal(a.Key, b.Key); });
    StringBuilder sb = new StringBuilder();
    for(int i = 0; i < l.Count && i < k; i++){ if(sb.Length > 0) sb.Append(", "); sb.Append(l[i].Key); if(d.Count > 1) sb.Append(" (").Append(l[i].Value).Append(")"); }
    if(l.Count > k) sb.Append(", +").Append(l.Count - k).Append(Over[slot] ? "+" : "").Append(" more");
    return sb.ToString();
  }
  public string List(int slot){
    Dictionary<string,long> d = T[slot];
    if(d == null) return "";
    List<string> l = new List<string>(d.Keys); l.Sort(StringComparer.OrdinalIgnoreCase);
    return string.Join(", ", l.ToArray()) + (Over[slot] ? ", ..." : "");
  }
}

public class ZsTable {
  public string Name; public string[] Cols; public List<object[]> Rows = new List<object[]>();
  public int SortCol = -1; public bool Desc = true; public int SortCol2 = -1;
  public Predicate<object[]> Prio;
  public int Cap = 0;   // preview cap override (0 = ZsList.CAP)
  public ZsTable(string name, int sortCol, params string[] cols){ Name = name; Cols = cols; SortCol = sortCol; }
  public void Add(params object[] r){ Rows.Add(r); }
  public int Ix(string col){ return Array.IndexOf(Cols, col); }
  public static int Cmp(object a, object b){
    if(a is long && b is long) return ((long)a).CompareTo((long)b);
    string x = a == null ? "" : a.ToString(), y = b == null ? "" : b.ToString();
    return string.CompareOrdinal(x, y);
  }
  public Comparison<object[]> Order(){
    int sc = SortCol, sc2 = SortCol2; bool desc = Desc;
    return delegate(object[] a, object[] b){ if(sc < 0) return 0; int r = Cmp(a[sc], b[sc]); if(desc) r = -r; if(r == 0 && sc2 >= 0) r = -Cmp(a[sc2], b[sc2]); return r; };
  }
  public void Sort(){ if(SortCol >= 0) Rows.Sort(Order()); }
}

/* event list: every row streams to its full CSV the moment it is seen (nothing is ever dropped from the CSV);
   memory holds only a bounded preview - priority rows plus the earliest of the rest (column 0 is Time_UTC) */
public class ZsList {
  public const int CAP = 6000;
  public string Name, PathCsv; public string[] Cols; public long Total, PrioTotal;
  public List<object[]> Prio = new List<object[]>(), Rest = new List<object[]>();
  StreamWriter W;
  public ZsList(string name, string dir, string stamp, params string[] cols){ Name = name; Cols = cols; PathCsv = Path.Combine(dir, stamp + "_" + name + ".csv"); }
  public void Add(bool prio, params object[] row){
    Total++;
    if(W == null){ W = new StreamWriter(PathCsv, false, new UTF8Encoding(true)); ZsEngine.CsvRow(W, Cols); }
    ZsEngine.CsvRow(W, row);
    if(prio){ PrioTotal++; Prio.Add(row); if(Prio.Count >= 2 * CAP) Trim(Prio, CAP); }
    else { Rest.Add(row); if(Rest.Count >= 2 * CAP) Trim(Rest, CAP); }
  }
  static void Trim(List<object[]> l, int n){
    l.Sort(delegate(object[] a, object[] b){ return ZsTable.Cmp(a[0], b[0]); });
    if(l.Count > n) l.RemoveRange(n, l.Count - n);
  }
  public List<object[]> Preview(){
    Trim(Prio, CAP); Trim(Rest, Math.Max(0, CAP - Prio.Count));
    List<object[]> o = new List<object[]>(Prio); o.AddRange(Rest);
    o.Sort(delegate(object[] a, object[] b){ return ZsTable.Cmp(a[0], b[0]); });
    return o;
  }
  public void Close(){ if(W != null){ W.Close(); W = null; } }
}

public class ZsFile {
  public string Path, Rel, Status = "", Note = "", Admin = "", Created = "", Filters = "", Unknown = "", Missing = "";
  public bool Read; public long Records, Lines, Bad, Incomplete, Asc, Desc, Outside;
  public List<string> IncompleteLines = new List<string>(); public long First = long.MaxValue, Last = long.MinValue;
  public List<string> FilterUsers = new List<string>();
  public Dictionary<string,long> Tz = new Dictionary<string,long>(StringComparer.Ordinal);
}

public static class ZsEngine {
  static void Log(string s){ Console.WriteLine(s); }

  /* ---------------- column map (header NAME -> field) ---------------- */
  /* the core Web Insights columns (sample-validated), then optional ones other column choices add (PROVISIONAL: mapped
     by documented portal names, not yet seen in a real export) */
  static readonly string[][] COLMAP = new string[][]{
    new string[]{"no", "No."},
    new string[]{"time", "Event Time", "Time", "Logged Time", "Datetime", "Date Time"},
    new string[]{"user", "User", "User Name", "Login"},
    new string[]{"url", "URL", "Request URL"},
    new string[]{"action", "Policy Action", "Action"},
    new string[]{"appclass", "Cloud Application Class", "Cloud App Class", "Application Class"},
    new string[]{"app", "Cloud Application", "Cloud App", "Application"},
    new string[]{"urlclass", "URL Class"},
    new string[]{"supercat", "URL Super Category", "Super Category"},
    new string[]{"cat", "URL Category", "Category"},
    new string[]{"threatcat", "Threat Category", "Malware Category"},
    new string[]{"threat", "Threat Name", "Malware Name"},
    new string[]{"location", "Location"},
    new string[]{"dept", "Department"},
    new string[]{"blocktype", "Blocked Policy Type"},
    new string[]{"certvalid", "Certificate Chain Validity"},
    new string[]{"selfsigned", "Server Certificate Self Signed"},
    new string[]{"dlpmd5", "DLP MD5"},
    new string[]{"dlpid", "DLP Identifier"},
    new string[]{"dlpengine", "DLP Engine", "DLP Engines"},
    new string[]{"dlpdict", "DLP Dictionaries", "DLP Dictionary"},
    new string[]{"alpn", "ALPN Protocol"},
    new string[]{"unscannable", "Unscannable Type"},
    new string[]{"fwdrule", "Forwarding Rule"},
    new string[]{"fwdmethod", "Forwarding Method"},
    new string[]{"appseg", "Application Segment"},
    new string[]{"gwip", "Gateway IP"},
    new string[]{"gwname", "Gateway Name"},
    /* optional - PROVISIONAL */
    new string[]{"clientip", "Client IP", "Client Source IP", "Source IP"},
    new string[]{"pubip", "Client Public IP", "Public IP", "Client External IP"},
    new string[]{"serverip", "Server IP", "Server Destination IP", "Destination IP"},
    new string[]{"method", "Request Method", "HTTP Method"},
    new string[]{"status", "Response Code", "Status Code", "HTTP Response Code"},
    new string[]{"reqsize", "Request Size", "Bytes Sent", "Sent Bytes", "Upload Size", "Request Bytes"},
    new string[]{"respsize", "Response Size", "Bytes Received", "Received Bytes", "Download Size", "Response Bytes"},
    new string[]{"filetype", "File Type", "Download File Type"},
    new string[]{"filename", "File Name", "Download File Name", "Filename"},
    new string[]{"filemd5", "MD5", "File MD5", "Malware MD5"},
    new string[]{"ua", "User Agent", "User-Agent"},
    new string[]{"referer", "Referer", "Referrer", "Referer URL"},
    new string[]{"devhost", "Device Hostname", "Device Host Name", "Hostname"},
    new string[]{"devowner", "Device Owner"},
    new string[]{"risk", "Page Risk", "Suspicious Content", "Risk Score"}
  };
  static Dictionary<string,int> IX = new Dictionary<string,int>(StringComparer.Ordinal);
  static string[] REC;
  static string F(string k){ int i; if(!IX.TryGetValue(k, out i) || i >= REC.Length) return ""; string v = REC[i]; return v == null ? "" : v.Trim(); }
  /* "None" / "N/A" / "" mean "no value" in a ZIA export */
  static string Fz(string k){ string v = F(k); if(v.Length == 0 || v == "None" || v == "N/A" || v == "NA" || v == "-") return ""; return v; }
  static long Fn(string k){ string v = Fz(k).Replace(",", ""); long n; return long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : 0; }

  /* ---------------- CSV ---------------- */
  /* split one physical line; returns false when a quoted field is still open (the record continues on the next line) */
  static bool SplitCsv(string s, List<string> o){
    o.Clear(); StringBuilder b = new StringBuilder(); bool q = false; int n = s.Length;
    for(int i = 0; i < n; i++){
      char c = s[i];
      if(q){
        if(c == '"'){ if(i + 1 < n && s[i + 1] == '"'){ b.Append('"'); i++; } else q = false; }
        else b.Append(c);
      } else {
        if(c == ',') { o.Add(b.ToString()); b.Length = 0; }
        else if(c == '"') q = true;
        else b.Append(c);
      }
    }
    o.Add(b.ToString());
    return !q;
  }
  static bool Balanced(string s){ int q = 0; foreach(char c in s) if(c == '"') q++; return (q & 1) == 0; }

  /* ---------------- time ---------------- */
  static readonly string[] TFMT = {
    "MMMM d, yyyy h:mm:ss tt", "MMM d, yyyy h:mm:ss tt", "MMMM d, yyyy H:mm:ss", "MMM d, yyyy H:mm:ss",
    "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd HH:mm:ss.fff", "yyyy-MM-dd'T'HH:mm:ss.fff",
    "M/d/yyyy h:mm:ss tt", "M/d/yyyy H:mm:ss", "d/M/yyyy H:mm:ss", "ddd MMM d HH:mm:ss yyyy", "ddd MMM dd HH:mm:ss yyyy",
    "dd-MMM-yyyy HH:mm:ss", "MMM dd yyyy HH:mm:ss"
  };
  static readonly Dictionary<string,int> TZ = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase){
    {"UTC",0},{"GMT",0},{"Z",0},{"PDT",-420},{"PST",-480},{"MDT",-360},{"MST",-420},{"CDT",-300},{"CST",-360},{"EDT",-240},{"EST",-300},
    {"AKDT",-480},{"AKST",-540},{"HST",-600},{"HDT",-540},{"AST",-240},{"ADT",-180},{"NST",-210},{"NDT",-150},{"BRT",-180},{"ART",-180},
    {"BST",60},{"IST",330},{"WET",0},{"WEST",60},{"CET",60},{"CEST",120},{"EET",120},{"EEST",180},{"MSK",180},{"SAST",120},{"CAT",120},
    {"EAT",180},{"WAT",60},{"GST",240},{"PKT",300},{"NPT",345},{"ICT",420},{"WIB",420},{"SGT",480},{"HKT",480},{"AWST",480},{"PHT",480},
    {"KST",540},{"JST",540},{"ACST",570},{"ACDT",630},{"AEST",600},{"AEDT",660},{"NZST",720},{"NZDT",780}
  };
  static readonly HashSet<string> TZAMBIG = new HashSet<string>(StringComparer.OrdinalIgnoreCase){ "IST", "CST", "BST", "AST", "GST" };
  static readonly Regex TZNUM = new Regex(@"^(?:GMT|UTC)?([+-])(\d{1,2}):?(\d{2})?$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
  static int OVERRIDE = int.MinValue;
  public static Dictionary<string,long> TZSEEN = new Dictionary<string,long>(StringComparer.Ordinal);
  static string LASTTS = null; static long LASTMS = 0; static string LASTZ = ""; static int FMTHINT = -1;
  static readonly DateTime EPOCH = new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc);
  static int ParseOffset(string z, out bool ok){
    ok = false; if(string.IsNullOrEmpty(z)) return 0;
    int m; if(TZ.TryGetValue(z, out m)){ ok = true; return m; }
    /* the sign applies to the whole offset: -00:30 is minus thirty minutes, not plus */
    Match mm = TZNUM.Match(z); if(mm.Success){ ok = true; int mag = int.Parse(mm.Groups[2].Value) * 60 + (mm.Groups[3].Success ? int.Parse(mm.Groups[3].Value) : 0); return mm.Groups[1].Value == "-" ? -mag : mag; }
    return 0;
  }
  /* an ISO-style value whose zone is attached to the time: ...T10:00:00Z, ...10:00:00+10:00, ...10:00:00.123 -0700 */
  static readonly Regex ISOZ = new Regex(@"^(.*\d:\d{2}(?::\d{2}(?:\.\d+)?)?)\s?(Z|[+-]\d{2}:?\d{2})$", RegexOptions.Compiled);
  /* -> UTC ms; zone = the abbreviation / offset text the row carried ("" when none). Throws on an unknown zone.
     Every parse path (exact formats, then a general fallback) yields a WALL time plus the zone text written with it;
     one policy then applies: the override when set (it replaces the written zone on every row), else the written zone,
     else the run stops. A zone-free value is never assumed to be UTC. */
  static long TimeMs(string s, out string zone){
    zone = "";
    if(s.Length == 0) return 0;
    if(LASTTS != null && s == LASTTS){ zone = LASTZ; return LASTMS; }
    string b = s, z = "";
    Match iz = ISOZ.Match(s);
    if(iz.Success){ b = iz.Groups[1].Value; z = iz.Groups[2].Value; }
    else {
      int sp = s.LastIndexOf(' ');
      if(sp > 0){
        string suf = s.Substring(sp + 1);
        bool alpha = suf.Length >= 1 && suf.Length <= 5; foreach(char ch in suf) if(!char.IsLetter(ch)){ alpha = false; break; }
        if(suf != "AM" && suf != "PM" && suf != "am" && suf != "pm" && (alpha || ((suf[0] == '+' || suf[0] == '-' || suf.StartsWith("GMT") || suf.StartsWith("UTC")) && TZNUM.IsMatch(suf)))){ z = suf; b = s.Substring(0, sp); }
      }
    }
    DateTime dt = DateTime.MinValue; bool got = false;
    if(FMTHINT >= 0 && DateTime.TryParseExact(b, TFMT[FMTHINT], CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dt)) got = true;
    else {
      for(int i = 0; i < TFMT.Length && !got; i++){ if(DateTime.TryParseExact(b, TFMT[i], CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dt)){ got = true; FMTHINT = i; } }
      /* general fallback on the zone-stripped text only; a result the parser converted (it found a zone we did not strip) is rejected */
      if(!got){ if(!DateTime.TryParse(b, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dt) || dt.Kind != DateTimeKind.Unspecified) return 0; }
    }
    if(z == "Z") z = "UTC";
    int off;
    if(OVERRIDE != int.MinValue){ off = OVERRIDE; zone = (z.Length > 0 ? z : "(none)") + " -> override"; }
    else {
      if(z.Length == 0) throw new Exception("Event Time values carry no timezone (e.g. '" + s + "'). Set Source timezone (+HH:MM) in the control panel to the exporting admin's portal timezone, then process again.");
      bool ok; off = ParseOffset(z, out ok);
      if(!ok) throw new Exception("Unknown timezone abbreviation '" + z + "' in Event Time ('" + s + "'). Set Source timezone (+HH:MM) in the control panel, then process again.");
      zone = z;
    }
    long ms = (long)(DateTime.SpecifyKind(dt, DateTimeKind.Utc) - EPOCH).TotalMilliseconds - off * 60000L;
    LASTTS = s; LASTMS = ms; LASTZ = zone;
    return ms;
  }
  public static string Ts(long ms){
    if(ms <= 0 || ms == long.MaxValue || ms == long.MinValue) return "";
    return EPOCH.AddMilliseconds(ms).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
  }

  /* ---------------- URL / host helpers ---------------- */
  static string HostOf(string url){
    string u = url; int p = u.IndexOf("://"); if(p >= 0 && p < 10) u = u.Substring(p + 3);
    int e = u.IndexOfAny(new char[]{ '/', '?', '#' }); if(e >= 0) u = u.Substring(0, e);
    int at = u.LastIndexOf('@'); if(at >= 0) u = u.Substring(at + 1);
    if(u.StartsWith("[")){ int rb = u.IndexOf(']'); if(rb > 0) return u.Substring(1, rb - 1).ToLowerInvariant(); }
    int c = u.LastIndexOf(':'); if(c > 0 && u.IndexOf(':') == c) u = u.Substring(0, c);
    return u.Trim().TrimEnd('.').ToLowerInvariant();
  }
  static readonly Regex IPV4 = new Regex(@"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", RegexOptions.Compiled);
  static bool IsIp(string h){ return IPV4.IsMatch(h) || (h.IndexOf(':') >= 0 && Regex.IsMatch(h, "^[0-9a-f:]+$")); }
  static readonly HashSet<string> SLD2 = new HashSet<string>(StringComparer.Ordinal){ "co","com","net","org","gov","ac","edu","ltd","plc","sch","nic","res","gen","firm","ind","mil","or","ne","go" };
  static string DomainOf(string h){
    if(IsIp(h)) return h;
    string[] p = h.Split('.'); if(p.Length <= 2) return h;
    int n = p.Length;
    if(p[n - 1].Length == 2 && SLD2.Contains(p[n - 2])) return p[n - 3] + "." + p[n - 2] + "." + p[n - 1];
    return p[n - 2] + "." + p[n - 1];
  }
  static double Entropy(string h){
    string d = DomainOf(h); int dot = d.IndexOf('.'); string s = dot > 0 ? d.Substring(0, dot) : d;
    if(s.Length == 0 || IsIp(h)) return 0;
    Dictionary<char,int> f = new Dictionary<char,int>(); foreach(char c in s){ int v; f.TryGetValue(c, out v); f[c] = v + 1; }
    double e = 0; foreach(int v in f.Values){ double pr = (double)v / s.Length; e -= pr * Math.Log(pr, 2); }
    return Math.Round(e, 2);
  }

  /* ---------------- classification ---------------- */
  /* egress / bypass channels a row belongs to (may be several) */
  static readonly Regex RX_REMOTE = new Regex(@"anydesk|teamviewer|screenconnect|connectwise|splashtop|rustdesk|logmein|gotoassist|goto\.com|ammyy|ultraviewer|supremo|atera|netsupport|zoho ?assist|assist\.zoho|bomgar|beyondtrust|remotepc|dwservice|meshcentral|tacticalrmm|level\.io|action1|remoteutilities|getscreen|parsec\.app|nomachine|chrome ?remote ?desktop|remotedesktop\.google", RegexOptions.IgnoreCase | RegexOptions.Compiled);
  static readonly Regex RX_TUNNEL = new Regex(@"ngrok|trycloudflare|loca\.lt|localtunnel|serveo|localhost\.run|tailscale|zerotier|playit\.gg|portmap\.io|pinggy|bore\.pub|cloudflared|torproject|\.onion", RegexOptions.IgnoreCase | RegexOptions.Compiled);
  static readonly Regex RX_PASTE = new Regex(@"pastebin|paste\.ee|hastebin|ghostbin|rentry\.|transfer\.sh|file\.io|temp\.sh|gofile\.io|anonfiles|catbox\.moe|0x0\.st|tmpfiles|bashupload|filebin|termbin|privatebin|controlc\.com|justpaste|dpaste|workers\.dev|pages\.dev|glitch\.me|webhook\.site|requestbin|pipedream|api\.telegram\.org|discord(app)?\.com/api/webhooks|cdn\.discordapp|mega\.nz|mega\.io|wetransfer|sendspace|anonymfile|ufile\.io|filemail|send\.vis\.ee|limewire\.com|easyupload|file\.pizza|krakenfiles|pixeldrain|qu\.ax|uguu\.se|bayfiles", RegexOptions.IgnoreCase | RegexOptions.Compiled);
  static readonly Regex RX_SEC_ACTION = new Regex(@"malic|malware|virus|exploit|phish|botnet|suspicious|sandbox|spyware|threat|ransom|crypto ?min|command and control|c2|dlp|data loss|quarantin", RegexOptions.IgnoreCase | RegexOptions.Compiled);
  static List<string> THEMES = new List<string>();
  static Dictionary<string,string[]> THEMECACHE = new Dictionary<string,string[]>(StringComparer.Ordinal);
  static string[] THEMEARR = new string[0];
  /* classification depends only on host / category / app / class (plus the webhook path test), so it is cached per
     distinct combination - a million rows hit a few thousand combinations */
  static void Themes(string host, string url, string cat, string supercat, string urlclass, string appclass, string app){
    bool hook = (host.IndexOf("discord", StringComparison.Ordinal) >= 0 && url.IndexOf("/api/webhooks", StringComparison.OrdinalIgnoreCase) >= 0);
    string key = host + "\u0001" + cat + "\u0001" + appclass + "\u0001" + app + "\u0001" + urlclass + (hook ? "\u0001h" : "");
    string[] hitc; if(THEMECACHE.TryGetValue(key, out hitc)){ THEMEARR = hitc; return; }
    ThemesCompute(host, hook ? host + "/api/webhooks" : host, cat, supercat, urlclass, appclass, app);
    THEMEARR = THEMES.ToArray(); THEMECACHE[key] = THEMEARR;
  }
  static void ThemesCompute(string host, string url, string cat, string supercat, string urlclass, string appclass, string app){
    THEMES.Clear();
    string ca = cat + " | " + appclass;
    if(IsIp(host)) THEMES.Add("Raw IP destination");
    if(ca.IndexOf("File Shar", StringComparison.OrdinalIgnoreCase) >= 0 || cat.IndexOf("FileHost", StringComparison.OrdinalIgnoreCase) >= 0 || cat.IndexOf("Online Storage", StringComparison.OrdinalIgnoreCase) >= 0 || ca.IndexOf("Peer-to-Peer", StringComparison.OrdinalIgnoreCase) >= 0 || ca.IndexOf("P2P", StringComparison.Ordinal) >= 0) THEMES.Add("File sharing / storage");
    if(ca.IndexOf("Web Mail", StringComparison.OrdinalIgnoreCase) >= 0 || cat.IndexOf("Webmail", StringComparison.OrdinalIgnoreCase) >= 0) THEMES.Add("Webmail");
    if(appclass.IndexOf("AI & ML", StringComparison.OrdinalIgnoreCase) >= 0 || cat.IndexOf("Generative AI", StringComparison.OrdinalIgnoreCase) >= 0) THEMES.Add("Generative AI");
    if(cat.IndexOf("Remote Access", StringComparison.OrdinalIgnoreCase) >= 0 || RX_REMOTE.IsMatch(app) || RX_REMOTE.IsMatch(host)) THEMES.Add("Remote access tool");
    if(ca.IndexOf("DNS Over HTTPS", StringComparison.OrdinalIgnoreCase) >= 0) THEMES.Add("DNS over HTTPS");
    if((Regex.IsMatch(cat, "Anonymi|Proxy|Tor\\b|\\bVPN|Tunnel", RegexOptions.IgnoreCase) && cat.IndexOf("Zscaler", StringComparison.OrdinalIgnoreCase) < 0) || RX_TUNNEL.IsMatch(host)) THEMES.Add("Anonymiser / proxy / tunnel");
    if(RX_PASTE.IsMatch(url)) THEMES.Add("Paste / temp file hosting / webhook");
    if(Regex.IsMatch(cat, "Newly Reg|Newly Rev|Newly Obs|Miscellaneous or Unknown|^Unknown|Non-Categoriz|Parked|Dynamic DNS", RegexOptions.IgnoreCase)) THEMES.Add("Newly registered / uncategorised");
    if(cat.IndexOf("Crypto", StringComparison.OrdinalIgnoreCase) >= 0) THEMES.Add("Cryptocurrency");
    if(Regex.IsMatch(cat, "Spyware|Adware", RegexOptions.IgnoreCase) || urlclass.IndexOf("Privacy Risk", StringComparison.OrdinalIgnoreCase) >= 0) THEMES.Add("Spyware / adware (privacy risk)");
  }
  static string ThemeKey(string t){
    switch(t){
      case "Raw IP destination": return "rawip"; case "File sharing / storage": return "file"; case "Webmail": return "mail"; case "Generative AI": return "ai";
      case "Remote access tool": return "remote"; case "DNS over HTTPS": return "doh"; case "Anonymiser / proxy / tunnel": return "anon";
      case "Paste / temp file hosting / webhook": return "paste"; case "Newly registered / uncategorised": return "newuncat"; case "Cryptocurrency": return "crypto";
      default: return "spy";
    }
  }
  static readonly string[] UTHEME = { "rawip", "file", "mail", "ai", "remote", "doh", "anon", "paste", "newuncat", "crypto", "spy" };
  static Dictionary<string,int> ACTCACHE = new Dictionary<string,int>(StringComparer.Ordinal);
  /* bit 1 allowed, 2 security-type action, 4 SSL / certificate block */
  static int ActClass(string action){
    int v; if(ACTCACHE.TryGetValue(action, out v)) return v;
    bool al = Allowed(action);
    v = (al ? 1 : 0) | (!al && RX_SEC_ACTION.IsMatch(action) ? 2 : 0) | (!al && Regex.IsMatch(action, "SSL|handshake|certificate", RegexOptions.IgnoreCase) ? 4 : 0);
    ACTCACHE[action] = v; return v;
  }
  static Dictionary<string,bool> SECCAT = new Dictionary<string,bool>(StringComparer.Ordinal);
  static bool SecCat(string supercat, string urlclass){
    string k = supercat + "\u0001" + urlclass; bool v; if(SECCAT.TryGetValue(k, out v)) return v;
    v = supercat.IndexOf("Advanced Security", StringComparison.OrdinalIgnoreCase) >= 0 || Regex.IsMatch(urlclass, "Security Risk", RegexOptions.IgnoreCase);
    SECCAT[k] = v; return v;
  }
  /* an EMPTY action is an unknown outcome - never counted as allowed (or blocked) */
  static bool Allowed(string action){ return action.StartsWith("Allow", StringComparison.OrdinalIgnoreCase) || action.Equals("Caution", StringComparison.OrdinalIgnoreCase) || action.StartsWith("Isolat", StringComparison.OrdinalIgnoreCase); }
  /* implant-style URL paths, tested on EVERY record's full path (not on the bounded display samples), so detection does
     not depend on export order. Strong: command / tasking endpoints, or a query that reports host and user. Weak: generic
     tasking / check-in words - the viewer only scores them on raw-IP / uncategorised hosts. Same expressions as the viewer. */
  static readonly Regex RX_C2 = new Regex(@"/(cmd|cmds|getcmd|sendcmd|implant|exfil|gate\.php)(/|\?|\s|$)|[?&](h|host|hostname|computer|pc|machine|hwid)=[^&\s]+&(u|user|username)=", RegexOptions.IgnoreCase | RegexOptions.Compiled);
  static readonly Regex RX_C2WEAK = new Regex(@"/(command|commands|task|tasks|tasking|checkin|check-in|hello|register)(/|\?|\s|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

  /* ---------------- aggregates ---------------- */
  static Dictionary<string,ZsAgg> USERS, HOSTS, CATS, APPS, ACTS, BLOCKED, CHAN, COVDAY, IOCT;
  static Dictionary<string,List<int>> PAIRS;
  static Dictionary<string,int[]> HOW;
  static Dictionary<long,HashSet<string>> HOURUSERS;
  static ZsList SEC, UNSC, IOCH, BIGUP;
  static string[] IOCS = new string[0];
  static long FROMMS = 0, TOMS = 0, BASEMS = 0;
  static long RECS = 0, PARSED = 0, BAD = 0, INCOMPLETE = 0, OUTWIN = 0, SECN = 0, THREATN = 0, ALLOWN = 0, BLOCKN = 0, UNKN = 0, AMBIG = 0;
  static int HDRN = 0;
  static Dictionary<string,Dictionary<long,long>> SER = new Dictionary<string,Dictionary<long,long>>(StringComparer.Ordinal);
  static void Hit(string name, long ms, long v){
    if(v <= 0 || ms <= 0) return;
    long b = ms / 3600000L;
    Dictionary<long,long> d; if(!SER.TryGetValue(name, out d)){ d = new Dictionary<long,long>(); SER[name] = d; }
    long c; d.TryGetValue(b, out c); d[b] = c + v;
  }
  static ZsAgg Get(Dictionary<string,ZsAgg> m, string k){ ZsAgg a; if(!m.TryGetValue(k, out a)){ a = new ZsAgg(); m[k] = a; } return a; }

  static void OnRecord(ZsFile f, long line, long ms, string rawLine){
    string user = Fz("user"); if(user.Length == 0) user = "(no user)";
    string url = F("url"), host = HostOf(url); if(host.Length == 0) host = "(no host)";
    string action = Fz("action"), appclass = Fz("appclass"), app = Fz("app"), urlclass = Fz("urlclass"), supercat = Fz("supercat"), cat = Fz("cat");
    string threatcat = Fz("threatcat"), threat = Fz("threat"), dept = Fz("dept"), loc = Fz("location"), bt = Fz("blocktype");
    string certv = Fz("certvalid"), selfs = Fz("selfsigned"), dlpmd5 = Fz("dlpmd5"), dlpid = Fz("dlpid"), dlpeng = Fz("dlpengine"), unsc = Fz("unscannable");
    int acls = ActClass(action); bool allowed = (acls & 1) != 0, known = action.Length > 0, blocked = known && !allowed;
    long req = Fn("reqsize"), resp = Fn("respsize");
    /* why this row is a security event (several reasons may apply) */
    List<string> why = new List<string>();
    if(threat.Length > 0) why.Add("threat name");
    if(threatcat.Length > 0) why.Add("threat category");
    if(bt.Length > 0 && !bt.Equals("URL Filtering", StringComparison.OrdinalIgnoreCase)) why.Add("policy: " + bt);
    if((acls & 2) != 0) why.Add("action");
    if(SecCat(supercat, urlclass)) why.Add("security category");
    if(dlpmd5.Length > 0 || dlpid.Length > 0 || dlpeng.Length > 0) why.Add("DLP");
    if(certv.Equals("Fail", StringComparison.OrdinalIgnoreCase) || selfs.Equals("Yes", StringComparison.OrdinalIgnoreCase)) why.Add("certificate");
    if(Fz("filemd5").Length > 0 && (threat.Length > 0 || threatcat.Length > 0)) why.Add("file hash");
    bool sec = why.Count > 0;
    bool sslIssue = (acls & 4) != 0;
    Themes(host, url, cat, supercat, urlclass, appclass, app);
    string extra = Extra();

    if(allowed) ALLOWN++; else if(blocked) BLOCKN++; else UNKN++;
    Hit("req", ms, 1); Hit(!known ? "unknown" : (allowed ? "allowed" : (sec ? "blocked.sec" : (sslIssue ? "blocked.ssl" : "blocked.policy"))), ms, 1);
    if(sec){ SECN++; Hit(!known ? "sec.unknown" : (allowed ? "sec.allowed" : "sec.blocked"), ms, 1); }
    if(threat.Length > 0 || threatcat.Length > 0){ THREATN++; Hit("threat", ms, 1); }
    if(unsc.Length > 0) Hit("unscannable", ms, 1);
    if(known) foreach(string th in THEMEARR) Hit("ch." + ThemeKey(th) + (allowed ? ".a" : ".b"), ms, 1);
    Hit("u|" + user, ms, 1);
    if(dept.Length > 0) Hit("d|" + dept, ms, 1);
    if(req > 0) Hit("bytes.out", ms, req); if(resp > 0) Hit("bytes.in", ms, resp);
    { long hb = ms / 3600000L; HashSet<string> hs; if(!HOURUSERS.TryGetValue(hb, out hs)){ hs = new HashSet<string>(StringComparer.OrdinalIgnoreCase); HOURUSERS[hb] = hs; } hs.Add(user); }
    { int[] hw; if(!HOW.TryGetValue(user, out hw)){ hw = new int[336]; HOW[user] = hw; } long dayN = ms / 86400000L; int dow = (int)((dayN + 4) % 7); int hh = (int)((ms % 86400000L) / 1800000L); hw[dow * 48 + hh]++;
      int[] ha; if(!HOW.TryGetValue("*", out ha)){ ha = new int[336]; HOW["*"] = ha; } ha[dow * 48 + hh]++; }

    ZsAgg u = Get(USERS, user); if(u.S0.Length == 0){ u.S0 = user; u.Cap = 200000; }
    u.Seen(ms); u.Add(0, host); u.Add(1, cat); u.Add(3, dept); u.Add(4, loc); u.Day(ms);
    if(allowed) u.C[0]++; else if(blocked){ u.C[1]++; u.Add(2, cat); } else u.C[6]++;
    if(sec) u.C[2]++; if(threat.Length > 0 || threatcat.Length > 0) u.C[3]++;
    if(unsc.Length > 0) u.C[4]++; if(sslIssue) u.C[5]++;
    u.C[14] += req; u.C[15] += resp;
    foreach(string th in THEMEARR){ int k = Array.IndexOf(UTHEME, ThemeKey(th)); if(k >= 0 && k < 11) u.Add(5, ThemeKey(th)); }
    if(IsIp(host)) u.Add(6, host);
    if(Fz("clientip").Length > 0) u.Add(7, Fz("clientip")); if(Fz("pubip").Length > 0) u.Add(8, Fz("pubip")); if(Fz("devhost").Length > 0) u.Add(9, Fz("devhost"));

    ZsAgg h = Get(HOSTS, host); if(h.S0.Length == 0){ h.S0 = host; h.Cap = 100000; }
    h.Seen(ms); h.Add(0, user); h.Add(1, cat); h.Add(2, supercat); h.Add(3, urlclass); h.Add(4, app); h.Add(5, appclass); h.Add(6, action.Length > 0 ? action : "(none)"); h.Day(ms);
    foreach(string th in THEMEARR) h.Add(7, th);
    if(Fz("serverip").Length > 0) h.Add(8, Fz("serverip"));
    if(allowed) h.C[0]++; else if(blocked) h.C[1]++; if(sec) h.C[2]++; h.C[3] += req; h.C[4] += resp;
    { int sl = url.IndexOf('/'); string fullPath = sl >= 0 ? url.Substring(sl) : "";
      /* C2 path test on the FULL path of every record; the first hits keep their path and citation */
      if(fullPath.Length > 1){ bool strong = RX_C2.IsMatch(fullPath), weak = !strong && RX_C2WEAK.IsMatch(fullPath);
        if(strong || weak){ if(strong) h.C[5]++; else h.C[6]++; string ex = fullPath.Length > 200 ? fullPath.Substring(0, 200) + "..." : fullPath; h.HitPath((strong ? "strong " : "weak ") + ex + " [" + f.Rel + "#row=" + line + "]", strong ? 4 : 2); } }
      string path = fullPath.Length > 160 ? fullPath.Substring(0, 160) + "..." : fullPath; h.Sample(path, 6); }
    List<int> pl; string pk = user + "\t" + host; if(!PAIRS.TryGetValue(pk, out pl)){ pl = new List<int>(); PAIRS[pk] = pl; } pl.Add((int)((ms - BASEMS) / 1000L));

    ZsAgg c = Get(CATS, supercat + "\t" + cat + "\t" + urlclass); if(c.N == 0){ c.S0 = supercat; c.S1 = cat; c.S2 = urlclass; c.Cap = 50000; }
    c.Seen(ms); c.Add(0, host); c.Add(1, user); if(allowed) c.C[0]++; else if(blocked) c.C[1]++;

    if(app.Length > 0){ ZsAgg a = Get(APPS, appclass + "\t" + app); if(a.N == 0){ a.S0 = appclass; a.S1 = app; a.Cap = 50000; }
      a.Seen(ms); a.Add(0, host); a.Add(1, user); if(allowed) a.C[0]++; else if(blocked) a.C[1]++; a.C[3] += req; a.C[4] += resp; }

    { ZsAgg ac = Get(ACTS, (action.Length > 0 ? action : "(none)") + "\t" + bt); if(ac.N == 0){ ac.S0 = action.Length > 0 ? action : "(none)"; ac.S1 = bt; ac.Cap = 50000; }
      ac.Seen(ms); ac.Add(0, host); ac.Add(1, user); ac.Add(2, cat); }

    if(blocked){ ZsAgg bl = Get(BLOCKED, user + "\t" + host + "\t" + action); if(bl.N == 0){ bl.S0 = user; bl.S1 = host; bl.S2 = action; bl.S3 = url; }
      bl.Seen(ms); bl.Add(0, bt); bl.Add(1, cat); bl.Add(2, app); }

    foreach(string th in THEMEARR){
      ZsAgg ch = Get(CHAN, th + "\t" + user + "\t" + host); if(ch.N == 0){ ch.S0 = th; ch.S1 = user; ch.S2 = host; ch.S3 = url; }
      ch.Seen(ms); ch.Add(0, cat); ch.Add(1, app); ch.Add(2, action); if(allowed) ch.C[0]++; else if(blocked) ch.C[1]++; ch.C[3] += req; ch.C[4] += resp; ch.Day(ms);
    }

    { ZsAgg cd = Get(COVDAY, (ms / 86400000L).ToString()); if(cd.N == 0){ cd.C[9] = ms / 86400000L; cd.Cap = 200000; } cd.Seen(ms); cd.Add(0, user); cd.Add(1, host); if(allowed) cd.C[0]++; else if(blocked) cd.C[1]++; if(sec) cd.C[2]++; }

    string ts = Ts(ms), traw = F("time");
    if(sec){
      bool prio = threat.Length > 0 || threatcat.Length > 0 || allowed || why.Contains("DLP");
      SEC.Add(prio, ts, user, host, url, action, bt, threatcat, threat, urlclass, supercat, cat, app, dept, certv, selfs, dlpmd5, dlpid, unsc, string.Join("; ", why.ToArray()), extra, traw, f.Rel, line);
    }
    if(unsc.Length > 0) UNSC.Add(allowed, ts, user, host, url, action, unsc, cat, app, dept, extra, traw, f.Rel, line);
    if(req >= 10485760L) BIGUP.Add(req >= 104857600L, ts, user, host, url, action, req, resp, cat, app, extra, traw, f.Rel, line);
    if(IOCS.Length > 0){
      string low = rawLine.ToLowerInvariant();
      foreach(string term in IOCS){
        int p = low.IndexOf(term, StringComparison.Ordinal);
        while(p >= 0){
          bool lb = p == 0 || !char.IsLetterOrDigit(low[p - 1]), rb = p + term.Length >= low.Length || !char.IsLetterOrDigit(low[p + term.Length]);
          if((lb || !char.IsLetterOrDigit(term[0])) && (rb || !char.IsLetterOrDigit(term[term.Length - 1]))){
            IOCH.Add(true, ts, term, user, host, url, action, cat, threat, f.Rel, line);
            ZsAgg it = Get(IOCT, term); it.S0 = term; it.Seen(ms); it.Add(0, user); it.Add(1, host); it.Add(2, action);
            Hit("ioc", ms, 1);
            break;
          }
          p = low.IndexOf(term, p + 1, StringComparison.Ordinal);
        }
      }
    }
  }
  static readonly string[][] EXTRA = { new string[]{"clientip","ClientIP"}, new string[]{"pubip","PublicIP"}, new string[]{"serverip","ServerIP"}, new string[]{"method","Method"},
    new string[]{"status","Status"}, new string[]{"reqsize","ReqBytes"}, new string[]{"respsize","RespBytes"}, new string[]{"filetype","FileType"}, new string[]{"filename","FileName"},
    new string[]{"filemd5","MD5"}, new string[]{"devhost","Device"}, new string[]{"devowner","Owner"}, new string[]{"ua","UA"}, new string[]{"referer","Referer"}, new string[]{"risk","Risk"},
    new string[]{"alpn","ALPN"}, new string[]{"fwdrule","FwdRule"}, new string[]{"fwdmethod","FwdMethod"}, new string[]{"gwname","Gateway"}, new string[]{"gwip","GatewayIP"}, new string[]{"location","Location"} };
  static string Extra(){
    StringBuilder b = new StringBuilder();
    foreach(string[] e in EXTRA){ string v = Fz(e[0]); if(v.Length == 0) continue; if(b.Length > 0) b.Append("; "); b.Append(e[1]).Append('=').Append(v.Length > 200 ? v.Substring(0, 200) + "..." : v); }
    return b.ToString();
  }

  /* ---------------- input ---------------- */
  [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
  static extern int GetLongPathName(string shortPath, StringBuilder longPath, int bufferLength);
  /* one spelling per file: absolute, ".." resolved, 8.3 short names (PROGRA~1) expanded; compared case-insensitively */
  static string Canon(string p){
    string full = Path.GetFullPath(p);
    try{ StringBuilder sb = new StringBuilder(1024); int n = GetLongPathName(full, sb, sb.Capacity);
      if(n > sb.Capacity){ sb = new StringBuilder(n + 1); n = GetLongPathName(full, sb, sb.Capacity); }
      if(n > 0) full = sb.ToString(); }catch{}
    return full;
  }
  public static int DUPINPUTS = 0;
  /* every source file is read ONCE however it was reached (parent + child folder, folder + one of its files, the same
     path twice, differently spelled aliases), and its SourceFile id is its path relative to the common root of the
     whole unique file set - unique within the run, and the same whichever way the same files were selected */
  public static List<ZsFile> Enumerate(string input){
    List<ZsFile> o = new List<ZsFile>();
    HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    DUPINPUTS = 0;
    foreach(string part in input.Split('|')){
      string p = part.Trim(); if(p.Length == 0) continue;
      List<string> found = new List<string>();
      if(File.Exists(p)) found.Add(p);
      else if(Directory.Exists(p)){
        foreach(string x in Directory.GetFiles(p, "*", SearchOption.AllDirectories)){ if(x.IndexOf("\\_Processed\\", StringComparison.OrdinalIgnoreCase) >= 0) continue; found.Add(x); }
      }
      foreach(string x in found){ string c = Canon(x); if(!seen.Add(c)){ DUPINPUTS++; continue; } ZsFile f = new ZsFile(); f.Path = c; o.Add(f); }
    }
    o.Sort(delegate(ZsFile a, ZsFile b){ return StringComparer.OrdinalIgnoreCase.Compare(a.Path, b.Path); });
    /* common root directory of all unique files (none when they span drives -> the full path is the id) */
    string common = null;
    foreach(ZsFile f in o){ string dir = Path.GetDirectoryName(f.Path).TrimEnd('\\') + "\\";
      if(common == null){ common = dir; continue; }
      while(common.Length > 0 && !dir.StartsWith(common, StringComparison.OrdinalIgnoreCase)){ string t = common.TrimEnd('\\'); int cut = t.LastIndexOf('\\'); common = cut >= 0 ? t.Substring(0, cut + 1) : ""; } }
    foreach(ZsFile f in o) f.Rel = (common != null && common.Length > 0 && f.Path.StartsWith(common, StringComparison.OrdinalIgnoreCase)) ? f.Path.Substring(common.Length) : f.Path;
    foreach(ZsFile f in o){
      string why; int hl = Sniff(f.Path, out why);
      if(hl > 0) f.Read = true; else { f.Status = why.StartsWith("FAILED") ? why : "skipped - not a Zscaler web-log CSV"; f.Note = why.StartsWith("FAILED") ? "" : why; }
    }
    return o;
  }
  /* a ZIA web-log CSV: within the first 40 lines, a header row naming a time column, URL and an action column */
  public static int Sniff(string path, out string why){
    why = "";
    if(!Regex.IsMatch(path, @"\.(csv|txt)$", RegexOptions.IgnoreCase)){ why = "not a .csv / .txt file"; return 0; }
    try{
      using(StreamReader r = new StreamReader(path, Encoding.UTF8, true)){
        List<string> o = new List<string>(); string line; int n = 0;
        while((line = r.ReadLine()) != null && n < 40){
          n++; SplitCsv(line, o);
          bool t = false, u = false, a = false;
          foreach(string c in o){ string x = c.Trim(); if(x == "Event Time" || x == "Time" || x == "Logged Time" || x == "Datetime") t = true; if(x == "URL") u = true; if(x == "Policy Action" || x == "Action") a = true; }
          if(t && u && a) return n;
        }
      }
      why = "no Zscaler web-log header row (Event Time, URL, Policy Action) in the first 40 lines";
    } catch(Exception ex){ why = "FAILED - " + ex.GetType().Name + ": " + ex.Message; }
    return 0;
  }

  public static string Run(string input, string outDir, string host, string stamp, string from, string to, string tzOverride, string iocFile, string progress, string appVersion){
    DateTime t0 = DateTime.UtcNow;
    USERS = new Dictionary<string,ZsAgg>(StringComparer.OrdinalIgnoreCase); HOSTS = new Dictionary<string,ZsAgg>(StringComparer.OrdinalIgnoreCase);
    CATS = new Dictionary<string,ZsAgg>(); APPS = new Dictionary<string,ZsAgg>(); ACTS = new Dictionary<string,ZsAgg>(); BLOCKED = new Dictionary<string,ZsAgg>(StringComparer.OrdinalIgnoreCase);
    CHAN = new Dictionary<string,ZsAgg>(StringComparer.OrdinalIgnoreCase); COVDAY = new Dictionary<string,ZsAgg>(); IOCT = new Dictionary<string,ZsAgg>();
    PAIRS = new Dictionary<string,List<int>>(StringComparer.OrdinalIgnoreCase); HOW = new Dictionary<string,int[]>(StringComparer.OrdinalIgnoreCase);
    HOURUSERS = new Dictionary<long,HashSet<string>>(); SER.Clear(); TZSEEN.Clear();
    if(!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);
    string[] SECCOLS = { "Time_UTC", "User", "Host", "URL", "Action", "BlockedPolicyType", "ThreatCategory", "ThreatName", "URLClass", "SuperCategory", "Category", "CloudApp", "Department", "CertChain", "SelfSigned", "DLP_MD5", "DLP_Identifier", "Unscannable", "Reason", "Extra", "Time_Source", "SourceFile", "SourceLine" };
    SEC = new ZsList("security_events", outDir, stamp, SECCOLS);
    UNSC = new ZsList("unscannable", outDir, stamp, "Time_UTC", "User", "Host", "URL", "Action", "UnscannableType", "Category", "CloudApp", "Department", "Extra", "Time_Source", "SourceFile", "SourceLine");
    BIGUP = new ZsList("large_uploads", outDir, stamp, "Time_UTC", "User", "Host", "URL", "Action", "ReqBytes", "RespBytes", "Category", "CloudApp", "Extra", "Time_Source", "SourceFile", "SourceLine");
    IOCH = new ZsList("ioc_hits", outDir, stamp, "Time_UTC", "Term", "User", "Host", "URL", "Action", "Category", "ThreatName", "SourceFile", "SourceLine");
    ZsList[] lists = { SEC, UNSC, BIGUP, IOCH };
    DateTime df;
    FROMMS = 0; TOMS = 0; RECS = 0; PARSED = 0; BAD = 0; INCOMPLETE = 0; OUTWIN = 0; SECN = 0; THREATN = 0; ALLOWN = 0; BLOCKN = 0; UNKN = 0; AMBIG = 0; HDRN = 0; BASEMS = 0; LASTTS = null; FMTHINT = -1;
    if(from.Length > 0 && DateTime.TryParseExact(from, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out df)) FROMMS = (long)(df - EPOCH).TotalMilliseconds;
    if(to.Length > 0 && DateTime.TryParseExact(to, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out df)) TOMS = (long)(df.AddDays(1) - EPOCH).TotalMilliseconds - 1;
    OVERRIDE = int.MinValue;
    if(tzOverride.Length > 0){ bool ok; int off = ParseOffset(tzOverride, out ok); if(!ok) throw new Exception("Source timezone override '" + tzOverride + "' is not +HH:MM / -HH:MM"); OVERRIDE = off; }
    List<string> terms = new List<string>();
    if(iocFile.Length > 0 && File.Exists(iocFile)){
      foreach(string ln in File.ReadAllLines(iocFile)){ foreach(string t in ln.Split(new char[]{ ',', ';' })){ string x = t.Trim().ToLowerInvariant(); if(x.Length >= 3 && x[0] != '#' && !terms.Contains(x)) terms.Add(x); } }
    }
    IOCS = terms.ToArray();
    Log("ZScaler engine " + appVersion + " - target " + host + " - IOC terms " + IOCS.Length + (OVERRIDE != int.MinValue ? (" - timezone override " + tzOverride) : "") + (FROMMS > 0 || TOMS > 0 ? (" - window " + from + " .. " + to) : ""));
    List<ZsFile> cands = Enumerate(input);
    List<ZsFile> files = cands.FindAll(delegate(ZsFile f){ return f.Read; });
    int nFailed = 0, nSkipped = 0;
    foreach(ZsFile f in cands){ if(!f.Read){ if(f.Status.StartsWith("FAILED")) nFailed++; else nSkipped++; } }
    if(files.Count == 0){ foreach(ZsList l in lists) l.Close(); throw new Exception("No Zscaler web-log CSV found under: " + input + " (a header row with Event Time, URL and Policy Action is expected)"); }
    long totalBytes = 0; foreach(ZsFile f in files){ try{ totalBytes += new FileInfo(f.Path).Length; }catch{} }
    Log("Files: " + files.Count + " (" + (totalBytes / 1048576) + " MB)" + (nFailed > 0 ? (" - " + nFailed + " UNREADABLE") : "") + (nSkipped > 0 ? (" - " + nSkipped + " not Zscaler web-log CSV") : "") + (DUPINPUTS > 0 ? (" - " + DUPINPUTS + " duplicate path(s) reached through overlapping inputs ignored") : ""));
    int fi = 0; DateTime lastProg = DateTime.MinValue; long doneBytes = 0; List<string> fl = new List<string>();
    foreach(ZsFile f in files){
      fi++;
      long flen = 0; try{ flen = new FileInfo(f.Path).Length; }catch{}
      Log("[" + fi + "/" + files.Count + "] " + f.Rel + " (" + (flen / 1048576) + " MB)");
      long ln = 0, prevMs = 0;
      try{
        using(StreamReader r = new StreamReader(f.Path, Encoding.UTF8, true, 1 << 20)){
          string line; bool inHdr = false; IX.Clear(); string pending = null; long pendLine = 0;
          while((line = r.ReadLine()) != null){
            ln++;
            if(!inHdr){
              SplitCsv(line, fl);
              string k0 = fl.Count > 0 ? fl[0].Trim() : "", v1 = fl.Count > 1 ? fl[1].Trim() : "";
              bool t = false, u = false; foreach(string c in fl){ string x = c.Trim(); if(x == "Event Time" || x == "Time" || x == "Logged Time" || x == "Datetime") t = true; if(x == "URL") u = true; }
              if(t && u){ inHdr = true; MapHeader(fl, f); continue; }
              if(k0 == "Administrator") f.Admin = v1; else if(k0 == "Report Created") f.Created = v1;
              else if(k0.Length > 0){ f.Filters += (f.Filters.Length > 0 ? " | " : "") + k0 + ": " + (v1.Length > 300 ? v1.Substring(0, 300) + "..." : v1);
                if(k0 == "Users" || k0 == "User"){ Match mm = Regex.Match(v1, @"\[(.*)\]"); if(mm.Success) foreach(string x in mm.Groups[1].Value.Split(',')) if(x.Trim().Length > 0) f.FilterUsers.Add(x.Trim()); } }
              continue;
            }
            if(pending != null){ pending = pending + "\n" + line; if(!Balanced(pending)) continue; line = pending; pending = null; }
            else if(!Balanced(line)){ pending = line; pendLine = ln; continue; }
            long recLine = pendLine > 0 ? pendLine : ln; pendLine = 0;
            if(line.Length == 0) continue;
            SplitCsv(line, fl);
            if(fl.Count < 4){ BAD++; f.Bad++; continue; }
            RECS++; f.Records++;
            if(fl.Count != HDRN){ bool extraEmpty = fl.Count > HDRN; for(int xi = HDRN; extraEmpty && xi < fl.Count; xi++) if(fl[xi].Trim().Length > 0) extraEmpty = false;
              if(!extraEmpty){ INCOMPLETE++; f.Incomplete++; if(f.IncompleteLines.Count < 10) f.IncompleteLines.Add(recLine + " (" + fl.Count + " of " + HDRN + " fields)"); continue; } }
            REC = fl.ToArray();
            string zone; long ms = TimeMs(F("time"), out zone);
            if(ms <= 0){ BAD++; f.Bad++; continue; }
            if(zone.Length > 0){ long zc; f.Tz.TryGetValue(zone, out zc); f.Tz[zone] = zc + 1; TZSEEN.TryGetValue(zone, out zc); TZSEEN[zone] = zc + 1; if(TZAMBIG.Contains(zone)) AMBIG++; }
            if(prevMs > 0){ if(ms > prevMs) f.Asc++; else if(ms < prevMs) f.Desc++; } prevMs = ms;
            if((FROMMS > 0 && ms < FROMMS) || (TOMS > 0 && ms > TOMS)){ OUTWIN++; f.Outside++; continue; }
            if(BASEMS == 0) BASEMS = ms - 86400000L * 400;   // pair offsets stay positive ints for any export order
            PARSED++;
            if(ms < f.First) f.First = ms; if(ms > f.Last) f.Last = ms;
            OnRecord(f, recLine, ms, line);
            if((PARSED & 32767) == 0 && progress.Length > 0 && (DateTime.UtcNow - lastProg).TotalSeconds > 1){
              lastProg = DateTime.UtcNow;
              try{ File.WriteAllText(progress, "File " + fi + "/" + files.Count + " " + f.Rel + " - " + f.Records.ToString("N0") + " records - " + (doneBytes / 1048576) + " MB of earlier files done"); }catch{}
            }
          }
          if(pending != null){ BAD++; f.Bad++; f.Note += "last record has an unterminated quoted field (file truncated?); "; }
          if(!inHdr){ f.Status = "FAILED - header row not found"; nFailed++; }
          else f.Status = (f.Bad + f.Incomplete) > 0 ? "read (" + (f.Bad > 0 ? f.Bad + " unparsed" : "") + (f.Bad > 0 && f.Incomplete > 0 ? ", " : "") + (f.Incomplete > 0 ? f.Incomplete + " incomplete" : "") + " records)" : "read";
        }
      } catch(Exception ex){
        if(ex.Message.IndexOf("timezone", StringComparison.OrdinalIgnoreCase) >= 0){ foreach(ZsList l in lists) l.Close(); throw; }
        f.Status = "FAILED after " + ln + " lines"; f.Note += ex.GetType().Name + ": " + ex.Message; nFailed++; Log("WARN " + f.Rel + ": " + f.Note);
      }
      f.Lines = ln; doneBytes += flen;
      if(progress.Length > 0){ try{ File.WriteAllText(progress, "File " + fi + "/" + files.Count + " done - " + RECS.ToString("N0") + " records so far"); }catch{} }
    }
    foreach(ZsList l in lists) l.Close();
    Log("Parsed " + PARSED.ToString("N0") + " of " + RECS.ToString("N0") + " records (" + BAD + " unparsed, " + INCOMPLETE + " incomplete, " + OUTWIN + " outside window) in " + (DateTime.UtcNow - t0).TotalSeconds.ToString("0.0") + " s");
    if(progress.Length > 0){ try{ File.WriteAllText(progress, "Building tables (beacon timing, rarity)..."); }catch{} }
    List<ZsTable> tabs = BuildTables(cands);
    List<string> produced = new List<string>();
    foreach(ZsTable t in tabs){
      if(t.Rows.Count == 0) continue;
      string cp = Path.Combine(outDir, stamp + "_" + t.Name + ".csv");
      WriteCsv(cp, t); produced.Add(Path.GetFileName(cp));
    }
    foreach(ZsList l in lists){ if(l.Total > 0) produced.Add(Path.GetFileName(l.PathCsv)); else { try{ if(File.Exists(l.PathCsv)) File.Delete(l.PathCsv); }catch{} } }
    /* distinct users per hour */
    foreach(KeyValuePair<long,HashSet<string>> kv in HOURUSERS){ Dictionary<long,long> d; if(!SER.TryGetValue("users", out d)){ d = new Dictionary<long,long>(); SER["users"] = d; } d[kv.Key] = kv.Value.Count; }
    /* per-user series: keep the 60 busiest users only */
    List<KeyValuePair<string,ZsAgg>> ul = new List<KeyValuePair<string,ZsAgg>>(USERS); ul.Sort(delegate(KeyValuePair<string,ZsAgg> a, KeyValuePair<string,ZsAgg> b){ return b.Value.N.CompareTo(a.Value.N); });
    HashSet<string> keepU = new HashSet<string>(StringComparer.OrdinalIgnoreCase); for(int i = 0; i < ul.Count && i < 60; i++) keepU.Add(ul[i].Key);
    string jp = Path.Combine(outDir, San(host) + "-ZScaler-" + stamp + ".json");
    StringBuilder sb = new StringBuilder(1 << 22);
    long gFirst = long.MaxValue, gLast = 0; foreach(ZsFile f in files){ if(f.First < gFirst) gFirst = f.First; if(f.Last > gLast && f.Last != long.MinValue) gLast = f.Last; }
    sb.Append("{\"app\":\"ZScaler-Log-Analyzer\",\"appVersion\":").Append(J(appVersion)).Append(",\"host\":").Append(J(host));
    sb.Append(",\"stamp\":").Append(J(stamp)).Append(",\"input\":").Append(J(input)).Append(",\"outDir\":").Append(J(Path.GetFullPath(outDir))).Append(",\"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")));
    sb.Append(",\"elapsedSec\":").Append(((long)(DateTime.UtcNow - t0).TotalSeconds).ToString());
    sb.Append(",\"winFrom\":").Append(J(from)).Append(",\"winTo\":").Append(J(to)).Append(",\"tzOverride\":").Append(J(tzOverride));
    sb.Append(",\"records\":").Append(RECS).Append(",\"parsed\":").Append(PARSED).Append(",\"unparsed\":").Append(BAD).Append(",\"incomplete\":").Append(INCOMPLETE).Append(",\"outsideWindow\":").Append(OUTWIN);
    sb.Append(",\"filesRead\":").Append(files.Count).Append(",\"filesFailed\":").Append(nFailed).Append(",\"filesSkipped\":").Append(nSkipped).Append(",\"duplicateInputs\":").Append(DUPINPUTS);
    sb.Append(",\"first\":").Append(J(Ts(gFirst))).Append(",\"last\":").Append(J(Ts(gLast)));
    sb.Append(",\"previewCap\":").Append(ZsList.CAP);
    sb.Append(",\"stats\":{\"allowed\":").Append(ALLOWN).Append(",\"blocked\":").Append(BLOCKN).Append(",\"unknownOutcome\":").Append(UNKN).Append(",\"security\":").Append(SECN).Append(",\"threats\":").Append(THREATN)
      .Append(",\"users\":").Append(USERS.Count).Append(",\"hosts\":").Append(HOSTS.Count).Append(",\"ambiguousTzRows\":").Append(AMBIG).Append(",\"unscannable\":").Append(UNSC.Total).Append("}");
    sb.Append(",\"timeseries\":{\"bucketMs\":3600000,\"series\":{");
    { bool fs1 = true; List<string> names = new List<string>(SER.Keys); names.Sort(StringComparer.Ordinal);
      foreach(string nm in names){ if(nm.StartsWith("u|") && !keepU.Contains(nm.Substring(2))) continue;
        if(!fs1) sb.Append(","); fs1 = false; sb.Append(J(nm)).Append(":[");
        List<long> ks = new List<long>(SER[nm].Keys); ks.Sort(); bool f2 = true;
        foreach(long k in ks){ if(!f2) sb.Append(","); f2 = false; sb.Append("[").Append(k).Append(",").Append(SER[nm][k]).Append("]"); }
        sb.Append("]"); } }
    sb.Append("}}");
    /* half-hour-of-week activity (UTC; Sunday 00:00 = bin 0) for the busiest 100 users and everyone ("*") */
    sb.Append(",\"how\":{"); { bool fh = true; int kept = 0;
      List<string> hk = new List<string>(); hk.Add("*"); for(int i = 0; i < ul.Count && kept < 100; i++, kept++) hk.Add(ul[i].Key);
      foreach(string k in hk){ int[] a; if(!HOW.TryGetValue(k, out a)) continue; if(!fh) sb.Append(","); fh = false; sb.Append(J(k)).Append(":["); for(int i = 0; i < a.Length; i++){ if(i > 0) sb.Append(","); sb.Append(a[i]); } sb.Append("]"); } }
    sb.Append("}");
    sb.Append(",\"timezones\":{"); { bool fz = true; foreach(KeyValuePair<string,long> kv in TZSEEN){ if(!fz) sb.Append(","); fz = false; sb.Append(J(kv.Key)).Append(":").Append(kv.Value); } } sb.Append("}");
    sb.Append(",\"iocTerms\":["); for(int i = 0; i < IOCS.Length; i++){ if(i > 0) sb.Append(","); sb.Append(J(IOCS[i])); } sb.Append("]");
    sb.Append(",\"csvFiles\":["); for(int i = 0; i < produced.Count; i++){ if(i > 0) sb.Append(","); sb.Append(J(produced[i])); } sb.Append("]");
    sb.Append(",\"tables\":{");
    bool first = true;
    foreach(ZsTable t in tabs){
      if(!first) sb.Append(","); first = false;
      List<object[]> pv = PreviewOf(t); long pt = 0; if(t.Prio != null) foreach(object[] r in t.Rows) if(t.Prio(r)) pt++;
      JsonTable(sb, t.Name, t.Cols, pv, t.Rows.Count, pt);
    }
    foreach(ZsList l in lists){ sb.Append(","); JsonTable(sb, l.Name, l.Cols, l.Preview(), l.Total, l.PrioTotal); }
    sb.Append("}}");
    File.WriteAllText(jp, sb.ToString(), new UTF8Encoding(false));
    Log("Wrote " + jp + " (" + (new FileInfo(jp).Length / 1024) + " KB) + " + produced.Count + " CSVs");
    Log("ENGINE_OK " + jp);
    return jp;
  }
  static void MapHeader(List<string> hdr, ZsFile f){
    IX.Clear(); HDRN = hdr.Count; List<string> unk = new List<string>();
    for(int i = 0; i < hdr.Count; i++){
      string h = hdr[i].Trim(); bool hit = false;
      foreach(string[] m in COLMAP){ for(int j = 1; j < m.Length; j++){ if(string.Equals(m[j], h, StringComparison.OrdinalIgnoreCase)){ if(!IX.ContainsKey(m[0])) IX[m[0]] = i; hit = true; break; } } if(hit) break; }
      if(!hit && h.Length > 0) unk.Add(h);
    }
    f.Unknown = string.Join(", ", unk.ToArray());
    List<string> miss = new List<string>(); foreach(string k in new string[]{ "user", "action", "cat", "threat", "dept" }) if(!IX.ContainsKey(k)) miss.Add(k);
    f.Missing = string.Join(", ", miss.ToArray());
  }
  static List<object[]> PreviewOf(ZsTable t){
    int cap = t.Cap > 0 ? t.Cap : ZsList.CAP;
    if(t.Rows.Count <= cap) return t.Rows;
    List<object[]> o = new List<object[]>(), rest = new List<object[]>();
    foreach(object[] r in t.Rows){ if(t.Prio != null && t.Prio(r) && o.Count < cap) o.Add(r); else rest.Add(r); }
    for(int i = 0; i < rest.Count && o.Count < cap; i++) o.Add(rest[i]);
    o.Sort(t.Order());
    return o;
  }
  static void JsonTable(StringBuilder sb, string name, string[] cols, List<object[]> rows, long total, long prioTotal){
    sb.Append(J(name)).Append(":{\"total\":").Append(total).Append(",\"prioTotal\":").Append(prioTotal).Append(",\"cols\":[");
    for(int c = 0; c < cols.Length; c++){ if(c > 0) sb.Append(","); sb.Append(J(cols[c])); }
    sb.Append("],\"rows\":[");
    for(int r = 0; r < rows.Count; r++){
      if(r > 0) sb.Append(",");
      object[] row = rows[r]; sb.Append("[");
      for(int c = 0; c < row.Length; c++){ if(c > 0) sb.Append(","); object v = row[c]; if(v is long) sb.Append(((long)v).ToString()); else if(v is double) sb.Append(((double)v).ToString("0.##", CultureInfo.InvariantCulture)); else sb.Append(J(v == null ? "" : v.ToString())); }
      sb.Append("]");
    }
    sb.Append("]}");
  }
  static string San(string s){ StringBuilder b = new StringBuilder(); foreach(char c in s){ b.Append(char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' ? c : '-'); } return b.ToString(); }
  static long Lg(object[] r, int i){ return (i >= 0 && r[i] is long) ? (long)r[i] : 0; }
  static string St(object[] r, int i){ return (i >= 0 && r[i] != null) ? r[i].ToString() : ""; }
  static readonly long[] ROWCAPS = { 1000000, 500000, 250000, 100000, 50000, 25000, 10000 };

  /* ---------------- beacon timing ----------------
     one user -> one host: requests within 2 s of each other are one burst; the gaps between bursts are the intervals.
     Regular = share of intervals within +-20 % (min +-3 s) of the median - a timer-driven client (C2 implant, agent,
     updater, heartbeat) scores high; a human browsing does not. Pairs with fewer than 8 bursts are not scored. */
  static object[] Beacon(string user, string host, List<int> ts, ZsAgg h){
    ts.Sort();
    /* the first request always opens a burst (t - int.MinValue would overflow and drop it) */
    List<int> b = new List<int>(); int last = 0;
    foreach(int t in ts){ if(b.Count == 0 || (long)t - last > 2) b.Add(t); last = t; }
    if(b.Count < 8) return null;
    int[] iv = new int[b.Count - 1]; for(int i = 1; i < b.Count; i++) iv[i - 1] = b[i] - b[i - 1];
    int[] s = (int[])iv.Clone(); Array.Sort(s);
    double med = s[s.Length / 2]; if(s.Length % 2 == 0) med = (s[s.Length / 2 - 1] + s[s.Length / 2]) / 2.0;
    double[] dev = new double[s.Length]; for(int i = 0; i < s.Length; i++) dev[i] = Math.Abs(s[i] - med); Array.Sort(dev);
    double mad = dev[dev.Length / 2];
    double tol = Math.Max(3, med * 0.2); int reg = 0; foreach(int x in iv) if(Math.Abs(x - med) <= tol) reg++;
    HashSet<int> hours = new HashSet<int>(); foreach(int t in b) hours.Add(t / 3600);
    long first = BASEMS + (long)b[0] * 1000L, lastMs = BASEMS + (long)b[b.Count - 1] * 1000L;
    return new object[]{ user, host, (long)ts.Count, (long)b.Count, (long)Math.Round(med), (long)(med > 0 ? Math.Round(mad / med * 100) : 0), (long)Math.Round(100.0 * reg / iv.Length),
      (long)hours.Count, (long)Math.Round((lastMs - first) / 3600000.0), h == null ? "" : h.Most(1), h == null ? "" : h.Most(4), h == null ? "" : h.Top(6, 3), h == null ? 0L : h.C[5], h == null ? 0L : h.C[6], (h == null || h.Samples == null) ? "" : string.Join("  ", h.Samples.ToArray()), Ts(first), Ts(lastMs) };
  }

  /* ---------------- tables ---------------- */
  static List<ZsTable> BuildTables(List<ZsFile> cands){
    List<ZsTable> T = new List<ZsTable>();
    ZsTable t;
    long gFirst = long.MaxValue; foreach(ZsFile f in cands) if(f.Read && f.First < gFirst) gFirst = f.First;
    long baseline = gFirst == long.MaxValue ? 0 : gFirst + 86400000L;
    t = new ZsTable("files", 0, "File", "Status", "Bytes", "Lines", "Records", "Unparsed", "Incomplete", "OutsideWindow", "First_UTC", "Last_UTC", "TimeZones", "RowCap", "Order", "Administrator", "ReportCreated", "ReportFilters", "FilterUsersNoRows", "UnrecognisedColumns", "MissingColumns", "Note", "Path");
    foreach(ZsFile f in cands){
      long bytes = 0; try{ bytes = new FileInfo(f.Path).Length; }catch{}
      List<string> tz = new List<string>(); foreach(KeyValuePair<string,long> kv in f.Tz) tz.Add(kv.Key + " (" + kv.Value + ")");
      string cap = ""; foreach(long c in ROWCAPS) if(f.Records == c) cap = "yes - exactly " + c.ToString("N0") + " records";
      string order = f.Asc + f.Desc == 0 ? "" : (f.Desc == 0 ? "ascending" : (f.Asc == 0 ? "descending" : ("mixed (" + f.Asc + " up / " + f.Desc + " down)")));
      List<string> nr = new List<string>(); foreach(string u in f.FilterUsers) if(!USERS.ContainsKey(u)) nr.Add(u);
      if(f.IncompleteLines.Count > 0) f.Note += "incomplete records (field count differs from the header) at line(s) " + string.Join(", ", f.IncompleteLines.ToArray()) + (f.Incomplete > f.IncompleteLines.Count ? " ..." : "") + "; ";
      t.Add(f.Rel, f.Status, bytes, f.Lines, f.Records, f.Bad, f.Incomplete, f.Outside, Ts(f.First), Ts(f.Last), string.Join(", ", tz.ToArray()), cap, order, f.Admin, f.Created, f.Filters, string.Join(", ", nr.ToArray()), f.Unknown, f.Missing, f.Note, f.Path);
    }
    t.Desc = false; t.Sort(); T.Add(t);
    t = new ZsTable("coverage_days", 0, "Day_UTC", "Requests", "Users", "Hosts", "Allowed", "Blocked", "SecurityEvents", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in COVDAY.Values) t.Add(Ts(a.C[9] * 86400000L).Substring(0, 10), a.N, a.Distinct(0), a.Distinct(1), a.C[0], a.C[1], a.C[2], Ts(a.First), Ts(a.Last));
    t.Desc = false; t.Sort(); T.Add(t);
    t = new ZsTable("users", 3, "User", "Department", "Location", "Requests", "Allowed", "Blocked", "UnknownOutcome", "SecurityEvents", "Threats", "Hosts", "RawIPHosts", "ActiveDays", "Channels", "Unscannable", "SSLIssues", "BytesSent", "BytesReceived", "ClientIPs", "PublicIPs", "Devices", "TopBlockedCategories", "TopCategories", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in USERS.Values) t.Add(a.S0, a.Most(3), a.List(4), a.N, a.C[0], a.C[1], a.C[6], a.C[2], a.C[3], a.Distinct(0), a.Distinct(6), (long)(a.Days == null ? 0 : a.Days.Count), a.Top(5, 11), a.C[4], a.C[5], a.C[14], a.C[15], a.Top(7, 4), a.Top(8, 4), a.Top(9, 4), a.Top(2, 4), a.Top(1, 5), Ts(a.First), Ts(a.Last));
    t.Sort(); { int s = t.Ix("SecurityEvents"); t.Prio = delegate(object[] r){ return Lg(r, s) > 0; }; } T.Add(t);
    t = new ZsTable("hosts", 2, "Host", "Domain", "Requests", "Users", "TopUsers", "Allowed", "Blocked", "SecurityEvents", "Category", "SuperCategory", "URLClass", "CloudApp", "AppClass", "Actions", "Channels", "IsIP", "Entropy", "ActiveDays", "NewAfterBaseline", "C2PathHits", "C2WeakHits", "C2Paths", "BytesSent", "BytesReceived", "ServerIPs", "SamplePaths", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in HOSTS.Values) t.Add(a.S0, DomainOf(a.S0), a.N, a.Distinct(0), a.Top(0, 4), a.C[0], a.C[1], a.C[2], a.Most(1), a.Most(2), a.Most(3), a.Most(4), a.Most(5), a.Top(6, 3), a.List(7), IsIp(a.S0) ? "yes" : "no", Entropy(a.S0), (long)(a.Days == null ? 0 : a.Days.Count), (baseline > 0 && a.First > baseline) ? "yes" : "no", a.C[5], a.C[6], a.Hits == null ? "" : string.Join("  ", a.Hits.ToArray()), a.C[3], a.C[4], a.Top(8, 3), a.Samples == null ? "" : string.Join("  ", a.Samples.ToArray()), Ts(a.First), Ts(a.Last));
    t.Sort(); { int s = t.Ix("SecurityEvents"), ip = t.Ix("IsIP"), us = t.Ix("Users"), ch = t.Ix("Channels"), c2 = t.Ix("C2PathHits"), c2w = t.Ix("C2WeakHits"); t.Prio = delegate(object[] r){ return Lg(r, s) > 0 || Lg(r, c2) > 0 || Lg(r, c2w) > 0 || St(r, ip) == "yes" || Lg(r, us) == 1 || St(r, ch).Length > 0; }; } T.Add(t);
    t = new ZsTable("beacons", 6, "User", "Host", "Requests", "Bursts", "MedianIntervalSec", "JitterPct", "RegularPct", "ActiveHours", "SpanHours", "Category", "CloudApp", "Actions", "C2PathHits", "C2WeakHits", "SamplePaths", "First_UTC", "Last_UTC");
    foreach(KeyValuePair<string,List<int>> kv in PAIRS){ if(kv.Value.Count < 8) continue; int tab = kv.Key.IndexOf('\t'); string hh = kv.Key.Substring(tab + 1); ZsAgg ha; HOSTS.TryGetValue(hh, out ha);
      object[] row = Beacon(kv.Key.Substring(0, tab), hh, kv.Value, ha); if(row != null) t.Rows.Add(row); }
    t.SortCol2 = 3; t.Sort(); { int rg = t.Ix("RegularPct"), md = t.Ix("MedianIntervalSec"), bu = t.Ix("Bursts"); t.Prio = delegate(object[] r){ return Lg(r, rg) >= 60 && Lg(r, md) >= 20 && Lg(r, bu) >= 20; }; } T.Add(t);
    /* every user -> host pair with its request count and span: the complete membership behind the TopUsers summaries */
    t = new ZsTable("user_hosts", 2, "User", "Host", "Requests", "First_UTC", "Last_UTC");
    foreach(KeyValuePair<string,List<int>> kv in PAIRS){ int tab = kv.Key.IndexOf('\t'); List<int> ts = kv.Value; int mn = int.MaxValue, mx = int.MinValue; foreach(int x in ts){ if(x < mn) mn = x; if(x > mx) mx = x; }
      t.Add(kv.Key.Substring(0, tab), kv.Key.Substring(tab + 1), (long)ts.Count, Ts(BASEMS + (long)mn * 1000L), Ts(BASEMS + (long)mx * 1000L)); }
    t.Cap = 100000; t.Sort(); T.Add(t);
    t = new ZsTable("channels", 3, "Channel", "User", "Host", "Requests", "Allowed", "Blocked", "ActiveDays", "Category", "CloudApp", "Actions", "BytesSent", "BytesReceived", "SampleURL", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in CHAN.Values) t.Add(a.S0, a.S1, a.S2, a.N, a.C[0], a.C[1], (long)(a.Days == null ? 0 : a.Days.Count), a.Most(0), a.Most(1), a.Top(2, 3), a.C[3], a.C[4], a.S3.Length > 300 ? a.S3.Substring(0, 300) + "..." : a.S3, Ts(a.First), Ts(a.Last));
    t.Sort(); { int c0 = t.Ix("Channel"), al = t.Ix("Allowed"); t.Prio = delegate(object[] r){ string c = St(r, c0); return Lg(r, al) > 0 && (c.StartsWith("Remote") || c.StartsWith("Anonym") || c.StartsWith("Paste") || c.StartsWith("Raw IP") || c.StartsWith("Crypto")); }; } T.Add(t);
    t = new ZsTable("blocked", 5, "User", "Host", "Action", "BlockedPolicyType", "Category", "Count", "CloudApp", "SampleURL", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in BLOCKED.Values) t.Add(a.S0, a.S1, a.S2, a.Most(0), a.Most(1), a.N, a.Most(2), a.S3.Length > 300 ? a.S3.Substring(0, 300) + "..." : a.S3, Ts(a.First), Ts(a.Last));
    t.Sort(); { int ac = t.Ix("Action"); t.Prio = delegate(object[] r){ return RX_SEC_ACTION.IsMatch(St(r, ac)); }; } T.Add(t);
    t = new ZsTable("policy_actions", 2, "Action", "BlockedPolicyType", "Count", "Users", "Hosts", "TopHosts", "TopUsers", "TopCategories", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in ACTS.Values) t.Add(a.S0, a.S1, a.N, a.Distinct(1), a.Distinct(0), a.Top(0, 5), a.Top(1, 5), a.Top(2, 4), Ts(a.First), Ts(a.Last));
    t.Sort(); T.Add(t);
    t = new ZsTable("categories", 3, "SuperCategory", "Category", "URLClass", "Requests", "Users", "Hosts", "Allowed", "Blocked", "TopHosts", "TopUsers", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in CATS.Values) t.Add(a.S0, a.S1, a.S2, a.N, a.Distinct(1), a.Distinct(0), a.C[0], a.C[1], a.Top(0, 5), a.Top(1, 4), Ts(a.First), Ts(a.Last));
    t.Sort(); T.Add(t);
    t = new ZsTable("cloud_apps", 2, "AppClass", "CloudApp", "Requests", "Users", "Hosts", "Allowed", "Blocked", "BytesSent", "BytesReceived", "TopHosts", "TopUsers", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in APPS.Values) t.Add(a.S0, a.S1, a.N, a.Distinct(1), a.Distinct(0), a.C[0], a.C[1], a.C[3], a.C[4], a.Top(0, 4), a.Top(1, 4), Ts(a.First), Ts(a.Last));
    t.Sort(); T.Add(t);
    t = new ZsTable("ioc_terms", 1, "Term", "Hits", "Users", "Hosts", "Actions", "First_UTC", "Last_UTC");
    foreach(ZsAgg a in IOCT.Values) t.Add(a.S0, a.N, a.Top(0, 5), a.Top(1, 5), a.Top(2, 3), Ts(a.First), Ts(a.Last));
    t.Sort(); T.Add(t);
    return T;
  }
  /* ---------------- writers ---------------- */
  static string J(string s){
    StringBuilder b = new StringBuilder(s.Length + 2); b.Append('"');
    foreach(char c in s){
      switch(c){
        case '"': b.Append("\\\""); break;
        case '\\': b.Append("\\\\"); break;
        case '\n': b.Append("\\n"); break;
        case '\r': b.Append("\\r"); break;
        case '\t': b.Append("\\t"); break;
        case '<': b.Append("\\u003c"); break;
        default: if(c < 32 || c > 126) b.Append("\\u").Append(((int)c).ToString("x4")); else b.Append(c); break;
      }
    }
    b.Append('"'); return b.ToString();
  }
  static string Cq(object o){
    string v = o == null ? "" : (o is double ? ((double)o).ToString("0.##", CultureInfo.InvariantCulture) : o.ToString());
    if(!(o is long) && !(o is double) && v.Length > 0 && "=+-@\t\r".IndexOf(v[0]) >= 0) v = "'" + v;   // spreadsheet formula guard
    if(v.IndexOfAny(new char[]{ ',', '"', '\r', '\n' }) >= 0) v = "\"" + v.Replace("\"", "\"\"") + "\"";
    return v;
  }
  public static void CsvRow(TextWriter w, object[] r){ for(int c = 0; c < r.Length; c++){ if(c > 0) w.Write(','); w.Write(Cq(r[c])); } w.Write("\r\n"); }
  static void WriteCsv(string path, ZsTable t){
    using(StreamWriter w = new StreamWriter(path, false, new UTF8Encoding(true))){
      CsvRow(w, t.Cols);
      foreach(object[] r in t.Rows) CsvRow(w, r);
    }
  }
}
'@
try {
  if (-not ('ZsEngine' -as [type])) { Add-Type -TypeDefinition $cs -Language CSharp }
} catch {
  Write-Output "ENGINE_FAIL could not compile the parser (Add-Type): $($_.Exception.Message)"
  exit 2
}
if (-not $Stamp) { $Stamp = (Get-Date).ToString('yyyyMMdd_HHmmss') }
try {
  $json = [ZsEngine]::Run($InputPath, $OutDir, $TargetHost, $Stamp, $From, $To, $TzOverride, $IocFile, $ProgressFile, $AppVersion)
} catch {
  $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
  Write-Output "ENGINE_FAIL $m"
  exit 1
}
