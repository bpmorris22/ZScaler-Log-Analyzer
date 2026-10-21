// viewer-tests.js - runs the viewer's pure functions, extracted unchanged from ZScaler-Log-Analyzer.src.hta, in node.
// Usage: node viewer-tests.js <path to ZScaler-Log-Analyzer.src.hta>
"use strict";
const fs = require("fs");
const src = fs.readFileSync(process.argv[2], "utf8");
function grab(name) {
  const start = src.indexOf("function " + name + "(");
  if (start < 0) throw new Error("function not found: " + name);
  let i = src.indexOf("{", start), depth = 0;
  for (; i < src.length; i++) { if (src[i] === "{") depth++; else if (src[i] === "}" && --depth === 0) break; }
  return src.substring(start, i + 1);
}
function grabVar(name) { const m = src.match(new RegExp("^var " + name + "=.*$", "m")); if (!m) throw new Error("var not found: " + name); return m[0]; }
function grabObj(name) {   // "var NAME={ ... };" by brace matching
  const start = src.indexOf("var " + name + "={"); if (start < 0) throw new Error("object not found: " + name);
  let i = src.indexOf("{", start), depth = 0;
  for (; i < src.length; i++) { if (src[i] === "{") depth++; else if (src[i] === "}" && --depth === 0) break; }
  return src.substring(start, i + 1) + ";";
}
const code = [grabVar("INFRA_RE"), grabVar("SECACT_RE"), grabVar("C2_RE"), grabVar("C2_WEAK_RE"),
  "var USERF='', TABLES={}, HEAT={}, ACT_BINS={}, SUSPECT={}, THREATHOST={}, SUSPECT_USERS={}, MEDDAY=0;",
  grab("v"), grab("n"), grab("topUserIds"), grab("userHostSet"), grab("userMatch"), grab("resetRunCaches"),
  grab("isAllowedAction"), grab("outcomeOf"), grab("isInfra"), grab("uncCat"), grab("isIpHost"), grab("c2Level"), grab("c2Of"), grabObj("RULES"),
  "var USERHOSTS=null, USERHOSTS_FOR='', USERHOSTS_FULL=false, DEPTF='';",
  "var CTRL={fUser:{value:''},fDept:{value:''}}; function $(id){ return CTRL[id]; }",
  grab("outOf"), grab("reconcileFilters"),
  "module.exports={set:function(u,t){USERF=u;TABLES=t;USERHOSTS=null;USERHOSTS_FOR='';},setTables:function(t){TABLES=t;},userHostSet:userHostSet,resetRunCaches:resetRunCaches,",
  "  userMatch:userMatch,isAllowedAction:isAllowedAction,c2Level:c2Level,c2Of:c2Of,RULES:RULES,outOf:outOf,",
  "  reconcile:function(u,d,list,dm){ USERF=u; DEPTF=d; CTRL.fUser.value=''; CTRL.fDept.value=''; var note=reconcileFilters(list,dm); return {note:note, USERF:USERF, DEPTF:DEPTF, ctl:CTRL.fUser.value}; }};"].join("\n");
const m = { exports: {} }; new Function("module", code)(m); const V = m.exports;
let fails = 0;
function check(name, cond) { console.log((cond ? "PASS  " : "FAIL  ") + "viewer: " + name); if (!cond) fails++; }
function tbl(cols, rows) { const ix = {}; cols.forEach((c, i) => ix[c] = i); return { cols, rows, ix, total: rows.length }; }

const agg = tbl(["Category", "TopUsers"], [["x", "alice@example.test.evil (5)"], ["y", "bob@example.test (3), alice@example.test (2), +4 more"], ["z", "alice@example.test"]]);
V.set("alice@example.test", {});
check("prefix identity does not match", V.userMatch(agg, agg.rows[0]) === false);
check("exact identity in a list with counts matches", V.userMatch(agg, agg.rows[1]) === true);
check("exact identity alone matches", V.userMatch(agg, agg.rows[2]) === true);
V.set("ALICE@example.test", {});
check("identity match is case-insensitive", V.userMatch(agg, agg.rows[1]) === true);

const uh = tbl(["User", "Host", "Requests"], [["carol@example.test", "203.0.113.5", 3], ["other@example.test", "198.51.100.9", 1]]);
const hosts = tbl(["Host", "TopUsers"], [["203.0.113.5", "a@example.test (90), b@example.test (50)"], ["198.51.100.9", "carol@example.test (1)"]]);
V.set("carol@example.test", { user_hosts: uh });
check("host outside TopUsers found via user_hosts", V.userMatch(hosts, hosts.rows[0]) === true);
check("complete user_hosts excludes a TopUsers-only coincidence", V.userMatch(hosts, hosts.rows[1]) === false);

check("empty action is not allowed", V.isAllowedAction("") === false);
check("Allowed is allowed", V.isAllowedAction("Allowed") === true);
check("C2 strong on raw IP scores 3", V.c2Level("203.0.113.20", 1, 0, "Internet Services") === 3);
check("C2 weak on categorised host scores 0", V.c2Level("example.test", 0, 5, "Business") === 0);

// membership cache must not survive a run change (same selected user, opposite memberships)
const uhA = tbl(["User", "Host", "Requests"], [["alice@example.test", "alpha.example.test", 1]]);
const uhB = tbl(["User", "Host", "Requests"], [["alice@example.test", "beta.example.test", 1], ["bob@example.test", "alpha.example.test", 1]]);
V.set("alice@example.test", { user_hosts: uhA }); V.userHostSet();
V.setTables({ user_hosts: uhB }); V.resetRunCaches();
const hsB = V.userHostSet();
check("after a reload the new run's host is in the user's set", !!hsB["beta.example.test"]);
check("after a reload the old run's host is gone from the user's set", !hsB["alpha.example.test"]);
check("loadObj resets the run caches", /DATA=obj; TABLES=\{\}; resetRunCaches\(\);/.test(src));

// unknown outcomes are never presented as blocked
function flags(rule, cols, row) { const t = tbl(cols, [row]); const T = []; V.RULES[rule](t, row, T); return T.map(x => x[1]); }
const seCols = ["Host", "Action", "ThreatName", "ThreatCategory", "BlockedPolicyType", "DLP_MD5", "DLP_Identifier", "CertChain", "SelfSigned"];
let f = flags("security_events", seCols, ["remote.example.test", "", "Test.Threat", "", "", "", "", "", ""]);
check("threat with no action -> THREAT-OUTCOME-UNKNOWN, not THREAT-BLOCKED", f.includes("THREAT-OUTCOME-UNKNOWN") && !f.includes("THREAT-BLOCKED"));
f = flags("security_events", seCols, ["x.example.test", "Malicious file Blocked", "Test.Threat", "", "", "", "", "", ""]);
check("threat with a blocking action -> THREAT-BLOCKED", f.includes("THREAT-BLOCKED"));
f = flags("security_events", seCols, ["x.example.test", "", "", "", "Advanced Threat Protection", "", "", "", ""]);
check("ATP policy with no action is not ATP-BLOCK", !f.includes("ATP-BLOCK"));
const chCols = ["Channel", "Host", "Category", "Requests", "Allowed", "Blocked", "BytesSent"];
f = flags("channels", chCols, ["Remote access tool", "remote.example.test", "Remote Access", 1, 0, 0, 0]);
check("remote access with unknown outcome -> OUTCOME-UNKNOWN, not BLOCKED", f.includes("REMOTE-ACCESS-OUTCOME-UNKNOWN") && !f.includes("REMOTE-ACCESS-BLOCKED"));
f = flags("channels", chCols, ["Remote access tool", "remote.example.test", "Remote Access", 3, 0, 3, 0]);
check("remote access fully blocked -> REMOTE-ACCESS-BLOCKED", f.includes("REMOTE-ACCESS-BLOCKED"));

// a v0.1.0 run (no C2 counters) still detects from its sample paths; a new run uses the counters
const legacy = tbl(["Host", "Category", "SamplePaths"], [["203.0.113.50", "Internet Services", "/api/cmd/x1  /api/out/x1"]]);
check("legacy run without counters: sample-path C2 still detected", V.c2Of(legacy, legacy.rows[0]) === 3);
const modern = tbl(["Host", "Category", "SamplePaths", "C2PathHits", "C2WeakHits"], [["203.0.113.50", "Internet Services", "/benign", 5, 0]]);
check("new run: counters decide, not the samples", V.c2Of(modern, modern.rows[0]) === 3);

// Allowed only / Blocked only: unknown outcomes ("(none)" in Policy actions, "" in event rows) are in neither
const pa = tbl(["Action", "BlockedPolicyType", "Count"], [["(none)", "", 1], ["", "", 1], ["Allowed", "", 5], ["Not allowed to browse this category", "URL Filtering", 2]]);
let o = V.outOf(pa, pa.rows[0]); check("'(none)' action is neither allowed nor blocked", !o.a && !o.b);
o = V.outOf(pa, pa.rows[1]); check("empty action is neither allowed nor blocked", !o.a && !o.b);
o = V.outOf(pa, pa.rows[2]); check("Allowed row passes Allowed only", o.a && !o.b);
o = V.outOf(pa, pa.rows[3]); check("blocking row passes Blocked only", !o.a && o.b);

// filters rebuilt after a reload: an absent identity is cleared (model and control), a case-only difference adopts the run's spelling
const users = [["bob@example.test", 1]], depts = { "#Sales": 1 };
let rc = V.reconcile("alice@example.test", "", users, depts);
check("absent selected user is cleared and reported", rc.USERF === "" && rc.ctl === "" && /alice@example\.test cleared/.test(rc.note));
rc = V.reconcile("BOB@example.test", "", users, depts);
check("case-only difference adopts the run's identity", rc.USERF === "bob@example.test" && rc.ctl === "bob@example.test" && rc.note === "");
rc = V.reconcile("bob@example.test", "Finance", users, depts);
check("absent department is cleared, present user kept", rc.USERF === "bob@example.test" && rc.DEPTF === "" && /department filter Finance cleared/.test(rc.note));
check("copy row copies the bound selection, not a re-looked-up index", /var t=DETSEL\.t, row=DETSEL\.row/.test(src) && /DETSEL\.t!==curTable\(\)/.test(src));
check("loadObj clears the detail selection", /clearDetail\(\); SORTS=\{\};/.test(src));
{ const ex = new Function(grab("c2Example") + "; return c2Example;")();
  check("C2 finding example prefers a strong path over an earlier weak one", ex("weak /api/register/WS07 [f#row=2]  strong /api/hello?h=WS07&u=x [f#row=3]") === "/api/hello?h=WS07&u=x [f#row=3]");
  check("C2 finding example falls back to the first path", ex("weak /api/task/1 [f#row=2]") === "/api/task/1 [f#row=2]"); }
process.exitCode = fails ? 1 : 0;
