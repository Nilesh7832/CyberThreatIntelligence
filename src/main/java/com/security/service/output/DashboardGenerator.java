package com.security.service.output;

import com.security.config.AppConfig;
import com.security.dao.LoginDAO;
import com.security.dao.RiskScoreDAO;
import com.security.dao.ThreatDAO;
import com.security.model.LoginLog;
import com.security.model.RiskScore;
import com.security.model.ThreatAlert;
import com.security.utils.DateHelper;
import com.security.utils.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * DashboardGenerator - Builds a fully offline, interactive HTML
 * dashboard summarizing threats, risk scores, and failed logins.
 * No internet / external libraries required — pure HTML + inline
 * CSS + vanilla JS (Canvas 2D donut chart, live search/filter/sort,
 * and client-side CSV download / print-to-PDF).
 * Output: reports/dashboard.html
 */
public class DashboardGenerator {

    private static final Logger log    = Logger.getInstance();
    private static final String SOURCE = "DashboardGenerator";

    private final AppConfig    config    = AppConfig.getInstance();
    private final ThreatDAO    threatDAO = new ThreatDAO();
    private final LoginDAO     loginDAO  = new LoginDAO();
    private final RiskScoreDAO riskDAO   = new RiskScoreDAO();

    /** Generates the dashboard.html file inside the reports/ folder. */
    public void generate() {
        try {
            Files.createDirectories(Paths.get(config.getReportOutputPath()));

            List<ThreatAlert> threats      = threatDAO.getAllThreats();
            List<LoginLog>     failedLogins = loginDAO.getFailedLogins();
            List<RiskScore>    riskScores  = riskDAO.getAll();

            String html = buildHtml(threats, failedLogins, riskScores);
            String path = config.getReportOutputPath() + "dashboard.html";

            // Write as UTF-8 explicitly so emoji/icons render correctly
            // regardless of the OS's default console/file encoding.
            try (PrintWriter pw = new PrintWriter(
                    new OutputStreamWriter(
                            new FileOutputStream(path),
                            StandardCharsets.UTF_8))) {
                pw.print(html);
            }

            log.info(SOURCE, "Dashboard generated -> " + path);
            System.out.println("  Dashboard: " + path + "  (open in any browser)");

        } catch (IOException e) {
            log.error(SOURCE, "Dashboard generation failed: " + e.getMessage());
        }
    }

    // ── HTML Builder ─────────────────────────────────

    private String buildHtml(List<ThreatAlert> threats,
                             List<LoginLog> failedLogins,
                             List<RiskScore> riskScores) {

        Map<String, Integer> sev = new TreeMap<>();
        sev.put("CRITICAL", 0);
        sev.put("HIGH", 0);
        sev.put("MEDIUM", 0);
        sev.put("LOW", 0);
        for (ThreatAlert t : threats) {
            sev.merge(t.getSeverity(), 1, Integer::sum);
        }

        long blockedCount = riskScores.stream()
                .filter(r -> "CRITICAL".equals(r.getRiskLevel()))
                .count();

        JSONObject severityJson = new JSONObject();
        severityJson.put("CRITICAL", sev.get("CRITICAL"));
        severityJson.put("HIGH", sev.get("HIGH"));
        severityJson.put("MEDIUM", sev.get("MEDIUM"));
        severityJson.put("LOW", sev.get("LOW"));

        return HTML_TEMPLATE
                .replace("@@GENERATED_AT@@", DateHelper.now())
                .replace("@@TOTAL@@", String.valueOf(threats.size()))
                .replace("@@CRITICAL@@", String.valueOf(sev.get("CRITICAL")))
                .replace("@@HIGH@@", String.valueOf(sev.get("HIGH")))
                .replace("@@LOGINS_COUNT@@", String.valueOf(failedLogins.size()))
                .replace("@@BLOCKED_COUNT@@", String.valueOf(blockedCount))
                .replace("@@THREATS_JSON@@", threatsToJson(threats).toString())
                .replace("@@RISK_JSON@@", riskToJson(riskScores).toString())
                .replace("@@LOGINS_JSON@@", loginsToJson(failedLogins).toString())
                .replace("@@SEVERITY_JSON@@", severityJson.toString());
    }

    // ── JSON Converters ──────────────────────────────

    private JSONArray threatsToJson(List<ThreatAlert> threats) {
        JSONArray arr = new JSONArray();
        for (ThreatAlert t : threats) {
            JSONObject o = new JSONObject();
            o.put("type", t.getThreatType());
            o.put("ip", t.getSourceIp());
            o.put("target", t.getTargetSystem());
            o.put("severity", t.getSeverity());
            o.put("score", t.getRiskScore());
            o.put("status", t.getStatus());
            o.put("time", t.getDetectedAt());
            arr.put(o);
        }
        return arr;
    }

    private JSONArray riskToJson(List<RiskScore> scores) {
        JSONArray arr = new JSONArray();
        for (RiskScore r : scores) {
            JSONObject o = new JSONObject();
            o.put("ip", r.getIpAddress());
            o.put("score", r.getTotalScore());
            o.put("level", r.getRiskLevel());
            o.put("fails", r.getFailCount());
            o.put("ml", r.getMlPrediction());
            o.put("time", r.getCalculatedAt());
            arr.put(o);
        }
        return arr;
    }

    private JSONArray loginsToJson(List<LoginLog> logs) {
        JSONArray arr = new JSONArray();
        for (LoginLog l : logs) {
            JSONObject o = new JSONObject();
            o.put("username", l.getUsername());
            o.put("ip", l.getIpAddress());
            o.put("time", l.getLoginTime());
            o.put("reason", l.getFailureReason());
            o.put("location", l.getLocation());
            arr.put(o);
        }
        return arr;
    }

    // ── HTML/CSS/JS Template ──────────────────────────

    private static final String HTML_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Cyber Threat Intelligence Dashboard</title>
            <style>
            :root{
              --bg-1:#0b0e17; --bg-2:#141a2b; --card-bg:rgba(255,255,255,.045);
              --border:rgba(255,255,255,.08); --text:#eef1f8; --muted:#8b93a7;
              --critical:#ff4d6d; --high:#ff9f43; --medium:#feca57; --low:#1dd1a1;
              --info:#54a0ff; --accent:#a55eea;
            }
            *{box-sizing:border-box;margin:0;padding:0;}
            html{scroll-behavior:smooth;}
            body{
              font-family:'Segoe UI',Tahoma,Arial,sans-serif;
              background:linear-gradient(160deg,var(--bg-1),var(--bg-2) 60%);
              color:var(--text); min-height:100vh; padding:26px 32px 60px;
              position:relative; overflow-x:hidden;
            }
            body::before,body::after{
              content:''; position:fixed; width:480px; height:480px; border-radius:50%;
              filter:blur(120px); opacity:.16; z-index:-1; animation:float 18s ease-in-out infinite;
            }
            body::before{background:var(--info); top:-140px; left:-120px;}
            body::after{background:var(--accent); bottom:-160px; right:-100px; animation-delay:-9s;}
            @keyframes float{0%,100%{transform:translate(0,0);}50%{transform:translate(40px,60px);}}
            @keyframes fadeUp{from{opacity:0;transform:translateY(14px);}to{opacity:1;transform:translateY(0);}}

            header{margin-bottom:22px;}
            header h1{font-size:26px;font-weight:700;display:flex;align-items:center;gap:10px;
              background:linear-gradient(90deg,#fff,#9db4ff);-webkit-background-clip:text;
              background-clip:text;color:transparent;}
            header .sub{color:var(--muted);font-size:12.5px;margin-top:4px;}

            .toolbar{
              display:flex;flex-wrap:wrap;gap:10px;align-items:center;
              background:var(--card-bg);border:1px solid var(--border);border-radius:14px;
              padding:14px 16px;margin-bottom:26px;backdrop-filter:blur(10px);
              position:sticky;top:12px;z-index:50;
            }
            .search-box{
              flex:1;min-width:180px;display:flex;align-items:center;gap:8px;
              background:rgba(255,255,255,.05);border:1px solid var(--border);
              border-radius:10px;padding:8px 12px;
            }
            .search-box input{
              flex:1;background:transparent;border:none;outline:none;color:var(--text);
              font-size:13px;
            }
            .chips{display:flex;gap:6px;flex-wrap:wrap;}
            .chip{
              padding:6px 14px;border-radius:20px;font-size:11.5px;font-weight:600;
              text-transform:uppercase;letter-spacing:.4px;cursor:pointer;
              border:1px solid var(--border);background:rgba(255,255,255,.04);
              color:var(--muted);transition:.2s ease;
            }
            .chip:hover{color:var(--text);border-color:rgba(255,255,255,.25);}
            .chip.active{color:#fff;border-color:transparent;}
            .chip[data-severity="ALL"].active{background:var(--info);}
            .chip[data-severity="CRITICAL"].active{background:var(--critical);}
            .chip[data-severity="HIGH"].active{background:var(--high);color:#1a1d27;}
            .chip[data-severity="MEDIUM"].active{background:var(--medium);color:#1a1d27;}
            .chip[data-severity="LOW"].active{background:var(--low);color:#1a1d27;}

            .btn{
              display:inline-flex;align-items:center;gap:6px;padding:8px 14px;
              border-radius:10px;font-size:12.5px;font-weight:600;cursor:pointer;
              border:1px solid var(--border);background:rgba(255,255,255,.05);
              color:var(--text);transition:.2s ease;white-space:nowrap;
            }
            .btn:hover{transform:translateY(-2px);border-color:var(--info);
              box-shadow:0 6px 18px rgba(84,160,255,.25);}
            .btn.primary{background:linear-gradient(135deg,var(--info),var(--accent));border:none;}
            .btn.primary:hover{box-shadow:0 6px 20px rgba(165,94,234,.4);}

            .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
              gap:16px;margin-bottom:26px;}
            .card{
              background:var(--card-bg);border:1px solid var(--border);border-radius:14px;
              padding:18px;position:relative;overflow:hidden;backdrop-filter:blur(10px);
              animation:fadeUp .5s ease both;transition:.25s ease;
            }
            .card:hover{transform:translateY(-5px);}
            .card::before{content:'';position:absolute;top:0;left:0;width:5px;height:100%;}
            .card.blue::before{background:var(--info);} .card.blue:hover{box-shadow:0 10px 26px rgba(84,160,255,.25);}
            .card.red::before{background:var(--critical);} .card.red:hover{box-shadow:0 10px 26px rgba(255,77,109,.25);}
            .card.orange::before{background:var(--high);} .card.orange:hover{box-shadow:0 10px 26px rgba(255,159,67,.25);}
            .card.purple::before{background:var(--accent);} .card.purple:hover{box-shadow:0 10px 26px rgba(165,94,234,.25);}
            .card.teal::before{background:var(--low);} .card.teal:hover{box-shadow:0 10px 26px rgba(29,209,161,.25);}
            .card .icon{font-size:20px;margin-bottom:10px;}
            .card-value{font-size:30px;font-weight:800;}
            .card-label{font-size:11px;color:var(--muted);margin-top:4px;
              text-transform:uppercase;letter-spacing:.6px;}

            .grid2{display:grid;grid-template-columns:1.1fr 1.4fr;gap:20px;margin-bottom:24px;}
            @media(max-width:860px){.grid2{grid-template-columns:1fr;}}

            .panel{
              background:var(--card-bg);border:1px solid var(--border);border-radius:14px;
              padding:20px;backdrop-filter:blur(10px);animation:fadeUp .6s ease both;
            }
            .panel h2{font-size:15px;margin-bottom:14px;display:flex;align-items:center;gap:8px;}
            .panel h2 small{color:var(--muted);font-weight:400;font-size:11.5px;margin-left:auto;}

            .donut-wrap{display:flex;align-items:center;gap:22px;flex-wrap:wrap;}
            #donutChart{cursor:pointer;flex-shrink:0;}
            .legend{display:flex;flex-direction:column;gap:8px;font-size:12.5px;}
            .legend div{display:flex;align-items:center;gap:8px;}
            .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}

            .bar-row{display:flex;align-items:center;gap:10px;margin-bottom:12px;font-size:12px;}
            .bar-label{width:110px;flex-shrink:0;color:var(--muted);
              overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
            .bar-track{flex:1;height:16px;background:rgba(255,255,255,.06);border-radius:8px;overflow:hidden;}
            .bar-fill{height:100%;border-radius:8px;transition:width .8s cubic-bezier(.22,1,.36,1);}
            .bar-fill.critical{background:linear-gradient(90deg,var(--critical),#ff8fa3);}
            .bar-fill.high{background:linear-gradient(90deg,var(--high),#ffc78f);}
            .bar-fill.medium{background:linear-gradient(90deg,var(--medium),#fff3b0);}
            .bar-fill.low{background:linear-gradient(90deg,var(--low),#7ef2d1);}
            .bar-score{width:34px;text-align:right;color:var(--text);font-weight:600;flex-shrink:0;}

            table{width:100%;border-collapse:collapse;font-size:12.5px;}
            th{
              text-align:left;padding:9px 10px;border-bottom:2px solid var(--border);
              color:var(--muted);text-transform:uppercase;font-size:10.5px;
              letter-spacing:.4px;cursor:pointer;user-select:none;white-space:nowrap;
            }
            th:hover{color:var(--text);}
            td{padding:9px 10px;border-bottom:1px solid rgba(255,255,255,.05);}
            tbody tr{transition:.15s ease;}
            tbody tr:hover{background:rgba(255,255,255,.035);}
            .table-scroll{max-height:340px;overflow-y:auto;margin-top:4px;}

            .badge{
              padding:3px 10px;border-radius:20px;font-size:10.5px;font-weight:700;
              text-transform:uppercase;letter-spacing:.3px;
            }
            .badge.critical{background:linear-gradient(135deg,var(--critical),#c9184a);color:#fff;}
            .badge.high{background:linear-gradient(135deg,var(--high),#e07b1f);color:#1a1d27;}
            .badge.medium{background:linear-gradient(135deg,var(--medium),#e0b02f);color:#1a1d27;}
            .badge.low{background:linear-gradient(135deg,var(--low),#0fa383);color:#fff;}

            footer{text-align:center;color:#555;font-size:11.5px;margin-top:30px;}

            @media print{
              body::before,body::after{display:none;}
              .toolbar,.btn,.search-box,.chips{display:none !important;}
              .panel,.card{break-inside:avoid;border:1px solid #ccc;background:#fff;color:#000;}
              body{background:#fff;color:#000;}
              header h1{-webkit-text-fill-color:#000;color:#000;}
            }
            </style>
            </head>
            <body>

            <header>
              <h1>&#128737;&#65039; Cyber Threat Intelligence Dashboard</h1>
              <p class="sub">Generated on @@GENERATED_AT@@ &middot; Fully offline report</p>
            </header>

            <div class="toolbar no-print">
              <div class="search-box">
                <span>&#128269;</span>
                <input type="text" id="searchInput" placeholder="Search threats by IP or type...">
              </div>
              <div class="chips" id="severityChips">
                <span class="chip active" data-severity="ALL">All</span>
                <span class="chip" data-severity="CRITICAL">Critical</span>
                <span class="chip" data-severity="HIGH">High</span>
                <span class="chip" data-severity="MEDIUM">Medium</span>
                <span class="chip" data-severity="LOW">Low</span>
              </div>
              <span class="btn" id="downloadThreatsBtn">&#11015;&#65039; Threats CSV</span>
              <span class="btn" id="downloadRiskBtn">&#11015;&#65039; Risk CSV</span>
              <span class="btn" id="downloadLoginsBtn">&#11015;&#65039; Logins CSV</span>
              <span class="btn primary" id="downloadFullBtn">&#128230; Full Report</span>
              <span class="btn" id="printBtn">&#128424;&#65039; Print / PDF</span>
            </div>

            <section class="cards">
              <div class="card blue"><div class="icon">&#128737;&#65039;</div>
                <div class="card-value">@@TOTAL@@</div><div class="card-label">Total Threats</div></div>
              <div class="card red"><div class="icon">&#128308;</div>
                <div class="card-value">@@CRITICAL@@</div><div class="card-label">Critical</div></div>
              <div class="card orange"><div class="icon">&#128992;</div>
                <div class="card-value">@@HIGH@@</div><div class="card-label">High</div></div>
              <div class="card purple"><div class="icon">&#128273;</div>
                <div class="card-value">@@LOGINS_COUNT@@</div><div class="card-label">Failed Logins</div></div>
              <div class="card teal"><div class="icon">&#128683;</div>
                <div class="card-value">@@BLOCKED_COUNT@@</div><div class="card-label">High-Risk IPs</div></div>
            </section>

            <div class="grid2">
              <div class="panel">
                <h2>Threats by Severity <small>click a slice to filter</small></h2>
                <div class="donut-wrap">
                  <canvas id="donutChart" width="190" height="190"></canvas>
                  <div class="legend" id="donutLegend"></div>
                </div>
              </div>
              <div class="panel">
                <h2>Top Risky IP Addresses</h2>
                <div id="riskBars"></div>
              </div>
            </div>

            <section class="panel" id="threatsPanel" style="margin-bottom:24px;">
              <h2>Threat Alerts <small id="threatsCount"></small></h2>
              <div class="table-scroll">
              <table id="threatsTable">
                <thead><tr>
                  <th data-key="type">Type</th>
                  <th data-key="ip">Source IP</th>
                  <th data-key="target">Target</th>
                  <th data-key="severity">Severity</th>
                  <th data-key="score">Score</th>
                  <th data-key="status">Status</th>
                  <th data-key="time">Detected At</th>
                </tr></thead>
                <tbody id="threatsBody"></tbody>
              </table>
              </div>
            </section>

            <section class="panel" id="riskPanel" style="margin-bottom:24px;">
              <h2>IP Risk Scores <small id="riskCount"></small></h2>
              <div class="table-scroll">
              <table id="riskTable">
                <thead><tr>
                  <th data-key="ip">IP Address</th>
                  <th data-key="score">Total Score</th>
                  <th data-key="level">Risk Level</th>
                  <th data-key="fails">Fail Count</th>
                  <th data-key="ml">ML Prediction</th>
                </tr></thead>
                <tbody id="riskBody"></tbody>
              </table>
              </div>
            </section>

            <section class="panel" id="loginsPanel">
              <h2>Failed Login Attempts <small id="loginsCountLabel"></small></h2>
              <div class="table-scroll">
              <table id="loginsTable">
                <thead><tr>
                  <th>Username</th><th>IP Address</th><th>Login Time</th>
                  <th>Reason</th><th>Location</th>
                </tr></thead>
                <tbody id="loginsBody"></tbody>
              </table>
              </div>
            </section>

            <footer>Cyber Threat Intelligence Framework &mdash; Offline HTML Report</footer>

            <script>
            const threatsData  = @@THREATS_JSON@@;
            const riskData     = @@RISK_JSON@@;
            const loginsData   = @@LOGINS_JSON@@;
            const severityCounts = @@SEVERITY_JSON@@;

            /* ---------- CSV / DOWNLOAD HELPERS ---------- */
            function toCSV(data){
              if(!data.length) return '';
              const headers = Object.keys(data[0]);
              const rows = [headers.join(',')];
              data.forEach(row=>{
                rows.push(headers.map(h=>'"'+String(row[h]).replace(/"/g,'""')+'"').join(','));
              });
              return rows.join('\\n');
            }
            function triggerDownload(filename, content){
              const blob = new Blob([content], {type:'text/csv;charset=utf-8;'});
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url; a.download = filename;
              document.body.appendChild(a); a.click(); document.body.removeChild(a);
              URL.revokeObjectURL(url);
            }
            function downloadCSV(filename, data){
              if(!data.length){ alert('No data available to download.'); return; }
              triggerDownload(filename, toCSV(data));
            }
            document.getElementById('downloadThreatsBtn').onclick = ()=>downloadCSV('threats_report.csv', threatsData);
            document.getElementById('downloadRiskBtn').onclick    = ()=>downloadCSV('risk_scores_report.csv', riskData);
            document.getElementById('downloadLoginsBtn').onclick  = ()=>downloadCSV('failed_logins_report.csv', loginsData);
            document.getElementById('downloadFullBtn').onclick    = ()=>{
              const content =
                'THREAT ALERTS\\n' + toCSV(threatsData) +
                '\\n\\nIP RISK SCORES\\n' + toCSV(riskData) +
                '\\n\\nFAILED LOGIN ATTEMPTS\\n' + toCSV(loginsData);
              triggerDownload('cti_full_report.csv', content);
            };
            document.getElementById('printBtn').onclick = ()=>window.print();

            /* ---------- THREATS TABLE (search + filter + sort) ---------- */
            let threatState = {severity:'ALL', search:'', sortKey:null, sortDir:1};

            function renderThreats(){
              let rows = threatsData.filter(t=>
                (threatState.severity==='ALL' || t.severity===threatState.severity) &&
                (t.ip.toLowerCase().includes(threatState.search) ||
                 t.type.toLowerCase().includes(threatState.search))
              );
              if(threatState.sortKey){
                rows = rows.slice().sort((a,b)=>{
                  const va=a[threatState.sortKey], vb=b[threatState.sortKey];
                  if(typeof va==='number') return (va-vb)*threatState.sortDir;
                  return String(va).localeCompare(String(vb))*threatState.sortDir;
                });
              }
              document.getElementById('threatsBody').innerHTML = rows.map(t=>`
                <tr>
                  <td>${t.type}</td><td>${t.ip}</td><td>${t.target}</td>
                  <td><span class="badge ${t.severity.toLowerCase()}">${t.severity}</span></td>
                  <td>${t.score}</td><td>${t.status}</td><td>${t.time}</td>
                </tr>`).join('');
              document.getElementById('threatsCount').textContent =
                '(' + rows.length + ' of ' + threatsData.length + ')';
            }
            document.getElementById('searchInput').addEventListener('input', e=>{
              threatState.search = e.target.value.toLowerCase();
              renderThreats();
            });
            document.querySelectorAll('#severityChips .chip').forEach(chip=>{
              chip.addEventListener('click', ()=>{
                document.querySelectorAll('#severityChips .chip').forEach(c=>c.classList.remove('active'));
                chip.classList.add('active');
                threatState.severity = chip.dataset.severity;
                renderThreats();
              });
            });
            document.querySelectorAll('#threatsTable th[data-key]').forEach(th=>{
              th.addEventListener('click', ()=>{
                const key = th.dataset.key;
                threatState.sortDir = (threatState.sortKey===key) ? threatState.sortDir*-1 : 1;
                threatState.sortKey = key;
                renderThreats();
              });
            });

            /* ---------- RISK TABLE (sort only) ---------- */
            let riskState = {sortKey:null, sortDir:1};
            function renderRisk(){
              let rows = riskData.slice();
              if(riskState.sortKey){
                rows.sort((a,b)=>{
                  const va=a[riskState.sortKey], vb=b[riskState.sortKey];
                  if(typeof va==='number') return (va-vb)*riskState.sortDir;
                  return String(va).localeCompare(String(vb))*riskState.sortDir;
                });
              }
              document.getElementById('riskBody').innerHTML = rows.map(r=>`
                <tr>
                  <td>${r.ip}</td><td>${r.score}</td>
                  <td><span class="badge ${r.level.toLowerCase()}">${r.level}</span></td>
                  <td>${r.fails}</td><td>${r.ml}</td>
                </tr>`).join('');
              document.getElementById('riskCount').textContent = '(' + rows.length + ')';
            }
            document.querySelectorAll('#riskTable th[data-key]').forEach(th=>{
              th.addEventListener('click', ()=>{
                const key = th.dataset.key;
                riskState.sortDir = (riskState.sortKey===key) ? riskState.sortDir*-1 : 1;
                riskState.sortKey = key;
                renderRisk();
              });
            });

            /* ---------- LOGINS TABLE (static) ---------- */
            function renderLogins(){
              document.getElementById('loginsBody').innerHTML = loginsData.map(l=>`
                <tr>
                  <td>${l.username}</td><td>${l.ip}</td><td>${l.time}</td>
                  <td>${l.reason}</td><td>${l.location}</td>
                </tr>`).join('');
              document.getElementById('loginsCountLabel').textContent = '(' + loginsData.length + ')';
            }

            /* ---------- DONUT CHART (click-to-filter) ---------- */
            const donutColors = {CRITICAL:'#ff4d6d', HIGH:'#ff9f43', MEDIUM:'#feca57', LOW:'#1dd1a1'};
            let donutSegments = [];
            function drawDonut(){
              const canvas = document.getElementById('donutChart');
              const ctx = canvas.getContext('2d');
              const cx = canvas.width/2, cy = canvas.height/2, rOuter = 80, rInner = 48;
              const total = Object.values(severityCounts).reduce((a,b)=>a+b,0) || 1;
              let start = -Math.PI/2;
              donutSegments = [];
              ctx.clearRect(0,0,canvas.width,canvas.height);
              Object.keys(severityCounts).forEach(key=>{
                const val = severityCounts[key];
                const angle = (val/total) * Math.PI*2;
                if(val>0){
                  ctx.beginPath();
                  ctx.moveTo(cx,cy);
                  ctx.arc(cx,cy,rOuter,start,start+angle);
                  ctx.closePath();
                  ctx.fillStyle = donutColors[key];
                  ctx.fill();
                }
                donutSegments.push({key, start, end:start+angle});
                start += angle;
              });
              ctx.beginPath();
              ctx.arc(cx,cy,rInner,0,Math.PI*2);
              ctx.fillStyle = '#141a2b';
              ctx.fill();
              ctx.fillStyle = '#eef1f8';
              ctx.font = 'bold 22px Segoe UI';
              ctx.textAlign = 'center';
              ctx.fillText(total, cx, cy+6);
              ctx.font = '10px Segoe UI';
              ctx.fillStyle = '#8b93a7';
              ctx.fillText('TOTAL', cx, cy+22);

              document.getElementById('donutLegend').innerHTML =
                Object.keys(severityCounts).map(key=>
                  `<div><span class="dot" style="background:${donutColors[key]}"></span>
                   ${key} &mdash; ${severityCounts[key]}</div>`).join('');
            }
            document.getElementById('donutChart').addEventListener('click', e=>{
              const canvas = e.target;
              const rect = canvas.getBoundingClientRect();
              const x = e.clientX - rect.left - canvas.width/2;
              const y = e.clientY - rect.top - canvas.height/2;
              let angle = Math.atan2(y,x);
              if(angle < -Math.PI/2) angle += Math.PI*2;
              const seg = donutSegments.find(s => angle>=s.start && angle<=s.end);
              if(seg && severityCounts[seg.key] > 0){
                document.querySelectorAll('#severityChips .chip').forEach(c=>c.classList.remove('active'));
                document.querySelector(`.chip[data-severity="${seg.key}"]`).classList.add('active');
                threatState.severity = seg.key;
                renderThreats();
                document.getElementById('threatsPanel').scrollIntoView({behavior:'smooth', block:'center'});
              }
            });

            /* ---------- TOP RISKY IP BARS ---------- */
            function renderRiskBars(){
              const top = riskData.slice().sort((a,b)=>b.score-a.score).slice(0,8);
              const max = Math.max(...top.map(t=>t.score), 1);
              document.getElementById('riskBars').innerHTML = top.map(r=>`
                <div class="bar-row">
                  <span class="bar-label" title="${r.ip}">${r.ip}</span>
                  <div class="bar-track">
                    <div class="bar-fill ${r.level.toLowerCase()}" data-w="${(r.score/max*100)}" style="width:0%"></div>
                  </div>
                  <span class="bar-score">${r.score}</span>
                </div>`).join('');
              requestAnimationFrame(()=>{
                document.querySelectorAll('.bar-fill').forEach(el=>{
                  el.style.width = el.dataset.w + '%';
                });
              });
            }

            /* ---------- INITIAL RENDER ---------- */
            renderThreats();
            renderRisk();
            renderLogins();
            drawDonut();
            renderRiskBars();
            </script>

            </body>
            </html>
            """;
}