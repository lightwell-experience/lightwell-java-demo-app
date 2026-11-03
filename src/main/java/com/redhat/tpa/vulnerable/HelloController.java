package com.redhat.tpa.vulnerable;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.MediaType;

@RestController
public class HelloController {

    record DepStatus(String library, String groupId, String version, String cves, String lightwellFix, boolean loaded) {}

    private List<DepStatus> checkAll() {
        List<DepStatus> results = new ArrayList<>();

        results.add(check("Spring Boot", "org.springframework.boot", "2.6.6",
                "CVE-2025-22235, CVE-2026-40973", "",
                () -> Class.forName("org.springframework.boot.SpringApplication")));

        results.add(check("Spring Framework (core)", "org.springframework", "5.3.18",
                "CVE-2025-41249", "5.3.18.rhlw-00010",
                () -> Class.forName("org.springframework.core.SpringVersion")));

        results.add(check("Spring Framework (webmvc)", "org.springframework", "5.3.18",
                "CVE-2023-20860, CVE-2024-38816", "5.3.18.rhlw-00010",
                () -> Class.forName("org.springframework.web.servlet.DispatcherServlet")));

        results.add(check("Spring Framework (expression)", "org.springframework", "5.3.18",
                "CVE-2023-20861, CVE-2023-20863, CVE-2024-38808", "5.3.18.rhlw-00010",
                () -> Class.forName("org.springframework.expression.spel.standard.SpelExpressionParser")));

        results.add(check("Spring Security", "org.springframework.security", "5.6.2",
                "CVE-2024-22257, CVE-2024-38821, CVE-2026-22732, CVE-2026-22746", "",
                () -> Class.forName("org.springframework.security.core.SpringSecurityCoreVersion")));

        results.add(check("SnakeYAML", "org.yaml", "1.29",
                "CVE-2022-1471", "",
                () -> new org.yaml.snakeyaml.Yaml().dump(Map.of("test", "value"))));

        results.add(check("Jackson Databind", "com.fasterxml.jackson.core", "2.13.2",
                "CVE-2022-42003", "",
                () -> new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(Map.of("ok", true))));

        results.add(check("Apache HttpClient", "org.apache.httpcomponents", "4.5.12",
                "CVE-2020-13956", "",
                () -> org.apache.http.impl.client.HttpClients.createDefault().close()));

        results.add(check("json-smart", "net.minidev", "2.4.8",
                "CVE-2023-1370, CVE-2024-57699", "",
                () -> net.minidev.json.JSONValue.parse("{\"ok\":true}")));

        results.add(check("Woodstox", "com.fasterxml.woodstox", "6.0.3",
                "CVE-2022-40152", "6.0.3.rhlw-00001",
                () -> Class.forName("com.ctc.wstx.stax.WstxInputFactory")));

        results.add(check("org.json", "org.json", "20220320",
                "CVE-2022-45688, CVE-2023-5072", "20220320.0.0.rhlw-00003",
                () -> new org.json.JSONObject("{\"ok\":true}")));

        results.add(check("json-path", "com.jayway.jsonpath", "2.8.0",
                "CVE-2023-51074", "2.8.0.rhlw-00001",
                () -> com.jayway.jsonpath.JsonPath.read("{\"a\":1}", "$.a")));

        results.add(check("Commons FileUpload", "commons-fileupload", "1.4",
                "CVE-2023-24998", "",
                () -> Class.forName("org.apache.commons.fileupload.disk.DiskFileItemFactory")));

        results.add(check("Commons IO", "commons-io", "2.11.0",
                "CVE-2024-47554", "",
                () -> org.apache.commons.io.IOUtils.toString(new StringReader("ok"))));

        results.add(check("Logback", "ch.qos.logback", "1.2.11",
                "CVE-2023-6378", "",
                () -> Class.forName("ch.qos.logback.classic.Logger")));

        results.add(check("H2 Database", "com.h2database", "2.1.214",
                "CVE-2022-45868", "",
                () -> Class.forName("org.h2.Driver")));

        results.add(check("plexus-utils", "org.codehaus.plexus", "3.5.0",
                "CVE-2025-67030", "",
                () -> org.codehaus.plexus.util.StringUtils.trim(" test ")));

        results.add(check("hutool-json", "cn.hutool", "5.8.10",
                "CVE-2022-45688", "",
                () -> cn.hutool.json.JSONUtil.parseObj("{\"ok\":true}")));

        return results;
    }

    private DepStatus check(String name, String groupId, String version, String cves, String lwFix, CheckAction action) {
        boolean loaded;
        try {
            action.run();
            loaded = true;
        } catch (Exception e) {
            loaded = false;
        }
        return new DepStatus(name, groupId, version, cves, lwFix, loaded);
    }

    @FunctionalInterface
    interface CheckAction { void run() throws Exception; }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String index() {
        List<DepStatus> deps = checkAll();
        long loaded = deps.stream().filter(d -> d.loaded).count();

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        html.append("<title>Help, I'm Vulnerable!</title>");
        html.append("<style>");
        html.append("*{box-sizing:border-box;margin:0;padding:0}");
        html.append("body{font-family:'Red Hat Text','Segoe UI',sans-serif;background:#f0f0f0;color:#151515}");
        html.append(".header{background:#c9190b;color:#fff;padding:24px 40px}");
        html.append(".header h1{font-size:28px;font-weight:700}");
        html.append(".header p{font-size:14px;opacity:.85;margin-top:4px}");
        html.append(".content{max-width:1200px;margin:24px auto;padding:0 24px}");
        html.append(".card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);padding:24px;margin-bottom:24px}");
        html.append(".card h2{font-size:18px;margin-bottom:12px;color:#151515}");
        html.append(".card p{font-size:14px;line-height:1.6;color:#6a6e73}");
        html.append(".stats{display:flex;gap:16px;margin-bottom:24px}");
        html.append(".stat{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);padding:20px;flex:1;text-align:center}");
        html.append(".stat .num{font-size:32px;font-weight:700;color:#c9190b}");
        html.append(".stat .label{font-size:13px;color:#6a6e73;margin-top:4px}");
        html.append("table{width:100%;border-collapse:collapse;font-size:13px}");
        html.append("th{text-align:left;padding:10px 12px;background:#f0f0f0;border-bottom:2px solid #d2d2d2;font-weight:600;color:#151515}");
        html.append("td{padding:10px 12px;border-bottom:1px solid #d2d2d2;vertical-align:top}");
        html.append("tr:hover td{background:#fafafa}");
        html.append(".ok{color:#3e8635}.fail{color:#c9190b}");
        html.append(".lw{background:#fdf7e7;color:#795600;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;white-space:nowrap}");
        html.append(".cve{font-size:12px;color:#06c}");
        html.append(".footer{text-align:center;padding:24px;font-size:12px;color:#6a6e73}");
        html.append(".footer a{color:#06c}");
        html.append(".warn{background:#faeae8;border:1px solid #c9190b;border-radius:8px;padding:16px;margin-bottom:24px;font-size:13px;color:#a30000}");
        html.append("</style></head><body>");

        html.append("<div class='header'>");
        html.append("<h1>&#9888; Help, I'm Vulnerable!</h1>");
        html.append("<p>Intentionally vulnerable Spring Boot application for Red Hat Trusted Profile Analyzer demos</p>");
        html.append("</div>");

        html.append("<div class='content'>");

        html.append("<div class='warn'>&#9888; <strong>Do not deploy this application in production.</strong> ");
        html.append("It intentionally includes dependencies with known security vulnerabilities for demonstration purposes.</div>");

        long cveCount = deps.stream().mapToLong(d -> d.cves.split(",").length).sum();
        long lwCount = deps.stream().filter(d -> !d.lightwellFix.isEmpty()).count();
        html.append("<div class='stats'>");
        html.append("<div class='stat'><div class='num'>").append(deps.size()).append("</div><div class='label'>Vulnerable Dependencies</div></div>");
        html.append("<div class='stat'><div class='num'>").append(cveCount).append("</div><div class='label'>CVEs Covered</div></div>");
        html.append("<div class='stat'><div class='num'>").append(lwCount).append("</div><div class='label'>Lightwell Remediations</div></div>");
        html.append("<div class='stat'><div class='num'>").append(loaded).append("/").append(deps.size()).append("</div><div class='label'>Libraries Loaded</div></div>");
        html.append("</div>");

        html.append("<div class='card'>");
        html.append("<h2>About This Application</h2>");
        html.append("<p>This application bundles specific versions of open-source libraries that have known CVEs. ");
        html.append("When its SBOM is uploaded to Red Hat Trusted Profile Analyzer (TPA), the system identifies these ");
        html.append("vulnerabilities and — for libraries covered by Lightwell advisories — shows a safe, version-compatible ");
        html.append("remediation path using backported security fixes.</p>");
        html.append("</div>");

        html.append("<div class='card'>");
        html.append("<h2>Dependency Status</h2>");
        html.append("<table>");
        html.append("<tr><th>Library</th><th>Group ID</th><th>Version</th><th>CVEs</th><th>Lightwell Fix</th><th>Status</th></tr>");
        for (DepStatus d : deps) {
            html.append("<tr>");
            html.append("<td><strong>").append(d.library).append("</strong></td>");
            html.append("<td><code>").append(d.groupId).append("</code></td>");
            html.append("<td><code>").append(d.version).append("</code></td>");
            html.append("<td class='cve'>");
            for (String cve : d.cves.split(", ")) {
                html.append(cve).append("<br>");
            }
            html.append("</td>");
            html.append("<td>");
            if (!d.lightwellFix.isEmpty()) {
                html.append("<span class='lw'>").append(d.lightwellFix).append("</span>");
            } else {
                html.append("<span style='color:#6a6e73;font-size:12px'>-</span>");
            }
            html.append("</td>");
            html.append("<td>");
            if (d.loaded) {
                html.append("<span class='ok'>&#10004; Loaded</span>");
            } else {
                html.append("<span class='fail'>&#10008; Failed</span>");
            }
            html.append("</td>");
            html.append("</tr>");
        }
        html.append("</table>");
        html.append("</div>");

        html.append("<div class='footer'>");
        html.append("<p>Built for <a href='https://www.redhat.com/en/technologies/cloud-computing/trusted-profile-analyzer'>Red Hat Trusted Profile Analyzer</a> demos</p>");
        html.append("</div>");

        html.append("</div></body></html>");
        return html.toString();
    }

    @GetMapping(value = "/api/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> status() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (DepStatus d : checkAll()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("library", d.library);
            entry.put("groupId", d.groupId);
            entry.put("version", d.version);
            entry.put("cves", d.cves);
            entry.put("lightwellFix", d.lightwellFix);
            entry.put("loaded", d.loaded);
            result.add(entry);
        }
        return result;
    }
}
