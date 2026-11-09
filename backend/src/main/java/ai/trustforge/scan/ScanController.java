package ai.trustforge.scan;

import ai.trustforge.project.Project;
import ai.trustforge.project.ProjectRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:5173")
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final ProjectRepository projects;
    private final ScanRepository scans;
    private final ObjectMapper mapper;
    private final HttpClient httpClient;
    private final String analysisUrl;

    public ScanController(
            ProjectRepository projects,
            ScanRepository scans,
            ObjectMapper mapper,
            @Value("${trustforge.analysis-url:http://127.0.0.1:8000}") String analysisUrl) {
        this.projects = projects;
        this.scans = scans;
        this.mapper = mapper;
        this.analysisUrl = analysisUrl.replaceAll("/+$", "");
        this.httpClient = HttpClient.newBuilder()
                // Uvicorn's default HTTP stack serves HTTP/1.1. Do not negotiate h2c.
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @PostMapping("/projects/{id}/scans")
    public Map<String, Object> startScan(@PathVariable Long id) {
        Project project = projects.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Project not found"));

        String repositoryUrl = project.getRepositoryUrl();
        if (repositoryUrl == null || repositoryUrl.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Project repository URL is missing.");
        }

        JsonNode result;
        try {
            String jsonBody = mapper.writeValueAsString(
                    Map.of("repository_url", repositoryUrl));
            byte[] payload = jsonBody.getBytes(StandardCharsets.UTF_8);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(analysisUrl + "/api/v1/scan"))
                    .version(HttpClient.Version.HTTP_1_1)
                    .timeout(Duration.ofMinutes(3))
                    .header("Content-Type", "application/json; charset=utf-8")
                    .header("Accept", "application/json")
                    // Fallback accepted by FastAPI if the body is dropped by a local transport.
                    .header("X-Repository-Url", repositoryUrl)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
                    .build();

            log.info("Sending analysis request for project {} ({} JSON bytes; HTTP/1.1; JSON body plus repository header fallback) to {}",
                    id, payload.length, analysisUrl);
            log.debug("Analysis request payload: {}", jsonBody);

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                log.error("Analysis service returned HTTP {}: {}",
                        response.statusCode(), response.body());
                throw new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY,
                        "Analysis service returned HTTP " + response.statusCode()
                                + ": " + safeErrorBody(response.body()));
            }

            if (response.body() == null || response.body().isBlank()) {
                throw new IllegalStateException("Analysis service returned an empty response.");
            }
            result = mapper.readTree(response.body());

        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while waiting for analysis service", ex);
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY, "Analysis service request was interrupted.", ex);
        } catch (IOException | IllegalArgumentException ex) {
            log.error("Could not communicate with analysis service at {}", analysisUrl, ex);
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "Could not communicate with analysis service. Confirm it is running at "
                            + analysisUrl + ".", ex);
        } catch (Exception ex) {
            log.error("Unexpected analysis service failure", ex);
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY, "Analysis service request failed.", ex);
        }

        try {
            int findings = result.path("findings").size();
            int dependencies = result.path("dependencyCount").asInt();
            int score = result.path("riskScore").asInt();

            ScanRecord saved = scans.save(new ScanRecord(
                    id, "COMPLETED", findings, dependencies, score,
                    mapper.writeValueAsString(result)));

            return Map.of(
                    "id", saved.getId(),
                    "projectId", id,
                    "status", saved.getStatus(),
                    "findingCount", findings,
                    "dependencyCount", dependencies,
                    "riskScore", score,
                    "createdAt", saved.getCreatedAt());
        } catch (Exception ex) {
            log.error("Could not persist scan result for project {}", id, ex);
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "Could not persist scan result.", ex);
        }
    }

    private String safeErrorBody(String body) {
        if (body == null || body.isBlank()) return "(empty response body)";
        return body.length() > 1500 ? body.substring(0, 1500) : body;
    }

    @GetMapping("/scans")
    public List<Map<String, Object>> listScans() {
        return scans.findAllByOrderByCreatedAtDesc().stream()
                .map(s -> Map.<String, Object>of(
                        "id", s.getId(),
                        "projectId", s.getProjectId(),
                        "status", s.getStatus(),
                        "findingCount", s.getFindingCount(),
                        "dependencyCount", s.getDependencyCount(),
                        "riskScore", s.getRiskScore(),
                        "createdAt", s.getCreatedAt()))
                .toList();
    }

    @GetMapping("/scans/{id}")
    public JsonNode getScan(@PathVariable Long id) {
        ScanRecord record = scans.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Scan not found"));
        try {
            return mapper.readTree(record.getResultJson());
        } catch (Exception ex) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "Stored scan result is invalid.");
        }
    }

    @GetMapping(value = "/scans/{id}/report", produces = "text/markdown")
    public ResponseEntity<String> getReport(@PathVariable Long id) {
        ScanRecord record = scans.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Scan not found"));
        try {
            JsonNode result = mapper.readTree(record.getResultJson());
            String repository = result.path("repository").asText("unknown");
            StringBuilder report = new StringBuilder();
            report.append("# TrustForge AI Security Report\n\n")
                    .append("- **Repository:** ").append(repository).append("\n")
                    .append("- **Scan ID:** ").append(id).append("\n")
                    .append("- **Scanned at:** ").append(result.path("scannedAt").asText("not recorded")).append("\n")
                    .append("- **Status:** ").append(result.path("scanStatus").asText(record.getStatus())).append("\n")
                    .append("- **Files inspected:** ").append(result.path("filesInspected").asInt()).append("\n")
                    .append("- **Dependencies:** ").append(result.path("dependencyCount").asInt()).append("\n")
                    .append("- **Findings:** ").append(result.path("findings").size()).append("\n")
                    .append("- **Risk score:** ").append(result.path("riskScore").asInt()).append("/100 (heuristic priority, not probability of compromise)\n")
                    .append("- **Risk level:** ").append(result.path("riskLevel").asText("not classified")).append("\n\n")
                    .append("## Severity summary\n\n")
                    .append("| Severity | Count |\n|---|---:|\n");
            for (String severity : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")) {
                report.append("| ").append(severity).append(" | ")
                        .append(result.path("severityCounts").path(severity).asInt()).append(" |\n");
            }
            report.append("\n## Findings\n\n");
            JsonNode findings = result.path("findings");
            if (!findings.isArray() || findings.isEmpty()) {
                report.append("No findings were returned by the enabled checks. This is not a guarantee that the repository is secure.\n");
            } else {
                int index = 1;
                for (JsonNode finding : findings) {
                    report.append("### ").append(index++).append(". ")
                            .append(finding.path("title").asText("Untitled finding")).append("\n\n")
                            .append("- **Severity:** ").append(finding.path("severity").asText("UNKNOWN")).append("\n")
                            .append("- **Type:** ").append(finding.path("type").asText("unknown")).append("\n")
                            .append("- **Package:** ").append(finding.path("packageName").asText("—"))
                            .append(finding.hasNonNull("installedVersion") ? "@" + finding.path("installedVersion").asText() : "")
                            .append("\n")
                            .append("- **Advisory:** ").append(finding.path("advisoryId").asText(finding.path("cve").asText("—"))).append("\n");
                    if (finding.hasNonNull("cvssScore")) {
                        report.append("- **CVSS:** ").append(finding.path("cvssScore").asText()).append(" ")
                                .append(finding.path("cvssVector").asText()).append("\n");
                    }
                    JsonNode fixed = finding.path("fixedVersions");
                    if (fixed.isArray() && !fixed.isEmpty()) {
                        List<String> versions = new ArrayList<>();
                        fixed.forEach(value -> versions.add(value.asText()));
                        report.append("- **Fixed versions:** ").append(String.join(", ", versions)).append("\n");
                    }
                    String summary = finding.path("summary").asText("");
                    if (!summary.isBlank()) {
                        report.append("\n").append(summary.replace("\r", "")).append("\n");
                    }
                    String recommendation = finding.path("recommendation").asText("");
                    if (!recommendation.isBlank()) {
                        report.append("\n**Recommendation:** ").append(recommendation).append("\n");
                    }
                    JsonNode references = finding.path("references");
                    if (references.isArray() && !references.isEmpty()) {
                        report.append("\n**References:**\n");
                        references.forEach(ref -> report.append("- ").append(ref.asText()).append("\n"));
                    }
                    report.append("\n");
                }
            }
            JsonNode warnings = result.path("enrichmentWarnings");
            if (warnings.isArray() && !warnings.isEmpty()) {
                report.append("## Enrichment warnings\n\n");
                warnings.forEach(warning -> report.append("- ").append(warning.asText()).append("\n"));
                report.append("\n");
            }
            report.append("---\nGenerated by TrustForge AI. Verify findings with upstream advisory sources before remediation.\n");
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("text/markdown; charset=UTF-8"))
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=trustforge-scan-" + id + "-report.md")
                    .body(report.toString());
        } catch (Exception ex) {
            log.error("Could not generate report for scan {}", id, ex);
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "Could not generate scan report.");
        }
    }

    @GetMapping("/scans/{id}/sbom")
    public JsonNode getSbom(@PathVariable Long id) {
        ScanRecord record = scans.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Scan not found"));
        try {
            JsonNode result = mapper.readTree(record.getResultJson());
            String repo = result.path("repository").asText("unknown");
            JsonNode deps = result.path("dependencies");
            List<Map<String, Object>> components = new ArrayList<>();
            Map<String, String> purlByPackage = new java.util.HashMap<>();

            for (JsonNode dep : deps) {
                String ecosystem = dep.path("ecosystem").asText();
                String name = dep.path("name").asText();
                String version = dep.path("version").asText();
                String type = ecosystem.equalsIgnoreCase("npm") ? "npm"
                        : ecosystem.equalsIgnoreCase("pypi") ? "pypi" : "maven";
                String purl = type.equals("maven") && name.contains(":")
                        ? "pkg:maven/" + name.replace(":", "/") + "@" + version
                        : "pkg:" + type + "/" + name.replace("@", "%40") + "@" + version;
                components.add(Map.of(
                        "type", "library", "name", name, "version", version,
                        "purl", purl, "bom-ref", purl));
                purlByPackage.put(ecosystem.toLowerCase() + "|" + name.toLowerCase() + "|" + version, purl);
            }

            List<Map<String, Object>> vulnerabilities = new ArrayList<>();
            for (JsonNode finding : result.path("findings")) {
                if (!"DEPENDENCY_VULNERABILITY".equals(finding.path("type").asText())) {
                    continue;
                }
                String key = finding.path("ecosystem").asText().toLowerCase() + "|"
                        + finding.path("packageName").asText().toLowerCase() + "|"
                        + finding.path("installedVersion").asText();
                String componentRef = purlByPackage.get(key);
                if (componentRef == null) continue;

                Map<String, Object> vulnerability = new java.util.LinkedHashMap<>();
                vulnerability.put("id", finding.path("advisoryId").asText(finding.path("cve").asText("unknown")));
                vulnerability.put("source", Map.of("name", "OSV", "url", "https://osv.dev/vulnerability/" + finding.path("advisoryId").asText()));
                vulnerability.put("description", finding.path("summary").asText(finding.path("title").asText("Dependency vulnerability")));
                vulnerability.put("recommendation", finding.path("recommendation").asText("Review the upstream advisory and plan an update."));
                vulnerability.put("affects", List.of(Map.of("ref", componentRef)));

                if (finding.hasNonNull("cvssScore")) {
                    Map<String, Object> rating = new java.util.LinkedHashMap<>();
                    rating.put("source", Map.of("name", "OSV"));
                    rating.put("score", finding.path("cvssScore").asDouble());
                    rating.put("severity", finding.path("severity").asText("unknown").toLowerCase());
                    rating.put("method", "CVSSv3");
                    if (finding.hasNonNull("cvssVector")) rating.put("vector", finding.path("cvssVector").asText());
                    vulnerability.put("ratings", List.of(rating));
                }
                List<Map<String, String>> advisories = new ArrayList<>();
                for (JsonNode ref : finding.path("references")) {
                    if (ref.isTextual()) advisories.add(Map.of("url", ref.asText()));
                }
                if (!advisories.isEmpty()) vulnerability.put("advisories", advisories);

                List<Integer> cwes = new ArrayList<>();
                for (JsonNode cwe : finding.path("cwes")) {
                    String value = cwe.asText();
                    java.util.regex.Matcher matcher = java.util.regex.Pattern
                            .compile("(\\d+)")
                            .matcher(value);
                    if (matcher.find()) {
                        try {
                            int number = Integer.parseInt(matcher.group(1));
                            if (number > 0 && !cwes.contains(number)) cwes.add(number);
                        } catch (NumberFormatException ignored) {
                            log.debug("Skipping invalid CWE identifier: {}", value);
                        }
                    }
                }
                if (!cwes.isEmpty()) vulnerability.put("cwes", cwes);

                vulnerabilities.add(vulnerability);
            }

            Map<String, Object> bom = new java.util.LinkedHashMap<>();
            bom.put("bomFormat", "CycloneDX");
            bom.put("specVersion", "1.5");
            bom.put("version", 1);
            bom.put("metadata", Map.of("component", Map.of("type", "application", "name", repo)));
            bom.put("components", components);
            if (!vulnerabilities.isEmpty()) bom.put("vulnerabilities", vulnerabilities);
            return mapper.valueToTree(bom);
        } catch (Exception ex) {
            log.error("Could not generate SBOM for scan {}", id, ex);
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "Could not generate SBOM.");
        }
    }
}
