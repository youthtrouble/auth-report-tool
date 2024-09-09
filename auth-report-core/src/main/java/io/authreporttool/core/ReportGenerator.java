package io.authreporttool.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The ReportGenerator class is responsible for generating comprehensive reports based on the authorization
 * information collected by the AuthorizationScanner. It can generate both standard and differential reports,
 * including detailed security configuration information for each endpoint.
 *
 * This class serves as the final step in the authorization analysis process, transforming raw endpoint data
 * into structured, readable reports for security auditing and change tracking purposes.
 */
public class ReportGenerator {

    private static final Logger logger = LoggerFactory.getLogger(ReportGenerator.class);
    private final AuthorizationScanner scanner;

    /**
     * Constructs a new ReportGenerator with the specified AuthorizationScanner.
     *
     * @param scanner The AuthorizationScanner used to collect endpoint authorization information.
     */
    public ReportGenerator(AuthorizationScanner scanner) {
        this.scanner = scanner;
    }

    /**
     * Generates a comprehensive authorization report for the specified base package.
     * This method orchestrates the entire report generation process, from scanning to report creation.
     *
     * @param basePackage The base package to scan for endpoint authorization information.
     * @return An AuthorizationReport containing detailed endpoint authorization information.
     */
    public AuthorizationReport generateReport(String basePackage) {
        logger.info("Generating authorization report for package: " + basePackage);
        List<EndpointAuthInfo> authInfoList = scanner.scanApi(basePackage);
        return processAuthInfo(authInfoList);
    }

    /**
     * Processes a list of EndpointAuthInfo objects into a structured AuthorizationReport.
     * This method groups endpoints by their authorization expressions and creates authorization groups.
     *
     * @param authInfoList The list of endpoint authorization information.
     * @return An AuthorizationReport containing the grouped authorization information.
     */
    private AuthorizationReport processAuthInfo(List<EndpointAuthInfo> authInfoList) {
        Map<String, List<EndpointAuthInfo>> groupedByAuth = authInfoList.stream()
                .collect(Collectors.groupingBy(EndpointAuthInfo::getAuthExpression));

        List<AuthorizationGroup> groups = new ArrayList<>();
        for (Map.Entry<String, List<EndpointAuthInfo>> entry : groupedByAuth.entrySet()) {
            groups.add(new AuthorizationGroup(entry.getKey(), entry.getValue()));
        }

        return new AuthorizationReport(groups, LocalDateTime.now());
    }

    /**
     * Generates a detailed string representation of the authorization report.
     * This method is useful for creating human-readable output of the report.
     *
     * @param report The AuthorizationReport to convert to a string.
     * @return A formatted string representation of the authorization report.
     */
    public String generateDetailedReportString(AuthorizationReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("Authorization Report\n");
        sb.append("Generated at: ").append(report.getGeneratedAt()).append("\n");
        sb.append("Total endpoints: ").append(report.getTotalEndpoints()).append("\n\n");

        for (AuthorizationGroup group : report.getGroupedEndpoints()) {
            sb.append("Auth Expression: ").append(group.getAuthExpression()).append("\n");
            for (EndpointAuthInfo info : group.getEndpoints()) {
                sb.append("  ").append(info.getHttpMethod()).append(" ").append(info.getPath()).append("\n");
                sb.append("    API Key Required: ").append(info.isApiKeyRequired()).append("\n");
                sb.append("    Basic Auth Required: ").append(info.isBasicAuthRequired()).append("\n");
                sb.append("    Session Management: ").append(info.getSessionManagement()).append("\n");
                sb.append("    Security Features: ").append(String.join(", ", info.getSecurityFeatures())).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Generates a differential report by comparing an old authorization report with a new one.
     * This method is crucial for identifying changes in endpoint security configurations over time.
     *
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A DifferentialReport containing the differences between the two reports.
     */
    public DifferentialReport generateDifferentialReport(AuthorizationReport oldReport, AuthorizationReport newReport) {
        List<EndpointDiff> addedEndpoints = findAddedEndpoints(oldReport, newReport);
        List<EndpointDiff> removedEndpoints = findRemovedEndpoints(oldReport, newReport);
        List<EndpointDiff> changedEndpoints = findChangedEndpoints(oldReport, newReport);

        return new DifferentialReport(addedEndpoints, removedEndpoints, changedEndpoints);
    }

    /**
     * Finds the endpoints that were added in the new report compared to the old report.
     *
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A list of EndpointDiff objects representing the added endpoints.
     */
    private List<EndpointDiff> findAddedEndpoints(AuthorizationReport oldReport, AuthorizationReport newReport) {
        Map<String, EndpointAuthInfo> oldEndpointsMap = createEndpointMap(oldReport);

        return newReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .filter(endpoint -> !oldEndpointsMap.containsKey(endpoint.getPath()))
                .map(endpoint -> new EndpointDiff(endpoint, null))
                .collect(Collectors.toList());
    }

    /**
     * Finds the endpoints that were removed in the new report compared to the old report.
     *
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A list of EndpointDiff objects representing the removed endpoints.
     */
    private List<EndpointDiff> findRemovedEndpoints(AuthorizationReport oldReport, AuthorizationReport newReport) {
        Map<String, EndpointAuthInfo> newEndpointsMap = createEndpointMap(newReport);

        return oldReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .filter(endpoint -> !newEndpointsMap.containsKey(endpoint.getPath()))
                .map(endpoint -> new EndpointDiff(null, endpoint))
                .collect(Collectors.toList());
    }

    /**
     * Finds the endpoints that were changed between the old report and the new report.
     *
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A list of EndpointDiff objects representing the changed endpoints.
     */
    private List<EndpointDiff> findChangedEndpoints(AuthorizationReport oldReport, AuthorizationReport newReport) {
        Map<String, EndpointAuthInfo> oldEndpointsMap = createEndpointMap(oldReport);

        return newReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .filter(endpoint -> oldEndpointsMap.containsKey(endpoint.getPath()))
                .map(endpoint -> {
                    EndpointAuthInfo oldEndpoint = oldEndpointsMap.get(endpoint.getPath());
                    if (isEndpointChanged(endpoint, oldEndpoint)) {
                        return new EndpointDiff(endpoint, oldEndpoint);
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * Creates a map of endpoints keyed by their paths for efficient lookup.
     *
     * @param report The authorization report to create the map from.
     * @return A map of endpoint paths to EndpointAuthInfo objects.
     */
    private Map<String, EndpointAuthInfo> createEndpointMap(AuthorizationReport report) {
        return report.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .collect(Collectors.toMap(EndpointAuthInfo::getPath, Function.identity()));
    }

    /**
     * Determines if an endpoint has changed by comparing all relevant fields.
     *
     * @param newEndpoint The endpoint from the new report.
     * @param oldEndpoint The endpoint from the old report.
     * @return true if the endpoint has changed, false otherwise.
     */
    private boolean isEndpointChanged(EndpointAuthInfo newEndpoint, EndpointAuthInfo oldEndpoint) {
        return !newEndpoint.getAuthExpression().equals(oldEndpoint.getAuthExpression()) ||
                !newEndpoint.getHttpMethod().equals(oldEndpoint.getHttpMethod()) ||
                newEndpoint.isApiKeyRequired() != oldEndpoint.isApiKeyRequired() ||
                newEndpoint.isBasicAuthRequired() != oldEndpoint.isBasicAuthRequired() ||
                newEndpoint.isCsrfEnabled() != oldEndpoint.isCsrfEnabled() ||
                !newEndpoint.getSessionManagement().equals(oldEndpoint.getSessionManagement()) ||
                !newEndpoint.getSecurityFeatures().equals(oldEndpoint.getSecurityFeatures());
    }

    /**
     * Generates a detailed string representation of the differential report.
     *
     * @param report The DifferentialReport to convert to a string.
     * @return A formatted string representation of the differential report.
     */
    public String generateDetailedDiffReportString(DifferentialReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("Differential Authorization Report\n");
        sb.append("Generated at: ").append(LocalDateTime.now()).append("\n\n");

        sb.append("Added Endpoints:\n");
        report.getAddedEndpoints().forEach(diff -> appendEndpointDiff(sb, diff.getNewEndpoint(), "Added"));

        sb.append("Removed Endpoints:\n");
        report.getRemovedEndpoints().forEach(diff -> appendEndpointDiff(sb, diff.getOldEndpoint(), "Removed"));

        sb.append("Changed Endpoints:\n");
        report.getChangedEndpoints().forEach(diff -> {
            appendEndpointDiff(sb, diff.getNewEndpoint(), "Changed (New)");
            appendEndpointDiff(sb, diff.getOldEndpoint(), "Changed (Old)");
            sb.append("\n");
        });

        return sb.toString();
    }

    /**
     * Appends the details of a single endpoint to the StringBuilder.
     *
     * @param sb The StringBuilder to append to.
     * @param endpoint The EndpointAuthInfo to append.
     * @param changeType The type of change (Added, Removed, or Changed).
     */
    private void appendEndpointDiff(StringBuilder sb, EndpointAuthInfo endpoint, String changeType) {
        sb.append("  ").append(changeType).append(": ").append(endpoint.getHttpMethod()).append(" ").append(endpoint.getPath()).append("\n");
        sb.append("    Auth Expression: ").append(endpoint.getAuthExpression()).append("\n");
        sb.append("    API Key Required: ").append(endpoint.isApiKeyRequired()).append("\n");
        sb.append("    Basic Auth Required: ").append(endpoint.isBasicAuthRequired()).append("\n");
        sb.append("    CSRF Enabled: ").append(endpoint.isCsrfEnabled()).append("\n");
        sb.append("    Session Management: ").append(endpoint.getSessionManagement()).append("\n");
        sb.append("    Security Features: ").append(String.join(", ", endpoint.getSecurityFeatures())).append("\n");
        sb.append("\n");
    }
}