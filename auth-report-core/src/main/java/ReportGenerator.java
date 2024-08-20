import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The ReportGenerator class is responsible for generating reports based on the authorization
 * information collected by the AuthorizationScanner. It can also generate differential reports
 * that compare two authorization reports to identify changes.
 */
public class ReportGenerator {

    // Instance of AuthorizationScanner used to scan for endpoint authorization information
    private final AuthorizationScanner scanner;

    /**
     * Constructor to initialize the ReportGenerator with an AuthorizationScanner instance.
     * @param scanner The AuthorizationScanner used to scan for endpoint authorization information.
     */
    public ReportGenerator(AuthorizationScanner scanner) {
        this.scanner = scanner;
    }

    /**
     * Generates an authorization report by scanning the specified base package.
     * @param basePackage The base package to scan for endpoint authorization information.
     * @return An AuthorizationReport containing the scanned endpoint authorization information.
     */
    public AuthorizationReport generateReport(String basePackage) {
        // Scan the base package for endpoint authorization information
        List<EndpointAuthInfo> authInfoList = scanner.scanApi(basePackage);
        // Process the collected information into an authorization report
        return processAuthInfo(authInfoList);
    }

    /**
     * Processes a list of EndpointAuthInfo objects into an AuthorizationReport.
     * Groups endpoints by their authorization expressions and creates authorization groups.
     * @param authInfoList The list of endpoint authorization information.
     * @return An AuthorizationReport containing the grouped authorization information.
     */
    private AuthorizationReport processAuthInfo(List<EndpointAuthInfo> authInfoList) {
        // Group the endpoints by their authorization expressions (e.g., "ROLE_ADMIN", "ROLE_USER")
        Map<String, List<EndpointAuthInfo>> groupedByAuth = authInfoList.stream()
                .collect(Collectors.groupingBy(EndpointAuthInfo::getAuthExpression));

        // Create a list of AuthorizationGroup objects based on the grouped information
        List<AuthorizationGroup> groups = new ArrayList<>();
        for (Map.Entry<String, List<EndpointAuthInfo>> entry : groupedByAuth.entrySet()) {
            groups.add(new AuthorizationGroup(entry.getKey(), entry.getValue()));
        }

        // Return a new AuthorizationReport containing the groups and the current timestamp
        return new AuthorizationReport(groups, LocalDateTime.now());
    }

    /**
     * Generates a differential report by comparing an old authorization report with a new one.
     * Identifies endpoints that were added, removed, or changed between the two reports.
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A DifferentialReport containing the differences between the two reports.
     */
    public DifferentialReport generateDifferentialReport(AuthorizationReport oldReport, AuthorizationReport newReport) {
        // Find endpoints that were added in the new report
        List<EndpointDiff> addedEndpoints = findAddedEndpoints(oldReport, newReport);
        // Find endpoints that were removed from the old report
        List<EndpointDiff> removedEndpoints = findRemovedEndpoints(oldReport, newReport);
        // Find endpoints that were changed between the two reports
        List<EndpointDiff> changedEndpoints = findChangedEndpoints(oldReport, newReport);

        // Return a new DifferentialReport containing the added, removed, and changed endpoints
        return new DifferentialReport(addedEndpoints, removedEndpoints, changedEndpoints);
    }

    /**
     * Finds the endpoints that were added in the new report compared to the old report.
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A list of EndpointDiff objects representing the added endpoints.
     */
    private List<EndpointDiff> findAddedEndpoints(AuthorizationReport oldReport, AuthorizationReport newReport) {
        // Create a map of endpoints in the old report for efficient lookup
        Map<String, EndpointAuthInfo> oldEndpointsMap = oldReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .collect(Collectors.toMap(EndpointAuthInfo::getPath, Function.identity()));

        // Compare endpoints in the new report with the old report and find the added ones
        return newReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .filter(endpoint -> !oldEndpointsMap.containsKey(endpoint.getPath()))
                .map(endpoint -> new EndpointDiff(endpoint, null))
                .collect(Collectors.toList());
    }

    /**
     * Finds the endpoints that were removed in the new report compared to the old report.
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A list of EndpointDiff objects representing the removed endpoints.
     */
    private List<EndpointDiff> findRemovedEndpoints(AuthorizationReport oldReport, AuthorizationReport newReport) {
        // Create a map of endpoints in the new report for efficient lookup
        Map<String, EndpointAuthInfo> newEndpointsMap = newReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .collect(Collectors.toMap(EndpointAuthInfo::getPath, Function.identity()));

        // Compare endpoints in the old report with the new report and find the removed ones
        return oldReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .filter(endpoint -> !newEndpointsMap.containsKey(endpoint.getPath()))
                .map(endpoint -> new EndpointDiff(null, endpoint))
                .collect(Collectors.toList());
    }

    /**
     * Finds the endpoints that were changed between the old report and the new report.
     * @param oldReport The old authorization report.
     * @param newReport The new authorization report.
     * @return A list of EndpointDiff objects representing the changed endpoints.
     */
    private List<EndpointDiff> findChangedEndpoints(AuthorizationReport oldReport, AuthorizationReport newReport) {
        // Create a map of endpoints in the old report for efficient lookup
        Map<String, EndpointAuthInfo> oldEndpointsMap = oldReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .collect(Collectors.toMap(EndpointAuthInfo::getPath, Function.identity()));

        // Compare endpoints in the new report with the old report and find the changed ones
        return newReport.getGroupedEndpoints().stream()
                .flatMap(group -> group.getEndpoints().stream())
                .filter(endpoint -> oldEndpointsMap.containsKey(endpoint.getPath()))
                .map(endpoint -> {
                    EndpointAuthInfo oldEndpoint = oldEndpointsMap.get(endpoint.getPath());
                    if (!endpoint.getAuthExpression().equals(oldEndpoint.getAuthExpression()) ||
                            !endpoint.getHttpMethod().equals(oldEndpoint.getHttpMethod())) {
                        return new EndpointDiff(endpoint, oldEndpoint);
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }
}