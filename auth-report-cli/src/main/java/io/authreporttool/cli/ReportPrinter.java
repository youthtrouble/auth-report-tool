package io.authreporttool.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.authreporttool.core.AuthorizationGroup;
import io.authreporttool.core.AuthorizationReport;
import io.authreporttool.core.EndpointAuthInfo;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ReportPrinter is responsible for generating and outputting authorization reports
 * in both text and JSON formats. It provides functionality to write reports to
 * either a file or the console.
 */
public class ReportPrinter {

    /**
     * Prints the authorization report in the specified format to either a file or the console.
     *
     * @param report The AuthorizationReport to be printed
     * @param format The output format ("json" for JSON, any other value for text)
     * @param outputFile The file path to write the report to. If null, output is directed to the console.
     * @throws IOException If there's an error writing to the file
     */
    public static void printReport(AuthorizationReport report, String format, String outputFile) throws IOException {
        PrintWriter writer = outputFile != null ? new PrintWriter(new FileWriter(outputFile)) : new PrintWriter(System.out);

        if ("json".equalsIgnoreCase(format)) {
            printJsonReport(report, writer);
        } else {
            printTextReport(report, writer);
        }

        writer.flush();
        if (outputFile != null) {
            writer.close();
            System.out.println("Report written to: " + outputFile);
        }
    }

    /**
     * Prints the authorization report in a human-readable text format.
     *
     * @param report The AuthorizationReport to be printed
     * @param writer The PrintWriter to write the report to
     */
    private static void printTextReport(AuthorizationReport report, PrintWriter writer) {
        writer.println("Authorization Report");
        writer.println("Generated at: " + report.getGeneratedAt());
        writer.println("Total endpoints: " + report.getTotalEndpoints());
        writer.println();

        for (AuthorizationGroup group : report.getGroupedEndpoints()) {
            writer.println("Auth Expression: " + group.getAuthExpression());
            for (EndpointAuthInfo info : group.getEndpoints()) {
                writer.println("  " + info.getHttpMethod() + " " + info.getPath());
                writer.println("    API Key Required: " + info.isApiKeyRequired());
                writer.println("    Basic Auth Required: " + info.isBasicAuthRequired());
                writer.println("    Session Management: " + info.getSessionManagement());
                writer.println("    Security Features: " + String.join(", ", info.getSecurityFeatures()));
            }
            writer.println();
        }
    }

    /**
     * Prints the authorization report in JSON format.
     *
     * @param report The AuthorizationReport to be printed
     * @param writer The PrintWriter to write the report to
     * @throws IOException If there's an error during JSON serialization
     */
    private static void printJsonReport(AuthorizationReport report, PrintWriter writer) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(writer, new JsonReport(report));
    }

    /**
     * Internal class representing the structure of the JSON report.
     * This class is used to create a clean, serializable object for JSON output.
     */
    private static class JsonReport {
        public final String generatedAt;
        public final int totalEndpoints;
        public final int uniqueAuthExpressions;
        public final List<JsonAuthGroup> authorizationGroups;

        public JsonReport(AuthorizationReport report) {
            this.generatedAt = report.getGeneratedAt().toString();
            this.totalEndpoints = report.getTotalEndpoints();
            this.uniqueAuthExpressions = report.getUniqueAuthExpressions();
            this.authorizationGroups = report.getGroupedEndpoints().stream()
                    .map(JsonAuthGroup::new)
                    .collect(Collectors.toList());
        }
    }

    /**
     * Internal class representing an authorization group in the JSON structure.
     */
    private static class JsonAuthGroup {
        public final String authExpression;
        public final List<JsonEndpoint> endpoints;

        public JsonAuthGroup(AuthorizationGroup group) {
            this.authExpression = group.getAuthExpression();
            this.endpoints = group.getEndpoints().stream()
                    .map(JsonEndpoint::new)
                    .collect(Collectors.toList());
        }
    }

    /**
     * Internal class representing an individual endpoint in the JSON structure.
     */
    private static class JsonEndpoint {
        public final String httpMethod;
        public final String path;
        public final boolean apiKeyRequired;
        public final boolean basicAuthRequired;
        public final String sessionManagement;
        public final Set<String> securityFeatures;

        public JsonEndpoint(EndpointAuthInfo info) {
            this.httpMethod = info.getHttpMethod();
            this.path = info.getPath();
            this.apiKeyRequired = info.isApiKeyRequired();
            this.basicAuthRequired = info.isBasicAuthRequired();
            this.sessionManagement = info.getSessionManagement();
            this.securityFeatures = info.getSecurityFeatures();
        }
    }
}