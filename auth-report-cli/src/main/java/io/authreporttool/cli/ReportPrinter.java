package io.authreporttool.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.authreporttool.core.AuthorizationGroup;
import io.authreporttool.core.AuthorizationReport;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Handles formatting and printing the Authorization Report in various formats.
 */
public class ReportPrinter {

    /**
     * Prints the report in the specified format to the given output (console or file).
     *
     * @param reportString The string representation of the AuthorizationReport to print.
     * @param format The output format ("text" or "json").
     * @param outputFile The file to write the report to (null for console output).
     * @throws IOException If there's an error writing to the output file.
     */
    public static void printReport(String reportString, String format, String outputFile) throws IOException {
        PrintWriter writer = outputFile != null ? new PrintWriter(new FileWriter(outputFile)) : new PrintWriter(System.out);

        if ("json".equalsIgnoreCase(format)) {
            printJsonReport(reportString, writer);
        } else {
            printTextReport(reportString, writer);
        }

        writer.flush();
        if (outputFile != null) {
            writer.close();
            System.out.println("Report written to: " + outputFile);
        }
    }

    /**
     * Prints the report in text format.
     *
     * @param reportString The string representation of the report.
     * @param writer The PrintWriter to write the report to.
     */
    private static void printTextReport(String reportString, PrintWriter writer) {
        writer.println(reportString);
    }

    /**
     * Prints the report in JSON format.
     *
     * @param reportString The string representation of the report.
     * @param writer The PrintWriter to write the report to.
     * @throws IOException If there's an error during JSON conversion.
     */
    private static void printJsonReport(String reportString, PrintWriter writer) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        // Convert the report string to a JSON object
        Object jsonReport = convertReportToJson(reportString);

        // Write the JSON object to the writer
        mapper.writeValue(writer, jsonReport);
    }

    /**
     * Converts the string report to a JSON-compatible object structure.
     *
     * @param reportString The string representation of the report.
     * @return An object structure that can be serialized to JSON.
     */
    private static Object convertReportToJson(String reportString) {
        // This is a placeholder implementation. You'll need to parse the reportString
        // and create a proper object structure that represents the report in a JSON-friendly format.
        // For now, we'll just create a simple object with the raw string.
        return new Object() {
            public final String report = reportString;
        };
    }
    /**
     * A simplified version of the report for non-verbose JSON output.
     */
    private static class SimplifiedReport {
        public final String generatedAt;
        public final int totalEndpoints;
        public final int uniqueAuthExpressions;
        public final List<SimplifiedGroup> groups;

        public SimplifiedReport(AuthorizationReport report) {
            this.generatedAt = report.getGeneratedAt().toString();
            this.totalEndpoints = report.getTotalEndpoints();
            this.uniqueAuthExpressions = report.getUniqueAuthExpressions();
            this.groups = report.getGroupedEndpoints().stream()
                    .map(SimplifiedGroup::new)
                    .collect(Collectors.toList());
        }
    }

    private static class SimplifiedGroup {
        public final String authExpression;
        public final List<String> endpoints;

        public SimplifiedGroup(AuthorizationGroup group) {
            this.authExpression = group.getAuthExpression();
            this.endpoints = group.getEndpoints().stream()
                    .map(e -> e.getHttpMethod() + " " + e.getPath())
                    .collect(Collectors.toList());
        }
    }
}