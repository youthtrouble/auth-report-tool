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
import java.util.stream.Collectors;

/**
 * Handles formatting and printing the Authorization Report in various formats.
 */
public class ReportPrinter {

    /**
     * Prints the report in the specified format to the given output (console or file).
     *
     * @param report The io.authreporttool.core.AuthorizationReport to print.
     * @param format The output format ("text" or "json").
     * @param outputFile The file to write the report to (null for console output).
     * @param verbose Whether to include verbose output.
     * @throws IOException If there's an error writing to the output file.
     */
    public static void printReport(AuthorizationReport report, String format, String outputFile, boolean verbose) throws IOException {
        PrintWriter writer = outputFile != null ? new PrintWriter(new FileWriter(outputFile)) : new PrintWriter(System.out);

        if ("json".equalsIgnoreCase(format)) {
            printJsonReport(report, writer, verbose);
        } else {
            printTextReport(report, writer, verbose);
        }

        writer.flush();
        if (outputFile != null) {
            writer.close();
            System.out.println("Report written to: " + outputFile);
        }
    }

    /**
     * Prints the report in text format.
     */
    private static void printTextReport(AuthorizationReport report, PrintWriter writer, boolean verbose) {
        writer.println("Authorization Report");
        writer.println("Generated at: " + report.getGeneratedAt());
        writer.println("Total endpoints: " + report.getTotalEndpoints());
        writer.println("Unique auth expressions: " + report.getUniqueAuthExpressions());
        writer.println();

        for (AuthorizationGroup group : report.getGroupedEndpoints()) {
            writer.println("Auth Expression: " + group.getAuthExpression());
            for (EndpointAuthInfo endpoint : group.getEndpoints()) {
                writer.println("  " + endpoint.getHttpMethod() + " " + endpoint.getPath());
                if (verbose) {
                    writer.println("    Class: " + endpoint.getClassName());
                    writer.println("    Method: " + endpoint.getMethodName());
                }
            }
            writer.println();
        }
    }

    /**
     * Prints the report in JSON format.
     */
    private static void printJsonReport(AuthorizationReport report, PrintWriter writer, boolean verbose) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        if (verbose) {
            mapper.writeValue(writer, report);
        } else {
            // Create a simplified version of the report for non-verbose output
            SimplifiedReport simplifiedReport = new SimplifiedReport(report);
            mapper.writeValue(writer, simplifiedReport);
        }
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