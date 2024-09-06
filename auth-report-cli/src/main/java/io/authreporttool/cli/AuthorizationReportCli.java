package io.authreporttool.cli;

import io.authreporttool.core.AuthorizationReport;
import io.authreporttool.core.AuthorizationScanner;
import io.authreporttool.core.ReflectionUtils;
import io.authreporttool.core.ReportGenerator;
import io.authreporttool.core.SecurityConfigAnalyzer;

import java.io.IOException;

/**
 * Main class for the Authorization Report CLI tool.
 */
public class AuthorizationReportCli {

    public static void main(String[] args) {
        CommandLineOptions options = new CommandLineOptions(args);

        try {
            AuthorizationReport report = getAuthorizationReport(options);
            String reportString = generateReportString(report, options);

            // Print the report using the specified format and output option
            ReportPrinter.printReport(reportString, options.getOutputFormat(), options.getOutputFile());

        } catch (IOException e) {
            System.err.println("Error generating or printing the report: " + e.getMessage());
            System.exit(1);
        }
    }

    private static AuthorizationReport getAuthorizationReport(CommandLineOptions options) {
        ReflectionUtils reflectionUtils = new ReflectionUtils();
        SecurityConfigAnalyzer securityConfigAnalyzer = new SecurityConfigAnalyzer();

        // Create and configure the authorization scanner
        AuthorizationScanner scanner = new AuthorizationScanner(reflectionUtils, securityConfigAnalyzer);

        // Create the report generator
        ReportGenerator generator = new ReportGenerator(scanner);

        // Generate the authorization report
        return generator.generateReport(options.getBasePackage());
    }

    private static String generateReportString(AuthorizationReport report, CommandLineOptions options) {
        ReportGenerator generator = new ReportGenerator(null); // We don't need scanner here
        return generator.generateDetailedReportString(report);
    }
}