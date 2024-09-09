package io.authreporttool.cli;

import io.authreporttool.core.AuthorizationReport;
import io.authreporttool.core.AuthorizationScanner;
import io.authreporttool.core.ReflectionUtils;
import io.authreporttool.core.ReportGenerator;
import io.authreporttool.core.SecurityConfigAnalyzer;

import java.io.IOException;

/**
 * AuthorizationReportCli is the main entry point for the Authorization Report Command Line Interface tool.
 * This class orchestrates the process of scanning a specified package for authorization configurations,
 * generating a report, and outputting it in the desired format.
 */
public class AuthorizationReportCli {

    /**
     * The main method that drives the CLI tool's execution.
     * It parses command line arguments, generates the authorization report,
     * and outputs the report based on the specified options.
     *
     * @param args Command line arguments passed to the program.
     */
    public static void main(String[] args) {
        // Parse command line options
        CommandLineOptions options = new CommandLineOptions(args);

        try {
            // Generate the authorization report
            AuthorizationReport report = getAuthorizationReport(options);

            // Print the report using the specified format and output option
            ReportPrinter.printReport(report, options.getOutputFormat(), options.getOutputFile());

        } catch (IOException e) {
            // Handle any IO errors that occur during report generation or printing
            System.err.println("Error generating or printing the report: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Generates an AuthorizationReport by setting up and using the necessary components.
     *
     * @param options The parsed command line options.
     * @return An AuthorizationReport containing the analysis results.
     */
    private static AuthorizationReport getAuthorizationReport(CommandLineOptions options) {
        // Initialize utility classes
        ReflectionUtils reflectionUtils = new ReflectionUtils();
        SecurityConfigAnalyzer securityConfigAnalyzer = new SecurityConfigAnalyzer();

        // Create and configure the authorization scanner
        AuthorizationScanner scanner = new AuthorizationScanner(reflectionUtils, securityConfigAnalyzer);

        // Create the report generator
        ReportGenerator generator = new ReportGenerator(scanner);

        // Generate and return the authorization report
        return generator.generateReport(options.getBasePackage());
    }

    /**
     * Generates a string representation of the AuthorizationReport.
     *
     * @param report The AuthorizationReport to convert to a string.
     * @param options The parsed command line options (unused in this implementation, but could be used for customization).
     * @return A string representation of the report.
     */
    private static String generateReportString(AuthorizationReport report, CommandLineOptions options) {
        // Create a new ReportGenerator (scanner not needed for string generation)
        ReportGenerator generator = new ReportGenerator(null);

        // Generate and return the detailed report string
        return generator.generateDetailedReportString(report);
    }
}