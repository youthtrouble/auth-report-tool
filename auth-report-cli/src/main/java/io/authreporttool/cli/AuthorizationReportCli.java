package io.authreporttool.cli;

import io.authreporttool.core.AuthorizationReport;
import io.authreporttool.core.AuthorizationScanner;
import io.authreporttool.core.ReflectionUtils;
import io.authreporttool.core.ReportGenerator;

import java.io.IOException;

/**
 * Main class for the Authorization Report CLI tool.
 */
public class AuthorizationReportCli {

    public static void main(String[] args) {
        CommandLineOptions options = new CommandLineOptions(args);

        try {
            //Create new reflection utils
            ReflectionUtils reflectionUtils = new ReflectionUtils();

            // Create and configure the authorization scanner
            AuthorizationScanner scanner = new AuthorizationScanner(reflectionUtils);

            // Create the report generator
            ReportGenerator generator = new ReportGenerator(scanner);

            // Generate the authorization report
            AuthorizationReport report = generator.generateReport(options.getBasePackage());

            // Print the report using the specified format and output option
            ReportPrinter.printReport(report, options.getOutputFormat(), options.getOutputFile(), options.isVerbose());

        } catch (IOException e) {
            System.err.println("Error generating or printing the report: " + e.getMessage());
            System.exit(1);
        }
    }
}