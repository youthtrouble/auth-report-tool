package io.authreporttool.cli;

import org.apache.commons.cli.*;

/**
 * Handles parsing and storing command-line options for the Authorization Report CLI.
 */
public class CommandLineOptions {
    private String basePackage;
    private String outputFormat;
    private String outputFile;
    private boolean verbose;

    /**
     * Constructs CommandLineOptions by parsing the provided command-line arguments.
     *
     * @param args Command-line arguments to parse.
     */
    public CommandLineOptions(String[] args) {
        Options options = new Options();
        options.addOption("p", "package", true, "Base package to scan (required)");
        options.addOption("f", "format", true, "Output format (text/json, default: text)");
        options.addOption("o", "output", true, "Output file path (optional, default: console)");
        options.addOption("v", "verbose", false, "Enable verbose output");
        options.addOption("h", "help", false, "Display help information");

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("h")) {
                printHelp(options);
                System.exit(0);
            }

            basePackage = cmd.getOptionValue("p");
            outputFormat = cmd.getOptionValue("f", "text");
            outputFile = cmd.getOptionValue("o");
            verbose = cmd.hasOption("v");

            if (basePackage == null) {
                throw new ParseException("Base package is required. Use -p or --package option.");
            }
        } catch (ParseException e) {
            System.err.println("Error parsing command line options: " + e.getMessage());
            printHelp(options);
            System.exit(1);
        }
    }

    /**
     * Prints help information for the CLI tool.
     *
     * @param options The Options object containing all available options.
     */
    private void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar authorization-report-cli.jar", options);
    }

    // Getters for the command-line options
    public String getBasePackage() {
        return basePackage;
    }

    public String getOutputFormat() {
        return outputFormat;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public boolean isVerbose() {
        return verbose;
    }
}