package io.authreporttool.cli;

import org.apache.commons.cli.*;

/**
 * CommandLineOptions handles the parsing and storage of command-line options
 * for the Authorization Report CLI tool. It uses Apache Commons CLI for
 * robust command-line argument parsing.
 */
public class CommandLineOptions {
    private String basePackage;
    private String outputFormat;
    private String outputFile;
    private boolean verbose;

    /**
     * Constructs a CommandLineOptions object by parsing the provided command-line arguments.
     * This constructor defines the available options, parses the arguments, and stores the results.
     * If parsing fails or required options are missing, it prints help information and exits the program.
     *
     * @param args Command-line arguments to parse.
     */
    public CommandLineOptions(String[] args) {
        // Define the command-line options
        Options options = new Options();
        options.addOption("p", "package", true, "Base package to scan (required)");
        options.addOption("f", "format", true, "Output format (text/json, default: text)");
        options.addOption("o", "output", true, "Output file path (optional, default: console)");
        options.addOption("v", "verbose", false, "Enable verbose output");
        options.addOption("h", "help", false, "Display help information");

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);

            // Check if help is requested
            if (cmd.hasOption("h")) {
                printHelp(options);
                System.exit(0);
            }

            // Parse and store the option values
            basePackage = cmd.getOptionValue("p");
            outputFormat = cmd.getOptionValue("f", "text");
            outputFile = cmd.getOptionValue("o");
            verbose = cmd.hasOption("v");

            // Validate required options
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
     * This method uses Apache Commons CLI's HelpFormatter to generate
     * a formatted help message for all available options.
     *
     * @param options The Options object containing all available options.
     */
    private void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar authorization-report-cli.jar", options);
    }

    /**
     * Gets the base package to scan for authorization configurations.
     *
     * @return The base package specified by the user.
     */
    public String getBasePackage() {
        return basePackage;
    }

    /**
     * Gets the output format for the report.
     *
     * @return The output format (text or json) specified by the user, or "text" if not specified.
     */
    public String getOutputFormat() {
        return outputFormat;
    }

    /**
     * Gets the output file path for the report.
     *
     * @return The output file path specified by the user, or null if not specified (indicating console output).
     */
    public String getOutputFile() {
        return outputFile;
    }

    /**
     * Checks if verbose output is enabled.
     *
     * @return true if verbose output is enabled, false otherwise.
     */
    public boolean isVerbose() {
        return verbose;
    }
}