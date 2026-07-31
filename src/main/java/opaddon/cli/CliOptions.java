package opaddon.cli;

/**
 * Parsed command-line options.
 */
public final class CliOptions {

    private String inputPath;
    private String outputPath;
    private String configPath;
    private long seed;
    private boolean verbose;

    private CliOptions() {}

    public String getInputPath() { return inputPath; }
    public String getOutputPath() { return outputPath; }
    public String getConfigPath() { return configPath; }
    public long getSeed() { return seed; }
    public boolean isVerbose() { return verbose; }

    @SuppressWarnings("unused")
    public void setSeed(long seed) { this.seed = seed; }

    /**
     * Parse command-line arguments.
     * Supports: --input, --output, --config, --seed, --verbose
     */
    public static CliOptions parse(String[] args) {
        CliOptions opts = new CliOptions();
        opts.seed = System.currentTimeMillis();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--input":
                    opts.inputPath = args[++i];
                    break;
                case "--output":
                    opts.outputPath = args[++i];
                    break;
                case "--config":
                    opts.configPath = args[++i];
                    break;
                case "--seed":
                    opts.seed = Long.parseLong(args[++i]);
                    break;
                case "--verbose":
                    opts.verbose = true;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }

        if (opts.inputPath == null || opts.outputPath == null) {
            throw new IllegalArgumentException(
                "Usage: java -jar virtualizer.jar --input <jar> --output <jar> [--config config.json] [--seed N] [--verbose]");
        }

        return opts;
    }
}
