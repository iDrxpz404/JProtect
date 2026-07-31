package opaddon;

import opaddon.cli.CliOptions;
import opaddon.config.ProtectionPreset;
import opaddon.config.VirtualizerConfig;
import opaddon.rewriter.ClassRewriter;

import com.google.gson.Gson;
import java.nio.file.*;

/**
 * CLI entry point for the bytecode virtualizer.
 *
 * Usage: java -jar virtualizer.jar --input app.jar --output app-protected.jar [--config config.json] [--seed N] [--verbose]
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        CliOptions opts = CliOptions.parse(args);

        // Load config if specified
        VirtualizerConfig config;
        if (opts.getConfigPath() != null) {
            String json = Files.readString(Path.of(opts.getConfigPath()));
            config = new Gson().fromJson(json, VirtualizerConfig.class);
            if (opts.isVerbose()) {
                System.out.println("[virtualizer] Loaded config: " + opts.getConfigPath());
            }
        } else {
            config = VirtualizerConfig.defaults();
        }

        // Apply preset (overridden by explicit settings)
        config.applyPreset(ProtectionPreset.fromString(config.getPreset()));

        if (opts.isVerbose()) {
            System.out.println("[virtualizer] Input:  " + opts.getInputPath());
            System.out.println("[virtualizer] Output: " + opts.getOutputPath());
            System.out.println("[virtualizer] Preset: " + config.getPreset());
            System.out.println("[virtualizer] Seed:   " + (opts.getSeed() != 0 ? opts.getSeed() : "random"));
            System.out.println("[virtualizer] String encrypt: " + config.isStringEncryption());
            System.out.println("[virtualizer] Opcode shuffle: " + config.isOpcodeShuffle());
            System.out.println("[virtualizer] Integrity check: " + config.isIntegrityCheck());
            System.out.println("[virtualizer] Polymorphic VM:  " + config.isPolymorphicVM());
            if (!config.getVirtualize().isEmpty()) {
                System.out.println("[virtualizer] Virtualize patterns: " + config.getVirtualize());
            }
        }

        byte[] outputJar = ClassRewriter.processJar(opts, config,
            ClassRewriter.ObfuscatedNames.generate(opts.getSeed()));

        Files.write(Path.of(opts.getOutputPath()), outputJar);

        if (opts.isVerbose()) {
            System.out.println("[virtualizer] Done — wrote " + opts.getOutputPath());
        }
    }
}
