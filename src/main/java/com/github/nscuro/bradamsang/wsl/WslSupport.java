package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.ExecutionResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class WslSupport {

    private static final Pattern WSL_LIST_OUTPUT_COLUMNS_PATTERN =
            Pattern.compile("^[\\s]*NAME[\\s]+STATE[\\s]+VERSION[\\s]*$");

    private final CommandExecutor commandExecutor;

    public WslSupport(final CommandExecutor commandExecutor) {
        this.commandExecutor = commandExecutor;
    }

    boolean isWindows10() {
        return "Windows 10".equals(System.getProperty("os.name"));
    }

    public boolean isWslAvailable() throws IOException {
        return isWindows10()
                && commandExecutor.execute(List.of("where.exe", "/q", "wsl.exe")).getExitCode() == 0;
    }

    public List<WslDistribution> getInstalledDistributions() throws IOException {
        final ExecutionResult executionResult =
                commandExecutor.execute(List.of("wsl.exe", "--list", "--verbose"));

        if (executionResult.getExitCode() != 0) {
            throw new IOException();
        } else if (executionResult.getStdoutOutput().isEmpty()) {
            return Collections.emptyList();
        }

        final String output = new String(executionResult.getStdoutOutput().get(), StandardCharsets.UTF_16LE).strip();

        if (output.lines().map(WSL_LIST_OUTPUT_COLUMNS_PATTERN::matcher).noneMatch(Matcher::matches)) {
            return Collections.emptyList();
        }

        return output.lines()
                .skip(1)
                .map(this::parseWslDistribution)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());
    }

    Optional<WslDistribution> parseWslDistribution(final String line) {
        final boolean isDefault = line.startsWith("*");
        final String lineWithoutPrefix = line.replaceAll("^[\\s*]*", "");

        final String[] lineParts = lineWithoutPrefix.split("\\s+", 3);
        if (lineParts.length != 3) {
            return Optional.empty();
        }

        final int wslVersion;
        try {
            wslVersion = Integer.parseInt(lineParts[2]);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }

        return Optional.of(new WslDistribution(lineParts[0], isDefault, wslVersion));
    }

}
