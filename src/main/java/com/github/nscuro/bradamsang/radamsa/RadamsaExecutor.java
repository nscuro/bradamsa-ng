package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.ExecutionResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class RadamsaExecutor {

    private final CommandExecutor commandExecutor;
    private final String executablePath;

    public RadamsaExecutor(final CommandExecutor commandExecutor, final String executablePath) {
        this.commandExecutor = commandExecutor;
        this.executablePath = executablePath;
    }

    public byte[] execute(final RadamsaOptions options) throws IOException {
        if (options == null) {
            throw new IllegalArgumentException("No options provided");
        } else if (options.getSample().isEmpty() && options.getSamplePaths().isEmpty()) {
            throw new IllegalArgumentException("No sample data provided");
        }

        final var command = new ArrayList<>(List.of(executablePath));

        final ExecutionResult executionResult;
        if (options.getSample().isPresent()) {
            executionResult = commandExecutor.execute(command, options.getSample().get());
        } else {
            command.add("--recursive");
            command.addAll(options.getSamplePaths());

            executionResult = commandExecutor.execute(command);
        }

        if (executionResult.getExitCode() != 0) {
            throw new IOException("Radamsa execution failed with exit code " + executionResult.getExitCode());
        }

        return executionResult.getStdoutOutput().orElse(null);
    }

    public String getRadamsaVersion() throws IOException {
        final var command = List.of(executablePath, "-V");
        final ExecutionResult executionResult = commandExecutor.execute(command);

        if (executionResult.getExitCode() != 0) {
            throw new IOException("Radamsa execution failed with exit code " + executionResult.getExitCode());
        }

        return executionResult.getStdoutOutput()
                .map(output -> new String(output, StandardCharsets.UTF_8))
                .map(String::trim)
                .map(output -> output.split(" ", 2))
                .filter(outputParts -> outputParts.length == 2)
                .map(outputParts -> outputParts[1])
                .orElseThrow(() -> new IOException("Missing or unexpected output for command " + command));
    }

}
