package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.ExecutionResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class Radamsa {

    private final CommandExecutor commandExecutor;
    private final String executablePath;

    public Radamsa(final CommandExecutor commandExecutor, final String executablePath) {
        this.commandExecutor = commandExecutor;
        this.executablePath = executablePath;
    }

    /**
     * Generate a test case based on a given sample or one or more sample files.
     * <p>
     * When both {@link RadamsaParameters#getSample()} and {@link RadamsaParameters#getSamplePaths()}
     * are provided, {@link RadamsaParameters#getSample()} takes precedence.
     *
     * @param parameters A {@link RadamsaParameters} object
     * @return The generated test case as byte array
     * @throws IOException When the invocation of Radamsa failed
     */
    public byte[] fuzz(final RadamsaParameters parameters) throws IOException {
        if (parameters == null) {
            throw new IllegalArgumentException("No parameters provided");
        } else if (parameters.getSample().isEmpty() && parameters.getSamplePaths().isEmpty()) {
            throw new IllegalArgumentException("No sample data provided");
        }

        final var radamsaCommand = new ArrayList<String>();
        radamsaCommand.add(executablePath);

        final ExecutionResult executionResult;
        if (parameters.getSample().isPresent()) {
            executionResult = commandExecutor.execute(radamsaCommand, parameters.getSample().get());
        } else {
            radamsaCommand.add("--recursive");
            radamsaCommand.addAll(parameters.getSamplePaths());

            executionResult = commandExecutor.execute(radamsaCommand);
        }

        if (executionResult.getExitCode() != 0) {
            throw new IOException("Radamsa execution failed with exit code " + executionResult.getExitCode());
        }

        return executionResult.getStdoutOutput()
                .map(String::getBytes)
                .orElseThrow(IllegalStateException::new);
    }

    /**
     * @return The version of Radamsa
     * @throws IOException When the invocation of Radamsa failed
     */
    public String getVersion() throws IOException {
        final var command = List.of(executablePath, "-V");
        final ExecutionResult executionResult = commandExecutor.execute(command);

        if (executionResult.getExitCode() != 0) {
            throw new IOException("Radamsa execution failed with exit code " + executionResult.getExitCode());
        }

        return executionResult.getStdoutOutput()
                .map(String::trim)
                .map(output -> output.split(" ", 2))
                .filter(outputParts -> outputParts.length == 2)
                .map(outputParts -> outputParts[1])
                .orElseThrow(() -> new IOException("Missing or unexpected output for command " + command));
    }

}
