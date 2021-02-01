package com.github.nscuro.bradamsang.command;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.util.List;

public final class NativeCommandExecutor implements CommandExecutor {

    @Override
    public ExecutionResult execute(final List<String> command, final byte[] inputData) throws IOException {
        final Process process = new ProcessBuilder(command).start();

        if (inputData != null) {
            try (final var processStdin = process.getOutputStream()) {
                IOUtils.write(inputData, processStdin);
            }
        }

        final int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            throw new IOException(e);
        }

        return new ExecutionResult(exitCode,
                process.getInputStream().readAllBytes(),
                process.getErrorStream().readAllBytes());
    }

}
