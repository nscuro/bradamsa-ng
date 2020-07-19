package com.github.nscuro.bradamsang.command;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class NativeCommandExecutor implements CommandExecutor {

    @Override
    public ExecutionResult execute(final List<String> command, final byte[] inputData) throws IOException {
        final Process process = new ProcessBuilder(command).start();

        if (inputData != null) {
            try (final OutputStream processStdin = process.getOutputStream()) {
                IOUtils.write(inputData, processStdin);
            }
        }

        final int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            throw new IOException(e);
        }

        final String stdoutOutput = IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
        final String stderrOutput = IOUtils.toString(process.getErrorStream(), StandardCharsets.UTF_8);

        return new ExecutionResult(exitCode, stdoutOutput, stderrOutput);
    }

    @Override
    public ExecutionResult execute(final List<String> command) throws IOException {
        return execute(command, null);
    }


}
