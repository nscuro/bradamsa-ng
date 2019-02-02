package com.github.nscuro.bradamsang.io;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.List;
import java.util.Optional;

public class NativeCommandExecutor implements CommandExecutor {

    private static final Logger LOGGER = LoggerFactory.getLogger(NativeCommandExecutor.class);

    @Nonnull
    @Override
    public ExecutionResult execute(final List<String> command, @Nullable final byte[] stdinData) throws IOException {
        LOGGER.debug("Executing command \"{}\"", command);

        final Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();

        if (stdinData != null) {
            LOGGER.debug("Piping {} bytes to process stdin", stdinData.length);

            try (final OutputStream processStdin = process.getOutputStream()) {
                IOUtils.write(stdinData, processStdin);
            }
        }

        try (final InputStreamReader inputStreamReader = new InputStreamReader(process.getInputStream());
             final BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {

            final int exitCode = process.waitFor();
            LOGGER.debug("Command \"{}\" returned with exit code {}", command, exitCode);

            final StringBuilder processOutput = new StringBuilder();

            LOGGER.debug("Reading output from command \"{}\"", command);
            for (String line; (line = bufferedReader.readLine()) != null; ) {
                processOutput
                        .append(line)
                        .append(System.lineSeparator());
            }

            final String nonEmptyOutput = Optional
                    .of(processOutput.toString())
                    .filter(output -> !output.trim().isEmpty())
                    .orElse(null);

            return new ExecutionResult(exitCode, nonEmptyOutput);
        } catch (InterruptedException e) {
            throw new IOException(e);
        }
    }

}
