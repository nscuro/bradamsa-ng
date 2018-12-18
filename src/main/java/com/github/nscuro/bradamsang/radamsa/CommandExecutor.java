package com.github.nscuro.bradamsang.radamsa;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

class CommandExecutor {

    private static final Logger LOGGER = LoggerFactory.getLogger(CommandExecutor.class);

    List<String> parseCommand(final String command) {
        return Arrays
                .stream(command.split(" "))
                .filter(commandPart -> !commandPart.trim().isEmpty())
                .collect(Collectors.toList());
    }

    Optional<String> execute(final List<String> command) throws IOException {
        return execute(command, null);
    }

    Optional<String> execute(final List<String> command, @Nullable final byte[] stdinData) throws IOException {
        final Process process = new ProcessBuilder(command).start();

        if (stdinData != null) {
            try (final OutputStream processStdin = process.getOutputStream()) {
                IOUtils.write(stdinData, processStdin);
            }
        }

        try (final InputStreamReader inputStreamReader = new InputStreamReader(process.getInputStream());
             final BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {

            final int exitCode = process.waitFor();

            if (exitCode != 0) {
                LOGGER.error("Command \"{}\" returned with status {}", command, exitCode);
            }

            final StringBuilder processOutput = new StringBuilder();

            for (String line; (line = bufferedReader.readLine()) != null; ) {
                processOutput
                        .append(line)
                        .append(System.lineSeparator());
            }

            return Optional
                    .of(processOutput.toString())
                    .filter(output -> !output.trim().isEmpty());
        } catch (InterruptedException e) {
            throw new IOException(e);
        }
    }

}
