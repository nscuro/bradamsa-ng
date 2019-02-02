package com.github.nscuro.bradamsang.io;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public interface CommandExecutor {

    @Nonnull
    ExecutionResult execute(final List<String> command, @Nullable final byte[] stdinData) throws IOException;

    @Nonnull
    default ExecutionResult execute(final List<String> command) throws IOException {
        return execute(command, null);
    }

    @Nonnull
    static List<String> parseCommand(final String command) {
        return Arrays
                .stream(command.split(" "))
                .filter(commandPart -> !commandPart.trim().isEmpty())
                .collect(Collectors.toList());
    }

}
