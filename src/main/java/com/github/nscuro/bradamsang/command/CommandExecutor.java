package com.github.nscuro.bradamsang.command;

import java.io.IOException;
import java.util.List;

public interface CommandExecutor {

    ExecutionResult execute(final List<String> command, final byte[] inputData) throws IOException;

    default ExecutionResult execute(final List<String> command) throws IOException {
        return execute(command, null);
    }

}
