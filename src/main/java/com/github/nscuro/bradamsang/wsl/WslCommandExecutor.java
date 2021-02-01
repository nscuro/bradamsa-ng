package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.ExecutionResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link CommandExecutor} that executes commands inside a given WSL distribution.
 *
 * @since 1.1.0
 */
public final class WslCommandExecutor implements CommandExecutor {

    private final CommandExecutor delegateCommandExecutor;
    private final String distributionName;

    /**
     * @param delegateCommandExecutor {@link CommandExecutor} used for executing WSL
     * @param distributionName        Name of the WSL distribution to use
     */
    public WslCommandExecutor(final CommandExecutor delegateCommandExecutor, final String distributionName) {
        this.delegateCommandExecutor = delegateCommandExecutor;
        this.distributionName = distributionName;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExecutionResult execute(final List<String> command, final byte[] inputData) throws IOException {
        final var wslCommand = new ArrayList<>(List.of("wsl", "-d", distributionName, "-e"));
        wslCommand.addAll(command);

        return delegateCommandExecutor.execute(wslCommand, inputData);
    }

}
