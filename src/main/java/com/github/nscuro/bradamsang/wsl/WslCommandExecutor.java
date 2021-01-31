package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.ExecutionResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class WslCommandExecutor implements CommandExecutor {

    private final CommandExecutor delegateCommandExecutor;
    private final String distributionName;

    public WslCommandExecutor(final CommandExecutor delegateCommandExecutor, final String distributionName) {
        this.delegateCommandExecutor = delegateCommandExecutor;
        this.distributionName = distributionName;
    }

    @Override
    public ExecutionResult execute(final List<String> command, final byte[] inputData) throws IOException {
        final var wslCommand = new ArrayList<>(List.of("wsl", "-d", distributionName, "-e"));
        wslCommand.addAll(command);

        return delegateCommandExecutor.execute(wslCommand, inputData);
    }

}
