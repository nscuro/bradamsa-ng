package com.github.nscuro.bradamsang.command;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public final class WslCommandExecutor implements CommandExecutor {

    private final CommandExecutor delegateCommandExecutor;
    private final String distributionName;

    public WslCommandExecutor(final CommandExecutor delegateCommandExecutor,
                              final String distributionName) {
        this.delegateCommandExecutor = Objects.requireNonNull(delegateCommandExecutor);
        this.distributionName = Objects.requireNonNull(StringUtils.trimToNull(distributionName));
    }

    @Override
    public ExecutionResult execute(final List<String> command, final byte[] inputData) throws IOException {
        final var wslCommand = new ArrayList<String>();

        wslCommand.addAll(Arrays.asList("wsl", "-d", distributionName, "-e"));
        wslCommand.addAll(command);

        return delegateCommandExecutor.execute(wslCommand, inputData);
    }

}
