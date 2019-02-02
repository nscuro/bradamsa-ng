package com.github.nscuro.bradamsang.io;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A {@link CommandExecutor} that executes commands in context of a WSL distribution.
 */
public class WslCommandExecutor extends NativeCommandExecutor {

    private static final String WSL_COMMAND = "wsl";

    private final String distroName;

    public WslCommandExecutor(final String distroName) {
        this.distroName = distroName;
    }

    @Nonnull
    @Override
    public ExecutionResult execute(final List<String> command, @Nullable final byte[] stdinData) throws IOException {
        final List<String> wslCommand = new ArrayList<>();

        wslCommand.addAll(Arrays.asList(WSL_COMMAND, "-d", distroName, "-e"));
        wslCommand.addAll(command);

        return super.execute(wslCommand, stdinData);
    }

}
