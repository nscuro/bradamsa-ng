package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.io.ExecutionResult;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static java.lang.String.format;

public class WslHelper {

    private static final String COMMAND_WSL = "wsl";

    private static final String COMMAND_WSLCONFIG = "wslconfig";

    private static final String COMMAND_WSLPATH = "wslpath";

    private static final String COMMAND_WHERE = "where";

    private final NativeCommandExecutor nativeCommandExecutor;

    private WslCommandExecutor wslCommandExecutor;

    public WslHelper(final NativeCommandExecutor nativeCommandExecutor,
                     @Nullable final WslCommandExecutor wslCommandExecutor) {
        this.nativeCommandExecutor = nativeCommandExecutor;
        this.wslCommandExecutor = wslCommandExecutor;
    }

    public boolean isWslAvailable() throws IOException {
        return "Windows 10".equals(System.getProperty("os.name"))
                && nativeCommandExecutor.execute(Arrays.asList(COMMAND_WHERE, COMMAND_WSL)).getExitCode() == 0
                && nativeCommandExecutor.execute(Arrays.asList(COMMAND_WHERE, COMMAND_WSLCONFIG)).getExitCode() == 0;
    }

    @Nonnull
    public List<String> getInstalledDistros() throws IOException {
        final ExecutionResult executionResult = nativeCommandExecutor
                .execute(Arrays.asList(COMMAND_WSLCONFIG, "/list"));

        if (executionResult.getExitCode() != 0) {
            return Collections.emptyList();
        }

        return executionResult
                .getOutput()
                .map(output -> output.split(System.lineSeparator()))
                // The first line is "Windows Subsystem for Linux Distributions:", we don't need that
                .map(output -> Arrays.copyOfRange(output, 1, output.length))
                .map(Arrays::asList)
                .map(output -> output
                        .stream()
                        .map(String::trim)
                        // The default distro is marked with a "(Default)", we don't want that
                        .map(line -> line.split(" ")[0])
                        .filter(line -> !line.isEmpty())
                        // For some strange reason every second character from the output
                        // is an unprintable control character...
                        .map(line -> line.replaceAll("\\p{C}", ""))
                        .collect(Collectors.toList()))
                .orElseGet(Collections::emptyList);
    }

    @Nonnull
    public String getWslPathForNativePath(final Path nativePath) throws IOException {
        if (wslCommandExecutor == null) {
            throw new IllegalStateException("No WslCommandExecutor set");
        } else if (!nativePath.toFile().exists()) {
            throw new IllegalArgumentException(format("Native path \"%s\" does not exist", nativePath));
        }

        final ExecutionResult executionResult = wslCommandExecutor
                .execute(Arrays.asList(COMMAND_WSLPATH, "-a", "-u", nativePath.toString()));

        if (executionResult.getExitCode() != 0) {
            // TODO: Add message
            throw new IOException();
        }

        return executionResult
                .getOutput()
                .map(String::trim)
                .orElseThrow(IOException::new);
    }

    public boolean isCommandInWslPath(@Nullable final String command) throws IOException {
        if (wslCommandExecutor == null) {
            throw new IllegalStateException("No WslCommandExecutor set");
        } else if (command == null) {
            return false;
        }

        final ExecutionResult executionResult = wslCommandExecutor
                .execute(Arrays.asList("which", command));

        return executionResult.getExitCode() == 0;
    }

    public boolean isExistingFile(@Nullable final String filePath) throws IOException {
        if (wslCommandExecutor == null) {
            throw new IllegalStateException("No WslCommandExecutor set");
        } else if (filePath == null) {
            return false;
        }

        final ExecutionResult executionResult = wslCommandExecutor
                .execute(Arrays.asList("test", "-f", filePath));

        return executionResult.getExitCode() == 0;
    }

    public void setWslCommandExecutor(final WslCommandExecutor wslCommandExecutor) {
        this.wslCommandExecutor = wslCommandExecutor;
    }

}
