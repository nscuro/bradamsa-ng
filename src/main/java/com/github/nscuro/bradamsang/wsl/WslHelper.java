package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.io.ExecutionResult;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public final class WslHelper {

    static final String OS_NAME_WINDOWS_10 = "Windows 10";

    static final String COMMAND_WSL = "wsl";

    static final String COMMAND_WSLCONFIG = "wslconfig";

    static final String COMMAND_WHERE = "where";

    private static final String COMMAND_WHICH = "which";

    private static final String COMMAND_TEST = "test";

    private static final String EXCEPTION_MSG_NO_WSL_COMMAND_EXECUTOR_SET = "No WslCommandExecutor set. Please provide a distribution to use.";

    private final NativeCommandExecutor nativeCommandExecutor;

    private WslCommandExecutor wslCommandExecutor;

    public WslHelper(final NativeCommandExecutor nativeCommandExecutor,
                     @Nullable final WslCommandExecutor wslCommandExecutor) {
        this.nativeCommandExecutor = nativeCommandExecutor;
        this.wslCommandExecutor = wslCommandExecutor;
    }

    /**
     * Determine if the Windows Subsystem for Linux is available.
     * <p>
     * Basically verifies that the required WSL command line tools are available using {@value #COMMAND_WHERE}.
     *
     * @return true when WSL is available, otherwise false
     * @throws IOException When the execution of {@value #COMMAND_WHERE} failed
     */
    public boolean isWslAvailable() throws IOException {
        return OS_NAME_WINDOWS_10.equals(System.getProperty("os.name"))
                && nativeCommandExecutor.execute(Arrays.asList(COMMAND_WHERE, "/q", COMMAND_WSL)).getExitCode() == 0
                && nativeCommandExecutor.execute(Arrays.asList(COMMAND_WHERE, "/q", COMMAND_WSLCONFIG)).getExitCode() == 0;
    }

    /**
     * Get a list of available (as in: installed) WSL distributions.
     * <p>
     * The first element normally is the distro currently set as default.
     *
     * @return List of names of all available WSL distros
     * @throws IOException When the execution of {@value #COMMAND_WSLCONFIG} failed
     */
    @Nonnull
    public List<String> getAvailableDistributions() throws IOException {
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

    public Optional<String> which(@Nullable final String command) throws IOException, WslException {
        if (wslCommandExecutor == null) {
            throw new WslException(EXCEPTION_MSG_NO_WSL_COMMAND_EXECUTOR_SET);
        } else if (command == null) {
            return Optional.empty();
        }

        final ExecutionResult executionResult = wslCommandExecutor
                .execute(Arrays.asList(COMMAND_WHICH, command));

        if (executionResult.getExitCode() == 0) {
            return executionResult
                    .getOutput()
                    .map(String::trim);
        } else {
            return Optional.empty();
        }
    }

    /**
     * Check if a given file exists inside a WSL guest.
     *
     * @param filePath The file path to check
     * @return true when the file exists, otherwise false
     * @throws IOException  When the execution of {@value #COMMAND_TEST} inside the WSL guest failed
     * @throws WslException When no {@link WslCommandExecutor} is set
     */
    public boolean isExistingFile(@Nullable final String filePath) throws IOException, WslException {
        if (wslCommandExecutor == null) {
            throw new WslException(EXCEPTION_MSG_NO_WSL_COMMAND_EXECUTOR_SET);
        } else if (filePath == null) {
            return false;
        }

        final ExecutionResult executionResult = wslCommandExecutor
                .execute(Arrays.asList(COMMAND_TEST, "-f", filePath));

        return executionResult.getExitCode() == 0;
    }

    public void setWslCommandExecutor(final WslCommandExecutor wslCommandExecutor) {
        this.wslCommandExecutor = wslCommandExecutor;
    }

}
