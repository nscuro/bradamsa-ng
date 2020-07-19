package com.github.nscuro.bradamsang.util;

import com.github.nscuro.bradamsang.command.ExecutionResult;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.lang.String.format;

public final class WslSupport {

    private final NativeCommandExecutor nativeCommandExecutor;

    public WslSupport(final NativeCommandExecutor nativeCommandExecutor) {
        this.nativeCommandExecutor = nativeCommandExecutor;
    }

    boolean isWindows10() {
        return "Windows 10".equals(System.getProperty("os.name"));
    }

    public boolean isWslAvailable() throws IOException {
        return isWindows10()
                && nativeCommandExecutor.execute(List.of("where.exe", "/q", "wsl.exe")).getExitCode() == 0;
    }

    /**
     * Build 18363 -> Version 1909
     * Build 18362 -> Version 1903
     * Build 17763 -> Version 1809
     * ...
     *
     * @see <a href="https://pureinfotech.com/how-determine-version-windows-10-running-pc/">How to determine
     * installed version of Windows 10</a>
     */
    int getWindows10BuildNumber() throws IOException {
        final ExecutionResult executionResult = nativeCommandExecutor.execute(List.of("WMIC.exe", "os", "get", "version", "/format:LIST"));

        if (executionResult.getExitCode() != 0) {
            throw new IOException();
        }

        return executionResult.getStdoutOutput()
                .map(String::trim)
                // Output is something like "Version=10.0.18363"
                .map(output -> output.split("=")[1])
                .map(version -> version.split("\\.")[2])
                .map(Integer::parseInt)
                .orElseThrow(IOException::new);
    }

    /**
     * Before Windows 10 Version 1903, management of installed WSL distros had to be done via wslconfig.exe.
     * Starting with 1903, wsl.exe can be used for this task as well. Version 1809 is supported until May 2021,
     * so we need to make sure this extension works for that too.
     *
     * @return true, when wslconfig.exe instead of wsl.exe should be used. Otherwise false.
     * @see <a href="https://docs.microsoft.com/en-us/windows/wsl/wsl-config">Manage Linux Distributions</a>
     * @see <a href="https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet">Windows lifecycle
     * fact sheet</a>
     */
    boolean shouldUseWslConfig() throws IOException {
        return getWindows10BuildNumber() < 18362;
    }

    public List<String> getInstalledDistributions() throws IOException {
        final ExecutionResult executionResult;
        if (shouldUseWslConfig()) {
            executionResult = nativeCommandExecutor.execute(List.of("wslconfig.exe", "/list"));
        } else {
            executionResult = nativeCommandExecutor.execute(List.of("wsl.exe", "--list"));
        }

        if (executionResult.getExitCode() != 0) {
            throw new IOException();
        }

        return executionResult.getStdoutOutput()
                // The first line is "Windows Subsystem for Linux Distributions:", we don't need that
                .map(output -> output.split("\\r?\\n"))
                .map(outputLines -> Arrays.copyOfRange(outputLines, 1, outputLines.length))
                .map(Arrays::asList)
                .map(outputLines -> outputLines.stream()
                        // For some strange reason every second character is an unprintable control character...
                        .map(line -> line.replaceAll("\\p{C}", ""))
                        .map(String::trim)
                        // The default distro is marked with a "(Default)", we don't want that
                        .map(line -> line.split(" ")[0])
                        .filter(line -> !line.isEmpty())
                        .collect(Collectors.toList()))
                .orElseGet(Collections::emptyList);
    }

    public String convertToWslPath(final String windowsPath) {
        final Matcher driveLetterMatcher = Pattern.compile("^([a-zA-Z]):\\\\").matcher(windowsPath);

        if (!driveLetterMatcher.find() || driveLetterMatcher.groupCount() != 1) {
            throw new IllegalArgumentException(format("%s is not a valid absolute Windows path", windowsPath));
        }

        return "/mnt/" + driveLetterMatcher.group(1).toLowerCase() +
                "/" + driveLetterMatcher.replaceFirst("").replaceAll("\\\\", "/");
    }

}
