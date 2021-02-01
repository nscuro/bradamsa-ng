package com.github.nscuro.bradamsang.command;

import java.util.Optional;

public final class ExecutionResult {

    private final int exitCode;
    private final byte[] stdoutOutput;
    private final byte[] stderrOutput;

    ExecutionResult(final int exitCode, final byte[] stdoutOutput, final byte[] stderrOutput) {
        this.exitCode = exitCode;
        this.stdoutOutput = stdoutOutput;
        this.stderrOutput = stderrOutput;
    }

    public int getExitCode() {
        return exitCode;
    }

    public Optional<byte[]> getStdoutOutput() {
        return Optional.ofNullable(stdoutOutput);
    }

    public Optional<byte[]> getStderrOutput() {
        return Optional.ofNullable(stderrOutput);
    }

}
