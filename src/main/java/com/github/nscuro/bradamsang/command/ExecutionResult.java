package com.github.nscuro.bradamsang.command;

import java.util.Optional;

public final class ExecutionResult {

    private final int exitCode;
    private final String stdoutOutput;
    private final String stderrOutput;

    ExecutionResult(final int exitCode, final String stdoutOutput, final String stderrOutput) {
        this.exitCode = exitCode;
        this.stdoutOutput = stdoutOutput;
        this.stderrOutput = stderrOutput;
    }

    public int getExitCode() {
        return exitCode;
    }

    public Optional<String> getStdoutOutput() {
        return Optional.ofNullable(stdoutOutput);
    }

    public Optional<String> getStderrOutput() {
        return Optional.ofNullable(stderrOutput);
    }

    @Override
    public String toString() {
        return "ExecutionResult{" +
                "exitCode=" + exitCode +
                ", stdoutOutput='" + stdoutOutput + '\'' +
                ", stderrOutput='" + stderrOutput + '\'' +
                '}';
    }

}
