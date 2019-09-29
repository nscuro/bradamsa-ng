package com.github.nscuro.bradamsang.io;

import lombok.Data;

import javax.annotation.Nonnull;
import java.util.Optional;

@Data
public final class ExecutionResult {

    private final int exitCode;

    private final String output;

    @Nonnull
    public Optional<String> getOutput() {
        return Optional.ofNullable(output);
    }

}
