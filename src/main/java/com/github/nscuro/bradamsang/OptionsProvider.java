package com.github.nscuro.bradamsang;

import javax.annotation.Nonnull;
import java.nio.file.Path;
import java.util.Optional;

public interface OptionsProvider {

    @Nonnull
    Optional<String> getRadamsaCommand();

    @Nonnull
    Optional<Integer> getCount();

    @Nonnull
    Optional<Long> getSeed();

    @Nonnull
    Optional<Path> getRadamsaOutputDirectoryPath();

    @Nonnull
    Optional<Path> getIntruderInputDirectoryPath();

    boolean isWslModeEnabled();

    @Nonnull
    Optional<String> getWslDistributionName();

}
