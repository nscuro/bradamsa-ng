package com.github.nscuro.bradamsang;

import javax.annotation.Nonnull;
import java.nio.file.Path;
import java.util.Optional;

public interface OptionsProvider {

    @Nonnull
    String getRadamsaCommand();

    Optional<Integer> getCount();

    @Nonnull
    Optional<Long> getSeed();

    @Nonnull
    Path getRadamsaOutputDirectoryPath();

    @Nonnull
    Optional<Path> getIntruderInputDirectoryPath();

    boolean isWslModeEnabled();

    @Nonnull
    Optional<String> getWslDistributionName();

}
