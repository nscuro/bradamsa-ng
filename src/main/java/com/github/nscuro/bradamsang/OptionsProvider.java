package com.github.nscuro.bradamsang;

import javax.annotation.Nonnull;
import java.util.Optional;

public interface OptionsProvider {

    @Nonnull
    Optional<String> getRadamsaCommand();

    @Nonnull
    Optional<Integer> getCount();

    @Nonnull
    Optional<Long> getSeed();

    boolean isWslModeEnabled();

    @Nonnull
    Optional<String> getWslDistributionName();

}
