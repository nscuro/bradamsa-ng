package com.github.nscuro.bradamsang;

import java.nio.file.Path;
import java.util.Optional;

public interface OptionsProvider {

    String getRadamsaCommand();

    int getCount();

    Optional<Long> getSeed();

    Path getRadamsaOutputDirectoryPath();

    Optional<Path> getIntruderInputDirectoryPath();

}
