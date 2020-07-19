package com.github.nscuro.bradamsang;

import java.util.List;
import java.util.Optional;

public interface ExtensionSettingsProvider {

    Optional<String> getRadamsaExecutablePath();

    int getPayloadCount();

    List<String> getSamplePaths();

    boolean isWslModeEnabled();

    Optional<String> getWslDistributionName();

}
