package com.github.nscuro.bradamsang.intruder;

import com.github.nscuro.bradamsang.ExtensionSettingsProvider;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

public final class AttackSettings {

    private final int payloadCount;
    private final List<String> samplePaths;
    private final boolean wslModeEnabled;
    private final String wslDistributionName;

    public AttackSettings(int payloadCount, List<String> samplePaths,
                          boolean wslModeEnabled, String wslDistributionName) {
        this.payloadCount = payloadCount;
        this.samplePaths = samplePaths;
        this.wslModeEnabled = wslModeEnabled;
        this.wslDistributionName = wslDistributionName;
    }

    public static AttackSettings fromSettingsProvider(final ExtensionSettingsProvider settingsProvider) {
        return new AttackSettings(settingsProvider.getPayloadCount(), settingsProvider.getSamplePaths(),
                settingsProvider.isWslModeEnabled(), settingsProvider.getWslDistributionName().orElse(null));
    }

    public int getPayloadCount() {
        return payloadCount;
    }

    public List<String> getSamplePaths() {
        return Optional.ofNullable(samplePaths)
                .orElseGet(Collections::emptyList);
    }

    public boolean isWslModeEnabled() {
        return wslModeEnabled;
    }

    public Optional<String> getWslDistributionName() {
        return Optional.ofNullable(wslDistributionName);
    }

}
