package com.github.nscuro.bradamsang.intruder;

import com.github.nscuro.bradamsang.BurpExtensionSettingsProvider;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

public final class IntruderAttackOptions {

    private final int payloadCount;
    private final List<String> samplePaths;
    private final boolean wslModeEnabled;
    private final String wslDistributionName;

    public IntruderAttackOptions(final int payloadCount,
                                 final List<String> samplePaths,
                                 final boolean wslModeEnabled,
                                 final String wslDistributionName) {
        this.payloadCount = payloadCount;
        this.samplePaths = samplePaths;
        this.wslModeEnabled = wslModeEnabled;
        this.wslDistributionName = wslDistributionName;
    }

    public static IntruderAttackOptions fromSettings(final BurpExtensionSettingsProvider settingsProvider) {
        return new IntruderAttackOptions(
                settingsProvider.getPayloadCount(),
                settingsProvider.getSamplePaths(),
                settingsProvider.isWslModeEnabled(),
                settingsProvider.getWslDistributionName().orElse(null)
        );
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

    @Override
    public String toString() {
        return "IntruderAttackOptions{" +
                "payloadCount=" + payloadCount +
                ", samplePaths=" + samplePaths +
                ", wslModeEnabled=" + wslModeEnabled +
                ", wslDistributionName='" + wslDistributionName + '\'' +
                '}';
    }

}
