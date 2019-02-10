package com.github.nscuro.bradamsang.ui;

import com.github.nscuro.bradamsang.OptionsProvider;
import lombok.AccessLevel;
import lombok.Getter;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.swing.SwingUtilities;
import java.nio.file.Path;
import java.util.List;
import java.util.Observable;
import java.util.Optional;

@Getter(AccessLevel.PACKAGE)
public class SettingsTabModel extends Observable implements OptionsProvider {

    private String radamsaCommand;

    private Path radamsaOutputDir;

    private Integer payloadCount;

    private Path intruderInputDir;

    private boolean useCustomSeed;

    private Long customSeed;

    private boolean wslAvailable;

    private boolean wslModeEnabled;

    private List<String> availableWslDistros;

    private String wslDistroName;

    @Nonnull
    @Override
    public Optional<String> getRadamsaCommand() {
        return Optional.ofNullable(radamsaCommand);
    }

    @Nonnull
    @Override
    public Optional<Integer> getCount() {
        return Optional
                .ofNullable(payloadCount)
                .filter(count -> count >= 1);
    }

    @Nonnull
    @Override
    public Optional<Long> getSeed() {
        if (useCustomSeed) {
            return Optional.ofNullable(customSeed);
        } else {
            return Optional.empty();
        }
    }

    @Nonnull
    @Override
    public Optional<Path> getRadamsaOutputDirectoryPath() {
        return Optional.ofNullable(radamsaOutputDir);
    }

    @Nonnull
    @Override
    public Optional<Path> getIntruderInputDirectoryPath() {
        if (isWslAvailableAndEnabled()) {
            return Optional.ofNullable(intruderInputDir);
        } else {
            return Optional.empty();
        }
    }

    @Override
    public boolean isWslModeEnabled() {
        return wslModeEnabled;
    }

    @Nonnull
    @Override
    public Optional<String> getWslDistributionName() {
        return Optional.empty();
    }

    boolean isWslAvailableAndEnabled() {
        return wslAvailable && wslModeEnabled;
    }

    @Override
    public void notifyObservers() {
        // Changes to the UI need to be done in the EDT
        SwingUtilities.invokeLater(super::notifyObservers);
    }

    void setRadamsaCommand(@Nullable final String radamsaCommand) {
        this.radamsaCommand = radamsaCommand;
        signalChangeAndNotifyObservers();
    }

    void setRadamsaOutputDir(@Nullable final Path radamsaOutputDir) {
        this.radamsaOutputDir = radamsaOutputDir;
        signalChangeAndNotifyObservers();
    }

    void setPayloadCount(@Nullable final Integer payloadCount) {
        this.payloadCount = payloadCount;
        signalChangeAndNotifyObservers();
    }

    void setIntruderInputDir(@Nullable final Path intruderInputDir) {
        this.intruderInputDir = intruderInputDir;
        signalChangeAndNotifyObservers();
    }

    void setUseCustomSeed(final boolean useCustomSeed) {
        this.useCustomSeed = useCustomSeed;
        signalChangeAndNotifyObservers();
    }

    void setCustomSeed(@Nullable final Long customSeed) {
        this.customSeed = customSeed;
        signalChangeAndNotifyObservers();
    }

    void setWslAvailable(final boolean wslAvailable) {
        this.wslAvailable = wslAvailable;
        signalChangeAndNotifyObservers();
    }

    void setWslModeEnabled(final boolean wslModeEnabled) {
        this.wslModeEnabled = wslModeEnabled;
        signalChangeAndNotifyObservers();
    }

    void setAvailableWslDistros(final List<String> availableWslDistros) {
        this.availableWslDistros = availableWslDistros;
        signalChangeAndNotifyObservers();
    }

    void setWslDistroName(@Nullable final String wslDistroName) {
        this.wslDistroName = wslDistroName;
        signalChangeAndNotifyObservers();
    }

    private void signalChangeAndNotifyObservers() {
        setChanged();
        notifyObservers();
    }

}
