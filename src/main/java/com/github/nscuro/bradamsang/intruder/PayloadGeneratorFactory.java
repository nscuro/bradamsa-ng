package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.ExtensionSettingsProvider;
import com.github.nscuro.bradamsang.InvalidSettingsException;
import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import com.github.nscuro.bradamsang.command.WslCommandExecutor;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.util.BurpLogger;

public final class PayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final ExtensionSettingsProvider settingsProvider;
    private final BurpLogger logger;

    public PayloadGeneratorFactory(final ExtensionSettingsProvider settingsProvider,
                                   final BurpLogger logger) {
        this.settingsProvider = settingsProvider;
        this.logger = logger;
    }

    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(final IIntruderAttack attack) {
        if (settingsProvider.getRadamsaExecutablePath().isEmpty()) {
            throw new InvalidSettingsException("No Radamsa executable path provided");
        }

        final var attackSettings = AttackSettings.fromSettingsProvider(settingsProvider);

        final CommandExecutor commandExecutor;
        if (attackSettings.isWslModeEnabled()) {
            commandExecutor = attackSettings.getWslDistributionName()
                    .map(distroName -> new WslCommandExecutor(new NativeCommandExecutor(), distroName))
                    .orElseThrow(() -> new InvalidSettingsException("WSL mode enabled, but no distro selected"));
        } else {
            commandExecutor = new NativeCommandExecutor();
        }

        final var radamsa = new Radamsa(commandExecutor, settingsProvider.getRadamsaExecutablePath()
                .orElseThrow(() -> new InvalidSettingsException("No path to Radamsa executable provided")));

        logger.info("Launching Intruder attack with " + attackSettings);

        return new PayloadGenerator(logger, attackSettings, radamsa);
    }

}
