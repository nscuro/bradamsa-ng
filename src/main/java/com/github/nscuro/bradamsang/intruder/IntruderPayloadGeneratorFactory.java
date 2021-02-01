package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.BurpExtensionSettingsProvider;
import com.github.nscuro.bradamsang.BurpLogger;
import com.github.nscuro.bradamsang.radamsa.RadamsaExecutorFactory;

public final class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final RadamsaExecutorFactory radamsaExecutorFactory;
    private final BurpExtensionSettingsProvider settingsProvider;
    private final BurpLogger logger;

    public IntruderPayloadGeneratorFactory(final RadamsaExecutorFactory radamsaExecutorFactory,
                                           final BurpExtensionSettingsProvider settingsProvider,
                                           final BurpLogger logger) {
        this.radamsaExecutorFactory = radamsaExecutorFactory;
        this.settingsProvider = settingsProvider;
        this.logger = logger;
    }

    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(final IIntruderAttack intruderAttack) {
        final var attackOptions = IntruderAttackOptions.fromSettings(settingsProvider);
        logger.debug("Creating new payload generator with " + attackOptions);

        return new IntruderPayloadGenerator(
                radamsaExecutorFactory.create(settingsProvider),
                IntruderAttackOptions.fromSettings(settingsProvider),
                logger
        );
    }

}
