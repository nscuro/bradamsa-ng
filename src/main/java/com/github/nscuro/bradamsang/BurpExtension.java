package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import com.github.nscuro.bradamsang.intruder.PayloadGeneratorFactory;
import com.github.nscuro.bradamsang.intruder.PayloadProcessorFactory;
import com.github.nscuro.bradamsang.ui.SettingsTab;
import com.github.nscuro.bradamsang.util.BurpLogger;

public final class BurpExtension {

    public static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final var logger = new BurpLogger(extenderCallbacks, BurpLogger.LogLevel.DEBUG);

        logger.debug("Registering settings tab");
        final var settingsTab = new SettingsTab(new NativeCommandExecutor(), logger);
        extenderCallbacks.addSuiteTab(settingsTab);

        logger.debug("Registering payload generator factory");
        final var intruderPayloadGeneratorFactory = new PayloadGeneratorFactory(settingsTab, logger);
        extenderCallbacks.registerIntruderPayloadGeneratorFactory(intruderPayloadGeneratorFactory);

        logger.debug("Registering payload processor factory");
        final var intruderPayloadProcessorFactory = new PayloadProcessorFactory(settingsTab, logger);
        extenderCallbacks.registerIntruderPayloadProcessor(intruderPayloadProcessorFactory);
    }

}
