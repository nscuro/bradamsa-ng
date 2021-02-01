package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.BurpLogger.LogLevel;
import com.github.nscuro.bradamsang.intruder.IntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.intruder.IntruderPayloadProcessorFactory;
import com.github.nscuro.bradamsang.radamsa.RadamsaExecutorFactory;

public class BurpExtension {

    public static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final var logger = new BurpLogger(extenderCallbacks, LogLevel.DEBUG);
        final var radamsaExecutorFactory = new RadamsaExecutorFactory();
        final BurpExtensionSettingsProvider settingsProvider = null;

        logger.debug("Registering intruder payload generator factory");
        extenderCallbacks.registerIntruderPayloadGeneratorFactory(new IntruderPayloadGeneratorFactory(
                radamsaExecutorFactory,
                settingsProvider,
                logger
        ));

        logger.debug("Registering intruder payload processor factory");
        extenderCallbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessorFactory(
                radamsaExecutorFactory,
                settingsProvider,
                logger
        ));
    }

}
