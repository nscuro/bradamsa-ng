package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.io.CommandExecutor;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import com.github.nscuro.bradamsang.radamsa.Radamsa;

import javax.annotation.Nonnull;

class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final IBurpExtenderCallbacks extenderCallbacks;

    private final OptionsProvider optionsProvider;

    IntruderPayloadGeneratorFactory(@Nonnull final IBurpExtenderCallbacks extenderCallbacks,
                                    @Nonnull final OptionsProvider optionsProvider) {
        this.extenderCallbacks = extenderCallbacks;
        this.optionsProvider = optionsProvider;
    }

    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(@Nonnull final IIntruderAttack intruderAttack) {
        final CommandExecutor commandExecutor;

        if (optionsProvider.isWslModeEnabled()) {
            if (optionsProvider.getWslDistributionName().isPresent()) {
                commandExecutor = new WslCommandExecutor(optionsProvider.getWslDistributionName().get());
            } else {
                throw new IllegalArgumentException("WSL mode enabled but not distribution provided");
            }
        } else {
            commandExecutor = new NativeCommandExecutor();
        }

        return new IntruderPayloadGenerator(extenderCallbacks, optionsProvider,
                new Radamsa(commandExecutor, optionsProvider.getRadamsaCommand()));
    }

}
