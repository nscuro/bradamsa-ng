package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.io.CommandExecutor;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.wsl.WslPathConverter;

import javax.annotation.Nonnull;

final class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final IBurpExtenderCallbacks extenderCallbacks;

    private final OptionsProvider optionsProvider;

    IntruderPayloadGeneratorFactory(final IBurpExtenderCallbacks extenderCallbacks,
                                    final OptionsProvider optionsProvider) {
        this.extenderCallbacks = extenderCallbacks;
        this.optionsProvider = optionsProvider;
    }

    @Nonnull
    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Nonnull
    @Override
    public IIntruderPayloadGenerator createNewInstance(final IIntruderAttack intruderAttack) {
        final CommandExecutor commandExecutor;

        if (optionsProvider.isWslModeEnabled()) {
            if (optionsProvider.getWslDistributionName().isPresent()) {
                commandExecutor = new WslCommandExecutor(optionsProvider.getWslDistributionName().get());
            } else {
                throw new IllegalStateException("WSL mode enabled but no distribution selected");
            }
        } else {
            commandExecutor = new NativeCommandExecutor();
        }

        if (!optionsProvider.getRadamsaCommand().isPresent()) {
            throw new IllegalStateException("No Radamsa command provided");
        }

        return new IntruderPayloadGenerator(new BurpLogger(extenderCallbacks), optionsProvider, new WslPathConverter(),
                new Radamsa(commandExecutor, optionsProvider.getRadamsaCommand().get()));
    }

}
