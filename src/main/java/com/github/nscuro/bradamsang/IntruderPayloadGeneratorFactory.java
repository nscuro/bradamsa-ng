package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

import javax.annotation.Nonnull;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final IBurpExtenderCallbacks extenderCallbacks;

    IntruderPayloadGeneratorFactory(@Nonnull final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(@Nonnull final IIntruderAttack intruderAttack) {
        final OptionsProvider optionsProvider = new OptionsProvider() {
            @Nonnull
            @Override
            public String getRadamsaCommand() {
                return "wsl -d kali-linux radamsa";
            }

            @Override
            public int getCount() {
                return 10;
            }

            @Nonnull
            @Override
            public Optional<Long> getSeed() {
                return Optional.empty();
            }

            @Nonnull
            @Override
            public Path getRadamsaOutputDirectoryPath() {
                return Paths.get("/mnt/c/Users/Niklas/Desktop");
            }

            @Nonnull
            @Override
            public Optional<Path> getIntruderInputDirectoryPath() {
                return Optional.of(Paths.get("C:/Users/Niklas/Desktop"));
            }
        };

        return new IntruderPayloadGenerator(extenderCallbacks, optionsProvider);
    }

}
