package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderPayloadGenerator;
import com.github.nscuro.bradamsang.radamsa.Parameters;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.radamsa.RadamsaException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

class IntruderPayloadGenerator implements IIntruderPayloadGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(IntruderPayloadGenerator.class);

    private final IBurpExtenderCallbacks extenderCallbacks;

    private final OptionsProvider optionsProvider;

    private final Radamsa radamsa;

    private final List<File> payloadFiles;

    private boolean firstRun = true;

    private int index;

    IntruderPayloadGenerator(@Nonnull final IBurpExtenderCallbacks extenderCallbacks,
                             @Nonnull final OptionsProvider optionsProvider) {
        this(extenderCallbacks, optionsProvider, new Radamsa(optionsProvider.getRadamsaCommand()), new ArrayList<>());
    }

    private IntruderPayloadGenerator(final IBurpExtenderCallbacks extenderCallbacks,
                                     final OptionsProvider optionsProvider,
                                     final Radamsa radamsa,
                                     final List<File> payloadFiles) {
        this.extenderCallbacks = extenderCallbacks;
        this.optionsProvider = optionsProvider;
        this.radamsa = radamsa;
        this.payloadFiles = payloadFiles;
    }

    @Override
    public boolean hasMorePayloads() {
        return firstRun || payloadFiles.size() > index;
    }

    @Override
    public byte[] getNextPayload(@Nullable final byte[] baseValue) {
        if (baseValue == null) {
            extenderCallbacks.printError("No baseValue provided. Be aware that you can't use bradamsa-ng with the battering ram attack!");

            return null;
        }

        if (firstRun) {
            try {
                generatePayloads(baseValue);
            } catch (RadamsaException e) {
                BurpUtils.printStackTrace(extenderCallbacks, e);

                return null;
            }

            final Path payloadFilesDirectoryPath = optionsProvider
                    .getIntruderInputDirectoryPath()
                    .orElseGet(optionsProvider::getRadamsaOutputDirectoryPath);

            if (!payloadFilesDirectoryPath.toFile().exists()
                    || !payloadFilesDirectoryPath.toFile().isDirectory()) {
                extenderCallbacks.printError(format("Payload input path \"%s\" does not exist or is not a directory", payloadFilesDirectoryPath));

                firstRun = false;

                return null;
            }

            final File[] outputFiles = payloadFilesDirectoryPath
                    .toFile()
                    .listFiles((dir, name) -> name.matches("^radamsa_[0-9]+\\.out$"));

            Optional
                    .ofNullable(outputFiles)
                    .map(Arrays::asList)
                    .ifPresent(payloadFiles::addAll);

            firstRun = false;

            if (payloadFiles.isEmpty()) {
                extenderCallbacks.printError(format("No payload files have been found in \"%s\". Please check your path settings", payloadFilesDirectoryPath));

                return null;
            }
        }

        final File file = payloadFiles.get(index);
        try {
            byte[] payload = Files.readAllBytes(file.toPath());

            if (!file.delete()) {
                extenderCallbacks.printError(format("\"%s\" was not deleted", file));
            }

            index++;

            return payload;
        } catch (IOException e) {
            BurpUtils.printStackTrace(extenderCallbacks, e);

            index++;

            return null;
        }
    }

    @Override
    public void reset() {
        // Delete all remaining payload files
        payloadFiles.forEach(File::delete);

        // Reset payload list
        payloadFiles.clear();
        index = 0;
    }

    private void generatePayloads(final byte[] baseValue) throws RadamsaException {
        LOGGER.debug("Generating payloads");

        final Parameters parameters = Parameters
                .builder()
                .count(optionsProvider.getCount())
                .seed(optionsProvider.getSeed().orElse(null))
                .baseValue(baseValue)
                .outputDirectoryPath(optionsProvider.getRadamsaOutputDirectoryPath())
                .build();

        radamsa.fuzz(parameters);
    }

}
