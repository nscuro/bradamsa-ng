package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderPayloadGenerator;
import com.github.nscuro.bradamsang.radamsa.Parameters;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.radamsa.RadamsaException;
import com.github.nscuro.bradamsang.wsl.WslPathConverter;
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

    private final WslPathConverter wslPathConverter;

    private final Radamsa radamsa;

    private final List<File> payloadFiles;

    private Path payloadFilesDirectoryPath;

    private int currentPayloadFileIndex;

    private boolean firstRun = true;

    IntruderPayloadGenerator(final IBurpExtenderCallbacks extenderCallbacks,
                             final OptionsProvider optionsProvider,
                             final WslPathConverter wslPathConverter,
                             final Radamsa radamsa) {
        this.extenderCallbacks = extenderCallbacks;
        this.optionsProvider = optionsProvider;
        this.wslPathConverter = wslPathConverter;
        this.radamsa = radamsa;
        this.payloadFiles = new ArrayList<>();
    }

    @Override
    public boolean hasMorePayloads() {
        return firstRun || payloadFiles.size() > currentPayloadFileIndex;
    }

    @Nullable
    @Override
    public byte[] getNextPayload(@Nullable final byte[] baseValue) {
        if (baseValue == null) {
            extenderCallbacks.printError("No baseValue provided. "
                    + "Be aware that you can't use bradamsa-ng with the battering ram attack!");

            return null;
        }

        if (firstRun) {
            firstRun = false;

            // Create a temporary directory put the payload files in
            try {
                payloadFilesDirectoryPath = Files.createTempDirectory("bradamsa-ng_");
                payloadFilesDirectoryPath.toFile().deleteOnExit();
            } catch (IOException e) {
                BurpUtils.printStackTrace(extenderCallbacks, e);

                return null;
            }

            try {
                generatePayloads(baseValue);
            } catch (RadamsaException e) {
                BurpUtils.printStackTrace(extenderCallbacks, e);

                return null;
            }

            // Collect all payload files from input directory
            Optional
                    .of(payloadFilesDirectoryPath)
                    .map(Path::toFile)
                    .map(directory -> directory.listFiles((dir, name) -> name.matches("^radamsa_[0-9]+\\.out$")))
                    .map(Arrays::asList)
                    .ifPresent(payloadFiles::addAll);

            if (payloadFiles.isEmpty()) {
                extenderCallbacks.printError(format("No payload files have been found in \"%s\"", payloadFilesDirectoryPath));

                return null;
            }
        }

        final File file = payloadFiles.get(currentPayloadFileIndex++);
        try {
            byte[] payload = Files.readAllBytes(file.toPath());

            if (!file.delete()) {
                extenderCallbacks.printError(format("\"%s\" was not deleted", file));
            }

            return payload;
        } catch (IOException e) {
            BurpUtils.printStackTrace(extenderCallbacks, e);

            return null;
        }
    }

    @Override
    public void reset() {
        // Delete all remaining payload files
        payloadFiles.forEach(File::delete);

        // Reset payload list
        payloadFiles.clear();
        payloadFilesDirectoryPath.toFile().delete();
        currentPayloadFileIndex = 0;
    }

    private void generatePayloads(final byte[] baseValue) throws RadamsaException {
        LOGGER.debug("Generating payloads");

        final Parameters parameters = Parameters
                .builder()
                .count(optionsProvider.getCount().orElse(null))
                .seed(optionsProvider.getSeed().orElse(null))
                .baseValue(baseValue)
                .outputDirectoryPath(determineRadamsaOutputDirectoryPath())
                .build();

        radamsa.fuzz(parameters);
    }

    @Nonnull
    private Path determineRadamsaOutputDirectoryPath() {
        if (optionsProvider.isWslModeEnabled()) {
            return wslPathConverter.convertToUnixPath(payloadFilesDirectoryPath);
        } else {
            return payloadFilesDirectoryPath;
        }
    }

}
