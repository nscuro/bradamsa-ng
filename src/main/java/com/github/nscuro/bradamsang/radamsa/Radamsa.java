package com.github.nscuro.bradamsang.radamsa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class Radamsa {

    private static final Logger LOGGER = LoggerFactory.getLogger(Radamsa.class);

    private final CommandExecutor commandExecutor;

    private final String radamsaCommand;

    public Radamsa(final CommandExecutor commandExecutor,
                   final String radamsaCommand) {
        this.commandExecutor = commandExecutor;
        this.radamsaCommand = radamsaCommand;
    }

    public void fuzz(final Parameters parameters) throws RadamsaException {
        if (!isValidRadamsaCommand(radamsaCommand)) {
            throw new RadamsaException(String.format("Invalid radamsa command \"%s\"", radamsaCommand));
        }

        final List<String> commandLine = new ArrayList<>(commandExecutor.parseCommand(radamsaCommand));

        Optional
                .of(parameters.getCount())
                .filter(count -> count > 0)
                .ifPresent(count -> commandLine.addAll(Arrays.asList("-n", String.valueOf(count))));

        Optional
                .ofNullable(parameters.getSeed())
                .ifPresent(seed -> commandLine.addAll(Arrays.asList("-s", String.valueOf(seed))));

        commandLine.addAll(Arrays.asList("-o", parameters.getRadamsaOutputDirectoryPath().resolve("%n.out").toString().replace("\\", "/")));

        LOGGER.info("CommandLine: {}", commandLine);

        try {
            commandExecutor.execute(commandLine, parameters.getBaseValue());
        } catch (IOException e) {
            throw new RadamsaException(e);
        }
    }

    boolean isValidRadamsaCommand(final String radamsaCommand) {
        if (radamsaCommand == null || radamsaCommand.trim().isEmpty()) {
            return false;
        } else if (!radamsaCommand.matches("^.*radamsa(\\.[a-zA-Z]+)?$")) {
            return false;
        }

        final List<String> versionCommand = commandExecutor.parseCommand(radamsaCommand);
        versionCommand.add("-V");

        final Optional<String> radamsaVersion;
        try {
            radamsaVersion = commandExecutor
                    .execute(versionCommand)
                    .filter(output -> output.toLowerCase().contains("radamsa"))
                    .map(output -> output.split(" ", 2))
                    .map(outputParts -> outputParts[1]);
        } catch (IOException e) {
            LOGGER.error("Failed to execute radamsa", e);
            return false;
        }

        if (radamsaVersion.isPresent()) {
            LOGGER.info("Using radamsa v{}", radamsaVersion.get());
            return true;
        } else {
            return false;
        }
    }

}
