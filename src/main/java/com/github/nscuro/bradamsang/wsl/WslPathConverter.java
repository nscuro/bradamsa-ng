package com.github.nscuro.bradamsang.wsl;

import javax.annotation.Nonnull;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;

public class WslPathConverter {

    private static final Pattern DRIVE_LETTER_PATTERN = Pattern.compile("^([a-zA-Z]):\\\\");

    @Nonnull
    public Path convertToUnixPath(final Path windowsPath) {
        if (!windowsPath.toFile().exists()) {
            throw new IllegalArgumentException(format("\"%s\" does not exist", windowsPath));
        }

        return Paths.get(convertToUnixPath(windowsPath.toString()));
    }

    @Nonnull
    String convertToUnixPath(final String windowsPath) {
        final Matcher driveLetterMatcher = DRIVE_LETTER_PATTERN.matcher(windowsPath);

        if (!driveLetterMatcher.find() || driveLetterMatcher.groupCount() != 1) {
            throw new IllegalArgumentException(format("\"%s\" is not a valid Windows path", windowsPath));
        }

        return "/mnt/" + driveLetterMatcher.group(1).toLowerCase() + "/"
                + driveLetterMatcher.replaceFirst("").replaceAll("\\\\", "/");
    }

}
