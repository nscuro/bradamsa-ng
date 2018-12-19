package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;

import javax.annotation.Nonnull;
import java.io.PrintWriter;

class BurpUtils {

    private BurpUtils() {
    }

    /**
     * Print the stacktrace of a given {@link Throwable} to Burp's error output.
     *
     * @param extenderCallbacks Extender to write the output to
     * @param throwable         The {@link Throwable} to print the stacktrace of
     */
    static void printStackTrace(@Nonnull final IBurpExtenderCallbacks extenderCallbacks,
                                @Nonnull final Throwable throwable) {
        try (final PrintWriter printWriter = new PrintWriter(extenderCallbacks.getStderr())) {
            throwable.printStackTrace(printWriter);
        }
    }

}
