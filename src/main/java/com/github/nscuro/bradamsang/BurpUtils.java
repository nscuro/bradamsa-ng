package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;

import javax.annotation.Nonnull;
import java.io.PrintWriter;

class BurpUtils {

    static void printStackTrace(@Nonnull final IBurpExtenderCallbacks extenderCallbacks,
                                @Nonnull final Throwable throwable) {
        try (final PrintWriter printWriter = new PrintWriter(extenderCallbacks.getStderr())) {
            throwable.printStackTrace(printWriter);
        }
    }

}
