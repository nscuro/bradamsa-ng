package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;

import java.io.PrintWriter;

public final class BurpLogger {

    private final IBurpExtenderCallbacks extenderCallbacks;

    public BurpLogger(final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    public void info(final String message) {
        extenderCallbacks.printOutput(message);
    }

    public void error(final String message) {
        extenderCallbacks.printError(message);
    }

    public void error(final Throwable throwable) {
        try (final PrintWriter printWriter = new PrintWriter(extenderCallbacks.getStderr())) {
            throwable.printStackTrace(printWriter);
        }
    }

}
