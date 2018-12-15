package burp;

public class BurpExtender implements IBurpExtender {

    private static final String EXTENSION_NAME = "bradamsa-ng";

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(EXTENSION_NAME);
    }

}
