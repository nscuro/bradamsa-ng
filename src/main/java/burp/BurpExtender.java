package burp;

import com.github.nscuro.bradamsang.BurpExtension;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks extenderCallbacks) {
        final BurpExtension extension = new BurpExtension(extenderCallbacks);

        extension.registerExtension();
    }

}
