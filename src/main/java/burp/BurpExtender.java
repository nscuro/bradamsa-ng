package burp;

import com.github.nscuro.bradamsang.BradamsaNgExtension;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks extenderCallbacks) {
        final BradamsaNgExtension extension = new BradamsaNgExtension(extenderCallbacks);
        extension.registerExtension();
    }

}
