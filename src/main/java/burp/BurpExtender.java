package burp;

import com.github.nscuro.bradamsang.BurpExtension;

public class BurpExtender implements IBurpExtender {

    private final BurpExtension burpExtension;

    BurpExtender(final BurpExtension burpExtension) {
        this.burpExtension = burpExtension;
    }

    public BurpExtender() {
        this(new BurpExtension());
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks extenderCallbacks) {
        burpExtension.registerExtension(extenderCallbacks);
    }

}
