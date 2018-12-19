package burp;

import com.github.nscuro.bradamsang.BurpExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class BurpExtenderTest {

    private IBurpExtenderCallbacks extenderCallbacksMock;

    private BurpExtension burpExtensionMock;

    private BurpExtender burpExtender;

    @BeforeEach
    void beforeEach() {
        extenderCallbacksMock = mock(IBurpExtenderCallbacks.class);

        burpExtensionMock = mock(BurpExtension.class);

        burpExtender = new BurpExtender(burpExtensionMock);
    }

    @Test
    void shouldRegisterExtension() {
        burpExtender.registerExtenderCallbacks(extenderCallbacksMock);

        verify(burpExtensionMock).registerExtension(extenderCallbacksMock);
    }

}