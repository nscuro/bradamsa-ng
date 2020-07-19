package burp;

import com.github.nscuro.bradamsang.BurpExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class BurpExtenderTest {

    @Mock
    private IBurpExtenderCallbacks extenderCallbacksMock;

    @Mock
    private BurpExtension burpExtensionMock;

    private BurpExtender burpExtender;

    @BeforeEach
    void beforeEach() {
        burpExtender = new BurpExtender(burpExtensionMock);
    }

    @Test
    void shouldRegisterExtension() {
        burpExtender.registerExtenderCallbacks(extenderCallbacksMock);

        verify(burpExtensionMock).registerExtension(extenderCallbacksMock);
    }

}