package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledOnOs(OS.WINDOWS)
class WslSupportIT {

    private static WslSupport wslSupport;

    @BeforeAll
    static void beforeAll() {
        wslSupport = new WslSupport(new NativeCommandExecutor());
    }

    @Nested
    class GetInstalledDistributionsIT {

        @Test
        void shouldReturnListOfInstalledDistributions() throws IOException {
            final List<WslDistribution> distributions = wslSupport.getInstalledDistributions();
            assertThat(distributions).isNotEmpty();

            assertThat(distributions)
                    .map(WslDistribution::getName)
                    .allSatisfy(name -> assertThat(name).isNotBlank());

            assertThat(distributions)
                    .map(WslDistribution::getWslVersion)
                    .allSatisfy(version -> assertThat(version).isGreaterThan(0));
        }

    }

}
