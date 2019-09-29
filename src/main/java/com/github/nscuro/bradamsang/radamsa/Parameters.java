package com.github.nscuro.bradamsang.radamsa;

import lombok.Builder;
import lombok.Data;

import java.nio.file.Path;

@Data
@Builder
public final class Parameters {

    private final Integer count;

    private final Long seed;

    private final byte[] baseValue;

    private final Path outputDirectoryPath;

}
