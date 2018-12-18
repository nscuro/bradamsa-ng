package com.github.nscuro.bradamsang.radamsa;

import lombok.Builder;
import lombok.Data;

import java.nio.file.Path;

@Data
@Builder
public class Parameters {

    private final int count;

    private final Long seed;

    private final byte[] baseValue;

    private final Path radamsaOutputDirectoryPath;

}
