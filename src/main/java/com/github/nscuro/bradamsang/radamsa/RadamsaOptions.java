package com.github.nscuro.bradamsang.radamsa;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

public final class RadamsaOptions {

    private final byte[] sample;
    private final List<String> samplePaths;

    private RadamsaOptions(final byte[] sample, final List<String> samplePaths) {
        this.sample = sample;
        this.samplePaths = samplePaths;
    }

    public static RadamsaOptions withSample(final byte[] sample) {
        return new RadamsaOptions(sample, null);
    }

    public static RadamsaOptions withSamplePaths(final List<String> samplePaths) {
        return new RadamsaOptions(null, samplePaths);
    }

    public Optional<byte[]> getSample() {
        return Optional.ofNullable(sample);
    }

    public List<String> getSamplePaths() {
        return Optional.ofNullable(samplePaths)
                .orElseGet(Collections::emptyList);
    }

}
