package com.github.nscuro.bradamsang.wsl;

public final class WslDistribution {

    private final String name;
    private final boolean isDefault;
    private final int wslVersion;

    public WslDistribution(final String name, final boolean isDefault, final int wslVersion) {
        this.name = name;
        this.isDefault = isDefault;
        this.wslVersion = wslVersion;
    }

    public String getName() {
        return name;
    }

    public boolean isDefault() {
        return isDefault;
    }

    public int getWslVersion() {
        return wslVersion;
    }

    @Override
    public String toString() {
        return "Distribution{" +
                "name='" + name + '\'' +
                ", isDefault=" + isDefault +
                ", wslVersion=" + wslVersion +
                '}';
    }

}
