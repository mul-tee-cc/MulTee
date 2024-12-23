package cc.multee;

public interface Key {

    /**
     * Provides "local" key name as understood by KMS.
     * @return local key name
     */
    public String getName();

    /**
     * Provides "global" key name, if available, otherwise "local" key name.
     * @return referentially transparent key name
     */
    public String getFullName();

    /**
     * Provides "strength" of implied crypto-algorithm supported by the key.
     * Measured in bits.
     * @return "strength" of the key
     */
    public int getLength();

    public Algorithm getAlgorithm();

    /**
     * For keys setup for key rotation returns revision(version) of the key.
     * Version is ordinal staring with 0 and incrementing after each rotation.
     * For keys not intended for key rotation always returns 0;
     * @return version
     */
    public int getVersion();
}
