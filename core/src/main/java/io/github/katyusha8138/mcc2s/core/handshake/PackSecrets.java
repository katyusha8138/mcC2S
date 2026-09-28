package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/** サーバーが受理する pack_secret の集合(現行 + ローテーション猶予中の旧鍵)。 */
public final class PackSecrets {
    private final List<PackSecret> secrets;

    public PackSecrets(List<PackSecret> secrets) {
        if (secrets.isEmpty()) {
            throw new IllegalArgumentException("at least one pack secret is required");
        }
        this.secrets = Collections.unmodifiableList(new ArrayList<>(secrets));
    }

    public Optional<PackSecret> find(byte[] id) {
        for (PackSecret s : secrets) {
            if (Digests.equal(s.id(), id)) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    public List<PackSecret> all() {
        return secrets;
    }
}
