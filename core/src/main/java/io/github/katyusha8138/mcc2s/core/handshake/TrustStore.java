package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/** クライアントが持つ信頼ファイルの集合。チャレンジのサーバー鍵 ID で該当ファイルを引く。 */
public final class TrustStore {
    private final List<TrustFile> files;

    public TrustStore(List<TrustFile> files) {
        this.files = Collections.unmodifiableList(new ArrayList<>(files));
    }

    public Optional<TrustFile> find(byte[] serverKeyId) {
        for (TrustFile f : files) {
            if (Digests.equal(f.serverKeyId(), serverKeyId)) {
                return Optional.of(f);
            }
        }
        return Optional.empty();
    }

    public boolean isEmpty() {
        return files.isEmpty();
    }
}
