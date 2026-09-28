// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.testsupport;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.ClientHandshake;
import io.github.katyusha8138.mcc2s.core.handshake.Contexts;
import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.handshake.HandshakeException;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecret;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecrets;
import io.github.katyusha8138.mcc2s.core.handshake.ServerHandshake;
import io.github.katyusha8138.mcc2s.core.handshake.TrustFile;
import io.github.katyusha8138.mcc2s.core.handshake.TrustStore;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

/** テスト用の「サーバー運営者 + 正規プレイヤー」一式。 */
public final class Fixtures {
    public static final SecureRandom RND = new SecureRandom();
    public static final Set<Scope> ALL_SCOPES = EnumSet.allOf(Scope.class);

    public final Ed25519Identity identity;
    public final PackSecret secret;
    public final PackSecrets secrets;
    public final TrustStore trust;
    public final UUID player = UUID.randomUUID();

    private Fixtures(Ed25519Identity identity, PackSecret secret) {
        this.identity = identity;
        this.secret = secret;
        this.secrets = new PackSecrets(List.of(secret));
        this.trust = new TrustStore(List.of(new TrustFile("test", identity.publicKey(), secret)));
    }

    public static Fixtures create() {
        try {
            return new Fixtures(Ed25519Identity.generate(RND), PackSecret.generate(RND));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public ServerHandshake newServer(Set<Scope> scopes, int proofRate) {
        try {
            return ServerHandshake.start(identity, secrets, scopes, proofRate, Contexts.player(player), RND);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public ClientHandshake newClient(ServerHandshake server) throws HandshakeException {
        return ClientHandshake.accept(trust, server.challenge(), Contexts.player(player), RND);
    }

    /** 正規クライアントが最後まで実行した結果。 */
    public static final class Session {
        public final ServerHandshake server;
        public final ClientHandshake client;
        public final byte[] attestation;
        public final ServerHandshake.Opened opened;

        Session(ServerHandshake server, ClientHandshake client, byte[] attestation, ServerHandshake.Opened opened) {
            this.server = server;
            this.client = client;
            this.attestation = attestation;
            this.opened = opened;
        }
    }

    /** チャレンジ → 添付 → サーバーの open までを実行する。entries はクライアントの測定証明を使って作れる。 */
    public Session run(Set<Scope> scopes, int proofRate, Function<ClientHandshake, List<Entry>> entries)
            throws HandshakeException {
        ServerHandshake server = newServer(scopes, proofRate);
        ClientHandshake client = newClient(server);
        byte[] attestation = client.attest(manifest(client.requestedScopes(), entries.apply(client)));
        return new Session(server, client, attestation, server.open(attestation));
    }

    public static Manifest manifest(Set<Scope> reported, List<Entry> entries) {
        return new Manifest("1.21.1", "neoforge", "21.1.0", "0.1.0", reported, entries);
    }

    public static Manifest manifest(Set<Scope> reported, Entry... entries) {
        return manifest(reported, Arrays.asList(entries));
    }

    public static String sha(String seed) {
        return Digests.hex(Digests.sha256(seed.getBytes(StandardCharsets.UTF_8)));
    }
}
