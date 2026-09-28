// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfigException;
import io.github.katyusha8138.mcc2s.core.release.OfficialBuilds;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * サーバー起動時の組み立て: 設定ファイルの生成/読み込み、自身の Mod の走査(許可の基準)、
 * 参照ファイル索引、ワーカースレッドの用意までを行う。ローダーアダプタはこれを 1 回呼ぶだけでよい。
 */
public final class ServerRuntime implements AutoCloseable {
    /** ローダーアダプタが渡す入力。 */
    public record Inputs(
            Path configDir,
            Path modsDir,
            Path logsDir,
            List<LoadedMod> loadedMods,
            Set<String> platformModIds,
            Path selfPath,
            String selfVersion,
            String serverLabel,
            Log log) {}

    /** `/mcc2s reload` の結果。失敗しても従来の設定のまま動き続ける。 */
    public record ReloadResult(boolean ok, String message) {}

    private volatile ServerContext context;
    private final ThreadPoolExecutor worker;
    private final ScheduledThreadPoolExecutor timer;
    private final Path trustFilePath;
    private final Path configDir;
    private final String selfSha;
    private final LastViolations lastViolations;
    private final String selfVersion;

    private ServerRuntime(
            ServerContext context,
            ThreadPoolExecutor worker,
            ScheduledThreadPoolExecutor timer,
            Path trustFilePath,
            Path configDir,
            String selfSha,
            LastViolations lastViolations,
            String selfVersion) {
        this.context = context;
        this.worker = worker;
        this.timer = timer;
        this.trustFilePath = trustFilePath;
        this.configDir = configDir;
        this.selfSha = selfSha;
        this.lastViolations = lastViolations;
        this.selfVersion = selfVersion;
    }

    public static ServerRuntime start(Inputs in, SecureRandom rnd)
            throws IOException, GeneralSecurityException, PolicyConfigException {
        Log log = in.log();
        ServerFiles.Loaded files = ServerFiles.loadOrCreate(in.configDir(), in.serverLabel(), log, rnd);

        HashCache cache = new HashCache();
        List<EntrySeed> own = ModScanner.scan(in.modsDir(), in.loadedMods(), in.platformModIds(), cache);
        String selfSha = cache.sha256(in.selfPath());
        EntrySeed self = new EntrySeed(
                EntryKind.SELF, "mcc2s", in.selfVersion(), selfSha, Files.isRegularFile(in.selfPath()) ? in.selfPath() : null);

        List<Entry> baseline = new ArrayList<>();
        for (EntrySeed s : own) {
            baseline.add(s.toEntry());
        }

        List<EntrySeed> referenceSources = new ArrayList<>(own);
        referenceSources.add(self);
        ReferenceIndex references = ReferenceIndex.build(referenceSources, in.configDir().resolve(ServerFiles.REFERENCE_DIR), cache, log);

        OfficialBuilds official = ServerFiles.loadOfficialBuilds(in.configDir(), log);
        Set<String> trustedSelf = new HashSet<>(official.hashes());
        trustedSelf.add(selfSha);

        ThreadPoolExecutor worker = new ThreadPoolExecutor(
                2, 2, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(256), daemon("mcC2S-verify"));
        ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1, daemon("mcC2S-timer"));
        timer.setRemoveOnCancelPolicy(true);

        LastViolations lastViolations = new LastViolations();
        ViolationLog violationLog = new ViolationLog(in.logsDir().resolve("violations.jsonl"), log);
        ServerContext ctx = ServerContext.builder()
                .identity(files.identity())
                .secrets(files.secrets())
                .policy(files.policy())
                .baseline(baseline)
                .trustedSelfHashes(trustedSelf)
                .references(references)
                .sink(report -> {
                    violationLog.report(report);
                    lastViolations.record(report);
                })
                .log(log)
                .random(rnd)
                .worker(worker)
                .build();

        log.info("[mcC2S] ready: mode=" + files.policy().mode() + ", baseline=" + baseline.size() + " server-side jar(s), references="
                + references.size() + ", trusted mcC2S builds=" + trustedSelf.size());
        log.info("[mcC2S] trust file to distribute to players (put it in the client's config/mcc2s/trust/): " + files.trustFilePath());
        return new ServerRuntime(ctx, worker, timer, files.trustFilePath(), in.configDir(), selfSha, lastViolations, in.selfVersion());
    }

    public ServerContext context() {
        return context;
    }

    /** プレイヤーごとの直近の違反(`/mcc2s whitelist add <player>` 用)。 */
    public LastViolations lastViolations() {
        return lastViolations;
    }

    public String selfVersion() {
        return selfVersion;
    }

    public Path policyPath() {
        return configDir.resolve(ServerFiles.POLICY);
    }

    /**
     * `policy.toml` と公式ビルド一覧を読み直す。進行中の検証には影響せず、以降の検証から新しい設定が使われる。
     * 読み込みに失敗した場合は従来の設定を維持する(設定ミスで検証が止まらない)。
     */
    public synchronized ReloadResult reload() {
        Log log = context.log();
        try {
            PolicyConfig policy = ServerFiles.loadPolicy(policyPath());
            OfficialBuilds official = ServerFiles.loadOfficialBuilds(configDir, log);
            Set<String> trusted = new HashSet<>(official.hashes());
            trusted.add(selfSha);
            context = context.toBuilder().policy(policy).trustedSelfHashes(trusted).build();
            String msg = "policy reloaded: mode=" + policy.mode() + ", scopes=" + policy.scopes() + ", trusted mcC2S builds=" + trusted.size();
            log.info("[mcC2S] " + msg);
            return new ReloadResult(true, msg);
        } catch (PolicyConfigException | IOException e) {
            String msg = "could not reload policy.toml; keeping the previous settings: " + e.getMessage();
            log.error("[mcC2S] " + msg, null);
            return new ReloadResult(false, msg);
        }
    }

    /** タイムアウト用のスケジューラ。 */
    public ScheduledThreadPoolExecutor timer() {
        return timer;
    }

    public Path trustFilePath() {
        return trustFilePath;
    }

    @Override
    public void close() {
        worker.shutdownNow();
        timer.shutdownNow();
    }

    private static ThreadFactory daemon(String name) {
        return r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        };
    }
}
