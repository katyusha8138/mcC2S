// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
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

    private final ServerContext context;
    private final ThreadPoolExecutor worker;
    private final ScheduledThreadPoolExecutor timer;
    private final Path trustFilePath;

    private ServerRuntime(ServerContext context, ThreadPoolExecutor worker, ScheduledThreadPoolExecutor timer, Path trustFilePath) {
        this.context = context;
        this.worker = worker;
        this.timer = timer;
        this.trustFilePath = trustFilePath;
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

        ServerContext ctx = ServerContext.builder()
                .identity(files.identity())
                .secrets(files.secrets())
                .policy(files.policy())
                .baseline(baseline)
                .trustedSelfHashes(trustedSelf)
                .references(references)
                .sink(new ViolationLog(in.logsDir().resolve("violations.jsonl"), log))
                .log(log)
                .random(rnd)
                .worker(worker)
                .build();

        log.info("[mcC2S] ready: mode=" + files.policy().mode() + ", baseline=" + baseline.size() + " server-side jar(s), references="
                + references.size() + ", trusted mcC2S builds=" + trustedSelf.size());
        log.info("[mcC2S] trust file to distribute to players (put it in the client's config/mcc2s/trust/): " + files.trustFilePath());
        return new ServerRuntime(ctx, worker, timer, files.trustFilePath());
    }

    public ServerContext context() {
        return context;
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
