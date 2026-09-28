// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * プレイ中のランダム再検証のスケジューラ(キー = プレイヤー/接続)。
 * <ul>
 *   <li>{@link #start}: 参加後、[min, max] のランダムな待ち時間で最初の再検証を予約する</li>
 *   <li>{@link #completed}: 再検証が成功したら次回を予約する。失敗(切断)したら {@link #stop}</li>
 *   <li>{@link #requestSoon}: クライアントが構成の変更を通知したとき、待たずに(ただし連続実行を避ける最小間隔で)実行する</li>
 * </ul>
 * ジョブは timer スレッドで呼ばれる。ゲームスレッドへの引き渡しはジョブ側で行う。
 */
public final class Reverifier<K> {
    /** 再検証の間隔設定(ミリ秒)。テストでは短くできる。 */
    public interface Intervals {
        boolean enabled();

        boolean onChange();

        long minMillis();

        long maxMillis();
    }

    public static Intervals intervalsOf(PolicyConfig cfg) {
        return new Intervals() {
            @Override
            public boolean enabled() {
                return cfg.reverifyEnabled();
            }

            @Override
            public boolean onChange() {
                return cfg.reverifyOnChange();
            }

            @Override
            public long minMillis() {
                return cfg.reverifyMinSeconds() * 1000L;
            }

            @Override
            public long maxMillis() {
                return cfg.reverifyMaxSeconds() * 1000L;
            }
        };
    }

    private final class State {
        final K key;
        final Runnable job;
        ScheduledFuture<?> next;
        long nextAtMillis;
        long lastStartMillis = Long.MIN_VALUE / 2;
        boolean running;

        State(K key, Runnable job) {
            this.key = key;
            this.job = job;
        }
    }

    private final ScheduledExecutorService timer;
    private final Random random;
    private final Supplier<Intervals> intervals;
    private final long minGapMillis;
    private final LongSupplier clockMillis;
    private final Map<K, State> states = new HashMap<>();

    /** @param minGapMillis 連続する再検証の最小間隔(通知の連打で負荷が上がらないように) */
    public Reverifier(ScheduledExecutorService timer, Random random, Supplier<Intervals> intervals, long minGapMillis) {
        this(timer, random, intervals, minGapMillis, System::currentTimeMillis);
    }

    Reverifier(ScheduledExecutorService timer, Random random, Supplier<Intervals> intervals, long minGapMillis, LongSupplier clock) {
        this.timer = timer;
        this.random = random;
        this.intervals = intervals;
        this.minGapMillis = minGapMillis;
        this.clockMillis = clock;
    }

    public synchronized void start(K key, Runnable job) {
        stop(key);
        State s = new State(key, job);
        states.put(key, s);
        if (intervals.get().enabled()) {
            schedule(s, randomDelay());
        }
    }

    /** 再検証が成功した。次回を予約する。 */
    public synchronized void completed(K key) {
        State s = states.get(key);
        if (s == null) {
            return;
        }
        s.running = false;
        if (intervals.get().enabled()) {
            schedule(s, randomDelay());
        }
    }

    /** クライアントが「構成が変わった」と通知してきた。 */
    public synchronized void requestSoon(K key) {
        State s = states.get(key);
        Intervals iv = intervals.get();
        if (s == null || s.running || !iv.enabled() || !iv.onChange()) {
            return;
        }
        long now = clockMillis.getAsLong();
        long delay = Math.max(0, minGapMillis - (now - s.lastStartMillis));
        if (s.next != null && s.nextAtMillis - now <= delay) {
            return; // すでにそれより早く予約されている
        }
        schedule(s, delay);
    }

    public synchronized void stop(K key) {
        State s = states.remove(key);
        if (s != null && s.next != null) {
            s.next.cancel(false);
        }
    }

    public synchronized void stopAll() {
        for (State s : states.values()) {
            if (s.next != null) {
                s.next.cancel(false);
            }
        }
        states.clear();
    }

    public synchronized boolean isTracking(K key) {
        return states.containsKey(key);
    }

    private long randomDelay() {
        Intervals iv = intervals.get();
        long min = iv.minMillis();
        long max = Math.max(min, iv.maxMillis());
        return min + (long) (random.nextDouble() * (max - min + 1));
    }

    private void schedule(State s, long delayMillis) {
        if (s.next != null) {
            s.next.cancel(false);
        }
        s.nextAtMillis = clockMillis.getAsLong() + delayMillis;
        s.next = timer.schedule(() -> fire(s), delayMillis, TimeUnit.MILLISECONDS);
    }

    private void fire(State s) {
        synchronized (this) {
            if (states.get(s.key) != s || s.running) {
                return;
            }
            s.running = true;
            s.next = null;
            s.lastStartMillis = clockMillis.getAsLong();
        }
        try {
            s.job.run();
        } catch (RuntimeException e) {
            // ジョブの失敗で監視を止めない(次回に再挑戦する)
            completed(s.key);
        }
    }
}
