// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReverifierTest {
    private ScheduledThreadPoolExecutor timer;

    private static Reverifier.Intervals intervals(boolean enabled, boolean onChange, long min, long max) {
        return new Reverifier.Intervals() {
            @Override
            public boolean enabled() {
                return enabled;
            }

            @Override
            public boolean onChange() {
                return onChange;
            }

            @Override
            public long minMillis() {
                return min;
            }

            @Override
            public long maxMillis() {
                return max;
            }
        };
    }

    @BeforeEach
    void setUp() {
        timer = new ScheduledThreadPoolExecutor(2);
    }

    @AfterEach
    void tearDown() {
        timer.shutdownNow();
    }

    @Test
    void runsAfterTheRandomDelayAndAgainAfterCompletion() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        CountDownLatch twice = new CountDownLatch(2);
        long[] firstAt = new long[1];
        long t0 = System.currentTimeMillis();
        Reverifier<String> rv = new Reverifier<>(timer, new Random(1), () -> intervals(true, true, 60, 90), 0);
        rv.start("p", () -> {
            if (runs.incrementAndGet() == 1) {
                firstAt[0] = System.currentTimeMillis() - t0;
            }
            twice.countDown();
            rv.completed("p");
        });
        assertTrue(twice.await(5, TimeUnit.SECONDS));
        assertTrue(firstAt[0] >= 55, "must not run before the minimum delay, ran at " + firstAt[0]);
        rv.stop("p");
    }

    @Test
    void doesNotScheduleTheNextRunUntilCompletionIsReported() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        Reverifier<String> rv = new Reverifier<>(timer, new Random(2), () -> intervals(true, true, 20, 30), 0);
        rv.start("p", runs::incrementAndGet);
        Thread.sleep(300);
        assertEquals(1, runs.get(), "the verification is still in progress; no overlapping runs");
        rv.completed("p");
        Thread.sleep(300);
        assertTrue(runs.get() >= 2);
        rv.stop("p");
    }

    @Test
    void stopCancelsPendingRuns() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        Reverifier<String> rv = new Reverifier<>(timer, new Random(3), () -> intervals(true, true, 100, 100), 0);
        rv.start("p", runs::incrementAndGet);
        rv.stop("p");
        Thread.sleep(300);
        assertEquals(0, runs.get());
        assertFalse(rv.isTracking("p"));
    }

    @Test
    void disabledPolicySchedulesNothing() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        Reverifier<String> rv = new Reverifier<>(timer, new Random(4), () -> intervals(false, true, 10, 10), 0);
        rv.start("p", runs::incrementAndGet);
        rv.requestSoon("p");
        Thread.sleep(200);
        assertEquals(0, runs.get());
    }

    @Test
    void requestSoonRunsMuchEarlierThanTheRandomSchedule() throws Exception {
        CountDownLatch ran = new CountDownLatch(1);
        Reverifier<String> rv = new Reverifier<>(timer, new Random(5), () -> intervals(true, true, 60_000, 60_000), 0);
        rv.start("p", ran::countDown);
        rv.requestSoon("p");
        assertTrue(ran.await(3, TimeUnit.SECONDS), "an on-change request must not wait for the periodic schedule");
        rv.stop("p");
    }

    @Test
    void requestSoonIsRateLimitedByTheMinimumGap() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        Reverifier<String> rv = new Reverifier<>(timer, new Random(6), () -> intervals(true, true, 60_000, 60_000), 400);
        rv.start("p", () -> {
            runs.incrementAndGet();
            rv.completed("p");
        });
        rv.requestSoon("p");
        Thread.sleep(150);
        assertEquals(1, runs.get());
        for (int i = 0; i < 20; i++) {
            rv.requestSoon("p"); // 連打しても
        }
        Thread.sleep(150);
        assertEquals(1, runs.get(), "the second run must wait for the minimum gap");
        Thread.sleep(600);
        assertEquals(2, runs.get(), "20 requests collapse into a single follow-up run");
        rv.stop("p");
    }

    @Test
    void requestsAreIgnoredWhenOnChangeIsOffOrARunIsInProgress() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        Reverifier<String> off = new Reverifier<>(timer, new Random(7), () -> intervals(true, false, 60_000, 60_000), 0);
        off.start("p", runs::incrementAndGet);
        off.requestSoon("p");
        Thread.sleep(200);
        assertEquals(0, runs.get());

        Reverifier<String> busy = new Reverifier<>(timer, new Random(8), () -> intervals(true, true, 20, 20), 0);
        busy.start("q", runs::incrementAndGet); // completed() を呼ばない = 実行中のまま
        Thread.sleep(200);
        int before = runs.get();
        busy.requestSoon("q");
        Thread.sleep(200);
        assertEquals(before, runs.get());
    }

    @Test
    void aFailingJobDoesNotStopMonitoring() throws Exception {
        AtomicInteger runs = new AtomicInteger();
        CountDownLatch three = new CountDownLatch(3);
        Reverifier<String> rv = new Reverifier<>(timer, new Random(9), () -> intervals(true, true, 20, 30), 0);
        rv.start("p", () -> {
            runs.incrementAndGet();
            three.countDown();
            throw new IllegalStateException("boom");
        });
        assertTrue(three.await(5, TimeUnit.SECONDS));
        rv.stop("p");
    }

    @Test
    void keysAreIndependent() throws Exception {
        AtomicInteger a = new AtomicInteger();
        AtomicInteger b = new AtomicInteger();
        Reverifier<String> rv = new Reverifier<>(timer, new Random(10), () -> intervals(true, true, 30, 40), 0);
        rv.start("a", () -> {
            a.incrementAndGet();
            rv.completed("a");
        });
        rv.start("b", () -> {
            b.incrementAndGet();
            rv.completed("b");
        });
        Thread.sleep(300);
        rv.stop("a");
        int aAtStop = a.get();
        Thread.sleep(300);
        assertEquals(aAtStop, a.get());
        assertTrue(b.get() > 2);
        rv.stopAll();
    }
}
