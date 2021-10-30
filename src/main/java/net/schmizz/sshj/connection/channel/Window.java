/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj.connection.channel;

import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.connection.ConnectionException;
import org.slf4j.Logger;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public abstract class Window {

    protected final Logger log;

    protected final int maxPacketSize;

    protected AtomicLong size;

    public Window(final long initialWinSize, final int maxPacketSize, final LoggerFactory loggerFactory) {
        size = new AtomicLong(initialWinSize);
        this.maxPacketSize = maxPacketSize;
        log = loggerFactory.getLogger(getClass());
    }

    public void expand(final long increment) {
        log.debug("Increasing Window Size [{}] by [{}]", size, increment);
        size.getAndAdd(increment);
    }

    public int getMaxPacketSize() {
        return maxPacketSize;
    }

    public long getSize() {
        return size.get();
    }

    public void consume(final long decrement) throws ConnectionException {
        log.debug("Decreasing Window Size [{}] by [{}]", size, decrement);
        size.getAndAdd(-decrement);
        if (size.get() < 0) {
            throw new ConnectionException("Window consumed to below 0");
        }
    }

    @Override
    public String toString() {
        return "[winSize=" + size + "]";
    }

    /** Controls how much data we can send before an adjustment notification from remote end is required. */
    public static final class Remote
            extends Window {
        private static final long INCREMENTAL_SLEEP = 50;

        private final long timeoutMs;

        public Remote(long initialWinSize, int maxPacketSize, long timeoutMs, LoggerFactory loggerFactory) {
            super(initialWinSize, maxPacketSize, loggerFactory);
            this.timeoutMs = timeoutMs;
        }

        public long awaitExpansion(final long previousWindowSize) throws ConnectionException {
            log.debug("Awaiting expansion of Remote Window Size [{}]", previousWindowSize);

            final long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
            while (size.get() <= previousWindowSize) {
                try {
                    Thread.sleep(INCREMENTAL_SLEEP);
                    if ((System.nanoTime() - end) > 0) {
                        final String message = String.format("Awaiting expansion of Remote Window Size Timeout [%d] exceeded", timeoutMs);
                        throw new ConnectionException(message);
                    }
                } catch (InterruptedException ie) {
                    throw new ConnectionException("Awaiting expansion of Remote Window Size interrupted", ie);
                }
            }
            return size.get();
        }

        public void consume(long howMuch) {
            try {
                super.consume(howMuch);
            } catch (ConnectionException e) { // It's a bug if we consume more than remote allowed
                throw new SSHRuntimeException(e);
            }
        }
    }

    /** Controls how much data remote end can send before an adjustment notification from us is required. */
    public static final class Local
            extends Window {

        private final long initialSize;
        private final long threshold;

        public Local(long initialWinSize, int maxPacketSize, LoggerFactory loggerFactory) {
            super(initialWinSize, maxPacketSize, loggerFactory);
            this.initialSize = initialWinSize;
            threshold = Math.min(maxPacketSize * 20, initialSize / 4);
        }

        public long neededAdjustment() {
            return (size.get() <= threshold) ? (initialSize - size.get()) : 0;
        }
    }
}
