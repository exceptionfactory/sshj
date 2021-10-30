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
package com.hierynomus.sshj.connection.channel;

import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.Window;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;

@RunWith(MockitoJUnitRunner.class)
public class WindowTest {
    private static final int TIMEOUT = 5000;

    private static final int MAX_PACKET_SIZE = 8192;

    private static final long INITIAL_WINDOW_SIZE = 2048;

    private static final long EXPECTED_WINDOW_SIZE = INITIAL_WINDOW_SIZE * 2;

    @Test(timeout = TIMEOUT)
    public void testWindowRemoteAwaitExpansion() throws InterruptedException {
        final Window.Remote window = new Window.Remote(INITIAL_WINDOW_SIZE, MAX_PACKET_SIZE, TIMEOUT, LoggerFactory.DEFAULT);

        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final Runnable awaitCommand = new Runnable() {
            @Override
            public void run() {
                try {
                    window.awaitExpansion(INITIAL_WINDOW_SIZE);
                    countDownLatch.countDown();
                } catch (ConnectionException e) {
                    throw new RuntimeException(e);
                }
            }
        };
        final Thread awaitThread = new Thread(awaitCommand);
        awaitThread.start();

        final Runnable expandCommand = new Runnable() {
            @Override
            public void run() {
                window.expand(INITIAL_WINDOW_SIZE);
            }
        };
        final Thread expandThread = new Thread(expandCommand);
        expandThread.start();

        countDownLatch.await();
        assertEquals(EXPECTED_WINDOW_SIZE, window.getSize());
    }
}
