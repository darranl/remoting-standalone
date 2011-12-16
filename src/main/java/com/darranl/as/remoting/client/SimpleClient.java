/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package com.darranl.as.remoting.client;

import static org.xnio.Options.SASL_POLICY_NOANONYMOUS;
import static org.xnio.Options.SSL_ENABLED;
import static org.xnio.Options.SSL_STARTTLS;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jboss.remoting3.Channel;
import org.jboss.remoting3.Connection;
import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.MessageOutputStream;
import org.jboss.remoting3.Registration;
import org.jboss.remoting3.Remoting;
import org.jboss.remoting3.remote.RemoteConnectionProviderFactory;
import org.xnio.IoFuture;
import org.xnio.OptionMap;
import org.xnio.OptionMap.Builder;
import org.xnio.Xnio;
import org.xnio.ssl.XnioSsl;

import com.darranl.as.remoting.SSLUtil;

/**
 * A simple client to communicate with the simple server.
 */
public class SimpleClient {

    private final Endpoint endpoint;
    private final Registration registration;

    private Connection connection;
    private Channel sendChannel;

    private final CallbackHandler cbh = new CallbackHandler() {

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback current : callbacks) {
                if (current instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) current;
                    ncb.setName("anonymous");
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }

        }

    };

    SimpleClient() throws IOException {
        Xnio xnio = Xnio.getInstance();
        endpoint = Remoting.createEndpoint("Simple Client", xnio, OptionMap.EMPTY);
        registration = endpoint.addConnectionProvider("remote", new RemoteConnectionProviderFactory(), OptionMap.EMPTY);
    }

    void connect(final Mode mode) throws IOException, URISyntaxException {
        Builder builder = OptionMap.builder();
        builder.set(SASL_POLICY_NOANONYMOUS, false);

        // Expecting this to mean we are SSL capable but expect the server to initiate SSL.
        builder.set(SSL_ENABLED, true);
        builder.set(SSL_STARTTLS, true);
        XnioSsl xnioSsl = null;
        if (Mode.NONE.equals(mode) == false) {
            xnioSsl = SSLUtil.getClientXnioSsl(mode.equals(Mode.CLIENT_CERT));
        }

        IoFuture<Connection> futureConnection = endpoint.connect(new URI("remote://127.0.0.1:6262"), builder.getMap(), cbh,
                xnioSsl);
        connection = futureConnection.get();

        IoFuture<Channel> futureChannel = connection.openChannel("org.jboss.darranl.server", OptionMap.EMPTY);
        sendChannel = futureChannel.get();
    }

    void send(String message) throws IOException {
        MessageOutputStream mos = sendChannel.writeMessage();
        mos.write(message.getBytes());
        mos.close();
    }

    void close() throws IOException {
        if (sendChannel != null) {
            sendChannel.close();
            sendChannel = null;
        }
        if (connection != null) {
            connection.close();
            connection = null;
        }
    }

    void end() throws IOException {
        registration.close();
        endpoint.close();
    }

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {
        Mode mode = Mode.PLAIN;
        if (args.length == 1) {
            mode = Mode.valueOf(args[0]);
        }

        SimpleClient sc = new SimpleClient();
        try {
            sc.connect(mode);
            sc.send("Howdy");
            Thread.sleep(2000); // Just make sure server has time to receive the message.
        } finally {
            sc.close();
            sc.end();
        }
    }

    private enum Mode {
        NONE, PLAIN, CLIENT_CERT
    }

}
