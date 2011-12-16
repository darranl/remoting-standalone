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

package com.darranl.as.remoting.server;

import static org.xnio.Options.SASL_POLICY_NOANONYMOUS;
import static org.xnio.Options.SSL_ENABLED;
import static org.xnio.Options.SASL_MECHANISMS;
import static org.xnio.Options.SSL_STARTTLS;
import static org.xnio.Options.SSL_CLIENT_AUTH_MODE;
import static org.xnio.SslClientAuthMode.REQUESTED;
import static org.xnio.SslClientAuthMode.REQUIRED;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Collection;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.jboss.remoting3.Channel;
import org.jboss.remoting3.Connection;
import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.MessageInputStream;
import org.jboss.remoting3.OpenListener;
import org.jboss.remoting3.Registration;
import org.jboss.remoting3.Remoting;
import org.jboss.remoting3.remote.RemoteConnectionProviderFactory;
import org.jboss.remoting3.security.ServerAuthenticationProvider;
import org.jboss.remoting3.spi.NetworkServerProvider;
import org.jboss.sasl.callback.VerifyPasswordCallback;
import org.xnio.OptionMap;
import org.xnio.OptionMap.Builder;
import org.xnio.Sequence;
import org.xnio.Xnio;
import org.xnio.channels.AcceptingChannel;
import org.xnio.channels.ConnectedStreamChannel;
import org.xnio.ssl.XnioSsl;

import com.darranl.as.remoting.SSLUtil;

/**
 * A simple server to allow standalone testing.
 */
public class SimpleServer {

    private final Mode mode;
    private final Endpoint endpoint;
    private final Registration registration;

    private NetworkServerProvider serverProvider;
    private AcceptingChannel<? extends ConnectedStreamChannel> server;

    private ServerAuthenticationProvider sap = new ServerAuthenticationProvider() {
        private CallbackHandler callbackHandler = new CallbackHandler() {

            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback current : callbacks) {
                    if (current instanceof PasswordCallback) {
                        PasswordCallback pcb = (PasswordCallback) current;
                        pcb.setPassword("darran_password".toCharArray());
                    } else if (current instanceof AuthorizeCallback) {
                        AuthorizeCallback acb = (AuthorizeCallback) current;
                        System.out.println("Authentication ID = " + acb.getAuthenticationID());
                        System.out.println("Authorization ID = " + acb.getAuthorizationID());
                        acb.setAuthorized(acb.getAuthenticationID().equals(acb.getAuthorizationID()));
                    } else if (current instanceof VerifyPasswordCallback) {
                        VerifyPasswordCallback vpc = (VerifyPasswordCallback) current;
                        vpc.setVerified("darran_password".equals(vpc.getPassword()));
                    }

                }
            }

        };

        public CallbackHandler getCallbackHandler(String mechanismName) {
            return callbackHandler;
        }
    };

    SimpleServer(final Mode mode) throws IOException {
        if (mode == null) {
            this.mode = Mode.PLAIN;
        } else {
            this.mode = mode;
        }
        Xnio xnio = Xnio.getInstance();
        /*
         * Ideally we do not want any security config at this level.
         */
        endpoint = Remoting.createEndpoint("SimpleServer", xnio, OptionMap.EMPTY);
        registration = endpoint.addConnectionProvider("remote", new RemoteConnectionProviderFactory(), OptionMap.EMPTY);
    }

    void start(int port) throws IOException {
        serverProvider = endpoint.getConnectionProviderInterface("remote", NetworkServerProvider.class);

        endpoint.registerService("org.jboss.darranl.server", new OpenListener() {

            public void registrationTerminated() {
                System.out.println("registrationTerminated");
            }

            public void channelOpened(Channel channel) {
                System.out.println("channelOpened");
                Connection connection = channel.getConnection();
                Collection<Principal> principals = connection.getPrincipals();
                for (Principal current : principals) {
                    System.out.println(current.getClass().getName() + " - " + current.getName());
                }
                channel.receiveMessage(new Receiver());
            }

        }, OptionMap.EMPTY);

        /*
         * Depending on the Mode this is where we will decide what options to specify, and construct an appropriate SSLContext
         * to be used during the calls.
         */

        XnioSsl xnioSsl = null;
        Builder builder = OptionMap.builder();
        switch (mode) {
            case PLAIN:
                builder.set(SASL_MECHANISMS, Sequence.of("ANONYMOUS"));
                builder.set(SASL_POLICY_NOANONYMOUS, false);
                builder.set(SSL_ENABLED, false);
                break;
            case SSL:
                builder.set(SASL_MECHANISMS, Sequence.of("ANONYMOUS"));
                builder.set(SASL_POLICY_NOANONYMOUS, false);
                builder.set(SSL_ENABLED, true);
                builder.set(SSL_STARTTLS, true);
                xnioSsl = SSLUtil.getServerXnioSSl(false);
                break;
            case CLIENT_CERT:
                builder.set(SASL_MECHANISMS, Sequence.of("EXTERNAL"));
                builder.set(SSL_ENABLED, true);
                builder.set(SSL_STARTTLS, true);
                // Maybe set to REQUIRED when EXTERNAL is the only supported mechanism.
                
                //builder.set(SSL_CLIENT_AUTH_MODE, REQUIRED);
                builder.set(SSL_CLIENT_AUTH_MODE, REQUESTED);
                xnioSsl = SSLUtil.getServerXnioSSl(true);
                break;
        }

        server = serverProvider.createServer(new InetSocketAddress("127.0.0.1", port), builder.getMap(), sap, xnioSsl);
    }

    private class Receiver implements Channel.Receiver {

        public void handleError(Channel channel, IOException error) {
            error.printStackTrace();
        }

        public void handleEnd(Channel channel) {
            System.out.println("The END");
        }

        public void handleMessage(Channel channel, MessageInputStream message) {
            try {
                byte[] buffer = new byte[256];
                int count = message.read(buffer);

                String theMessage = new String(buffer, 0, count);
                System.out.println("Received Message '" + theMessage + "'");
                new Throwable("handle TRACE").printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                channel.receiveMessage(this);
            }
        }

    }

    public static void main(String[] args) throws Exception {
        Mode mode = Mode.PLAIN;
        if (args.length == 1) {
            mode = Mode.valueOf(args[0]);
        }

        new SimpleServer(mode).start(6262);
    }

    private enum Mode {
        PLAIN, SSL, CLIENT_CERT
    }

}
