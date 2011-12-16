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

package com.darranl.as.remoting;

import static org.xnio.Options.SSL_PROTOCOL;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.jboss.sasl.util.HexConverter;
import org.xnio.OptionMap;
import org.xnio.OptionMap.Builder;
import org.xnio.Xnio;
import org.xnio.ssl.XnioSsl;

public class SSLUtil {

    private static final String SERVER_KEYSTORE = "server.keystore";
    private static final String SERVER_TRUSTSTORE = "server.truststore";

    private static final String KEYSTORE_PASSWORD = "keystore_password";

    private static final String CLIENT_KEYSTORE = "client.keystore";
    private static final String CLIENT_TRUSTSTORE = "client.truststore";

    private static final String TRUSTSTORE_PASSWORD = "truststore_password";

    private static KeyStore loadKeyStore(final String name, final char[] password) throws IOException {
        File keystore = new File(name);
        try {
            final KeyStore theKeyStore = KeyStore.getInstance("JKS");
            if (keystore.exists()) {
                FileInputStream fis = new FileInputStream(keystore);
                theKeyStore.load(fis, password);
                fis.close();
            }

            return theKeyStore;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private static KeyManager[] getKeyManager(final String name, final char[] password) throws IOException {
        try {
            KeyStore keystore = loadKeyStore(name, password);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keystore, password);
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            return keyManagers;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private static TrustManager[] getTrustManager(final String name, final char[] password, final boolean server)
            throws IOException {
        try {
            KeyStore keystore = loadKeyStore(name, password);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(keystore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            for (int i = 0; i < trustManagers.length; i++) {
                if (trustManagers[i] instanceof X509TrustManager) {
                    trustManagers[i] = new AcceptAllTrustManager((X509TrustManager) trustManagers[i]);
                }
            }

            return trustManagers;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private static XnioSsl getXnioSsl(final String keystore, final String truststore, final boolean server) throws IOException {
        Xnio xnio = Xnio.getInstance();
        try {
            KeyManager[] keyManagers = ((keystore != null) ? getKeyManager(keystore, KEYSTORE_PASSWORD.toCharArray()) : null);
            TrustManager[] trustManagers = ((truststore != null) ? getTrustManager(truststore,
                    TRUSTSTORE_PASSWORD.toCharArray(), server) : null);

            Builder builder = OptionMap.builder();
            builder.set(SSL_PROTOCOL, "TLS");

            return xnio.getSslProvider(keyManagers, trustManagers, builder.getMap());
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public static XnioSsl getServerXnioSSl(final boolean includeTruststore) throws IOException {
        return getXnioSsl(SERVER_KEYSTORE, includeTruststore ? SERVER_TRUSTSTORE : null, true);
    }

    public static XnioSsl getClientXnioSsl(final boolean includeKeyStore) throws IOException {
        return getXnioSsl(includeKeyStore ? CLIENT_KEYSTORE : null, CLIENT_TRUSTSTORE, false);
    }

    private static void saveClientCerts(X509Certificate[] chain) throws IOException {
        File keystore = new File(CLIENT_TRUSTSTORE);
        try {
            final KeyStore theKeyStore = KeyStore.getInstance("JKS");
            if (keystore.exists()) {
                FileInputStream fis = new FileInputStream(keystore);
                theKeyStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
                fis.close();
            } else {
                theKeyStore.load(null, null); // Force empty init.
            }

            for (X509Certificate current : chain) {
                theKeyStore.setCertificateEntry(current.getSubjectX500Principal().getName(), current);
            }
            FileOutputStream fos = new FileOutputStream(keystore);
            theKeyStore.store(fos, TRUSTSTORE_PASSWORD.toCharArray());
            fos.close();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private static class AcceptAllTrustManager implements X509TrustManager {

        private final X509TrustManager wrapped;

        public AcceptAllTrustManager(X509TrustManager toBeWrapped) {
            this.wrapped = toBeWrapped;
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            System.out.println(" * checkClientTrusted * ");
            new Throwable("TRACE").printStackTrace();
            for (X509Certificate current : chain) {
                System.out.println("Subject - " + current.getSubjectX500Principal());
            }

            try {
                wrapped.checkClientTrusted(chain, authType);
            } catch (CertificateException e) {
                System.out.println("Not trusting client.");
                throw e;
            }
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                wrapped.checkServerTrusted(chain, authType);
            } catch (CertificateException ce) {
                System.out.println("Swallowed CertificateException authType=" + authType);
                for (X509Certificate current : chain) {
                    System.out.println("Certificate - " + current.toString());
                    System.out.println("Subject - " + current.getSubjectX500Principal());
                    System.out.println("Issuer - " + current.getIssuerDN());
                    System.out.println("Signature Algorithm - " + current.getSigAlgName());

                    try {
                        Map<String, String> fingerprints = generateFingerprints(current.getEncoded());
                        System.out.println(" * Fingerprints * ");
                        for (String key : fingerprints.keySet()) {
                            System.out.println("(" + key + "): " + fingerprints.get(key));
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                try {
                    saveClientCerts(chain);
                } catch (Exception e) {
                    e.printStackTrace(); // Only a POC for now.
                }
            }
        }

        public X509Certificate[] getAcceptedIssuers() {
            return wrapped.getAcceptedIssuers();
        }

    }

    private static final String[] FINGERPRINT_ALOGRITHMS = new String[] { "MD5", "SHA1" };

    private static Map<String, String> generateFingerprints(final byte[] cert) throws Exception {
        Map<String, String> fingerprints = new HashMap<String, String>(FINGERPRINT_ALOGRITHMS.length);
        for (String current : FINGERPRINT_ALOGRITHMS) {
            fingerprints.put(current, generateFingerPrint(current, cert));
        }

        return fingerprints;
    }

    private static String generateFingerPrint(final String algorithm, final byte[] cert) throws Exception {
        StringBuilder sb = new StringBuilder();

        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digested = md.digest(cert);
        String hex = HexConverter.convertToHexString(digested);
        boolean started = false;
        for (int i = 0; i < hex.length() - 1; i += 2) {
            if (started) {
                sb.append(":");
            } else {
                started = true;
            }
            sb.append(hex.substring(i, i + 2));
        }

        return sb.toString();
    }

}
