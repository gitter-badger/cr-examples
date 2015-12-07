/*
 * Copyright (c) 2015 Bosch Software Innovations GmbH, Germany. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Bosch Software Innovations GmbH, Germany nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.bosch.cr.examples.inventorybrowser.server;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.ssl.SSLContextBuilder;

import javax.net.ssl.SSLContext;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

/**
 * ProxyServlet to forward IM requests to the target service.
 */

@WebServlet(ImProxyServlet.URL_PATTERN)
public class ImProxyServlet extends HttpServlet {

    private static final String URL_PREFIX = "/im";
    static final String URL_PATTERN = URL_PREFIX + "/*";

    private HttpHost targetHost;
    private CloseableHttpClient httpClient;
    private Properties props;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            props = new Properties(System.getProperties());
            if (new File("config.properties").exists()) {
                props.load(new FileReader("config.properties"));
            } else {
                InputStream i = Thread.currentThread().getContextClassLoader().getResourceAsStream("config.properties");
                props.load(i);
                i.close();
            }
            System.out.println("Config: " + props);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        targetHost = HttpHost.create(props.getProperty("imTargetHost", "https://im3-api.apps.bosch-iot-cloud.com"));
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String auth = req.getHeader("Authorization");
        if (auth == null) {
            resp.setHeader("WWW-Authenticate", "BASIC realm=\"Proxy\"");
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        try {
            long time = System.currentTimeMillis();
            CloseableHttpClient c = getHttpClient();

            String targetUrl = req.getPathInfo() + (req.getQueryString() != null ? ("?" + req.getQueryString()) : "");
            BasicHttpRequest targetReq = new BasicHttpRequest(req.getMethod(), targetUrl);

            String user = "";
            if (auth.toUpperCase().startsWith("BASIC ")) {
                String userpassDecoded = new String(new sun.misc.BASE64Decoder().decodeBuffer(auth.substring("BASIC ".length())));
                user = userpassDecoded.substring(0, userpassDecoded.indexOf(':'));
                String pass = userpassDecoded.substring(userpassDecoded.indexOf(':') + 1);
                UsernamePasswordCredentials creds = new UsernamePasswordCredentials(user, pass);
                targetReq.addHeader(new BasicScheme().authenticate(creds, targetReq, null));
            }

            targetReq.addHeader("x-im-client-access-token", props.getProperty("imClientAccessToken"));
            CloseableHttpResponse targetResp = c.execute(targetHost, targetReq);

            System.out.println("Request: " + targetHost + targetUrl + ", user " + user
                    + " -> " + (System.currentTimeMillis() - time) + " msec: " + targetResp.getStatusLine());

            resp.setStatus(targetResp.getStatusLine().getStatusCode());
            resp.setContentType("text/xml; charset=utf-8");
            targetResp.getEntity().writeTo(resp.getOutputStream());

        } catch (IOException | AuthenticationException ex) {
            throw new RuntimeException(ex);
        }
    }

    private synchronized CloseableHttpClient getHttpClient() {
        if (httpClient == null) {
            try {
                HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();

                // #### ONLY FOR TEST: Trust ANY certificate (self certified, any chain, ...)
                SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, (chain, authType) -> true).build();
                httpClientBuilder.setSSLContext(sslContext);

                // #### ONLY FOR TEST: Do NOT verify hostname
                SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);

                Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("http", PlainConnectionSocketFactory.getSocketFactory())
                        .register("https", sslConnectionSocketFactory)
                        .build();
                PoolingHttpClientConnectionManager httpClientConnectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
                httpClientBuilder.setConnectionManager(httpClientConnectionManager);

                if (props.getProperty("http.proxyHost") != null) {
                    httpClientBuilder.setProxy(new HttpHost(props.getProperty("http.proxyHost"), Integer.parseInt(props.getProperty("http.proxyPort"))));
                }

                httpClient = httpClientBuilder.build();
            } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException ex) {
                throw new RuntimeException(ex);
            }
        }

        return httpClient;
    }
}
