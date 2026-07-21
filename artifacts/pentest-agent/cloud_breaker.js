"use strict";
var CLOUD_BREAKER = {
    interceptedUrls: [],
    cloudCredentials: [],
    buckets: [],
    apiKeys: [],
    tokens: [],
    startTime: Date.now()
};
function log_cloud(kind, data) {
    send({type: "cloud", kind: kind, detail: JSON.stringify(data).substring(0, 500)});
}
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");
    Builder.build.implementation = function() {
        var client = this.build();
        try {
            var ArrayList = Java.use("java.util.ArrayList");
            var interceptors = Java.cast(client.interceptors(), ArrayList);
            var NetworkInterceptor = Java.registerClass({
                name: "com.hayo.CloudBreakerInterceptor",
                implements: [Java.use("okhttp3.Interceptor")],
                methods: {
                    intercept: function(chain) {
                        var request = chain.request();
                        var url = request.url().toString();
                        CLOUD_BREAKER.interceptedUrls.push(url);
                        var headers = request.headers();
                        if (headers) {
                            var auth = headers.get("Authorization");
                            if (auth && auth.toLowerCase().contains("bearer")) {
                                CLOUD_BREAKER.tokens.push(auth);
                                log_cloud("token", {source: url, token: auth.substring(0, 80)});
                            }
                            var xApiKey = headers.get("x-api-key");
                            if (xApiKey) {
                                CLOUD_BREAKER.apiKeys.push(xApiKey);
                                log_cloud("api_key", {source: url, key: xApiKey.substring(0, 40)});
                            }
                        }
                        var response = chain.proceed(request);
                        if (url.indexOf("amazonaws.com") > -1 || url.indexOf("cloudfunctions.net") > -1 ||
                            url.indexOf("azure.com") > -1 || url.indexOf("storage.googleapis.com") > -1 ||
                            url.indexOf("firebaseio.com") > -1) {
                            try {
                                var respBody = response.body();
                                if (respBody) {
                                    var content = Java.use("okio.Okio").buffer(respBody.source()).readUtf8();
                                    log_cloud("cloud_response", {url: url, size: content.length});
                                }
                            } catch(e) {}
                        }
                        return response;
                    }
                }
            });
            var list = Java.array("okhttp3.Interceptor", [NetworkInterceptor.$new()]);
            interceptors.addAll(Java.cast(Java.array("java.util.List", [list]), ArrayList));
        } catch(e) {
            log_cloud("error", "OkHttp interceptor: " + e.message);
        }
        return client;
    };
} catch(e) {}
try {
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.getInputStream.implementation = function() {
        var url = this.getURL().toString();
        if (url.indexOf("s3.") > -1 || url.indexOf("amazonaws.com") > -1 ||
            url.indexOf("storage.googleapis.com") > -1 || url.indexOf("blob.core.windows.net") > -1) {
            log_cloud("cloud_download", {url: url});
        }
        return this.getInputStream();
    };
} catch(e) {}
try {
    var S3Client = Java.use("com.amazonaws.services.s3.AmazonS3Client");
    S3Client.getObject.implementation = function(req) {
        log_cloud("s3_get", {bucket: req.bucketName, key: req.key});
        return this.getObject(req);
    };
    S3Client.listObjects.implementation = function(req) {
        log_cloud("s3_list", {bucket: req.bucketName});
        return this.listObjects(req);
    };
} catch(e) {}
try {
    var FirebaseDatabase = Java.use("com.google.firebase.database.FirebaseDatabase");
    FirebaseDatabase.getInstance.implementation = function() {
        log_cloud("firebase", "getInstance called");
        return this.getInstance();
    };
} catch(e) {}
try {
    var Storage = Java.use("com.google.cloud.storage.Storage");
    Storage.get.implementation = function(blobId) {
        log_cloud("gcp_storage", {bucket: blobId.bucket, name: blobId.name});
        return this.get(blobId);
    };
} catch(e) {}
try {
    var BlobClient = Java.use("com.azure.storage.blob.BlobClient");
    BlobClient.download.implementation = function(stream) {
        log_cloud("azure_blob", "download called");
        return this.download(stream);
    };
} catch(e) {}
try {
    var Retrofit = Java.use("retrofit2.Retrofit");
    Retrofit.create.implementation = function(service) {
        log_cloud("retrofit", "Service created: " + (service ? service.getName() : "?"));
        return this.create(service);
    };
} catch(e) {}
try {
    var Request = Java.use("com.android.volley.Request");
    Request.deliverResponse.implementation = function(response) {
        var url = this.getUrl();
        if (url && (url.indexOf("api.") > -1 || url.indexOf("cloud") > -1)) {
            log_cloud("volley_response", {url: url, body: String(response).substring(0, 200)});
        }
        return this.deliverResponse(response);
    };
} catch(e) {}
console.log("[CLOUD_BREAKER] Engine active - intercepting cloud traffic");
send({type: "log", message: "CLOUD_BREAKER: Cloud interception engine loaded"});
setInterval(function() {
    send({type: "cloud_summary", totalUrls: CLOUD_BREAKER.interceptedUrls.length, totalTokens: CLOUD_BREAKER.tokens.length, totalKeys: CLOUD_BREAKER.apiKeys.length});
}, 30000);
