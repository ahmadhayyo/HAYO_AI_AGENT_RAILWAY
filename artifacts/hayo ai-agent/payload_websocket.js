/* HAYO Cipher-7 — WebSocket/gRPC/SSE Interception (payload_websocket.js)
 * =================================================================== */
Java.perform(function () {
    console.log("[WS] Hooking WebSocket/gRPC/SSE stack...");
    try {
        var RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");
        console.log("[WS] okhttp3 WebSocket found");
        try { RealWebSocket.onReadMessage.overload('java.lang.String').implementation = function (t) { console.log("[WS][okhttp3] IN: " + t.substring(0,500)); if (/eyJ[a-zA-Z0-9_\-]{10,}/.test(t)) console.log("[WS][JWT] " + t.match(/eyJ[a-zA-Z0-9_\-]{10,}/)[0]); return this.onReadMessage(t); }; } catch(e){}
        try { RealWebSocket.queue.overload('java.lang.String').implementation = function (t) { console.log("[WS][okhttp3] OUT: " + t.substring(0,500)); return this.queue(t); }; } catch(e){}
    } catch(e) { console.log("[WS] okhttp3 not found"); }
    try {
        var JWSClient = Java.use("org.java_websocket.client.WebSocketClient");
        console.log("[WS] Java-WebSocket found");
        try { JWSClient.send.overload('java.lang.String').implementation = function (t) { console.log("[WS][java-ws] SEND: " + t.substring(0,500)); return this.send(t); }; } catch(e){}
        try { JWSClient.onMessage.overload('java.lang.String').implementation = function (m) { console.log("[WS][java-ws] RECV: " + m.substring(0,500)); return this.onMessage(m); }; } catch(e){}
    } catch(e) {}
    try {
        var GrpcManagedChannel = Java.use("io.grpc.ManagedChannel");
        console.log("[WS][gRPC] gRPC found");
        try { GrpcManagedChannel.newCall.overload('io.grpc.MethodDescriptor','io.grpc.CallOptions').implementation = function(m,o){ console.log("[WS][gRPC] newCall: "+(m?m.getFullMethodName():"?")); return this.newCall(m,o); }; } catch(e){}
    } catch(e) {}
    try {
        var MethodDescriptor = Java.use("io.grpc.MethodDescriptor");
        MethodDescriptor.getFullMethodName.implementation = function(){ var n=this.getFullMethodName(); console.log("[WS][gRPC] Method: "+n); return n; };
    } catch(e) {}
    try {
        var RealEventSource = Java.use("okhttp3.internal.sse.RealEventSource");
        console.log("[WS][SSE] EventSource found");
        try { RealEventSource.onEvent.overload('java.lang.String','java.lang.String').implementation = function(id,d){ console.log("[WS][SSE] Event: "+(d?d.substring(0,500):"null")); return this.onEvent(id,d); }; } catch(e){}
    } catch(e) {}
    try {
        var SocketIO = Java.use("io.socket.client.Socket");
        console.log("[WS] Socket.IO found");
        try { SocketIO.emit.overload('java.lang.String','org.json.JSONArray').implementation = function(e,a){ console.log("[WS][socket.io] EMIT: "+e+" "+(a?a.toString().substring(0,200):"")); return this.emit(e,a); }; } catch(e2){}
    } catch(e) {}
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        try { OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(r){ var u=r&&r.url?r.url.toString():"?"; console.log("[WS][HTTP] "+u); return this.newCall(r); }; } catch(e){}
    } catch(e) {}
    console.log("[WS] All WebSocket/gRPC/SSE hooks installed.");
});
