"use strict";

var dtls = require("../");

dtls.setLogLevel(dtls.logLevel.FINE);

var client = dtls.connect(4433, "localhost", "udp4", function () {
    client.send(new Buffer("foo\n"));
});

client.on("message", function (msg) {
    console.log("Received application data");
    console.log(msg);
});
