"use strict";

var log = require("logg").getLogger("dtls.ServerHandshakeHandler");
var crypto = require("crypto");
var constants = require("constants");

var dtls = require("./dtls");
var HandshakeBuilder = require("./HandshakeBuilder");
var CipherInfo = require("./CipherInfo");
var prf = require("./prf");

var DtlsHandshake = require("./packets/DtlsHandshake");
var DtlsClientHello = require("./packets/DtlsClientHello");
var DtlsHelloVerifyRequest = require("./packets/DtlsHelloVerifyRequest");
var DtlsServerHello = require("./packets/DtlsServerHello");
var DtlsCertificate = require("./packets/DtlsCertificate");
var DtlsServerHelloDone = require("./packets/DtlsServerHelloDone");
var DtlsClientKeyExchange_rsa = require("./packets/DtlsClientKeyExchange_rsa");
var DtlsChangeCipherSpec = require("./packets/DtlsChangeCipherSpec");
var DtlsFinished = require("./packets/DtlsFinished");
var DtlsRandom = require("./packets/DtlsRandom");
var DtlsExtension = require("./packets/DtlsExtension");
const { pki } = require("node-forge");

/* Note the methods in this class aren't grouped with similar methods. Instead
 * the handle_ and send_ methods follow the logical order as defined in the
 * DTLS/TLS specs.
 */

/**
 * Implements the DTLS server handshake.
 */
var ServerHandshakeHandler = function(parameters, keyContext, rinfo) {
    this.parameters = parameters;
    this.keyContext = keyContext;
    this.rinfo = rinfo;

    this.handshakeBuilder = new HandshakeBuilder();

    // Handshake builder makes sure that the normal handling methods never
    // receive duplicate packets. Duplicate packets may mean that the last
    // flight of packets we sent got lost though so we need to handle these.
    this.handshakeBuilder.onRetransmission = this.retransmitLast.bind(this);
};

/**
 * Processes an incoming handshake message from the client.
 *
 * @param {DtlsPlaintext} message
 *      The TLS envelope containing the handshake message.
 */
ServerHandshakeHandler.prototype.process = function(message) {
    // Enqueue the current handshake.
    var newHandshake = new DtlsHandshake(message.fragment);
    var newHandshakeName = dtls.HandshakeTypeName[newHandshake.msgType];
    log.info(
        "Received handshake fragment; sequence:",
        newHandshake.messageSeq + ":" + newHandshakeName
    );
    this.handshakeBuilder.add(newHandshake);

    // Process available defragmented handshakes.
    var handshake = this.handshakeBuilder.next();
    while (handshake) {
        var handshakeName = dtls.HandshakeTypeName[handshake.msgType];

        var handler = this["handle_" + handshakeName];
        if (!handler) {
            log.error("Handshake handler not found for ", handshakeName);
            continue;
        }

        log.info(
            "Processing handshake:",
            handshake.messageSeq + ":" + handshakeName
        );
        var action = this["handle_" + handshakeName](handshake, message);

        // Digest this message after handling it.
        // This way the ClientHello can create the new SecurityParamters before
        // we digest this so it'll get digested in the correct context AND the
        // Finished message can verify its digest without counting itself in
        // it.
        //
        // TODO: Make sure 'message' contains the defragmented buffer.
        // We read the buffer in HandshakeBuilder anyway so there's no real
        // reason to call getBuffer() here.
        if (this.newParameters) {
            this.newParameters.digestHandshake(handshake.getBuffer());
        }

        // However to get the digests in correct order, the handle_ method
        // above couldn't have invoked the send_ methods as those take care of
        // digesting their own messages. So instead they returned the action
        // and we'll invoke them after the digest.
        if (action) action.call(this);

        handshake = this.handshakeBuilder.next();
    }
};

/**
 * Handles the ClientHello message.
 *
 * The message is accepted only if it contains the correct cookie. If the
 * cookie is wrong, we'll send a HelloVerifyRequest packet instead of
 * proceeding with the handshake.
 */
ServerHandshakeHandler.prototype.handle_clientHello = function(
    handshake,
    message
) {
    var clientHello = new DtlsClientHello(handshake.body);

    // TODO: If this is the very first handshake, the version of the initial
    // SecurityParameters hasn't been set. Set it to equal the current version.
    if (!this.parameters.first.version)
        this.parameters.first.version = clientHello.clientVersion;

    // Derive the cookie from the internal cookieSecret and client specific
    // information, including client address and information present in
    // the ClientHello message.
    //
    // The information used from ClientHello includes the cipher suites,
    // compression methods and extensions. Assuming extensions don't contain
    // random data, these fields should remain static between handshakes.
    //
    // (It might be worth it to exclude extensions from these though.. as
    // we can't guarantee that all extensions use static values in
    // ClientHello)
    //
    // The cookie is derived using the PRF of the clientHello.clientVersion
    // which means the clientVersion affects the cookie formation as well.
    if (!this.cookie) {
        this.cookie = prf(clientHello.clientVersion)(
            this.keyContext.cookieSecret,
            this.rinfo.address,
            handshake.body.slice(
                /* clientVersion */ 2 +
                    /* Random */ 32 +
                    /* sessionId */ clientHello.sessionId.length +
                    /* cookie */ clientHello.cookie.length
            ),
            16
        );
    }

    if (
        clientHello.cookie.length === 0 ||
        !clientHello.cookie.equals(this.cookie)
    ) {
        log.fine("ClientHello without cookie. Requesting verify.");

        var cookieVerify = new DtlsHelloVerifyRequest({
            serverVersion: clientHello.clientVersion,
            cookie: this.cookie
        });

        // Generate the Handshake message containing the HelloVerifyRequest
        // This message should be small enough to not require fragmentation.
        var handshakes = this.handshakeBuilder.createHandshakes(cookieVerify);

        // The server MUST use the record sequence number in the ClientHello
        // as the record sequence number in the HelloVerifyRequest.
        //  - RFC
        handshakes.__sequenceNumber = message.sequenceNumber;

        this.setResponse(handshakes);
    } else {
        log.fine(
            "ClientHello received. Client version:",
            ~clientHello.clientVersion.major +
                "." +
                ~clientHello.clientVersion.minor
        );

        // ClientHello is the first message of a new handshake. This is a good
        // place to create the new SecurityParamters that will be negotiated
        // with this handshake sequence.
        // TODO: Validate client version
        this.version = clientHello.clientVersion;

        this.newParameters = this.parameters.initNew(this.version);
        this.newParameters.clientRandom = clientHello.random.getBuffer();

        log.fine("Client ciphers");
        log.fine(clientHello.cipherSuites);

        // The handle_ methods should RETURN the response action.
        // See the handle() method for explanation.
        return this.send_serverHello;
    }
};

/**
 * Sends the ServerHello message
 */
ServerHandshakeHandler.prototype.send_serverHello = function() {
    // TLS spec require all implementations MUST implement the
    // TLS_RSA_WITH_AES_128_CBC_SHA cipher.
    var cipher = CipherInfo.TLS_RSA_WITH_AES_128_CBC_SHA;

    var serverHello = new DtlsServerHello({
        serverVersion: this.version,
        random: new DtlsRandom(),
        sessionId: new Buffer(0),
        cipherSuite: cipher.id,
        compressionMethod: 0,

        // TODO: Remove the requirement for extensions. Currently packets with
        // 0 extensions will serialize wrong. I don't even remember which
        // extension this is. Maybe heartbeat? Whatever it is, we definitely do
        // not implement it. :)
        extensions: [
            new DtlsExtension({
                extensionType: 0x000f,
                extensionData: new Buffer([1])
            })
        ]
    });

    log.info("Server cipher used:", cipher.id);

    // Store more parameters.
    this.newParameters.serverRandom = serverHello.random.getBuffer();
    this.newParameters.setFrom(cipher);

    var certificate = new DtlsCertificate({
        certificateList: [this.keyContext.certificate]
    });

    var helloDone = new DtlsServerHelloDone();

    log.info("Sending ServerHello, Certificate, HelloDone");
    var handshakes = this.handshakeBuilder.createHandshakes([
        serverHello,
        certificate,
        helloDone
    ]);

    handshakes = handshakes.map(function(h) {
        return h.getBuffer();
    });
    this.newParameters.digestHandshake(handshakes);

    var packets = this.handshakeBuilder.fragmentHandshakes(handshakes);

    this.setResponse(packets);
};

/**
 * Handles the ClientKeyExchange message.
 */
ServerHandshakeHandler.prototype.handle_clientKeyExchange = function(
    handshake
) {
    var clientKeyExchange = new DtlsClientKeyExchange_rsa(handshake.body);

    // TODO: if this fails, create random preMasterKey to guard against chosen
    // ciphertext/PKCS#1 attack.
    const privKey = pki.privateKeyFromPem(`-----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3dz3nvtn/RGWU
    cRcucfUk7qSm2Zlb2v1mtrrLLu4A5GVuNeG8ZObBNnsEXnoZNfJV/rmIPEndktH9
    nhKokwhVhDFm9DLhO+iDpRyzhFUUppfP0EXSq6CcEXWUQUas6HEoC7o0B80Cmtb0
    I7pQy0LsKDg3mQ/BuYg4QBl64/3KTB4plshf7SrDGqDr3t0PgcE7XIME6x3F1IBJ
    om5Fv1bc30xXhqjYm5/rBaSxK0NeGO/lYcwCEG63VnJeQRVB5ivYfpAYsasM5uGN
    R3+D8kvOs0+oG2GB+Q0qnhYupW2rBFlj3c9VglkOBN05tnvOA5xqEI1Mkj8ADHBc
    nMOYuIO5AgMBAAECggEAXMJGI1iEQaLkNPQkw0/MoRqjVtSnzCBhhEAZG0ekAAF6
    IwnNEwJ1BPU1p1TZKMv0tXPvfCj3M7bawv7b8i08xnfqvmHzI5u1iHG/nCfpGGLO
    WLy1wLkToDTXnNiQEjYHmDats0bKaWm+CnvR5K2QLXR8T+fsZocWj1IhT9fb5h5P
    7ktmL3uKvOglkVxeGs3Lt06H1P4n0XJZJOoe0ioT6QPx7Xgvq8HSIwwsUn64D2zK
    NLUbDFx8FKSS0ustLhylanq58Bc278hwI2IZQKKl+hUr3ZssX+uVSfnVZ/gxWDTg
    SUjti5r4DFs2fInUhRaHQYzB6N3tnYjflirWskQFcQKBgQDuhURTtzJAM5I3iRDc
    6oKAZRVoRNQy+L2mfXXij/CxaOy7l5BUzyInaV2AZ7tQUIa3NH7Nbpew5G3yqmy4
    LhvdXryUg4cHIuPGBCZJuYc9jphIrXAXJdH7Xn0xT0zBmjUQQK6j/AHdmodcfclA
    Y/4DAa89uI4kzGad7MfRAXim1QKBgQDE6SCE4Hem+mg2wPYqDnwAH55UYc1ITct+
    rOmmC7p/E8qNljPVaKeWffIpUaxBCa+pBdDdDKoxJ/lKnwn5K6ozeO4SVkqcMiWI
    +65L/0ewbaYmMZ2rc5X3aqYkEI5hcfZKUXoDGdX+9cdrHmZCSnf4yr1E/xtggSag
    4dU8CnIjVQKBgF1UsEPBr1wH0fMBIyQObzomU5YVOKMpSaxX80TP5fLFh7xvtf45
    frfFNt0DufvXRp9xXxyrZZfGCm+l2BzJjgW1CD1kqfVU5aOaBBFdE1o27ceidfXY
    yq19b6dXzEUFPjY52Rw5g9FeohDC93jGp6ItipCwIo6rnIu3FwjldnxxAoGBAMFt
    qI4e2iri7KBsqOPjWpfcd3G4qSkPkoibXuHHv6m5TU4McFqA9a91hP5lxmoVE8Nb
    fTLHkB+9frt4wxlLdWQetO66aYxKDmkjorHw0QFUlNQMBTA42OY0k4P154d9pUyY
    AN0u8fIEiaKGODmCYZu5vHccik4gUEvVy9uw/zIJAoGAZVS6FTwSSljweyG25amH
    +AXFJ9BN2TwffwJiotwnKkw5HlibgvwWPcIhXFga6DBnmde5lMJfB64mg56ndKnv
    EKvW676x4lCHOGlWtNXpLym0HPm6qKkwW+3xSY/yqbLfUC1/iQaEDYXdcpcbQP1z
    YI48pPDuxoMiqJDcd6qDdQM=
    -----END PRIVATE KEY-----`);

    var preMasterSecret = crypto.privateDecrypt(
        {
            key: pki.privateKeyToPem(privKey),
            padding: constants.RSA_PKCS1_PADDING
        },
        clientKeyExchange.exchangeKeys
    );

    this.newParameters.calculateMasterKey(preMasterSecret);

    // Do nothing here. We're still waiting for the Finished message.
    //
    // Set the response to null though as we know the client got the last
    // flight.
    this.setResponse(null);
};

/**
 * Handles the client Finished message.
 *
 * Technically there is a ChangeCipherSpec message between ClientKeyExchange
 * and Finished messages. ChangeCipherSpec isn't a handshake message though so
 * it never makes it here. That message is handled in the RecordLayer.
 */
ServerHandshakeHandler.prototype.handle_finished = function(
    handshake,
    message
) {
    var finished = new DtlsFinished(handshake.body);

    var prf_func = prf(this.version);

    var expected = prf_func(
        this.newParameters.masterKey,
        "client finished",
        this.newParameters.getHandshakeDigest(),
        finished.verifyData.length
    );

    if (!finished.verifyData.equals(expected)) {
        log.warn(
            "Finished digest does not match. Expected:",
            expected,
            "Actual:",
            finished.verifyData
        );
        return;
    }

    // The handle_ methods should RETURN the response action.
    // See the handle() method for explanation.
    return this.send_serverFinished;
};

ServerHandshakeHandler.prototype.send_serverFinished = function() {
    var changeCipherSpec = new DtlsChangeCipherSpec({ value: 1 });

    var prf_func = prf(this.version);

    var finished = new DtlsFinished({
        verifyData: prf_func(
            this.newParameters.masterKey,
            "server finished",
            this.newParameters.getHandshakeDigest(),
            12
        )
    });

    var handshakes = this.handshakeBuilder.createHandshakes([finished]);
    handshakes = this.handshakeBuilder.fragmentHandshakes(handshakes);
    handshakes.unshift(changeCipherSpec);

    log.info("Verify data:", finished.verifyData);
    log.info("Sending ChangeCipherSpec, Finished");

    var messages = this.setResponse(handshakes, this.onHandshake);
};

/**
 * Sets the response for the last client message.
 *
 * The last flight of packets is stored so we can somewhat automatically handle
 * retransmission when we see the client doing it.
 */
ServerHandshakeHandler.prototype.setResponse = function(packets, done) {
    this.lastFlight = packets;

    if (packets) this.onSend(packets, done);
};

/**
 * Retransmits the last response in case it got lost on the way last time.
 *
 * @param {DtlsPlaintext} message
 *      The received packet that triggered this retransmit.
 */
ServerHandshakeHandler.prototype.retransmitLast = function(message) {
    if (this.lastFlight) this.onSend(this.lastFlight);
};

module.exports = ServerHandshakeHandler;
