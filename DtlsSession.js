
"use strict";

var log = require( 'logg' ).getLogger( 'dtls.DtlsSession' );
var crypto = require( 'crypto' );
var constants = require( 'constants' );

var dtls = require( './dtls' );
var prf = require( './prf' );
var SecurityParameterContainer = require( './SecurityParameterContainer' );
var DtlsRecordLayer = require( './DtlsRecordLayer' );
var HandshakeBuilder = require( './HandshakeBuilder' );
var CipherInfo = require( './CipherInfo' );

var DtlsHandshake = require( './packets/DtlsHandshake' );

var DtlsClientHello = require( './packets/DtlsClientHello' );
var DtlsHelloVerifyRequest = require( './packets/DtlsHelloVerifyRequest' );
var DtlsServerHello = require( './packets/DtlsServerHello' );
var DtlsCertificate = require( './packets/DtlsCertificate' );
var DtlsServerHelloDone = require( './packets/DtlsServerHelloDone' );
var DtlsClientKeyExchange_rsa = require( './packets/DtlsClientKeyExchange_rsa' );
var DtlsPreMasterSecret = require( './packets/DtlsPreMasterSecret' );
var DtlsChangeCipherSpec = require( './packets/DtlsChangeCipherSpec' );
var DtlsFinished = require( './packets/DtlsFinished' );

var DtlsExtension = require( './packets/DtlsExtension' );
var DtlsProtocolVersion = require( './packets/DtlsProtocolVersion' );
var DtlsRandom = require( './packets/DtlsRandom' );

var SessionState = {
    uninitialized: 0,
    sendHello: 1,
    handshakeDone: 2,
};

var DtlsSession = function( dgram, rinfo, keyContext ) {
    log.info( 'New session' );

    this.dgram = dgram;
    this.rinfo = rinfo;
    this.keyContext = keyContext;

    this.parameters = new SecurityParameterContainer();
    this.state = SessionState.uninitialized;
    this.recordLayer = new DtlsRecordLayer( dgram, rinfo, this.parameters );

    this.handshakeBuilder = new HandshakeBuilder();
    this.handshakeMessages = [];

    this.sequence = 0;
    this.messageSeq = 0;
};

DtlsSession.prototype.handle = function( buffer ) {
    var self = this;

    log.fine( 'Incoming packet; length:', buffer.length );
    this.recordLayer.getPackets( buffer, function( packet ) {

        var msgType = dtls.MessageTypeName[ packet.type ];
        var handler = self[ 'process_' + msgType ];

        if( !handler )
            return log.error( 'Handler not found for', msgType, 'message' );

        handler.call( self, packet );
    });
};

DtlsSession.prototype.changeState = function( state ) {

    log.info( 'DTLS session state changed to', state );
    this.state = state;

    if( this.invokeAction( this.state ) ) {
        // TODO: Launch timer.
    }
};

DtlsSession.prototype.process_handshake = function( message ) {
    this.handshakeMessages.push( message.fragment );

    // Enqueue the current handshake.
    var newHandshake = new DtlsHandshake( message.fragment );
    var newHandshakeName = dtls.HandshakeTypeName[ newHandshake.msgType ];
    log.info( 'Received handshake fragment; sequence:',
        newHandshake.messageSeq + ':' + newHandshakeName );
    this.handshakeBuilder.add( newHandshake );

    // Process available defragmented handshakes.
    var handshake = this.handshakeBuilder.next();
    while( handshake ) {
        var handshakeName = dtls.HandshakeTypeName[ handshake.msgType ];

        var handler = this[ 'process_handshake_' + handshakeName ];
        if( handler ) {
            log.info( 'Processing handshake:',
                handshake.messageSeq + ':' + handshakeName );
            this[ 'process_handshake_' + handshakeName ]( handshake );
        } else {
            log.error( 'Handshake handler not found for ' + handshakeName + ' message' );
        }

        handshake = this.handshakeBuilder.next();
    }
};

DtlsSession.prototype.process_handshake_clientHello = function( handshake ) {

    var clientHello = new DtlsClientHello( handshake.body );

    if( clientHello.cookie.length === 0 ) {

        this.cookie = crypto.pseudoRandomBytes( 16 );
        var cookieVerify = new DtlsHelloVerifyRequest({
            serverVersion: clientHello.clientVersion,
            cookie: this.cookie
        });

        var handshakes = this.handshakeBuilder.createHandshakes( cookieVerify );

        log.fine( 'ClientHello without cookie. Requesting verify.' );
        this.recordLayer.send( handshakes );

    } else {
        log.fine( 'ClientHello received. Client version:', ~clientHello.clientVersion.major + '.' + ~clientHello.clientVersion.minor );
        this.parameters.pending.clientRandom = clientHello.random.getBytes();
        this.parameters.pending.version = clientHello.clientVersion;
        this.changeState( SessionState.sendHello );
    }
};

DtlsSession.prototype.process_handshake_clientKeyExchange = function( handshake ) {

    var clientKeyExchange = new DtlsClientKeyExchange_rsa( handshake.body );

    var preMasterSecret = crypto.privateDecrypt({
            key: this.keyContext.key,
            padding: constants.RSA_PKCS1_PADDING
        }, clientKeyExchange.exchangeKeys );

    //preMasterSecret = new DtlsPreMasterSecret( preMasterSecret );

    this.parameters.pending.preMasterKey = preMasterSecret;
    this.parameters.pending.masterKey = prf( this.parameters.pending.version )(
        preMasterSecret,
        "master secret", 
        Buffer.concat([
            this.parameters.pending.clientRandom,
            this.parameters.pending.serverRandom ]), 48 );

    //this.changeState( SessionState.handshakeDone );
};

DtlsSession.prototype.invokeAction = function( state ) {

    if( !this.actions[ state ] )
        return false;

    this.actions[ state ].call( this );
};

DtlsSession.prototype.actions = {};
DtlsSession.prototype.actions[ SessionState.sendHello ] = function() {

    var cipher = CipherInfo.TLS_RSA_WITH_AES_128_CBC_SHA;

    var serverHello = new DtlsServerHello({
        serverVersion: this.parameters.pending.version,
        random: new DtlsRandom(),
        sessionId: new Buffer(0),
        cipherSuite: cipher.id,
        compressionMethod: 0,
        extensions: [
            new DtlsExtension({
                extensionType: 0x000f,
                extensionData: new Buffer([ 1 ])
            })
        ]
    });

    this.parameters.pending.serverRandom = serverHello.random.getBytes();
    this.parameters.pending.setFrom( cipher );

    var certificate = new DtlsCertificate({
        certificateList: [ this.keyContext.certificate ]
    });

    var helloDone = new DtlsServerHelloDone();

    log.info( 'Sending ServerHello, Certificate, HelloDone' );
    var handshakes = this.handshakeBuilder.createHandshakes([
        serverHello,
        certificate,
        helloDone
    ]);
    this.recordLayer.send( handshakes );

};

DtlsSession.prototype.actions[ SessionState.handshakeDone ] = function() {

    var changeCipherSpec = new DtlsChangeCipherSpec({ value: 1 });
    var handshakes = this.handshakeBuilder.createHandshakes([
        new DtlsFinished({
            verifyData: prf( this.parameters.pending.version )(
                this.parameters.pending.masterKey,
                "server finished",
                Buffer.concat( this.handshakeMessages )
            )
        })
    ]);

    handshakes.unshift( changeCipherSpec );

    log.info( 'Sending ChangeCipherSpec, Finished' );
    this.recordLayer.send( handshakes );
};

module.exports = DtlsSession;