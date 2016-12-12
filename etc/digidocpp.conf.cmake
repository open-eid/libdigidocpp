<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="schema/conf.xsd">
    <!--Logging settings-->
    <!--<param name="log.level" lock="false">2</param>-->
    <!--<param name="log.file" lock="false">/tmp/digidocpp.log</param>-->
    <!--<param name="log.file" lock="false">C:\Documents and Settings\All Users\Documents\digidocpp.log</param>-->

    <!--Digest algorithm settings-->
    <!--<param name="signer.digestUri" lock="false">http://www.w3.org/2001/04/xmlenc#sha256</param>-->
    <!--<param name="signer.signatureDigestUri" lock="false">http://www.w3.org/2001/04/xmlenc#sha256</param>-->

    <!--PKCS#11 driver’s location, if not using default driver-->
    <!--<param name="pkcs11.driver.path" lock="false">@PKCS11_MODULE@</param>-->

    <!--HTTP proxy settings, if needed-->
    <!--<param name="proxy.forceSSL" lock="false">false</param>-->
    <!--<param name="proxy.tunnelSSL" lock="false">true</param>-->
    <!--<param name="proxy.host" lock="false"></param>-->
    <!--<param name="proxy.port" lock="false"></param>-->
    <!--<param name="proxy.user" lock="false"></param>-->
    <!--<param name="proxy.pass" lock="false"></param>-->

    <!--OCSP request signing options-->
    <!--<param name="pkcs12.cert" lock="false"></param>-->
    <!--<param name="pkcs12.pass" lock="false"></param>-->
    <!--<param name="pkcs12.disable" lock="false">false</param>-->

    <!--Time-stamping service settings-->
    <!--<param name="ts.url" lock="false">@TSA_URL@</param>-->

    <!--TSL settings-->
    <!--<param name="tsl.autoupdate" lock="false">true</param>-->
    <!--<param name="tsl.cache" lock="false"></param>-->
    <!--<param name="tsl.onlineDigest" lock="false">true</param>-->
    <!--<param name="tsl.timeOut" lock="false">10</param>-->

    <!--Verify service settings-->
    <!--<param name="verify.serivceUri" lock="false">@PDF_URL@</param>-->

    <!-- OCSP responder url. Used for validating signing certificates and generating BDoc-TM signatures-->
    <!--<ocsp issuer="ESTEID-SK 2007">http://ocsp.sk.ee</ocsp>-->
    <!--<ocsp issuer="ESTEID-SK 2011">http://ocsp.sk.ee</ocsp>-->
    <!--<ocsp issuer="ESTEID-SK 2015">http://ocsp.sk.ee</ocsp>-->
    <!--<ocsp issuer="EID-SK 2011">http://ocsp.sk.ee</ocsp>-->
    <!--<ocsp issuer="EID-SK 2016">http://ocsp.sk.ee</ocsp>-->
    <!--<ocsp issuer="KLASS3-SK 2010">http://ocsp.sk.ee</ocsp>-->

    <!--OCSP responder settings for test OCSP service-->
    <!--<ocsp issuer="TEST of ESTEID-SK 2011">http://demo.sk.ee/ocsp</ocsp>-->
    <!--<ocsp issuer="TEST of ESTEID-SK 2015">http://demo.sk.ee/ocsp</ocsp>-->
    <!--<ocsp issuer="TEST of KLASS3-SK 2010">http://demo.sk.ee/ocsp</ocsp>-->
    <!--<ocsp issuer="TEST of EID-SK 2011">http://demo.sk.ee/ocsp</ocsp>-->
    <!--<ocsp issuer="TEST of EID-SK 2016">http://demo.sk.ee/ocsp</ocsp>-->
</configuration>
