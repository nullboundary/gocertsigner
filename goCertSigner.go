package goCertSigner

/*
#cgo !windows LDFLAGS: -lcrypto
#cgo windows LDFLAGS: /DEV/openssl-1.0.1e/libcrypto.a -lgdi32
#cgo windows CFLAGS: -I /DEV/openssl-1.0.1e/include

 #include <openssl/pem.h>
 #include <openssl/x509.h>
 #include <openssl/x509v3.h>
 #include <openssl/pkcs12.h>
 #include <openssl/pkcs7.h>
 #include <openssl/err.h>
 #include <openssl/safestack.h>
 #include <stdio.h>

typedef STACK_OF(X509) STACK;

static STACK_OF(X509)* X509NewNull() {
	return sk_X509_new_null();
}

static void X509Push(STACK_OF(X509) *ca,X509 *cert) {
	sk_X509_push(ca, cert);
}

static void X509PopFree(STACK_OF(X509) *ca) {
	sk_X509_pop_free(ca, X509_free);
}

*/
import "C"

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"unsafe"
)

type KeysAndCerts struct {
	Password string      //password for the p12 cert
	scert    *C.X509     //cert from the p12 developer cert
	skey     *C.EVP_PKEY //key from the p12 developer cert
	ca       *C.STACK    //stack of certificate authorities. CA from 2 sources, p12 & wwdr
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func init() {
	C.OpenSSL_add_all_ciphers()
	C.OpenSSL_add_all_digests()

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func free(kc *KeysAndCerts) {
	C.X509PopFree(kc.ca)
	C.X509_free(kc.scert)
	C.EVP_PKEY_free(kc.skey)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func FileToBytes(fileName string) []byte {

	//open file
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)

	return buf.Bytes()

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func BytesToFile(fileName string, outBytes []byte) {

	err := ioutil.WriteFile(fileName, outBytes, 0644)
	if err != nil {
		panic(err)
	}

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func parseP12(kc *KeysAndCerts, p12Bytes []byte) {

	var p12 *C.PKCS12
	kc.ca = C.X509NewNull()
	kc.scert = nil
	kc.skey = nil
	p12 = nil
	defer C.PKCS12_free(p12)

	p12BufLen := C.long(len(p12Bytes))
	p12Buf := ((*C.uchar)(unsafe.Pointer(&p12Bytes[0]))) //go []bytes to C * unsigned char

	if C.d2i_PKCS12(&p12, &p12Buf, p12BufLen) == nil {
		panic("p12 convert error")
	}

	pass := C.CString(kc.Password)
	defer C.free(unsafe.Pointer(pass))

	if C.PKCS12_parse(p12, pass, &kc.skey, &kc.scert, &kc.ca) == 0 { //parse pkcs12 into 3 files

		var cstr [256]C.char
		C.ERR_error_string(C.ERR_peek_error(), &cstr[0])
		errorStr := C.GoString(&cstr[0])
		panic(errorStr)
	}

	if kc.skey == nil {
		panic("skey == nil")
	}

	if kc.scert == nil {
		panic("scert == nil")
	}

	if kc.ca == nil {
		panic("ca == nil")
	}

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func addCA(kc *KeysAndCerts, ca []byte) {
	/* Read intermediate & CA root certificates */

	var caCert *C.X509
	caCert = nil
	defer C.X509_free(caCert)

	caBufLen := C.long(len(ca))
	caBuf := ((*C.uchar)(unsafe.Pointer(&ca[0]))) //bytes[] to * unsigned char

	if C.d2i_X509(&caCert, &caBuf, caBufLen) == nil {

		panic("add CA fail")
	}

	if caCert == nil {

		panic("caCert == nil")
	}

	//Add the intermediate CA certificate to the signing stack
	if kc.ca == nil {
		kc.ca = C.X509NewNull()
	}
	C.X509Push(kc.ca, caCert)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func signDoc(kc *KeysAndCerts, document []byte) []byte {

	flags := C.int(C.PKCS7_DETACHED | C.PKCS7_BINARY)

	documentBufLen := C.int(len(document))
	documentBuf := (unsafe.Pointer(&document[0])) //bytes[] to * unsigned char

	//load the data into a BIO buffer
	in := C.BIO_new_mem_buf(documentBuf, documentBufLen)
	defer C.BIO_free(in)
	if in == nil {
		panic("new openssl bio error")
	}

	//sign the data and create a pkcs7
	p7 := C.PKCS7_sign(kc.scert, kc.skey, kc.ca, in, flags)
	defer C.PKCS7_free(p7)
	if p7 == nil {
		panic("p7 sign error")
	}

	//output pkcs7 to []byte
	var buf (*C.uchar)
	defer C.free(unsafe.Pointer(buf))

	len := C.i2d_PKCS7(p7, &buf)
	if len == 0 {
		panic("i2d Pkcs7 error")
	}

	return C.GoBytes(unsafe.Pointer(buf), len)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func SignDocument(doc []byte, pkcs12 []byte, pkcsPass string, caCert []byte) (signature []byte, err error) {

	//recover from panics and return error messages
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("signer: %v", r)
			}
		}
	}()

	var kc KeysAndCerts
	defer free(&kc) //free the C allocated memory

	kc.Password = pkcsPass //set the password to open the encrypted pkcs12 cert

	parseP12(&kc, pkcs12)         //parse the p12 into various keys and certificates
	addCA(&kc, caCert)            //add the intermediate CA certificate
	return signDoc(&kc, doc), err //sign the document

}
