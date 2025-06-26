#ifndef FIRMAS
#define FIRMAS

#include <string>
#include <iostream>


#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pem.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace std;
using namespace CryptoPP;


string rsa_sign(const string& mensaje, const string& pathClavePrivada) {
    // Cargar la clave privada desde el archivo
    RSA::PrivateKey clavePrivada;
    FileSource file(pathClavePrivada.c_str(), true);
    PEM_Load(file, clavePrivada);
    // Crear un objeto de firma
    RSASS<PSSR, SHA256>::Signer signer(clavePrivada);
    AutoSeededRandomPool rng;
    // La longitud de la firma depende de la clave
    size_t sigLen = signer.MaxSignatureLength();
    string firma(sigLen, '\0');
    sigLen = signer.SignMessage(rng, (const CryptoPP::byte*)mensaje.data(), mensaje.size(), (CryptoPP::byte*)&firma[0]);
    firma.resize(sigLen);
    return firma;
}

bool rsa_verify(const string& mensaje, const string& firma, const string& pathClavePublica) {
    // Cargar la clave pública desde el archivo
    RSA::PublicKey clavePublica;
    FileSource file(pathClavePublica.c_str(), true);
    PEM_Load(file, clavePublica);

    RSASS<PSSR, SHA256>::Verifier verifier(clavePublica);
    bool result = verifier.VerifyMessage((const CryptoPP::byte*)mensaje.data(), mensaje.size(),
                                         (const CryptoPP::byte*)firma.data(), firma.size());
    if(!result) throw runtime_error("Firma no válida");
    return true;
}


#endif // FIRMAS