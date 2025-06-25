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

    // Generar la firma
    AutoSeededRandomPool rng;
    string firma;
    StringSource(mensaje, true, new SignerFilter(rng, signer, new StringSink(firma)));

    return firma;
}

bool rsa_verify(const string& mensaje, const string& firma, const string& pathClavePublica) {
    // Cargar la clave pública desde el archivo
    RSA::PublicKey clavePublica;
    FileSource file(pathClavePublica.c_str(), true);
    PEM_Load(file, clavePublica);

    // Crear un objeto de verificación
    RSASS<PSSR, SHA256>::Verifier verifier(clavePublica);

    // Verificar la firma
    StringSource ss(firma + mensaje, true,
        new SignatureVerificationFilter(verifier, nullptr, SignatureVerificationFilter::THROW_EXCEPTION));

    return true; // Si no se lanza una excepción, la firma es válida
}


#endif // FIRMAS