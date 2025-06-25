#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pem.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/pssr.h>
using namespace std;
using namespace CryptoPP;

/*
    Esta función convierte un string binario a su representación hexadecimal.
    Utiliza HexEncoder para codificar el string binario.
*/
string binToHex(const string &bin) {
    string hex;
    StringSource(bin, true, new HexEncoder(new StringSink(hex)));
    return hex;
}

/*
    Esta función convierte un string hexadecimal a su representación binaria.
    Utiliza HexDecoder para decodificar el string hexadecimal.
*/
string hexToBin(const string &hex) {
    string bin;
    StringSource(hex, true, new HexDecoder(new StringSink(bin)));
    return bin;
}

// Función que recibe un mensaje y una ruta de clave pública o privada, y devuelve el mensaje cifrado en formato hexadecimal.
string rsa_encrypt(const string &mensaje, const string &path_clave, bool usePublicKey) {
    AutoSeededRandomPool rng;
    string cifrado;
    if (usePublicKey) {
        RSA::PublicKey pub_key;
        FileSource fs(path_clave.c_str(), true);
        CryptoPP::PEM_Load(fs, pub_key);
        RSAES_OAEP_SHA_Encryptor encriptador(pub_key); // Crear el encriptador RSA
        StringSource(mensaje, true, new PK_EncryptorFilter(rng, encriptador, new StringSink(cifrado))); // Cifrar el mensaje
        cout << "test asdf" << endl;
        return binToHex(cifrado); // Convertir el mensaje cifrado a formato hexadecimal
    } else { // Si usePublicKey es false, se asume que se está utilizando una clave privada
        RSA::PrivateKey priv_key;
        FileSource fs(path_clave.c_str(), true);
        CryptoPP::PEM_Load(fs, priv_key);
        RSAES_OAEP_SHA_Encryptor encriptador(priv_key); // Crear el encriptador RSA
        StringSource(mensaje, true, new PK_EncryptorFilter(rng, encriptador, new StringSink(cifrado))); // Cifrar el mensaje
        return binToHex(cifrado); // Convertir el mensaje cifrado a formato hexadecimal
    }
}

// ---------- Descifrado ----------
string rsa_decrypt(const string &cifradoHex, const string &path_clave, bool usePublicKey) {
    AutoSeededRandomPool rng;
    string cifrado = hexToBin(cifradoHex);
    string mensaje_recuperado;

    if (usePublicKey) { // Si usePublicKey es true, se asume que se está utilizando una clave pública
        RSA::PublicKey pub_key;
        FileSource fs(path_clave.c_str(), true);
        CryptoPP::PEM_Load(fs, pub_key);
        RSAES_OAEP_SHA_Decryptor decriptador(pub_key); // Crear el decriptador RSA
        StringSource(cifrado, true, new PK_DecryptorFilter(rng, decriptador, new StringSink(mensaje_recuperado))); // Descifrar el mensaje
    } else { // Si usePublicKey es false, se asume que se está utilizando una clave privada
        RSA::PrivateKey priv_key;
        FileSource fs(path_clave.c_str(), true);
        CryptoPP::PEM_Load(fs, priv_key);
        RSAES_OAEP_SHA_Decryptor decriptador(priv_key); // Crear el decriptador RSA
        StringSource(cifrado, true, new PK_DecryptorFilter(rng, decriptador, new StringSink(mensaje_recuperado))); // Descifrar el mensaje
    }

    return mensaje_recuperado; // Devolver el mensaje recuperado
}


#endif // RSA_UTILS_H
