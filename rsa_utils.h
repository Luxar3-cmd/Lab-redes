#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pem.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

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

/*
    Estructura para almacenar el resultado de las operaciones RSA.
    Contiene el texto cifrado en formato hexadecimal y el mensaje recuperado.
*/
struct RSAResult {
    string cifradoHex;
    string mensajeRecuperado;
};


string rsa_encrypt_helper( const string &mensaje,const PublicKey &clave_publica) {

    AutoSeededRandomPool rng;
    string cifrado;
    RSAES_OAEP_SHA_Encryptor enc(clave_publica); //
    StringSource(mensaje, true,new PK_EncryptorFilter(rng, enc,new StringSink(cifrado)));
    return binToHex(cifrado);
}

string rsa_encrypt(const string &mensaje,const string &path_clave_publica) {
    RSA::PublicKey pub_key;
    FileSource fs(path_clave_publica.c_str(), true);
    CryptoPP::PEM_Load(fs, pub_key); // Cargar clave pública desde archivo PEM
    return rsa_encrypt_helper(mensaje, pub_key);
}

// ---------- Descifrado ----------
string rsa_decrypt_helper(const string &cifradoHex,const PrivateKey &clave_privada) {
    AutoSeededRandomPool rng;
    string cipher = hexToBin(cifradoHex); // Convertir de HEX a binario
    string mensaje_recuperado; // Variable para almacenar el mensaje recuperado
    RSAES_OAEP_SHA_Decryptor decifrador(clave_privada); // Crear el descifrador RSA
    StringSource(cipher, true,new PK_DecryptorFilter(rng, decifrador,new StringSink(mensaje_recuperado))); // Descifrar el mensaje
    return mensaje_recuperado;
}

string rsa_decrypt(const string &cipherHex,const string &privPemPath) {
    RSA::PrivateKey priv_key; // Declarar clave privada
    FileSource fs(privPemPath.c_str(), true); // Cargar clave privada desde archivo PEM
    CryptoPP::PEM_Load(fs, priv_key);
    return rsa_decrypt_helper(cipherHex, priv_key);
}


#endif // RSA_UTILS_H
