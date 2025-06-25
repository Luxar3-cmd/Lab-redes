#ifndef AES_UTILS_H
#define AES_UTILS_H

#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
using namespace std;




/*
    Estructura para almacenar el resultado de las operaciones AES.
    Contiene el texto cifrado en formato hexadecimal, el texto plano recuperado y el IV utilizado.
*/
struct AESResult {
    string cipherHex;
    string plain;
    string ivHex;
};

// ---------- Funciones requeridas ----------
/*
    Cifra un texto plano utilizando AES-128 en modo CBC.
    Genera un IV aleatorio y devuelve el texto cifrado en formato hexadecimal.
    El IV se devuelve en formato hexadecimal a través del parámetro ivHexOut.
*/
string aes_encrypt(const string &mensaje,const SecByteBlock &clave,string &ivHexOut) {
    AutoSeededRandomPool prng;
    CryptoPP::byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string cifrado;
    CBC_Mode<AES>::Encryption encriptador;
    encriptador.SetKeyWithIV(clave, clave.size(), iv); // Configura el cifrador con la clave y el IV
    StringSource(mensaje, true, new StreamTransformationFilter(encriptador, new StringSink(cifrado))); // Aquí se aplica el cifrado

    ivHexOut = binToHex(string(reinterpret_cast<char*>(iv), AES::BLOCKSIZE)); // Esta linea convierte el IV a HEX
    return binToHex(cifrado);
}
/*
    Esta función descifra un texto cifrado en formato hexadecimal utilizando AES-128 en modo CBC.
*/
string aes_decrypt( const string &cifradoHex,const SecByteBlock &clave,const string &ivHex) {

    string cipher = hexToBin(cifradoHex);
    string iv = hexToBin(ivHex);
    string recovered;

    CBC_Mode<AES>::Decryption decifrador;
    decifrador.SetKeyWithIV(clave, clave.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data()));
    StringSource(cipher, true, new StreamTransformationFilter(decifrador, new StringSink(recovered)));

    return recovered;
}

// Función combinada (encrypt + decrypt) para uso rápido en pruebas
AESResult aesEncryptDecrypt( const string &mensaje,const CryptoPP::byte *clave, size_t claveLen) {
    SecByteBlock key(clave, claveLen);
    string ivHex;
    string cipherHex = aes_encrypt(mensaje, key, ivHex);
    string plain = aes_decrypt(cipherHex, key, ivHex);
    return {cipherHex, plain, ivHex};
}

#endif // AES_UTILS_H


