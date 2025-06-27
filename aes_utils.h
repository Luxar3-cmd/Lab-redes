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

string binToHex(const string &bin);
string hexToBin(const string &hex);

// ---------- Funciones requeridas ----------
/*
    Cifra un texto plano utilizando AES-128 en modo CBC.
    Genera un IV aleatorio y devuelve el texto cifrado en formato hexadecimal.
    El IV se devuelve en formato hexadecimal a través del parámetro ivHexOut.
*/
string aes_encrypt(const string &mensaje,const SecByteBlock &clave,SecByteBlock& iv) {
    string cifrado;
    CBC_Mode<AES>::Encryption encriptador;
    encriptador.SetKeyWithIV(clave, clave.size(), iv); // Configura el cifrador con la clave y el IV
    StringSource(mensaje, true, new StreamTransformationFilter(encriptador, new StringSink(cifrado))); // Aquí se aplica el cifrado

    return binToHex(cifrado);
}
/*
    Esta función descifra un texto cifrado en formato hexadecimal utilizando AES-128 en modo CBC.
*/
string aes_decrypt( const string &cifradoHex,const SecByteBlock &clave,SecByteBlock& iv) {

    string cipher = hexToBin(cifradoHex);
    string recovered;

    CBC_Mode<AES>::Decryption decifrador;
    decifrador.SetKeyWithIV(clave, clave.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data()));
    StringSource(cipher, true, new StreamTransformationFilter(decifrador, new StringSink(recovered)));

    return recovered;
}


#endif // AES_UTILS_H


