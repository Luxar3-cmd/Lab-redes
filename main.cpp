#include <iostream>
#include <string>

#include "rsa_utils.h"
#include "aes_utils.h"

using namespace std;
using namespace CryptoPP;

int main() {
    // Cifrado Simétrico con AES

    // Mensaje a cifrar
    string mensaje = "La cámara descansa bajo el sauce llorón en el jardín del martillo.";
    // Clave de 16 bytes para AES-128
    CryptoPP::byte clave[CryptoPP::AES::DEFAULT_KEYLENGTH] = {
        0x67, 0x70, 0x81, 0x92, // Word 1
        0xA3, 0xB4, 0xC5, 0xD6, // Word 2
        0xE7, 0xF8, 0xA2,       // Word 3
        0x20, 0x22, 0x73, 0x10, 0x79 // Rol USM = 202273107-9
    };

    SecByteBlock claveAES(clave, sizeof(clave));

    // Variable para almacenar el IV en formato hexadecimal
    string ivHex;

    string cifradoAES = aes_encrypt(mensaje, claveAES, ivHex); // Obtención del texto cifrado
    /*-----------------------------------------------------------------------------*/
    cout << "Texto cifrado (AES): " << cifradoAES << endl;
    

}