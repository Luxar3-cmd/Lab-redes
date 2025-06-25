#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>

#include <cryptopp/aes.h> // Para AES
#include <cryptopp/modes.h> // Para modos de operación (CBC)
#include <cryptopp/filters.h> // Para StreamTransformationFilter, HexEncoder/Decoder
#include <cryptopp/osrng.h> // Para AutoSeededRandomPool (generación de IV y claves aleatorias)
#include <cryptopp/rsa.h> // Para RSA
#include <cryptopp/sha.h> // Para SHA256 (hashing para RSA)
#include <cryptopp/hex.h> // Para HexEncoder/Decoder
#include <cryptopp/files.h> // Para FileSource, FileSink (manejo de archivos)
#include <cryptopp/cryptlib.h>
#include <cryptopp/pem.h>

// Definiciones para evitar escribir CryptoPP:: constantemente
using namespace CryptoPP;
using namespace std;
#include <string>

void cifradoAES() {
    // Mensaje original
    string mensaje = "La camara descansa bajo el sauce lloron en el jardin del martillo.";
    
    // Clave acordada (16 bytes = 128 bits), incluyendo el ROL: 6F708192 A3B4C5D6 E7F8A2 + ROLUSM
    // ROL: 202273107-9 
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH] = {
        0x6F, 0x70, 0x81, 0x92, 
        0xA3, 0xB4, 0xC5, 0xD6,
        0xE7, 0xF8, 0xA2, 
        0x20, 0x22, 0x73, 0x10, 0x79 // último bloque es ROLUSM → en hex
    };

    // Vector de inicialización aleatorio (IV)
    AutoSeededRandomPool prng;
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string cifrado, descifrado;

    // Cifrado AES CBC
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);

    StringSource ss1(mensaje, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(cifrado)
        )
    );

    // Descifrado
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv);

    StringSource ss2(cifrado, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(descifrado)
        )
    );

    // Imprimir resultados
    cout << "Mensaje Original: " << mensaje << endl;
    cout << "Mensaje Cifrado (hex): ";
    StringSource(cifrado, true, new HexEncoder(new FileSink(cout)));
    cout << "\nMensaje Descifrado: " << descifrado << endl;
}

void cifradoRSA() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Cargar clave pública del Gran Maestro
    RSA::PublicKey publicKey;
    FileSource fs("gm_publica.pem", true);
    PEM_Load(fs, publicKey);

    // Mensaje a cifrar
    string mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido.";
    string cifrado;

    // Cifrar
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    StringSource ss1(mensaje, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(cifrado)
        )
    );

    cout << "Mensaje Cifrado (hex): ";
    StringSource(cifrado, true, new HexEncoder(new FileSink(cout)));
    cout << endl;
}

void canalSeguro() {
    // Lyra genera una clave AES aleatoria
    AutoSeededRandomPool rng;
    SecByteBlock claveAES(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(claveAES, claveAES.size());

    // Cifrar mensaje con AES
    string mensaje = "¡Este es un canal seguro, Maestro!";
    CryptoPP::byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));
    string cifrado;

    CBC_Mode<AES>::Encryption aesEncryptor;
    aesEncryptor.SetKeyWithIV(claveAES, claveAES.size(), iv);

    StringSource ss(mensaje, true,
        new StreamTransformationFilter(aesEncryptor,
            new StringSink(cifrado)
        )
    );

    // Cargar clave pública del Gran Maestro
    RSA::PublicKey publicKey;
    FileSource fs("gm_publica.pem", true);
    PEM_Load(fs, publicKey);

    // Cifrar clave AES con RSA
    string claveCifrada;
    RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
    StringSource ss2(claveAES, claveAES.size(), true,
        new PK_EncryptorFilter(rng, rsaEncryptor,
            new StringSink(claveCifrada)
        )
    );

    // Mostrar resultados
    cout << "Mensaje cifrado (AES): ";
    StringSource(cifrado, true, new HexEncoder(new FileSink(cout)));
    cout << "\nClave AES cifrada (RSA): ";
    StringSource(claveCifrada, true, new HexEncoder(new FileSink(cout)));
    cout << endl;
}


int main() {
    // Llamar a la función de cifrado AES
    cifradoAES();
    cifradoRSA();
    canalSeguro();

    // Aquí podrías agregar más funciones para RSA, etc.
    // Por ejemplo, podrías llamar a una función de cifrado RSA aquí.

    return 0;
}