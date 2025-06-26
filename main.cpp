#include <iostream>
#include <string>

#include "rsa_utils.h"
#include "aes_utils.h"
#include "firmas.h"

using namespace std;
using namespace CryptoPP;

void HexToBytes( const string& hex, CryptoPP::byte* bytes) {
    StringSource(hex, true, new HexDecoder(new ArraySink(bytes, hex.size() / 2)));
}


/*
    Esta función convierte un array de bytes a su representación hexadecimal.
    Utiliza HexEncoder para codificar el array de bytes.
*/
string BytesToHex(const CryptoPP::byte* bytes, size_t len) {
    string encoded;
    ArraySource(bytes,len,true, new HexEncoder( new StringSink(encoded)));
    return encoded;
}

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

// Generar clave AES y IV aleatorios
void GenerateAESKeyAndIV(SecByteBlock & key, SecByteBlock& iv) {
    AutoSeededRandomPool prng;
    key.New(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    iv.New(CryptoPP::AES::BLOCKSIZE); 
    prng.GenerateBlock(iv, iv.size());
}



int main() {
    // Sección 1: Cifrado Simétrico con AES: Simulando un cifrado de un mensaje con AES-128 en modo CBC
    // Mensaje a cifrar
    cout << endl;
    cout << endl;
    cout << " ----------------------------- Cifrado Simétrico con AES -----------------------------" << endl;
    string mensaje = "La cámara descansa bajo el sauce llorón en el jardín del martillo.";
    cout << "Mensaje a cifrar: " << mensaje << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;

    // Clave de 16 bytes para AES-128
    CryptoPP::byte clave[CryptoPP::AES::DEFAULT_KEYLENGTH] = {
        0x67, 0x70, 0x81, 0x92, // Word 1
        0xA3, 0xB4, 0xC5, 0xD6, // Word 2
        0xE7, 0xF8, 0xA2,       // Word 3
        0x20, 0x22, 0x73, 0x10, 0x79 // Rol USM = 202273107-9
    };

    SecByteBlock claveAES(clave, sizeof(clave));
    // Generación de IV aleatorio
    SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, iv.size());

    string cifradoAES = aes_encrypt(mensaje, claveAES, iv); // Obtención del texto cifrado
    /*-----------------------------------------------------------------------------*/
    cout << "Texto cifrado (AES): " << cifradoAES << endl;
    cout << "ivHex (IV en formato hexadecimal): " << BytesToHex(iv,iv.size()) << endl;
    cout << " ------------------------- Ahora vamos a descifrar el texto cifrado con AES ------------------------- " << endl;
    string mensajeRecuperadoAES = aes_decrypt(cifradoAES, claveAES, iv); // Descifrado del texto cifrado
    cout << "Texto recuperado (AES): " << mensajeRecuperadoAES << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << endl;


    /*-----------------------------------------------------------------------------------------------------------------------*/

    // Cifrado Asimétrico con RSA: Simulando un cifrado de un mensaje con RSA
    cout << " ----------------------------- Cifrado Asimétrico con RSA -----------------------------" << endl;
    string mensajeSecreto = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido"; // Mensaje proveniente de la hermana Lyra
    cout << "Mensaje a cifrar: " << mensajeSecreto << endl;
    cout << "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" << endl;
    // Para que solamente el Gran Maestro pueda descifrar el mensaje, utilizaremos firmas digitales.
    


    // Emisor (Lyra) -> Receptor (Gran Maestro)
    cout << " --- Lado de la hermana Lyra (Remitente) ---" << endl;
    // 1. Generar clave AES y IV aleatorios
    SecByteBlock aesKey, aesIV;
    GenerateAESKeyAndIV(aesKey, aesIV); // Generación de clave AES (Cifrado Simétrico) y IV aleatorios
    cout << "Clave AES generada aleatoriamente (Hex): " << BytesToHex(aesKey,aesKey.size()) << endl;
    cout << "IV generado aleatoriamente (Hex): " << BytesToHex(aesIV, aesIV.size()) << endl;
    // 2. Cifrar el mensaje pesado con AES
    string MensajeCifradoAES = aes_encrypt(mensajeSecreto, aesKey, aesIV); // Cifrado del mensaje con AES (Cifrado Simétrico)
    cout << "Mensaje cifrado con AES (Hex): " << MensajeCifradoAES << endl;
    // 3. Cargar la clave pública del Gran Maestro
    string pathClavePublica = "Claves/gm_publica.pem";

    // 4. Cifrar (RSA) la clave AES y el IV
    string keyIvBin;
    // Concatenar clave AES y IV en un solo string binario
    keyIvBin.assign((char*)aesKey.BytePtr(), aesKey.SizeInBytes()); 
    keyIvBin.append((char*)aesIV.BytePtr(), aesIV.SizeInBytes());
    string claveCifradaRSA = rsa_encrypt(keyIvBin, pathClavePublica, true);
    cout << "Clave AES+IV cifrada (RSA hex): " << claveCifradaRSA << endl;

    // 5. Firmar el paquete AES-cipher + claveCifradaRSA con la privada de Lyra
    string pathLyraPriv = "Claves/lyra_privada.pem";
    string payload      = MensajeCifradoAES + claveCifradaRSA;   //  concat en hex
    string firmaBin     = rsa_sign(payload, pathLyraPriv);
    cout << "Firma generada (hex): " << binToHex(firmaBin) << endl;

    /* ---------- Receptor: Gran Maestro ---------- */
    cout << "\n--- Lado del Gran Maestro (Receptor) ---" << endl;

    // 1- Verificar firma con la pública de Lyra
    string pathLyraPub = "Claves/lyra_publica.pem";
    if(!rsa_verify(payload, firmaBin, pathLyraPub))
        throw runtime_error("Firma inválida");
    cout << "Resultado verificación de firma: VÁLIDA" << endl;

    // 2- Descifrar (RSA) clave AES+IV con la privada del Gran Maestro
    string pathGMPriv = "Claves/gm_privada.pem";
    string keyIvRec   = rsa_decrypt(claveCifradaRSA, pathGMPriv, /*usePublicKey=*/false);
    // Recuperar clave AES y IV del string binario
    SecByteBlock aesKeyRec((const CryptoPP::byte*)keyIvRec.data(), AES::DEFAULT_KEYLENGTH);
    SecByteBlock aesIVRec((const CryptoPP::byte*)keyIvRec.data()+AES::DEFAULT_KEYLENGTH, AES::BLOCKSIZE);

    // 3- Descifrar (AES) el mensaje
    string mensajeRec = aes_decrypt(MensajeCifradoAES, aesKeyRec, aesIVRec);
    cout << "Mensaje descifrado por el Gran Maestro: " << mensajeRec << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;

    return 0;
}
