#include <iostream>
#include <string>

#include <cryptopp/oaep.h>
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

    /*-----------------------------------------------------------------------------------------------------------------------*/

    // Sección 1: Cifrado Simétrico con AES: Simulando un cifrado de un mensaje con AES-128 en modo CBC
    // Mensaje a cifrar
    cout << endl;
    cout << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << " ----------------------------- Cifrado Simétrico con AES -----------------------------" << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << endl;
    cout << endl;

    string mensaje = "La cámara descansa bajo el sauce llorón en el jardín del martillo.";
    cout << "Mensaje a cifrar: " << mensaje << endl;
    cout << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << endl;

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
    cout << endl;
    cout << "ivHex (IV en formato hexadecimal): " << BytesToHex(iv,iv.size()) << endl;

    cout << "-----------------------------------------------------------------------------------------------------" << endl;
    cout << "-------------------------- Ahora vamos a descifrar el texto cifrado con AES -------------------------" << endl;
    cout << "-----------------------------------------------------------------------------------------------------" << endl;
    cout << endl;
    cout << endl;
    string mensajeRecuperadoAES = aes_decrypt(cifradoAES, claveAES, iv); // Descifrado del texto cifrado
    cout << "Texto recuperado (AES): " << mensajeRecuperadoAES << endl;
    cout << endl;
    cout << endl;
    cout << "-----------------------------------------------------------------------------------------------------" << endl;
    cout << "-                                            Fin demostración AES                                   -" << endl;
    cout << "-----------------------------------------------------------------------------------------------------" << endl;
    cout << endl;
    cout << endl;

    /*-----------------------------------------------------------------------------------------------------------------------*/

    // Sección 2: Cifrado Asimétrico con RSA: Simulando un cifrado de un mensaje con RSA


    /*
        NOTA: En vez de utilizar claves en formato PEM, se utilizarán archivos DER para las claves públicas y privadas. Al parecer 
        son mas ligeras y permiten cifrar sin problemas.

        Por poblemas sobre el largo de las claves, se simula que tango la firma como el mensaje se envían por separado.
    */
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << " ----------------------------- Cifrado Asimétrico con RSA -----------------------------" << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;

    
    cout << endl;
    mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido.";
    cout << " Mensaje a cifrar: " << mensaje << endl;
    cout << endl;
    
    string firma; 
    string mensajeCifrado;

    // Cargar clave privada lyra para firmar
    RSA::PrivateKey clavePrivadaLyra; // Clave privada de Lyra
    FileSource filePriv("Claves/lyra_privada.der", true); // Cargar clave privada de Lyra desde archivo DER
    clavePrivadaLyra.BERDecode(filePriv);

    // Firmar el mensaje

    RSASS<PSS, SHA256>::Signer firmanteLyra(clavePrivadaLyra); // Crear el firmante RSA
    StringSource(mensaje, true,
        new SignerFilter(prng, firmanteLyra,
            new StringSink(firma) // Firmar el mensaje
        )
    );

    cout << "Firma generada (hex)" << binToHex(firma) << endl;
    cout << endl;
    // Cargar clave pública del Gran Maestro para cifrar
    RSA::PublicKey clavePublicaGM; // Clave pública del Gran Maestro
    FileSource filePub("Claves/gm_publica.der", true); 
    clavePublicaGM.BERDecode(filePub); // Cargar clave pública del Gran Maestro desde archivo DER

    // Cifrar el mensaje con la clave pública del Gran Maestro
    RSAES_OAEP_SHA_Encryptor cifrador(clavePublicaGM);
    StringSource(mensaje,true, 
        new PK_EncryptorFilter(prng, cifrador, 
            new StringSink(mensajeCifrado) // Cifrar el mensaje
        )
    );
    cout << "Mensaje cifrado (RSA): " << binToHex(mensajeCifrado) << endl;
    cout << endl;

    cout << " --- Simulación Recepción ---" << endl;

    // Cargar clave privada del Gran Maestro para descifrar
    RSA::PrivateKey clavePrivadaGM; // Clave privada del Gran Maestro
    FileSource filePrivGM("Claves/gm_privada.der", true); // Cargar clave privada del Gran Maestro desde archivo DER
    clavePrivadaGM.BERDecode(filePrivGM);

    // Descifrar el mensaje
    string mensajeDescifrado; 
    RSAES_OAEP_SHA_Decryptor descifrador(clavePrivadaGM); // Crear el descifrador RSA
    StringSource(mensajeCifrado, true,
        new PK_DecryptorFilter(prng, descifrador,
            new StringSink(mensajeDescifrado) // Descifrar el mensaje
        )
    );
    cout << endl;
    cout << "Mensaje descifrado (RSA): " << mensajeDescifrado << endl;
    cout << endl;
    // Cargar calve pública de Lyra para verificar la firma
    RSA::PublicKey clavePublicaLyra; // Clave pública de Lyra
    FileSource filePubLyra("Claves/lyra_publica.der", true);
    clavePublicaLyra.BERDecode(filePubLyra); // Cargar clave pública

    // Verificar la firma
    RSASS<PSS, SHA256>::Verifier verificador(clavePublicaLyra); // Crear el verificador RSA
    bool firmaValida = verificador.VerifyMessage(
        (const CryptoPP::byte*)mensajeDescifrado.data(), mensajeDescifrado.size(),
        (const CryptoPP::byte*)firma.data(), firma.size()
    );

    if (firmaValida) {
        cout << endl;
        cout << "Firma verificada correctamente." << endl;
        cout << endl;
        cout << "Mensaje recibido: " << mensajeDescifrado << endl;
        cout << endl;
    } else {
        cout << "Firma inválida." << endl;
        cout << endl;
    }
    
    
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << "-------------------------- Fin demostración RSA -------------------------------------" << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << endl;
    cout << endl;

    /*-----------------------------------------------------------------------------------------------------------------------*/

    // Cifrado Asimétrico con RSA: Simulando un cifrado de un mensaje con RSA
    cout << " --------------------------------------------------------------------------------------" << endl;
    cout << "        ----------------------------- Canal Seguro -----------------------------      " << endl;
    cout << " --------------------------------------------------------------------------------------" << endl;

















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
