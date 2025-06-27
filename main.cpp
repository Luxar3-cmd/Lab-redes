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

    /*
        Para establecer un canal seguro en tre Pedrius Godoyius y el Gran Maestro, mediante
        cifrado asimétrico se cifrara la clave AES para que puedan establecer un canal seguro 
    */

    // Generar clave AES y IV aleatorios
    
    SecByteBlock aesKey, aesIV;
    GenerateAESKeyAndIV(aesKey, aesIV); // Generación de clave AES (Cifrado Simétrico) y IV aleatorios


    cout << endl;
    cout << "Clave AES generada aleatoriamente (Hex): " << BytesToHex(aesKey, aesKey.size()) << endl;
    cout << endl;
    cout << "IV generado aleatoriamente (Hex): " << BytesToHex(aesIV, aesIV.size()) << endl;
    cout << endl;

    // Construir bloque clave+iv
    string aesKEY_IV(reinterpret_cast<const char*>(aesKey.data()), aesKey.size());
    aesKEY_IV += string(reinterpret_cast<const char*>(aesIV.data()), aesIV.size());

    // Cargar Clave Privada Pedrius Godoyius
    RSA::PrivateKey clavePrivadaPedrius; // Clave privada de Pedrius Godoyius
    FileSource filePrivPedrius("Claves/pedrius_privada.der", true); // Cargar clave privada de Pedrius Godoyius desde archivo DER
    clavePrivadaPedrius.BERDecode(filePrivPedrius); // Decodificar clave privada

    // Firmar clave+IV con clave privada del emisor, en este caso elegimos Pedrius Godoyius como emisor
    string firmaClaveIV; 
    RSASS<PSS, SHA256>::Signer firmantePedrius(clavePrivadaPedrius); 
    StringSource(aesKEY_IV, true,
        new SignerFilter(prng, firmantePedrius,
            new StringSink(firmaClaveIV) // Firmar el bloque clave+IV
        )
    );

    string claveIVCifrada; // Clave AES+IV cifrada
    RSAES_OAEP_SHA_Encryptor cifradorGM(clavePublicaGM); // Crear el cifrador RSA
    StringSource(aesKEY_IV, true,
        new PK_EncryptorFilter(prng, cifradorGM,    
            new StringSink(claveIVCifrada) // Cifrar el bloque clave+IV
        )
    );

    /*
        Se asume que se transmiten concatenados claveIVCifrada + firmaClaveIV.
    */

    cout << "Resumen lado emisor (Pedrius Godoyius):" << endl;
    cout << "Clave AES+IV cifrada (RSA): " << binToHex(claveIVCifrada) << endl;
    cout << "Firma de la clave AES+IV (hex): " << binToHex(firmaClaveIV) << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;


    cout << endl;
    cout << "--- Lado Receptor (Gran Maestro) ---" << endl;

    string claveIVRecibida; 
    RSAES_OAEP_SHA_Decryptor descifradorGM(clavePrivadaGM); // Crear el descifrador RSA
    StringSource(claveIVCifrada, true,
        new PK_DecryptorFilter(prng, descifradorGM,
            new StringSink(claveIVRecibida) // Descifrar el bloque clave+IV
        )
    );

    
    RSA::PublicKey clavePublicaPedrius; // Clave pública de Pedrius Godoyius
    FileSource filePubPedrius("Claves/pedrius_publica.der", true); // Cargar clave pública de Pedrius Godoyius desde archivo DER
    clavePublicaPedrius.BERDecode(filePubPedrius); // Decodificar clave pública 

    // Verificar firma
    RSASS<PSS, SHA256>::Verifier verificadorPedrius(clavePublicaPedrius); // Crear el verificador RSA
    firmaValida = verificadorPedrius.VerifyMessage(
        (const CryptoPP::byte*)claveIVRecibida.data(), claveIVRecibida.size(),
        (const CryptoPP::byte*)firmaClaveIV.data(), firmaClaveIV.size()
    );

    SecByteBlock aesKeyRec, aesIVRec;

    if (firmaValida) {
        cout << "Firma verificada correctamente." << endl;
        
        // Separar clave AES y IV del bloque descifrado
        aesKeyRec.Assign((const CryptoPP::byte*)claveIVRecibida.data(), 16);
        aesIVRec.Assign((const CryptoPP::byte*)claveIVRecibida.data() + 16, AES::BLOCKSIZE);
        cout << endl;
        cout <<  "Clave AES recibida (Hex): " << BytesToHex(aesKeyRec, aesKeyRec.size()) << endl;
        cout << endl;
        cout << "IV recibido (Hex): " << BytesToHex(aesIVRec, aesIVRec.size()) << endl;
        cout << endl;

        cout << " Canal de comununicación establecido" << endl;


    } else {
        cout << "Firma inválida." << endl;
        return 1; // Salir si la firma no es válida
    }

    /*
        Ejemplo de intercambio de mensajes cifrados con AES en el canal seguro establecido
    */

    vector<string> remitentes = {"Pedrius", "Gran Maestro", "Pedrius", "Gran Maestro"};
    vector<string> mensajes = {
        "¿Has encontrado el cuarto sello?",
        "Sí, pero los guardianes lo vigilan.",
        "Debemos actuar al amanecer.",
        "Estaré preparado. Que el templo nos guíe."
    };

    cout << endl;
    cout << "\n --- Intercambio de mensajes cifrados en el canal seguro establecido --- \n" << endl;
    for (size_t i = 0; i < mensajes.size(); ++i) {
        cout << remitentes[i] << " (original): " << mensajes[i] << endl;
        
        // Usamos la clave compartida y el mismo IV acordado en canal seguro
        string mensajeCifradoHex = aes_encrypt(mensajes[i], aesKeyRec, aesIVRec);
        string mensajeDescifrado = aes_decrypt(mensajeCifradoHex, aesKeyRec, aesIVRec);
        
        cout << remitentes[i] << " (cifrado - hex): " << mensajeCifradoHex << endl;
        cout << remitentes[i] << " (descifrado): " << mensajeDescifrado << "\n" << endl;
    }
        

    cout << "--------------------------------------------------------------------------------------" << endl;

    return 0;
}
