#include <iostream>
#include <string>

#include "rsa_utils.h"
#include "aes_utils.h"
#include "firmas.h"

using namespace std;
using namespace CryptoPP;

int main() {
    // Sección 1: Cifrado Simétrico con AES: Simulando un cifrado de un mensaje con AES-128 en modo CBC

    // Mensaje a cifrar

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

    // Variable para almacenar el IV en formato hexadecimal
    string ivHex;

    string cifradoAES = aes_encrypt(mensaje, claveAES, ivHex); // Obtención del texto cifrado
    /*-----------------------------------------------------------------------------*/
    cout << "Texto cifrado (AES): " << cifradoAES << endl;

    cout << " ------------------------- Ahora vamos a descifrar el texto cifrado con AES ------------------------- " << endl;
    string mensajeRecuperadoAES = aes_decrypt(cifradoAES, claveAES, ivHex); // Descifrado del texto cifrado
    cout << "Texto recuperado (AES): " << mensajeRecuperadoAES << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << "--------------------------------------------------------------------------------------" << endl;
    cout << endl;




    // Cifrado Asimétrico con RSA: Simulando un cifrado de un mensaje con RSA
    cout << " ----------------------------- Cifrado Asimétrico con RSA -----------------------------" << endl;
    mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido "; // Mensaje proveniente de la hermana Lyra
    cout << "Mensaje a cifrar: " << mensaje << endl;
    cout << "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" << endl;
    // Para que solamente el Gran Maestro pueda descifrar el mensaje, utilizaremos firmas digitales.
    


    // Emisor (Lyra) -> Receptor (Gran Maestro)

    // a. Lyra firma el mensaje con su clave privada
    string pathClavePrivadaLyra = "Claves/lyra_privada.pem";
    string firmaLyra = rsa_sign(mensaje, pathClavePrivadaLyra); // Firma del mensaje con la clave privada de Lyra
    cout << "Firma de Lyra: " << firmaLyra << endl;


    /*
    
    // Paso 1: Encriptar el mensaje con la clave privada de Lyra
    string pathClavePrivada = "Claves/lyra_privada.pem"; // Ruta al archivo de clave privada de lyra
    string cifradoRSA = rsa_encrypt(mensaje, pathClavePrivada, false); // Cifrado del mensaje con la clave privada de Lyra
    cout << "Mensaje cifrado (RSA): " << cifradoRSA << endl;
    // Paso 2: Volver a cifrar el mensaje con la clave pública del Gran Maestro
    string pathClavePublicaGranMaestro = "Claves/gm_publica.pem"; 
    
    string cifradoFinal = rsa_encrypt(cifradoRSA, pathClavePublicaGranMaestro, true); // Cifrado del mensaje con la clave pública del Gran Maestro
    cout << "Mensaje cifrado (RSA con clave pública del Gran Maestro): " << cifradoFinal << endl;
    
    */
}