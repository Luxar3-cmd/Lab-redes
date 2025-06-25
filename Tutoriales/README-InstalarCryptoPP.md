### Como instalar Crypto++

En nuestro caso utilizamos linux, por ello, para poder utilizar esta librería ejecutar en bash: 

```bash
sudo apt update
sudo apt install libcrypto++-dev libcrypto++-doc libcrypto++-utils
```


---


¡Claro\! Con gusto te preparo un tutorial completo en formato README con todos los pasos que hemos seguido para que puedas replicar tu éxito y compartirlo.

-----

# Tutorial: Instalación de Crypto++ con Soporte PEM en Zorin OS (Compilación desde Fuente)

Este tutorial te guiará paso a paso a través de la desinstalación de versiones anteriores de Crypto++, la preparación del entorno, la descarga, compilación e instalación de Crypto++ junto con el módulo PEM para permitir funciones como `PEM_Load`, y finalmente, cómo verificar que todo funciona correctamente en Zorin OS.

-----

## 1\. Desinstalar Versiones Anteriores de Crypto++

Es crucial eliminar cualquier instalación previa de Crypto++ para evitar conflictos.

### Opción 1: Si instalaste con `apt-get` (lo más probable en tu caso)

Si usaste comandos como `sudo apt-get install libcrypto++-dev`, desinstala los paquetes con `purge` para eliminar también sus archivos de configuración:

```bash
sudo apt-get purge libcrypto++-dev libcrypto++-doc libcrypto++-utils
```

### Opción 2: Si compilaste e instalaste desde el código fuente previamente

Si en algún momento instalaste Crypto++ compilándolo manualmente, intenta desinstalarlo desde el directorio fuente original.

1.  **Navega al directorio fuente original de Crypto++** (por ejemplo, `~/Descargas/cryptopp-8.x.x`). Si no lo recuerdas, puedes intentar buscarlo:
    ```bash
    sudo find / -name "GNUmakefile" 2>/dev/null | grep -i cryptopp
    ```
2.  Una vez en el directorio correcto, ejecuta:
    ```bash
    sudo make uninstall
    ```
    Si `make uninstall` falla o no existe, no te preocupes demasiado. La nueva instalación sobrescribirá la mayoría de los archivos. Para una limpieza más profunda, podrías eliminar manualmente los archivos en `/usr/local/include/cryptopp/` y `/usr/local/lib/` que pertenezcan a Crypto++. **¡Ten extrema precaución con `rm -rf`\!**

-----

## 2\. Instalar Dependencias Necesarias

Para compilar Crypto++ y el módulo PEM, necesitas algunas herramientas de desarrollo y las cabeceras de OpenSSL.

1.  **Actualiza la lista de paquetes:**
    ```bash
    sudo apt update
    ```
2.  **Instala las dependencias de compilación:**
    ```bash
    sudo apt install build-essential libssl-dev git
    ```
      * `build-essential`: Proporciona herramientas fundamentales como el compilador `g++` y `make`.
      * `libssl-dev`: Contiene las cabeceras de desarrollo de OpenSSL, esenciales para muchas funciones criptográficas.
      * `git`: Necesario para clonar los repositorios de Crypto++ y el PEM Pack.

-----

## 3\. Descargar y Preparar el Código Fuente de Crypto++ y el PEM Pack

El módulo PEM es una extensión que se integra colocando sus archivos en el directorio fuente principal de Crypto++ antes de la compilación.

1.  **Crea un directorio de trabajo para tu compilación y navega a él:**

    ```bash
    mkdir ~/crypto_build && cd ~/crypto_build
    ```

2.  **Clona el repositorio de Crypto++:**
    Esto descargará el código fuente principal de Crypto++.

    ```bash
    git clone https://github.com/weidai11/cryptopp.git
    cd cryptopp
    ```

    Ahora te encuentras en el directorio `~/crypto_build/cryptopp`.

3.  **Descarga y Coloca el PEM Pack:**
    El PEM Pack se descarga por separado y sus archivos se copian *dentro* del directorio `cryptopp`.

    ```bash
    # Vuelve al directorio 'crypto_build'
    cd ..
    # Clona el repositorio del PEM Pack
    git clone https://github.com/noloader/cryptopp-pem.git

    # Copia los archivos del PEM Pack (incluyendo los scripts de prueba y el código fuente)
    # al directorio raíz de Crypto++.
    cp cryptopp-pem/* cryptopp/

    # Vuelve al directorio de Crypto++ para continuar
    cd cryptopp
    ```

    En este punto, el directorio `~/crypto_build/cryptopp` contiene tanto el código fuente de Crypto++ como los archivos del PEM Pack.

-----

## 4\. Compilar e Instalar Crypto++

Ahora que todos los archivos están en su lugar, puedes compilar la librería.

1.  **Limpia archivos de compilación antiguos (opcional pero recomendado):**

    ```bash
    make distclean
    ```

2.  **Compila Crypto++:**
    Este comando compilará la librería junto con las extensiones del PEM Pack.

    ```bash
    make
    # (Opcional) Para compilar también las versiones estática y dinámica, y las herramientas de prueba:
    # make static dynamic cryptest.exe (YO HICE ESTEEEE !!!!)
    ```

    Este proceso puede tardar unos minutos.

3.  **Instala Crypto++:**
    Una vez que la compilación haya terminado sin errores, instala la librería en las ubicaciones estándar del sistema (`/usr/local/include/cryptopp/` y `/usr/local/lib/`).

    ```bash
    sudo make install
    ```

-----

## 5\. Verificar la Instalación y la Funcionalidad de PEM

Es crucial confirmar que Crypto++ se instaló correctamente y que el soporte PEM está operativo.

1.  **Actualiza el caché de librerías del sistema:**
    Esto asegura que el sistema pueda encontrar la nueva librería dinámica (`.so`).
    ```bash
    sudo ldconfig
    ```
2.  **Asegura que el cargador de librerías conozca la ruta `/usr/local/lib`:**
    Si al ejecutar un programa obtienes un error como `libcryptopp.so.8: cannot open shared object file`, es porque el sistema no sabe dónde buscar la librería. Crea un archivo de configuración para indicárselo:
    ```bash
    echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/cryptopp.conf
    sudo ldconfig
    ```
3.  **Verifica la presencia de los archivos instalados:**
    ```bash
    ls -l /usr/local/lib/libcryptopp.*
    ls -l /usr/local/include/cryptopp/
    ```
4.  **Ejecuta los scripts de prueba del PEM Pack:**
    Estos scripts, que se encuentran ahora dentro de tu directorio `~/crypto_build/cryptopp`, compilarán y ejecutarán un programa de prueba para verificar las funciones PEM. Asegúrate de estar en el directorio correcto:
    ```bash
    cd ~/crypto_build/cryptopp
    ./pem_create_keys.sh && ./pem_verify_keys.sh
    ```
    Si los scripts se ejecutan sin errores y `pem_verify_keys.sh` reporta éxito, ¡significa que el PEM Pack se integró y funciona correctamente\!

-----

## 6\. Ejemplo de Código para Usar `PEM_Load`

Aquí tienes el código `test.cpp` que usamos para probar la funcionalidad de `PEM_Load`:

```cpp
#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/pem.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h> // Para AutoSeededRandomPool

int main() {
    try {
        // Genera una clave pública RSA simple y la guarda en formato PEM
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::RSA::PrivateKey privateKey;
        // Genera una clave RSA de 1024 bits. Puedes usar 2048 para mayor seguridad.
        privateKey.GenerateRandomWithKeySize(prng, 1024); 
        CryptoPP::RSA::PublicKey newPublicKey(privateKey);

        CryptoPP::FileSink fs_out("test_public_key.pem", true);
        CryptoPP::PEM_Save(fs_out, newPublicKey);
        std::cout << "Clave pública RSA de prueba guardada en 'test_public_key.pem'." << std::endl;

        // Ejemplo: Cargar una clave pública desde el archivo PEM generado
        CryptoPP::RSA::PublicKey loadedPublicKey;
        CryptoPP::FileSource fs_in("test_public_key.pem", true /*pump all*/);
        CryptoPP::PEM_Load(fs_in, loadedPublicKey);
        std::cout << "Clave pública RSA cargada exitosamente desde el archivo PEM." << std::endl;

        // Opcional: Validar la clave cargada
        if (loadedPublicKey.Validate(prng, 3)) { // Validar con 3 rondas de prueba
            std::cout << "La clave pública cargada es válida." << std::endl;
        } else {
            std::cout << "Advertencia: La clave pública cargada no es válida." << std::endl;
        }

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Excepción de Crypto++: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Excepción estándar: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

```

### Compilar y Ejecutar el Ejemplo:

Guarda el código anterior como `test.cpp` y compílalo usando `g++`. Asegúrate de incluir las librerías de Crypto++ y especificar la ruta donde se encuentran:

```bash
g++ -o my_pem_test test.cpp -lcryptopp -L/usr/local/lib
```

Finalmente, ejecuta tu programa:

```bash
./my_pem_test
```

Deberías ver una salida que indica que la clave pública se generó, se guardó en PEM, se cargó y se validó correctamente.

¡Felicidades\! Ahora tienes Crypto++ instalado con soporte para PEM en tu Zorin OS. ¿Hay algo más en lo que pueda ayudarte con tu proyecto?