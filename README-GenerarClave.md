
### **Generación de Claves RSA para Lyra usando OpenSSL**

OpenSSL es una biblioteca de criptografía de código abierto que proporciona una línea de comandos robusta para tareas como la generación de claves.

1.  **Generar una clave privada RSA:**
    Este comando generará una clave privada RSA de 2048 bits (un tamaño de clave recomendado para buena seguridad) y la guardará en un archivo llamado `lyra_privada.pem`. Puedes ajustar el número `2048` para cambiar el tamaño de la clave.

    ```bash
    openssl genrsa -out lyra_privada.pem 2048
    ```

      * **`genrsa`**: Comando para generar claves RSA.
      * **`-out lyra_privada.pem`**: Especifica el archivo de salida para la clave privada.
      * **`2048`**: Define el tamaño de la clave en bits.

2.  **Extraer la clave pública de la clave privada:**
    Una vez que tienes la clave privada, puedes extraer fácilmente la clave pública correspondiente y guardarla en un archivo llamado `lyra_publica.pem`.

    ```bash
    openssl rsa -in lyra_privada.pem -pubout -out lyra_publica.pem
    ```

      * **`rsa`**: Comando para operar con claves RSA.
      * **`-in lyra_privada.pem`**: Especifica el archivo de entrada (tu clave privada).
      * **`-pubout`**: Indica que la salida debe ser la clave pública.
      * **`-out lyra_publica.pem`**: Especifica el archivo de salida para la clave pública.

Después de ejecutar estos dos comandos, tendrás dos archivos en tu directorio actual:

  * `lyra_privada.pem`: La clave privada de Lyra.
  * `lyra_publica.pem`: La clave pública de Lyra.

-----

