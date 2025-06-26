# Lab-redes

Para compilar:

```bash
make all
```

Luego ejecutar 

```bash
./lab1
```

## Transformación de claves .pem a .der


### Clave privada
```bash
openssl rsa -in lyra_privada.pem -out lyra_privada.der -outform DER
```

### Clave pública
```bash
openssl pkey -pubin  -in nombre_clave_publica.pem -out nombre_clave_publica.der -outform DER 
``` 