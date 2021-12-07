#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include "sodium.h"
using namespace std;

void menu() {
    cout << "1. Generacion de llaves\n";
    cout << "2. Cifrado de archivos\n";
    cout << "3. Descifrado de archivos\n";
    cout << "4. Firma de archivos\n";
    cout << "5. Verificacion de firma de archivos\n";
    cout << "0. Salir\n";
    cout << "Escoge la opcion a trabajar: ";
}

void cifrarArchivo(const char* nombre, unsigned char* key, unsigned char* nonce) {
    FILE* textoPlano;
    FILE* textoCifrado;
    string ruta = "C:/Users/D-ani/source/repos/ConsoleApplication1/";
    ruta.append(nombre);
    char* c = const_cast<char*>(ruta.c_str());
    ifstream myFile(ruta);
    errno_t leerArchivo = fopen_s(&textoPlano, c, "rb");
    // tamaño
    fseek(textoPlano, 0, SEEK_END);
    long size1 = ftell(textoPlano);
    cout << "size: " << size1;
    unsigned char* plain_text = (unsigned char*)malloc(size1 + 1);
    fseek(textoPlano, 0, SEEK_SET);
    fread(plain_text, 1, size1, textoPlano);
    fclose(textoPlano);

    unsigned char* cipherText = new unsigned char[size1];

    int errorCode = crypto_stream_chacha20_xor(cipherText, plain_text, size1, nonce, key);

    char cifrado[450];
    strcpy_s(cifrado, 450, "C:/Users/D-ani/source/repos/ConsoleApplication1/c_");
    strcat_s(cifrado, 450, nombre);

    // cout << "cipherText: " << cipherText << "\n";
    errno_t ferr = fopen_s(&textoPlano, cifrado, "wb");
    fwrite(cipherText, 1, size1, textoPlano);
    fclose(textoPlano);

    cout << "\nArchivo cifradoooooo\n";
}

void descifrarArchivo(const char* nombre, unsigned char* key, unsigned char* nonce) {
    FILE * textoCifrado;
    FILE * textoDescifrado;
    string ruta = "C:/Users/D-ani/source/repos/ConsoleApplication1/";
    ruta.append(nombre);
    char* c = const_cast<char*>(ruta.c_str());
    ifstream myFile(ruta);
    errno_t leerArchivo = fopen_s(&textoCifrado, c, "rb");
    // tamaño
    fseek(textoCifrado, 0, SEEK_END);
    long size1 = ftell(textoCifrado);
    unsigned char* cipher_text = (unsigned char*)malloc(size1 + 1);
    fseek(textoCifrado, 0, SEEK_SET);
    fread(cipher_text, 1, size1, textoCifrado);
    fclose(textoCifrado);

    unsigned char* decipherText = new unsigned char[size1];

    int errorCode = crypto_stream_chacha20_xor(decipherText, cipher_text, size1, nonce, key);

    char cifrado[450];
    strcpy_s(cifrado, 450, "C:/Users/D-ani/source/repos/ConsoleApplication1/d_");
    strcat_s(cifrado, 450, nombre);
    // cout << "decipher: " << decipherText << "\n";
    errno_t ferr = fopen_s(&textoDescifrado, cifrado, "wb");
    fwrite(decipherText, 1, size1, textoDescifrado);
    fclose(textoDescifrado);

    // cout << decipherText;
    cout << "\nArchivo descifrado\n";
}

void firmarArchivo(const char* nombre, unsigned char* sk) {
    FILE* textoCifrado;
    FILE* archivoFirmado;
    string ruta = "C:/Users/D-ani/source/repos/ConsoleApplication1/";
    ruta.append(nombre);
    char* c = const_cast<char*>(ruta.c_str());
    ifstream myFile(ruta);
    errno_t leerArchivo = fopen_s(&textoCifrado, c, "rb");
    // tamaño
    fseek(textoCifrado, 0, SEEK_END);
    long size1 = ftell(textoCifrado);
    unsigned char* texto = (unsigned char*)malloc(size1 + 1);
    fseek(textoCifrado, 0, SEEK_SET);
    fread(texto, 1, size1, textoCifrado);
    fclose(textoCifrado);

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, texto, size1, sk);

    char cifrado[450];
    strcpy_s(cifrado, 450, "C:/Users/D-ani/source/repos/ConsoleApplication1/f_");
    strcat_s(cifrado, 450, nombre);

    errno_t ferr = fopen_s(&textoCifrado, cifrado, "wb");
    fwrite(sig, 1, size1, textoCifrado);
    fwrite(texto, 1, size1, textoCifrado);
    fclose(textoCifrado);
    cout << "\nArchivo firmado\n";
}

void revisarFirma(const char* nombre, unsigned char* pk) {
    FILE* textoCifrado;    
    string ruta = "C:/Users/D-ani/source/repos/ConsoleApplication1/";
    ruta.append(nombre);
    cout << "Nombre: " << ruta;
    char* c = const_cast<char*>(ruta.c_str());
    errno_t leerArchivo = fopen_s(&textoCifrado, c, "rb");
    // tamaño
    fseek(textoCifrado, 0, SEEK_END);
    long size1 = ftell(textoCifrado);
    fseek(textoCifrado, 0, SEEK_SET);
    unsigned char* texto = (unsigned char*)malloc(size1 + 1);
    fread(texto, 1, size1, textoCifrado);
    fclose(textoCifrado);
    unsigned char sig[crypto_sign_BYTES];
    // crypto_sign_keypair(pk, sk);

    if (crypto_sign_verify_detached(sig, texto, size1, pk) != 0) {
        /* Incorrect signature! */
        cout << "\nFirma incorrecta\n";
        return;
    }
    cout << "\nFirma correcta\n";
    return;
}

int main()
{

    if (sodium_init() < 0) {
        return -1;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];    
    unsigned char sig[crypto_sign_BYTES];
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];

    menu();
    int opcion = 0;
    cin >> opcion;
    
    while (opcion != 0) {
        char nombre[50];
        cout << "Ingresa el nombre del archivo: ";
        cin >> nombre;
        if (opcion == 1) {
            // generación de keys
            crypto_secretbox_keygen(key);
            randombytes_buf(nonce, crypto_stream_chacha20_NONCEBYTES);
            crypto_sign_keypair(pk, sk);
            cout << pk << sk << key << nonce << "\n";
            cout << "Llaves generadas\n";
            // generarLlaves(nombre, key, nonce, pk, sk);
            cout << "Ingresa otra opcion: ";
            cin >> opcion;
        }
        else if (opcion == 2) {
            // cifrado de archivos
            cifrarArchivo(nombre, key, nonce);
            cout << "Ingresa otra opcion: ";
            cin >> opcion;
        }
        else if (opcion == 3) {
            // descifrado de archivos
            cout << key << nonce << "\n";
            descifrarArchivo(nombre, key, nonce);
            cout << "Ingresa otra opcion: ";
            cin >> opcion;
        }
        else if (opcion == 4) {
            // firma de archivos
            firmarArchivo(nombre, sk);
            cout << "Ingresa otra opcion: ";
            cin >> opcion;
        }
        else if (opcion == 5) {
            // verificación de firmas
            revisarFirma(nombre, pk);
            cout << "Ingresa otra opcion: ";
            cin >> opcion;
        }
        else {
            cout << "Opcion no valida.";
            cout << "Ingresa otra opcion: ";
            cin >> opcion;
        }
    }
    return 0;
}