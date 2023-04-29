#include <iostream>
#include <string>
#include <ctime>
#include "blowfish.h"
#include "xor.h"
#include "magma.h"
#define Blowfish_BUFF_SIZE 1024
#define Magma_BUFF_SIZE 1024
using namespace std;
/*
Enceladus-ES - software for encryption sensitive information. Made by Innokentiy Gerasimov.
This program is under development and may have flaws.
Always back up your data before encrypting. I am not responsible if you lose your information.
I do not guarantee that my software will protect your data 100%.
The implementation of cryptographic methods for C++ is partially based on https://github.com/number571/C/tree/master/Cryptography
*/
/*Example usage
* Welcome to the Enceladus-ES (Encryption Software)
Available encryption methods:
Choice method of enryption:
(1) Encode
(2) Decode
: 1
Encoding
plaintext: The quick brown fox jumps over the lazy dog
generated password (base64): c2htYXk/YXgtK2M8bHMyJGJySzlwZ2xPblh1aElRdGN1cVdlQXd2SmxNa1BoJGhKQ3BWaVQ9RlVaJFBh
ciphertext (base64): JS8FDTB3J0lMfC1OJTR4XQBBL0w5IDY5Cxs3GS0GRRQWCBUTJRogMyUFOT8ydyo5GigmXB16FCMAU21c

Welcome to the Enceladus-ES (Encryption Software)
Available encryption methods:
(1) XOR encryption
Choice method of enryption:
(1) Encode
(2) Decode
: 2
Decode
ciphertext: JS8FDTB3J0lMfC1OJTR4XQBBL0w5IDY5Cxs3GS0GRRQWCBUTJRogMyUFOT8ydyo5GigmXB16FCMAU21c
key: c2htYXk/YXgtK2M8bHMyJGJySzlwZ2xPblh1aElRdGN1cVdlQXd2SmxNa1BoJGhKQ3BWaVQ9RlVaJFBh
decoded: The quick brown fox jumps over the lazy dog

*/
int main() {
    int choice, choice2;
    cout << "Welcome to the Enceladus-ES (Encryption Software) v1.5.3 \nAvailable encryption methods: \n(1) XOR encryption  (for one time messages) \n(2) Blowfish \n(3) Magma encryption (GOST 28147-89)\nChoice method of enryption: ";
    cin >> choice;
    if (choice == 1) {
        //XOR cipher
        cout << "\n(1) Encode\n(2) Decode \n: ";
        //The program generates a key equal to the length of the message and encrypts the information using a gamma cipher (XOR). 
        //After, it encrypts this data with base64 for easier transfer and storage.
        cin >> choice2;
        string tmpplaintext, plaintext, tempkey, key, tempciphertext, ciphertext;
        int n;
        if (choice2 == 1) {
            cout << "Encoding\nplaintext: ";
            cin.ignore();
            getline(cin, tmpplaintext);
            plaintext = b64encode(tmpplaintext);
            n = plaintext.length();
            key = genpassXOR(n);
            cout << "generated password (base64): " << b64encode(key) << endl;
            ciphertext = xor_cipher(plaintext, key, n);
            cout << "ciphertext (base64): " << b64encode(ciphertext) << endl;
        }if (choice2 == 2) {
            cout << "Decoding\nciphertext: ";
            cin >> tempciphertext;
            ciphertext = b64decode(tempciphertext);
            n = ciphertext.length();
            cout << "key: ";
            cin >> tempkey;
            key = b64decode(tempkey);
            string decoded = xor_cipher(ciphertext, key, n);
            cout << "decoded: " << b64decode(decoded);
        }
    }
    else if (choice == 2) {
        //Blowfish cipher
        choice2;
        cout << "\n(1) Encode\n(2) Decode \n: ";
        cin >> choice2;
        if (choice2 == 1) {
            cout << "Encoding\n";
            char choice3;
            cout << "Generate key? Y/n: ";
            cin >> choice3;

            uint8_t encrypted[Blowfish_BUFF_SIZE], decrypted[Blowfish_BUFF_SIZE], buffer[Blowfish_BUFF_SIZE];
            uint8_t key64b[56] = "";
            if ((choice3 == 'Y') || (choice3 == 'y')) {      
                string genKey = genpass(56);
                for (int i = 0; i < genKey.length(); i++) {
                    key64b[i] = genKey[i];
                }
                cout << "plaintext: ";
                cin.ignore();
                size_t length = input_string(buffer);
                cout << "key: " << genKey << endl;
                key_extension(Keys32b, key64b, 448);
                length = blowfish(encrypted, 'E', Keys32b, buffer, length);
                //cout << "n: " << length << endl;
                //cout << "ciphertext in decimal: ";
                cout << "ciphertext: " << length << " " << return_array(encrypted, length);
                //print_array(encrypted, length);        
                
            }
            else if ((choice3 == 'N') || (choice3 == 'n')) {
                string inputKey;
                cout << "key: ";
                cin >> inputKey;
                for (int i = 0; i < inputKey.length(); i++) {
                    key64b[i] = inputKey[i];
                }
                cout << "plaintext: ";
                cin.ignore();
                size_t length = input_string(buffer);
                key_extension(Keys32b, key64b, 448);

                length = blowfish(encrypted, 'E', Keys32b, buffer, length);
                //cout << "n: " << length << endl;
                //cout << "ciphertext in decimal: ";
                //print_array(encrypted, length);
                cout << "ciphertext: " << length << " " << return_array(encrypted, length);

            }
        }
        else if (choice2 == 2) {
            cout << "Decoding\n";
            uint8_t encrypted[Blowfish_BUFF_SIZE], decrypted[Blowfish_BUFF_SIZE], buffer[Blowfish_BUFF_SIZE];
            uint8_t key64b[56] = "";
            string input_key;
           
            int n;
            //cout << "n: ";
            cout << "ciphertext: ";
            cin >> n;
            int b = 0;
            uint8_t* A = new uint8_t[n];
           
            for (int i = 0; i < n; i++) {
                cin >> b;
                uint8_t v = static_cast<uint8_t>(b);
                A[i] = v;
            }
            cin.ignore();
            cout << "key: ";
            cin >> input_key;
            cin.ignore();
            for (int i = 0; i < input_key.length(); i++) {
                key64b[i] = input_key[i];
            }
            size_t length = n;
            key_extension(Keys32b, key64b, 448);
            length = blowfish(decrypted, 'D', Keys32b, A, length);
            cout << "\n\nplaintext: ";
            print_text_dec(decrypted, n);
        }
    }
    else if (choice == 3) {
    cin.ignore();
    cout << "\n(1) Encode\n(2) Decode \n: ";
    cin >> choice2;
    if (choice2 == 1) {
        cout << "Encoding\n";
        char choice3;
        cout << "Generate key? Y/n: ";
        cin >> choice3;

        uint8_t encrypted[Magma_BUFF_SIZE], decrypted[Magma_BUFF_SIZE], buffer[Magma_BUFF_SIZE];
        uint8_t key256b[32] = "";
        uint8_t ch;
        size_t length = 0x00;

        if ((choice3 == 'Y') || (choice3 == 'y')) {       
            string genKey = genpass(32);
            for (int i = 0; i < genKey.length(); i++) {
                key256b[i] = genKey[i];
            }
            cout << "key: " << genKey;
            cin.ignore();
            cout << "\nplaintext: ";

            while ((ch = getchar()) != '\n' && length < Magma_BUFF_SIZE - 1) {
                buffer[length++] = ch;
            }
            buffer[length] = '\0';

            length = GOST_28147(encrypted, 'E', key256b, buffer, length);
            cout << "ciphertext: " << length << " " << return_array(encrypted, length);
            //return_array(encrypted, length);
            //print_array(encrypted, length);
        }
        else if ((choice3 == 'N') || (choice3 == 'n')) {
            string input_key;
            cout << "key: ";
            cin >> input_key;
            cin.ignore();
            cout << "plaintext: ";
            for (int i = 0; i < input_key.length(); i++) {
                key256b[i] = input_key[i];
            }

            while ((ch = getchar()) != '\n' && length < Magma_BUFF_SIZE - 1) {
                buffer[length++] = ch;
            }
            buffer[length] = '\0';

            length = GOST_28147(encrypted, 'E', key256b, buffer, length);
            cout << "ciphertext: " << length << " " << return_array(encrypted, length);
        }  
    }
    else if (choice2 == 2) {
        cout << "Decoding\n";
        uint8_t encrypted[Magma_BUFF_SIZE], decrypted[Magma_BUFF_SIZE], buffer[Magma_BUFF_SIZE];
        uint8_t key256b[32] = "";
        string input_key;
        int n;
        cout << "ciphertext: ";
        cin >> n;

        int b = 0;
        uint8_t* A = new uint8_t[n];
        
        for (int i = 0; i < n; i++) {
            cin >> b;
            uint8_t v = static_cast<uint8_t>(b);
            A[i] = v;
        }
        cin.ignore();
        cout << "key: ";
        cin >> input_key;
        for (int i = 0; i < input_key.length(); i++) {
            key256b[i] = input_key[i];
        }
        size_t length = n;
        length = GOST_28147(decrypted, 'D', key256b, A, length);
        printf("\nplaintext: "); print_text_dec(decrypted, length);
    }
}
    cout << "\nPress any key to exit.";
    cin.get();
    cin.get();
    return 0;
}
