#include <iostream>
std::string alphabet = "abcdefghijklmnopqrstuvwxyz";
int INDX(char w) {
    for (int i=0; i<alphabet.size(); ++i) {
        if (alphabet[i] == w){
            return i;
        }
    }
}

int main() {
    std::string plaintext;
    std::cout << "Plaintext: "; std::cin >> plaintext;

    int plaintext_size = plaintext.size(); // length of plaintext
    int plaintext_array[plaintext_size];
    for (int i=0; i<plaintext_size; ++i) {
        plaintext_array[i] = INDX(plaintext[i]);
    } // massive for plaintext`s elements


    std::string key;
    std::cout << "Key: "; std::cin >> key;
    int key_size = key.length();
    int key_array[key_size];
    for (int i=0; i<key_size; ++i) {
        key_array[i] = INDX(key[i]);
    } //massive for key`s elements
    //key = "key"

    int gamma_array[plaintext_size];
    for (int i=0; i<key_size; ++i) {
        gamma_array[i] = key_array[i];
    }
    for (int i=key_size; i<plaintext_size; ++i) {
        gamma_array[i] = (plaintext_array[i-key_size] + gamma_array[i-1])%26;
    }

    std::string word;
    for (int i=0; i<plaintext_size; ++i) {
        word += alphabet[(gamma_array[i] + plaintext_array[i])%26];
    }
    std:: cout << "Encryption: "<<word << std::endl;

    //--Decode--

    int new_array[plaintext_size];
    for (int i=0; i<plaintext_size; ++i) {
        new_array[i] = INDX(word[i]);
    }

    std::string decode;
    int res;
    for (int i=0; i<plaintext_size; ++i) {
        res = new_array[i] - gamma_array[i];
        if (res<0) {
            res = (res%26 + 26)%26;
        }
        decode += alphabet[(res)%26];
    }
    std:: cout << "Unencryption: "<<decode;

    return 0;
}