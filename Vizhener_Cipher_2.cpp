#include <iostream>
int INDX(char w) {
    std::string alphabet = "abcdefghijklmnopqrstuvwxyz";
    int res;
    for (int i=0; i<alphabet.size(); ++i) {
        if (alphabet[i] == w){
            res = i;
        }
    }
    return res;
}

int main() {
    std::string alphabet = "abcdefghijklmnopqrstuvwxyz";

    std::string plaintext;
    std::cout << "Plaintext: ";
    std::cin >> plaintext;

    int plaintext_size = plaintext.size(); // length of plaintext
    int plaintext_array[plaintext_size];
    for (int i=0; i<plaintext_size; ++i) {
        plaintext_array[i] = INDX(plaintext[i]);
    } // massive for plaintext`s elements

    std::string key;
    std::cout << "Key: " ;
    std::cin >> key;
    int key_size = key.size();
    int key_array[key_size];
    for (int i=0; i<key_size; ++i) {
        key_array[i] = INDX(key[i]);
    } //massive for key`s elements

    int gamma_array[plaintext_size];
    for (int i=0; i<key_size; ++i) {
        gamma_array[i] = key_array[i];
    }
    for (int i=0; i<plaintext_size; ++i) {
        gamma_array[i + key_size] = plaintext_array[i];
    }

    std::string word;
    for (int i=0; i<plaintext_size; ++i) {
        int sum;
        sum = (plaintext_array[i] + gamma_array[i])%26;
        word += alphabet[sum];
    }
    std:: cout << "Encryption: "<<word << std::endl;

    std::string unencrypted;
    int new_array[plaintext_size];
    for (int i=0; i<plaintext_size; ++i) {
        new_array[i] = INDX(word[i]);
    }
    int res;
    for (int i=0; i<plaintext_size; ++i) {
        res = new_array[i] - gamma_array[i];
        if (res<0) {
            res = (res%26 + 26)%26;
        }
        unencrypted+= alphabet[res%26];
    }
    std:: cout << "Unencryption: " << unencrypted;
    return 0;
}