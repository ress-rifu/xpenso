#include <iostream>
#include <fstream>
#include <openssl/aes.h>

using namespace std;

struct User
{
    string username;
    string password;
    double balance;
};

User *current_user = nullptr;

unsigned char *encrypt_data(const unsigned char *data, const unsigned char *key)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, AES_BLOCK_SIZE, &aes_key);

    unsigned char *encrypted_data = new unsigned char[AES_BLOCK_SIZE];
    AES_encrypt(data, encrypted_data, &aes_key);

    return encrypted_data;
}

unsigned char *decrypt_data(const unsigned char *encrypted_data, const unsigned char *key)
{
    AES_KEY aes_key;
    AES_set_decrypt_key(key, AES_BLOCK_SIZE, &aes_key);

    unsigned char *decrypted_data = new unsigned char[AES_BLOCK_SIZE];
    AES_decrypt(encrypted_data, decrypted_data, &aes_key);

    return decrypted_data;
}

void save_user_data(const User &user)
{
    unsigned char key[AES_BLOCK_SIZE];
    RAND_bytes(key, AES_BLOCK_SIZE);

    unsigned char *encrypted_user_data = encrypt_data((const unsigned char *)&user, key);

    ofstream out(user.username + ".dat");
    out << encrypted_user_data << endl;
    out.close();
}

User load_user_data(const string &username)
{
    ifstream in(username + ".dat");
    string encrypted_user_data;
    getline(in, encrypted_user_data);
    in.close();

    unsigned char *decrypted_user_data = decrypt_data((const unsigned char *)encrypted_user_data.c_str(), (const unsigned char *)username.c_str());

    User user;
    memcpy(&user, decrypted_user_data, sizeof(User));

    return user;
}

bool sign_in(const string &username, const string &password)
{
    User user = load_user_data(username);

    if (user.password != password)
    {
        return false;
    }

    current_user = &user;

    return true;
}

void sign_up(const string &username, const string &password)
{
    User user;
    user.username = username;
    user.password = password;
    user.balance = 0.0;

    save_user_data(user);
}

void add_budget(double amount)
{
    if (current_user == nullptr)
    {
        cout << "Please sign in first.";
        return;
    }

    current_user->balance += amount;

    save_user_data(*current_user);

    cout << "Budget added successfully.";
}

void add_transaction(double amount)
{
    if (current_user == nullptr)
    {
        cout << "Please sign in first.";
        return;
    }

    current_user->balance -= amount;

    save_user_data(*current_user);

    cout << "Transaction added successfully.";
}

int main()
{
    int option;

    do
    {
        cout << "1. Sign in" << endl;
        cout << "2. Sign up" << endl;
        cout << "3. Add budget" << endl;
        cout << "4. Add transaction" << endl;
        cout << "5. Exit" << endl;

        cout << "Enter your option: ";
        cin >> option;

        switch (option)
        {
        case 1:
        {
            string username, password;

            cout << "Enter your username: ";
            cin >> username;

            cout << "Enter your password: ";
            cin >> password;

            if (sign_in(username, password))
            {
                cout << "Sign in successful." << endl;
            }
            else
            {
                cout << "Invalid username or password." << endl;
            }
        case 2:
        {
            string username, password;

            cout << "Enter your username: ";
            cin >> username;

            cout << "Enter your password: ";
            cin >> password;

            sign_up(username, password);

            cout << "Sign up successful." << endl;
            break;
        }

        case 3:
        {
            double amount;

            cout << "Enter the amount to add: ";
            cin >> amount;

            add_budget(amount);

            break;
        }

        case 4:
        {
            double amount;

            cout << "Enter the amount to deduct: ";
            cin >> amount;

            add_transaction(amount);

            break;
        }

        case 5:
        {
            cout << "Goodbye!" << endl;

            break;
        }

        default:
        {
            cout << "Invalid option." << endl;
        }
        }
        }
        while (option != 5)
            ;

        return 0;
    }
    void add_budget(double amount)
    {
        if (current_user == nullptr)
        {
            cout << "Please sign in first.";
            return;
        }

        current_user->balance += amount;

        save_user_data(*current_user);

        cout << "Budget added successfully.";
    }
