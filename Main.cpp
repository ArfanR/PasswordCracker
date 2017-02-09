// Main.cpp : Defines the entry point for the console application.
//
#include <iostream>
#include <string>
#include "Sha1.h"
#include "PasswordCracker.hpp"


int main(int argc, char* argv[])
{
    if (argc == 2)
    {
        unsigned char hash[20];
        char hex_str[41];
        sha1::calc(argv[1], strlen(argv[1]), hash);
        sha1::toHexString(hash, hex_str);
        std::cout<< hex_str << std::endl;
    }
    
    else if (argc == 3)
    {
        PasswordCracker cracker(argv[1], argv[2]);
        
        if (cracker.ValidFiles())
        {
            cracker.ProcessDictionary();
            cracker.DecryptDictionary();
            cracker.BruteForce();
        }
        else
        {
            exit(0);
        }
    }
    
    return 0;
    
}

