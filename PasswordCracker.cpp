//
//  PasswordCracker.cpp
//  password-mac
//
//  Created by Arfan Rehab on 2/7/17.
//  Copyright © 2017 Sanjay Madhav. All rights reserved.
//

#include "PasswordCracker.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include "Timer.h"
#include "Sha1.h"
#include "SolvedPass.h"
#include "UnsolvedPass.h"
#include <tbb/parallel_invoke.h>

PasswordCracker::PasswordCracker(std::string dictionaryName, std::string passwordName)
{
    mDictionaryFile = dictionaryName;
    mPasswordFile = passwordName;
    mHashedDictionary.rehash(100000);
}

bool PasswordCracker::ValidFiles()
{
    bool dictFile = true;
    bool passFile = true;

    //check if dictionary file exists
    if (std::ifstream(mDictionaryFile))
    {
        std::cout << "Dictionary File exists!" << std::endl;
    }
    else
    {
        std::cout << "Dictionary file does not exist!" << std::endl;
        dictFile = false;
    }
    
    // check if password file exists
    if (std::ifstream(mPasswordFile))
    {
        std::cout << "Password File exists" << std::endl;
    }
    else
    {
        std::cout << "Password File does not exist!" << std::endl;
        passFile = false;
    }
    
    return (dictFile && passFile);
}

void PasswordCracker::ProcessDictionary()
{
    Timer timer;
    timer.start();
    
    std::ifstream dictFile(mDictionaryFile);
    std::string line;
    
    // iterate through dictionary line by line
    while (!dictFile.eof())
    {
        std::getline(dictFile, line);
        
        unsigned char hash[20];
        char hex_str[41];
        const char *pass = line.c_str();
        sha1::calc(pass, line.length(), hash);
        sha1::toHexString(hash, hex_str);
        mHashedDictionary[std::string(hex_str)] = line;
    }
    
    // print out time elapsed to load dictionary
    double elapsed = timer.getElapsed();
    std::cout << "Time to load the full dictionary: " << elapsed << std::endl;
    dictFile.close();
}

void PasswordCracker::DecryptDictionary()
{
    std::ifstream passFile(mPasswordFile);
    std::string outputFile = "pass_solved.txt";
    std::string hashCheck = "";
    int entryNum = 0;
    
    // iterate through each password
    while (!passFile.eof())
    {
        std::getline(passFile, hashCheck);
        auto iter = mHashedDictionary.find(hashCheck);
        
        // password is not found
        if (iter == mHashedDictionary.end())
        {
            // put question mark into solved map
            SolvedPass* solved = new SolvedPass;
            solved->hexPass = hashCheck;
            solved->plainText = "???";
            mSolved[entryNum] = solved;
            
            // put into unsolved vector
            UnsolvedPass* unsolved = new UnsolvedPass;
            unsolved->entryNum = entryNum;
            unsolved->hexPass = hashCheck;
            mUnsolved.push_back(unsolved);
        }
        // password is found
        else
        {
            // put into solved map
            SolvedPass* pass = new SolvedPass;
            pass->hexPass = iter->first;
            pass->plainText = iter->second;
            mSolved[entryNum] = pass;
        }
        entryNum++;
    }
    passFile.close();

}

void PasswordCracker::BruteForce()
{
    Timer brute;
    brute.start();
    
    // arrays to serialize passwords of up to size three
    char sizeOne[1], sizeTwo[2], sizeThree[3];
    for (int i = 0; i < 3; i++)
    {
        if (i == 0)
        {
            sizeOne[i] = 'a';
        }
        if (i == 0 || i == 1)
        {
            sizeTwo[i] = 'a';
        }
        sizeThree[i] = 'a';
    }
    
    // counting machine for password of size 1
    for (int i = 0; i < 35; i++)
    {
        // hash the current value
        std::string pass(1, sizeOne[0]);
        const char * sizeOnePass = pass.c_str();
        unsigned char hash[20];
        char hex_str[41];
        sha1::calc(sizeOnePass, 1, hash);
        sha1::toHexString(hash, hex_str);
        
        // search for unsolved password/put into map of solved passwords
        for(int j = 0; j < mUnsolved.size(); j++)
        {
            if(hex_str == (mUnsolved[j]->hexPass))
            {
                SolvedPass* pass = new SolvedPass;
                pass->hexPass = hex_str;
                pass->plainText = sizeOnePass;
                mSolved[mUnsolved[j]->entryNum] = pass;
            }
            
        }
        
        // update char to next value
        if (i == 25)
        {
            sizeOne[0] = '0';
        }
        else
        {
            sizeOne[0] = static_cast<char>(sizeOne[0] + 1);
        }
        
    }
    
    // counting machine for password of size 2
    for (int i = 0; i < 1296; i++)
    {
        // hash the current value
        char sizeTwoPass[] = {sizeTwo[0], sizeTwo[1], '\0'};
        unsigned char hash[20];
        char hex_str[41];
        sha1::calc(sizeTwoPass, 2, hash);
        sha1::toHexString(hash, hex_str);
        
        // search for unsolved password/put into map of solved passwords
        for(int j = 0; j < mUnsolved.size(); j++)
        {
            if(hex_str == (mUnsolved[j]->hexPass))
            {
                SolvedPass* pass = new SolvedPass;
                pass->hexPass = hex_str;
                pass->plainText = sizeTwoPass;
                mSolved[mUnsolved[j]->entryNum] = pass;
            }
            
        }
        
        // update char to next value
        if (sizeTwo[1] == 'z')
        {
            sizeTwo[1] = '0';
        }
        else
        {
            sizeTwo[1] = static_cast<char>(sizeTwo[1] + 1);
        }
        
        if ((i % 36 == 0) && (i > 0))
        {
            sizeTwo[1] = 'a';
            if (sizeTwo[0] == 'z')
            {
                sizeTwo[0] = '0';
            }
            else
            {
                sizeTwo[0] = static_cast<char>(sizeTwo[0] + 1);
            }
        }
        
    }
    
    // make counting machine for password of size 3
    for (int i = 0; i < 46656; i++)
    {
        // hash the current value
        char sizeThreePass[] = {sizeThree[0], sizeThree[1], sizeThree[2], '\0'};
        unsigned char hash[20];
        char hex_str[41];
        sha1::calc(sizeThreePass, 3, hash);
        sha1::toHexString(hash, hex_str);
        
        // search for unsolved password/put into map of solved passwords
        for(int j = 0; j < mUnsolved.size(); j++)
        {
            if(hex_str == (mUnsolved[j]->hexPass))
            {
                SolvedPass* pass = new SolvedPass;
                pass->hexPass = hex_str;
                pass->plainText = sizeThreePass;
                mSolved[mUnsolved[j]->entryNum] = pass;
            }
            
        }
        
        // update last char value
        if (sizeThree[2] == 'z')
        {
            sizeThree[2] = '0';
        }
        else
        {
            sizeThree[2] = static_cast<char>(sizeThree[2] + 1);
        }
        // update second to last char
        if ((i % 36 == 0) && (i > 0))
        {
            sizeThree[2] = 'a';
            if (sizeThree[1] == 'z')
            {
                sizeThree[1] = '0';
            }
            else
            {
                sizeThree[1] = static_cast<char>(sizeThree[1] + 1);
            }
        }
        // iteration for first char
        if ((i % 1296 == 0) && (i > 1295))
        {
            sizeThree[1] = 'a';
            sizeThree[2] = 'a';
            if (sizeThree[0] == 'z')
            {
                sizeThree[0] = '0';
            }
            else
            {
                sizeThree[0] = static_cast<char>(sizeThree[0] + 1);
            }
        }
    }
    
    // parallel brute force for size four
    int max = 1679616;
    tbb::parallel_invoke(
        [this, max] { SizeFourBrute(max, 0, (max/9)); },
        [this, max] { SizeFourBrute(max, max/9 + 1, 2*(max/9)); },
        [this, max] { SizeFourBrute(max, 2*(max/9) + 1, 3*(max/9)); },
        [this, max] { SizeFourBrute(max, 3*(max/9) + 1, 4*(max/9)); },
        [this, max] { SizeFourBrute(max, 4*(max/9) + 1, 5*(max/9)); },
        [this, max] { SizeFourBrute(max, 5*(max/9) + 1, 6*(max/9)); },
        [this, max] { SizeFourBrute(max, 6*(max/9) + 1, 7*(max/9)); },
        [this, max] { SizeFourBrute(max, 7*(max/9) + 1, 8*(max/9)); },
        [this, max] { SizeFourBrute(max, 8*(max/9) + 1, 9*(max/9)); }
    );
    
    std::cout << "Time elapsed for brute force: " << brute.getElapsed() << std::endl;
    
    // print solved passwords to the output file
    std::ofstream output("pass_solved.txt");
    for(int i = 0; i < mSolved.size(); i++)
    {
        output << i + 1 << ": " << mSolved[i]->hexPass << ", " << mSolved[i]->plainText << std::endl << std::endl;
    }
    output.close();
}

void PasswordCracker::SizeFourBrute(int max, int start, int end)
{
    char sizeFour[4];
    if (start == 0)
    {
        sizeFour[0] = 'a';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == (max/9)+1)
    {
        sizeFour[0] = 'e';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == 2*(max/9)+1)
    {
        sizeFour[0] = 'i';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == 3*(max/9)+1)
    {
        sizeFour[0] = 'm';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == 4*(max/9)+1)
    {
        sizeFour[0] = 'q';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == 5*(max/9)+1)
    {
        sizeFour[0] = 'u';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == 6*(max/9)+1)
    {
        sizeFour[0] = 'y';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == 7*(max/9)+1)
    {
        sizeFour[0] = '2';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    else if (start == 7*(max/9)+1)
    {
        sizeFour[0] = '6';
        sizeFour[1] = 'a';
        sizeFour[2] = 'a';
        sizeFour[3] = 'a';
    }
    
    // make counting machine for password of size 4
    for (int i = start; i < end; i++)
    {
        // hash the current value
        char sizeFourPass[] = {sizeFour[0], sizeFour[1], sizeFour[2], sizeFour[3], '\0'};
        unsigned char hash[20];
        char hex_str[41];
        sha1::calc(sizeFourPass, 4, hash);
        sha1::toHexString(hash, hex_str);
        
        // search for unsolved password/put into map of solved passwords
        for(int j = 0; j < mUnsolved.size(); j++)
        {
            if(hex_str == (mUnsolved[j]->hexPass))
            {
                SolvedPass* pass = new SolvedPass;
                pass->hexPass = hex_str;
                pass->plainText = sizeFourPass;
                mSolved[mUnsolved[j]->entryNum] = pass;
            }
            
        }
        
        // update last char value
        if (sizeFour[3] == 'z')
        {
            sizeFour[3] = '0';
        }
        else
        {
            sizeFour[3] = static_cast<char>(sizeFour[3] + 1);
        }
        // update third char
        if ((i % 36 == 0) && (i > 0))
        {
            sizeFour[3] = 'a';
            if (sizeFour[2] == 'z')
            {
                sizeFour[2] = '0';
            }
            else
            {
                sizeFour[2] = static_cast<char>(sizeFour[2] + 1);
            }
        }
        // iteration for second char
        if ((i % 1296 == 0) && (i > 1295))
        {
            sizeFour[2] = 'a';
            sizeFour[3] = 'a';
            if (sizeFour[1] == 'z')
            {
                sizeFour[1] = '0';
            }
            else
            {
                sizeFour[1] = static_cast<char>(sizeFour[1] + 1);
            }
        }
        // iteration for first char
        if ((i % 46656 == 0) && (i > 46655))
        {
            sizeFour[1] = 'a';
            sizeFour[2] = 'a';
            sizeFour[3] = 'a';
            if (sizeFour[0] == 'z')
            {
                sizeFour[0] = '0';
            }
            else
            {
                sizeFour[0] = static_cast<char>(sizeFour[0] + 1);
            }
        }
    }

}






