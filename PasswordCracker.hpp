//
//  PasswordCracker.hpp
//  password-mac
//
//  Created by Arfan Rehab on 2/7/17.
//  Copyright © 2017 Sanjay Madhav. All rights reserved.
//

#ifndef PasswordCracker_hpp
#define PasswordCracker_hpp

#include <stdio.h>
#include <unordered_map>
#include <map>
#include <vector>
#include <string>
#include "SolvedPass.h"
#include "UnsolvedPass.h"

class PasswordCracker
{
public:
    PasswordCracker(std::string dictionaryName, std::string passwordName);
    // check for valid files
    bool ValidFiles();
    // hash all dictionary passwords
    void ProcessDictionary();
    // find passwords that can easily be solved
    void DecryptDictionary();
    // counting machine method
    void BruteForce();
    // size four password brute force for parallelization
    void SizeFourBrute(int max, int start, int end);
    
private:
    // file name vars
    std::string mDictionaryFile;
    std::string mPasswordFile;
    // hash table of passwords
    std::unordered_map<std::string, std::string> mHashedDictionary;
    // map of all solved passwords
    std::map<int, SolvedPass*> mSolved;
    // vector of all unsolved passwords to brute force
    std::vector<UnsolvedPass*> mUnsolved;
    
};

#endif /* PasswordCracker_hpp */
