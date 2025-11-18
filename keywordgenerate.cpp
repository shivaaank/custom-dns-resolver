#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>

// Configuration
const std::string INPUT_FILE = "hosts.blocklist";
const std::string OUTPUT_FILE = "keywords.blocklist";
const int MIN_OCCURRENCES =30;
const size_t MIN_WORD_LENGTH = 5; // Safety: Avoid short generic words like "com", "net", "api"

// Helper to split string by delimiter
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

int main() {
    std::cout << "Opening " << INPUT_FILE << "..." << std::endl;
    std::ifstream infile(INPUT_FILE);
    if (!infile.is_open()) {
        std::cerr << "Error: Could not open " << INPUT_FILE << std::endl;
        return 1;
    }

    std::map<std::string, int> wordCounts;
    std::string line;
    long long processedLines = 0;

    while (std::getline(infile, line)) {
        // 1. Clean the line
        if (line.empty() || line[0] == '#') continue;
        
        // Lowercase the line for consistent matching
        for (auto & c: line) c = tolower(c);

        std::stringstream ss(line);
        std::string segment;
        std::vector<std::string> lineParts;
        while (ss >> segment) {
            lineParts.push_back(segment);
        }
        if (lineParts.empty()) continue;

        // 2. Extract the domain
        // Handle formats like "0.0.0.0 example.com" or just "example.com"
        std::string domain;
        if (lineParts.size() >= 2 && (lineParts[0] == "0.0.0.0" || lineParts[0] == "127.0.0.1")) {
             domain = lineParts[1];
        } else {
             domain = lineParts[0];
        }

        // 3. Split by '.'
        std::vector<std::string> parts = split(domain, '.');
        if (parts.empty()) continue;

        // 4. Find the longest word
        std::string longestWord;
        for (const auto& part : parts) {
            if (part.length() > longestWord.length()) {
                longestWord = part;
            }
        }

        // 5. Count it (if it meets safety length)
        if (longestWord.length() >= MIN_WORD_LENGTH) {
            wordCounts[longestWord]++;
        }
        
        processedLines++;
    }
    infile.close();
    std::cout << "Processed " << processedLines << " domains." << std::endl;

    // 6. Write valid keywords to file
    std::ofstream outfile(OUTPUT_FILE);
    if (!outfile.is_open()) {
        std::cerr << "Error: Could not create " << OUTPUT_FILE << std::endl;
        return 1;
    }

    int savedKeywords = 0;
    std::cout << "Filtering keywords with > " << MIN_OCCURRENCES << " occurrences..." << std::endl;

    for (const auto& pair : wordCounts) {
        // pair.first is the word, pair.second is the count
        if (pair.second > MIN_OCCURRENCES) {
            outfile << pair.first << std::endl;
            savedKeywords++;
        }
    }

    outfile.close();
    std::cout << "Success! Saved " << savedKeywords << " keywords to " << OUTPUT_FILE << std::endl;

    return 0;
}