

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <sstream>
#include <utility>
#include <vector>
#include <algorithm>

using namespace std;


int SOCKET_TIMEOUT_MS = 2000;  // Upstream query timeout
const char* BLOCKLIST_PATH = "hosts.blocklist";             // these contain lists to block
const char* KEYWORD_BLOCKLIST_PATH = "keywords.blocklist";              // these contain keywords to block created from the blocklist

const vector<string> ROOT_SERVERS = {
    "198.41.0.4",           // common root levels 
    "199.9.14.201", 
    "192.33.4.12",  
    "8.8.8.8",              // google dns server 
    "8.8.4.4",                      
    "1.1.1.1",              //Cloudfare dns server
    "1.0.0.1"                       
};


// Blocklist & Keywords

set<string> loadBlocklist(const string& path) {  
    ifstream file(path);
    set<string> blocked;     
    if (!file.is_open()) {
        cerr << "[!] Could not open blocklist: "<< path << "\n";
        return blocked;
    }

    string line;
    while (getline(file, line)) {              // traverse the blocklist and return all the hosts in a set 
        if (line.empty()|| line[0]=='#') {
            continue;
        }
        string host;
        string ip;
        istringstream iss(line);                
        if (iss>>ip>>host) {
            for (auto& c: host) c=static_cast<char>(tolower(c));
            blocked.insert(host);
        }
    }
    cout << "[+] Loaded "<<blocked.size() <<" blocked domains\n";
    return blocked;
}

vector<string> loadKeywords(const string& path) {
    ifstream file(path);
    vector<string> keywords;
    if (!file.is_open()) {
        cerr <<"[!] Could not open keyword blocklist: " <<path<<" (Running without keywords)\n";
            return keywords;
    }

        string line;
    while (getline(file, line)) {
                                                                                                        // Clean whitespace
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());                     //similar as hosts make a list of keywords from the file 
        
        if (!line.empty() && line[0]!='#') {
            for (auto& c: line)c=static_cast<char>(tolower(c));
            keywords.push_back(line);
        }
    }
    cout<<"[+] Loaded "<<keywords.size()<< "blocking keywords\n";
    return keywords;
}

// loaded the lists now we start caching 
struct CacheEntry {
    string ip;
    chrono::steady_clock::time_point timestamp;             // we let it go after designated time only temporary caching 
    bool failed;  // true if previous resolution failed
};

class DnsCache {            // this is our cache storage which stores each cache entry 
   public:
    string get(const string& domain) {
        auto it=cache_.find(domain);
        if (it ==cache_.end()) return "";
        if (it->second.failed) {
                                                                                // Allow retry after 6 minutes 
            auto elapsed = chrono::duration_cast<chrono::seconds>(              
                chrono::steady_clock::now() - it->second.timestamp);
            if (elapsed.count() < 360) {                                       
                return "0.0.0.0";               // dont retry keep it as failed 
            }
            cache_.erase(it);               // if its been 6 minutes then let it go and let the roots handle it 
            return "";
        }
        return it->second.ip;
    }

    void setSuccess(const string& domain, const string& ip) {
        cache_[domain] = CacheEntry{ip, chrono::steady_clock::now(), false};
    }

    void setFailure(const string& domain) {
        cache_[domain] = CacheEntry{"0.0.0.0", chrono::steady_clock::now(), true};
    }

   private:
    unordered_map<string, CacheEntry> cache_;
};

DnsCache dnsCache;

// ---------------------------
// DNS wire helpers
// ---------------------------
vector<uint8_t> encodeName(const string& name) {
    if (name.empty()) return {0};
    vector<uint8_t> out;
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == string::npos) dot = name.size();
        size_t len = dot - start;
        out.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) out.push_back(static_cast<uint8_t>(name[start + i]));
        start = dot + 1;
    }
    out.push_back(0);
    return out;
}

pair<string, size_t> decodeName(const vector<uint8_t>& data, size_t offset) {
    string name;
    size_t orig_offset = offset;
    bool jumped = false;
    while (offset < data.size()) {
        uint8_t len = data[offset];
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= data.size()) break;
            uint16_t pointer = static_cast<uint16_t>((len & 0x3F) << 8 | data[offset + 1]);
            if (!jumped) {
                orig_offset = offset + 2;
            }
            offset = pointer;
            jumped = true;
            continue;
        }
        if (len == 0) {
            offset += 1;
            break;
        }
        if (!name.empty()) name.push_back('.');
        if (offset + 1 + len > data.size()) break;
        name.append(reinterpret_cast<const char*>(&data[offset + 1]), len);
        offset += len + 1;
    }
    return {name, jumped ? orig_offset : offset};
}

pair<uint16_t, vector<uint8_t>> buildQuery(const string& domain, uint16_t qtype = 1) {
    static random_device rd;
    static mt19937 gen(rd());
    uniform_int_distribution<uint16_t> dist(0, 0xFFFF);
    uint16_t tid = dist(gen);

    vector<uint8_t> packet(12, 0);
    packet[0] = static_cast<uint8_t>(tid >> 8);
    packet[1] = static_cast<uint8_t>(tid & 0xFF);
    packet[2] = 0x01;  // RD=1
    packet[5] = 0x01;  // QDCOUNT=1

    auto qname = encodeName(domain);
    packet.insert(packet.end(), qname.begin(), qname.end());
    packet.push_back(static_cast<uint8_t>(qtype >> 8));
    packet.push_back(static_cast<uint8_t>(qtype & 0xFF));
    packet.push_back(0x00);
    packet.push_back(0x01);  // QCLASS IN

    return {tid, packet};
}

struct ResourceRecord {
    uint16_t type;
    uint16_t clas;
    uint32_t ttl;
    vector<uint8_t> rdata;
};

size_t parseQuestion(const vector<uint8_t>& data, size_t offset) {
    auto [_, new_offset] = decodeName(data, offset);
    if (new_offset + 4 > data.size()) return data.size();
    return new_offset + 4;
}

vector<ResourceRecord> readRRs(const vector<uint8_t>& data, size_t& offset, uint16_t count) {
    vector<ResourceRecord> out;
    for (uint16_t i = 0; i < count && offset < data.size(); ++i) {
        auto [name, next_offset] = decodeName(data, offset);
        offset = next_offset;
        if (offset + 10 > data.size()) break;
        uint16_t rtype = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        uint16_t rclass = static_cast<uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
        uint32_t ttl = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];
        uint16_t rdlen = static_cast<uint16_t>((data[offset + 8] << 8) | data[offset + 9]);
        offset += 10;
        if (offset + rdlen > data.size()) break;
        vector<uint8_t> rdata(data.begin() + offset, data.begin() + offset + rdlen);
        offset += rdlen;
        out.push_back({rtype, rclass, ttl, move(rdata)});
    }
    return out;
}

// ---------------------------
// Upstream communication
// ---------------------------
vector<uint8_t> sendUpstreamQuery(const string& server_ip, const vector<uint8_t>& packet) {
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) throw runtime_error("socket failed");

    timeval tv{};
    tv.tv_sec = SOCKET_TIMEOUT_MS / 1000;
    tv.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr(server_ip.c_str());

    if (sendto(sock, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        throw runtime_error("sendto failed");
    }

    vector<uint8_t> buffer(4096);
    socklen_t addrlen = sizeof(addr);
    ssize_t received = recvfrom(sock, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&addr), &addrlen);
    close(sock);
    if (received < 0) throw runtime_error("recvfrom failed");
    buffer.resize(static_cast<size_t>(received));
    return buffer;
}

string findARecord(const string& domain) {
    string domain_lower = domain;
    for (auto& c : domain_lower) c = static_cast<char>(tolower(c));

    // Cache check
    string cached = dnsCache.get(domain_lower);
    if (!cached.empty()) {
        if (cached == "0.0.0.0") {
            cout << "[CACHE] " << domain_lower << " failed previously.\n";
            return "0.0.0.0";
        }
        cout << "[CACHE] " << domain_lower << " -> " << cached << "\n";
        return cached;
    }

    cout << "[DEBUG] Resolving A record for " << domain_lower << "...\n";
    static random_device rd;
    static mt19937 gen(rd());
    uniform_int_distribution<size_t> dist(0, ROOT_SERVERS.size() - 1);

    for (int attempt = 0; attempt < 5; ++attempt) {
        string server = ROOT_SERVERS[dist(gen)];
        try {
            auto [tid, packet] = buildQuery(domain_lower, 1);
            cout << "[QUERY] " << server << " <- " << domain_lower << "\n";
            auto resp = sendUpstreamQuery(server, packet);

            if (resp.size() < 12) continue;
            uint16_t qdcount = static_cast<uint16_t>((resp[4] << 8) | resp[5]);
            uint16_t ancount = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
            size_t offset = 12;
            for (uint16_t i = 0; i < qdcount; ++i) {
                offset = parseQuestion(resp, offset);
            }
            auto answers = readRRs(resp, offset, ancount);
            for (const auto& rr : answers) {
                if (rr.type == 1 && rr.rdata.size() == 4) {
                    char ip_buf[INET_ADDRSTRLEN]{};
                    inet_ntop(AF_INET, rr.rdata.data(), ip_buf, sizeof(ip_buf));
                    string ip(ip_buf);
                    dnsCache.setSuccess(domain_lower, ip);
                    cout << "[ANSWER] " << domain_lower << " -> " << ip << "\n";
                    return ip;
                }
            }
        } catch (const exception& ex) {
            cerr << "[ERROR] Upstream " << server << ": " << ex.what() << "\n";
            continue;
        }
    }

    cerr << "[!] Could not resolve " << domain_lower << ", returning 0.0.0.0\n";
    dnsCache.setFailure(domain_lower);
    return "0.0.0.0";
}

// ---------------------------
// Response builder
// ---------------------------
vector<uint8_t> buildResponse(const vector<uint8_t>& request, const string& ip, bool nxdomain) {
    if (request.size() < 12) return {};
    vector<uint8_t> response;
    response.reserve(request.size() + 16);

    uint16_t tid = static_cast<uint16_t>((request[0] << 8) | request[1]);
    response.push_back(static_cast<uint8_t>(tid >> 8));
    response.push_back(static_cast<uint8_t>(tid & 0xFF));

    uint8_t rd_flag = request[2] & 0x01;
    uint16_t flags = 0x8000 | (rd_flag << 8);  // QR=1, RA=1
    if (nxdomain) {
        flags |= 0x0003;  // RCODE=3
    } else {
        flags |= 0x0080;  // RA
    }
    response.push_back(static_cast<uint8_t>(flags >> 8));
    response.push_back(static_cast<uint8_t>(flags & 0xFF));

    // QDCOUNT
    response.push_back(request[4]);
    response.push_back(request[5]);
    // ANCOUNT
    response.push_back(0x00);
    response.push_back(0x01);
    // NSCOUNT, ARCOUNT
    response.insert(response.end(), {0x00, 0x00, 0x00, 0x00});

    // Copy question
    size_t offset = 12;
    while (offset < request.size() && request[offset] != 0) {
        offset += request[offset] + 1;
    }
    offset += 1 + 4;  // null + QTYPE/QCLASS
    response.insert(response.end(), request.begin() + 12, request.begin() + offset);

    // Answer
    response.push_back(0xC0);
    response.push_back(0x0C);  // pointer to name
    response.push_back(0x00);
    response.push_back(0x01);  // TYPE A
    response.push_back(0x00);
    response.push_back(0x01);  // CLASS IN
    response.insert(response.end(), {0x00, 0x00, 0x00, 0x3C});  // TTL 60s
    response.push_back(0x00);
    response.push_back(0x04);  // RDLENGTH

    in_addr addr{};
    inet_aton(ip.c_str(), &addr);
    auto* raw = reinterpret_cast<uint8_t*>(&addr.s_addr);
    response.insert(response.end(), raw, raw + 4);

    return response;
}

// ---------------------------
// Main server
// ---------------------------
bool running = true;

void handleSignal(int) { running = false; }

void serve(const string& bind_addr, uint16_t port, 
           const set<string>& blocklist, 
           const vector<string>& keywordBlocklist) {
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw runtime_error("Failed to create socket");
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(bind_addr.c_str());

    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        throw runtime_error("Bind failed (try port 5353 if not root)");
    }

    cout << "[+] DNS UDP server listening on " << bind_addr << ":" << port << "\n";

    vector<uint8_t> buffer(4096);
    while (running) {
        sockaddr_in client{};
        socklen_t clen = sizeof(client);
        ssize_t n = recvfrom(sock, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&client), &clen);
        if (n <= 0) continue;

        vector<uint8_t> request(buffer.begin(), buffer.begin() + n);
        try {
            auto [qname, offset] = decodeName(request, 12);
            if (qname.empty()) {
                cerr << "[WARN] Empty query name\n";
                continue;
            }
            for (auto& c : qname) c = static_cast<char>(tolower(c));
            cout << "[QUERY] " << qname << " from " << inet_ntoa(client.sin_addr) << "\n";

            bool blocked = false;

            // 1. Standard Blocklist Check (Suffix Matching)
            size_t pos = 0;
            while (pos < qname.size()) {
                if (blocklist.count(qname.substr(pos))) {
                    cout << "[BLOCKED-DOMAIN] " << qname << " matched suffix: " << qname.substr(pos) << "\n";
                    blocked = true;
                    break; // Exit loop immediately if blocked
                }
                auto dot = qname.find('.', pos);
                if (dot == string::npos) break;
                pos = dot + 1;
            }

            // 2. Keyword Blocklist Check (Substring Matching)
            // Only run if not already blocked by the standard list
            if (!blocked) {
                for (const auto& keyword : keywordBlocklist) {
                    if (qname.find(keyword) != string::npos) {
                        cout << "[BLOCKED-KEYWORD] " << qname << " matched keyword: '" << keyword << "'\n";
                        blocked = true;
                        break; // Exit loop immediately if blocked
                    }
                }
            }

            string ip = "0.0.0.0";
            bool nxdomain = false;
            if (blocked) {
                nxdomain = true;
            } else {
                ip = findARecord(qname);
            }

            auto response = buildResponse(request, ip, nxdomain);
            sendto(sock, response.data(), response.size(), 0, reinterpret_cast<sockaddr*>(&client), clen);
        } catch (const exception& ex) {
            cerr << "[ERROR] Processing request: " << ex.what() << "\n";
        }
    }

    close(sock);
}

 // namespace

int main(int argc, char* argv[]) {
    string bind_addr = "0.0.0.0";
    uint16_t port = 53;
    if (argc >= 2) {
        port = static_cast<uint16_t>(stoi(argv[1]));
    }
    if (argc >= 3) {
        bind_addr = argv[2];
    }

    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);

    auto blocklist = loadBlocklist(BLOCKLIST_PATH);
    auto keywordBlocklist = loadKeywords(KEYWORD_BLOCKLIST_PATH);

    try {
        serve(bind_addr, port, blocklist, keywordBlocklist);
    } catch (const exception& ex) {
        cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }
    cout << "[!] Shutting down server\n";
    return 0;
}