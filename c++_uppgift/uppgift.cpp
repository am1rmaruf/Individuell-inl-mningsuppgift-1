#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cstring>

using namespace std;

/* Små hjälpfunktioner */
static string trim(const string& s)
{
    int start = 0;
    int end = (int)s.size() - 1;

    while (start <= end && isspace((unsigned char)s[start])) start++;
    while (end >= start && isspace((unsigned char)s[end])) end--;

    if (start > end) return "";
    return s.substr(start, end - start + 1);
}

static bool containsColon(const string& s)
{
    for (char ch : s) if (ch == ':') return true;
    return false;
}

/* MD5 (standardkod i samma fil, utan lambda och auto) */
static unsigned int L(unsigned int x, int c) { return (x << c) | (x >> (32 - c)); }

static unsigned int F(unsigned int x, unsigned int y, unsigned int z) { return (x & y) | (~x & z); }
static unsigned int G(unsigned int x, unsigned int y, unsigned int z) { return (x & z) | (y & ~z); }
static unsigned int H(unsigned int x, unsigned int y, unsigned int z) { return x ^ y ^ z; }
static unsigned int I(unsigned int x, unsigned int y, unsigned int z) { return y ^ (x | ~z); }

static void FF(unsigned int& a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, int s, unsigned int ac)
{
    a = a + F(b, c, d) + x + ac;
    a = L(a, s) + b;
}
static void GG(unsigned int& a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, int s, unsigned int ac)
{
    a = a + G(b, c, d) + x + ac;
    a = L(a, s) + b;
}
static void HH(unsigned int& a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, int s, unsigned int ac)
{
    a = a + H(b, c, d) + x + ac;
    a = L(a, s) + b;
}
static void II(unsigned int& a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, int s, unsigned int ac)
{
    a = a + I(b, c, d) + x + ac;
    a = L(a, s) + b;
}

static void md5_transform(unsigned int st[4], const unsigned char block[64])
{
    unsigned int a = st[0], b = st[1], c = st[2], d = st[3];
    unsigned int x[16];

    for (int i = 0; i < 16; i++)
    {
        int j = i * 4;
        x[i] = (unsigned int)block[j] |
               ((unsigned int)block[j + 1] << 8) |
               ((unsigned int)block[j + 2] << 16) |
               ((unsigned int)block[j + 3] << 24);
    }

    FF(a,b,c,d,x[0],7,0xd76aa478);  FF(d,a,b,c,x[1],12,0xe8c7b756);
    FF(c,d,a,b,x[2],17,0x242070db); FF(b,c,d,a,x[3],22,0xc1bdceee);
    FF(a,b,c,d,x[4],7,0xf57c0faf);  FF(d,a,b,c,x[5],12,0x4787c62a);
    FF(c,d,a,b,x[6],17,0xa8304613); FF(b,c,d,a,x[7],22,0xfd469501);
    FF(a,b,c,d,x[8],7,0x698098d8);  FF(d,a,b,c,x[9],12,0x8b44f7af);
    FF(c,d,a,b,x[10],17,0xffff5bb1);FF(b,c,d,a,x[11],22,0x895cd7be);
    FF(a,b,c,d,x[12],7,0x6b901122); FF(d,a,b,c,x[13],12,0xfd987193);
    FF(c,d,a,b,x[14],17,0xa679438e);FF(b,c,d,a,x[15],22,0x49b40821);

    GG(a,b,c,d,x[1],5,0xf61e2562);  GG(d,a,b,c,x[6],9,0xc040b340);
    GG(c,d,a,b,x[11],14,0x265e5a51);GG(b,c,d,a,x[0],20,0xe9b6c7aa);
    GG(a,b,c,d,x[5],5,0xd62f105d);  GG(d,a,b,c,x[10],9,0x02441453);
    GG(c,d,a,b,x[15],14,0xd8a1e681);GG(b,c,d,a,x[4],20,0xe7d3fbc8);
    GG(a,b,c,d,x[9],5,0x21e1cde6);  GG(d,a,b,c,x[14],9,0xc33707d6);
    GG(c,d,a,b,x[3],14,0xf4d50d87); GG(b,c,d,a,x[8],20,0x455a14ed);
    GG(a,b,c,d,x[13],5,0xa9e3e905); GG(d,a,b,c,x[2],9,0xfcefa3f8);
    GG(c,d,a,b,x[7],14,0x676f02d9); GG(b,c,d,a,x[12],20,0x8d2a4c8a);

    HH(a,b,c,d,x[5],4,0xfffa3942);  HH(d,a,b,c,x[8],11,0x8771f681);
    HH(c,d,a,b,x[11],16,0x6d9d6122);HH(b,c,d,a,x[14],23,0xfde5380c);
    HH(a,b,c,d,x[1],4,0xa4beea44);  HH(d,a,b,c,x[4],11,0x4bdecfa9);
    HH(c,d,a,b,x[7],16,0xf6bb4b60); HH(b,c,d,a,x[10],23,0xbebfbc70);
    HH(a,b,c,d,x[13],4,0x289b7ec6); HH(d,a,b,c,x[0],11,0xeaa127fa);
    HH(c,d,a,b,x[3],16,0xd4ef3085); HH(b,c,d,a,x[6],23,0x04881d05);
    HH(a,b,c,d,x[9],4,0xd9d4d039);  HH(d,a,b,c,x[12],11,0xe6db99e5);
    HH(c,d,a,b,x[15],16,0x1fa27cf8);HH(b,c,d,a,x[2],23,0xc4ac5665);

    II(a,b,c,d,x[0],6,0xf4292244);  II(d,a,b,c,x[7],10,0x432aff97);
    II(c,d,a,b,x[14],15,0xab9423a7);II(b,c,d,a,x[5],21,0xfc93a039);
    II(a,b,c,d,x[12],6,0x655b59c3); II(d,a,b,c,x[3],10,0x8f0ccc92);
    II(c,d,a,b,x[10],15,0xffeff47d);II(b,c,d,a,x[1],21,0x85845dd1);
    II(a,b,c,d,x[8],6,0x6fa87e4f);  II(d,a,b,c,x[15],10,0xfe2ce6e0);
    II(c,d,a,b,x[6],15,0xa3014314); II(b,c,d,a,x[13],21,0x4e0811a1);
    II(a,b,c,d,x[4],6,0xf7537e82);  II(d,a,b,c,x[11],10,0xbd3af235);
    II(c,d,a,b,x[2],15,0x2ad7d2bb); II(b,c,d,a,x[9],21,0xeb86d391);

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

struct MD5Ctx
{
    unsigned int st[4];
    unsigned int count[2];
    unsigned char buffer[64];
};

static void md5_init(MD5Ctx& ctx)
{
    ctx.st[0] = 0x67452301;
    ctx.st[1] = 0xefcdab89;
    ctx.st[2] = 0x98badcfe;
    ctx.st[3] = 0x10325476;
    ctx.count[0] = 0;
    ctx.count[1] = 0;
}

static void md5_update(MD5Ctx& ctx, const unsigned char* data, size_t len)
{
    size_t idx = (ctx.count[0] >> 3) & 63;
    unsigned int bits = (unsigned int)(len << 3);

    ctx.count[0] += bits;
    if (ctx.count[0] < bits) ctx.count[1]++;
    ctx.count[1] += (unsigned int)(len >> 29);

    size_t part = 64 - idx;
    size_t i = 0;

    if (len >= part)
    {
        memcpy(ctx.buffer + idx, data, part);
        md5_transform(ctx.st, ctx.buffer);

        for (i = part; i + 63 < len; i += 64)
            md5_transform(ctx.st, data + i);

        idx = 0;
    }

    memcpy(ctx.buffer + idx, data + i, len - i);
}

static void md5_final(MD5Ctx& ctx)
{
    unsigned char padding[64];
    for (int i = 0; i < 64; i++) padding[i] = 0;
    padding[0] = 0x80;

    unsigned char bits[8];
    bits[0] = ctx.count[0] & 255;
    bits[1] = (ctx.count[0] >> 8) & 255;
    bits[2] = (ctx.count[0] >> 16) & 255;
    bits[3] = (ctx.count[0] >> 24) & 255;
    bits[4] = ctx.count[1] & 255;
    bits[5] = (ctx.count[1] >> 8) & 255;
    bits[6] = (ctx.count[1] >> 16) & 255;
    bits[7] = (ctx.count[1] >> 24) & 255;

    size_t idx = (ctx.count[0] >> 3) & 63;
    size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);

    md5_update(ctx, padding, padLen);
    md5_update(ctx, bits, 8);
}

static string md5(const string& input)
{
    MD5Ctx ctx;
    md5_init(ctx);

    md5_update(ctx, (const unsigned char*)input.c_str(), input.size());
    md5_final(ctx);

    unsigned char out[16];
    for (int i = 0; i < 4; i++)
    {
        out[i*4]     = ctx.st[i] & 255;
        out[i*4 + 1] = (ctx.st[i] >> 8) & 255;
        out[i*4 + 2] = (ctx.st[i] >> 16) & 255;
        out[i*4 + 3] = (ctx.st[i] >> 24) & 255;
    }

    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < 16; i++) ss << setw(2) << (int)out[i];
    return ss.str();
}

/* Enkla kontroller */
static bool emailOk(const string& email)
{
    if (email.empty()) return false;
    if (containsColon(email)) return false;

    int at = -1;
    for (int i = 0; i < (int)email.size(); i++)
        if (email[i] == '@') { at = i; break; }

    if (at <= 0) return false;

    for (int i = at + 1; i < (int)email.size(); i++)
        if (email[i] == '.') return true;

    return false;
}

static bool passwordOk(const string& pw, string& msg)
{
    if (pw.size() < 8) { msg = "Minst 8 tecken"; return false; }

    bool upper = false, lower = false, digit = false, special = false;

    for (char ch : pw)
    {
        unsigned char c = (unsigned char)ch;
        if (isupper(c)) upper = true;
        else if (islower(c)) lower = true;
        else if (isdigit(c)) digit = true;
        else if (!isspace(c)) special = true;
    }

    if (!upper) { msg = "Minst en stor bokstav"; return false; }
    if (!lower) { msg = "Minst en liten bokstav"; return false; }
    if (!digit) { msg = "Minst en siffra"; return false; }
    if (!special) { msg = "Minst ett specialtecken"; return false; }

    msg = "";
    return true;
}

/* Fil */
static vector<pair<string,string>> loadUsers(const string& file)
{
    vector<pair<string,string>> users;
    ifstream in(file);
    string line;

    while (getline(in, line))
    {
        size_t pos = line.find(':');
        if (pos == string::npos) continue;

        string user = line.substr(0, pos);
        string hash = line.substr(pos + 1);

        if (!user.empty() && !hash.empty())
            users.push_back({user, hash});
    }

    return users;
}

static bool existsUser(const vector<pair<string,string>>& users, const string& email)
{
    for (int i = 0; i < (int)users.size(); i++)
        if (users[i].first == email) return true;
    return false;
}

static void createUser(const string& file)
{
    auto users = loadUsers(file);

    cout << "Epost: ";
    string email;
    getline(cin, email);
    email = trim(email);

    if (!emailOk(email)) { cout << "Fel: Ogiltig epost\n"; return; }
    if (existsUser(users, email)) { cout << "Fel: Finns redan\n"; return; }

    cout << "Losenord: ";
    string pw;
    getline(cin, pw);
    pw = trim(pw);

    string msg;
    if (!passwordOk(pw, msg)) { cout << "Fel: " << msg << "\n"; return; }

    ofstream out(file, ios::app);
    if (!out.is_open()) { cout << "Fel: Kunde inte spara\n"; return; }

    out << email << ":" << md5(pw) << "\n";
    cout << "OK: Konto skapat\n";
}

static void loginUser(const string& file)
{
    auto users = loadUsers(file);

    cout << "Epost: ";
    string email;
    getline(cin, email);
    email = trim(email);

    cout << "Losenord: ";
    string pw;
    getline(cin, pw);
    pw = trim(pw);

    string h = md5(pw);

    for (int i = 0; i < (int)users.size(); i++)
    {
        if (users[i].first == email)
        {
            if (users[i].second == h) cout << "OK Det gick att logga in\n";
            else cout << "Fel: Fel uppgifter\n";
            return;
        }
    }

    cout << "Fel: Fel uppgifter\n";
}

int main()
{
    const string file = "users.txt";

    while (true)
    {
        cout << "\n1 Skapa anvandare\n2 Test login\n0 Avsluta\nVal: ";
        string val;
        getline(cin, val);
        val = trim(val);

        if (val == "1") createUser(file);
        else if (val == "2") loginUser(file);
        else if (val == "0") break;
        else cout << "Fel: Ogiltigt val\n";
    }

    return 0;
}
