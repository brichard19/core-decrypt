#include "core-decrypt.h"
#include <string.h>

uint64_t ROTR(uint64_t x, int n)
{
    return (((x) >> (n)) | ((x) << (64 - (n))));
}

#define MAJ( x, y, z) ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) )

#define CH( x, y , z) ( ( x & y ) ^ ( ~x & z ) )

#define S0( x ) ( ROTR( (x), 28 ) ^ ROTR( (x), 34 ) ^ ROTR( (x), 39 ) )

#define S1( x ) ( ROTR( (x), 14 ) ^ ROTR( (x), 18 ) ^ ROTR( (x), 41 ) )

#define S2( x ) ( ROTR( (x), 1 ) ^ ROTR( (x), 8 ) ^ ( (x) >> 7 ) )

#define S3( x ) ( ROTR( (x), 19 ) ^ ROTR( (x), 61 ) ^ ( (x) >> 6 ) )

static const uint64_t k[] = {
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

const uint64_t _IV[8] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};

#define F( a, b, c, d, e, f, g, h, x, k ) (h) += S1( (e) ) + CH( (e), (f), (g) ) + (k) + (x); (d) += (h); (h) += S0((a)) + MAJ( (a), (b), (c) )

void sha512_init(uint64_t *state)
{
    state[0] = 0x6a09e667f3bcc908;
    state[1] = 0xbb67ae8584caa73b;
    state[2] = 0x3c6ef372fe94f82b;
    state[3] = 0xa54ff53a5f1d36f1;
    state[4] = 0x510e527fade682d1;
    state[5] = 0x9b05688c2b3e6c1f;
    state[6] = 0x1f83d9abfb41bd6b;
    state[7] = 0x5be0cd19137e2179;
}

void sha512(const uint64_t *msg, uint64_t *state)
{
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t w[16];

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for(int i = 0; i < 16; i++) {
        w[i] = msg[i];
    }

    F(a, b, c, d, e, f, g, h, w[0], k[0]);
    F(h, a, b, c, d, e, f, g, w[1], k[1]);
    F(g, h, a, b, c, d, e, f, w[2], k[2]);
    F(f, g, h, a, b, c, d, e, w[3], k[3]);
    F(e, f, g, h, a, b, c, d, w[4], k[4]);
    F(d, e, f, g, h, a, b, c, w[5], k[5]);
    F(c, d, e, f, g, h, a, b, w[6], k[6]);
    F(b, c, d, e, f, g, h, a, w[7], k[7]);
    F(a, b, c, d, e, f, g, h, w[8], k[8]);
    F(h, a, b, c, d, e, f, g, w[9], k[9]);
    F(g, h, a, b, c, d, e, f, w[10], k[10]);
    F(f, g, h, a, b, c, d, e, w[11], k[11]);
    F(e, f, g, h, a, b, c, d, w[12], k[12]);
    F(d, e, f, g, h, a, b, c, w[13], k[13]);
    F(c, d, e, f, g, h, a, b, w[14], k[14]);
    F(b, c, d, e, f, g, h, a, w[15], k[15]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[16]);
    F(h, a, b, c, d, e, f, g, w[1], k[17]);
    F(g, h, a, b, c, d, e, f, w[2], k[18]);
    F(f, g, h, a, b, c, d, e, w[3], k[19]);
    F(e, f, g, h, a, b, c, d, w[4], k[20]);
    F(d, e, f, g, h, a, b, c, w[5], k[21]);
    F(c, d, e, f, g, h, a, b, w[6], k[22]);
    F(b, c, d, e, f, g, h, a, w[7], k[23]);
    F(a, b, c, d, e, f, g, h, w[8], k[24]);
    F(h, a, b, c, d, e, f, g, w[9], k[25]);
    F(g, h, a, b, c, d, e, f, w[10], k[26]);
    F(f, g, h, a, b, c, d, e, w[11], k[27]);
    F(e, f, g, h, a, b, c, d, w[12], k[28]);
    F(d, e, f, g, h, a, b, c, w[13], k[29]);
    F(c, d, e, f, g, h, a, b, w[14], k[30]);
    F(b, c, d, e, f, g, h, a, w[15], k[31]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[32]);
    F(h, a, b, c, d, e, f, g, w[1], k[33]);
    F(g, h, a, b, c, d, e, f, w[2], k[34]);
    F(f, g, h, a, b, c, d, e, w[3], k[35]);
    F(e, f, g, h, a, b, c, d, w[4], k[36]);
    F(d, e, f, g, h, a, b, c, w[5], k[37]);
    F(c, d, e, f, g, h, a, b, w[6], k[38]);
    F(b, c, d, e, f, g, h, a, w[7], k[39]);
    F(a, b, c, d, e, f, g, h, w[8], k[40]);
    F(h, a, b, c, d, e, f, g, w[9], k[41]);
    F(g, h, a, b, c, d, e, f, w[10], k[42]);
    F(f, g, h, a, b, c, d, e, w[11], k[43]);
    F(e, f, g, h, a, b, c, d, w[12], k[44]);
    F(d, e, f, g, h, a, b, c, w[13], k[45]);
    F(c, d, e, f, g, h, a, b, w[14], k[46]);
    F(b, c, d, e, f, g, h, a, w[15], k[47]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[48]);
    F(h, a, b, c, d, e, f, g, w[1], k[49]);
    F(g, h, a, b, c, d, e, f, w[2], k[50]);
    F(f, g, h, a, b, c, d, e, w[3], k[51]);
    F(e, f, g, h, a, b, c, d, w[4], k[52]);
    F(d, e, f, g, h, a, b, c, w[5], k[53]);
    F(c, d, e, f, g, h, a, b, w[6], k[54]);
    F(b, c, d, e, f, g, h, a, w[7], k[55]);
    F(a, b, c, d, e, f, g, h, w[8], k[56]);
    F(h, a, b, c, d, e, f, g, w[9], k[57]);
    F(g, h, a, b, c, d, e, f, w[10], k[58]);
    F(f, g, h, a, b, c, d, e, w[11], k[59]);
    F(e, f, g, h, a, b, c, d, w[12], k[60]);
    F(d, e, f, g, h, a, b, c, w[13], k[61]);
    F(c, d, e, f, g, h, a, b, w[14], k[62]);
    F(b, c, d, e, f, g, h, a, w[15], k[63]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[64]);
    F(h, a, b, c, d, e, f, g, w[1], k[65]);
    F(g, h, a, b, c, d, e, f, w[2], k[66]);
    F(f, g, h, a, b, c, d, e, w[3], k[67]);
    F(e, f, g, h, a, b, c, d, w[4], k[68]);
    F(d, e, f, g, h, a, b, c, w[5], k[69]);
    F(c, d, e, f, g, h, a, b, w[6], k[70]);
    F(b, c, d, e, f, g, h, a, w[7], k[71]);
    F(a, b, c, d, e, f, g, h, w[8], k[72]);
    F(h, a, b, c, d, e, f, g, w[9], k[73]);
    F(g, h, a, b, c, d, e, f, w[10], k[74]);
    F(f, g, h, a, b, c, d, e, w[11], k[75]);
    F(e, f, g, h, a, b, c, d, w[12], k[76]);
    F(d, e, f, g, h, a, b, c, w[13], k[77]);
    F(c, d, e, f, g, h, a, b, w[14], k[78]);
    F(b, c, d, e, f, g, h, a, w[15], k[79]);

    // Add the new state to the old state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}


static void sha512(uint64_t w[16])
{
    uint64_t a, b, c, d, e, f, g, h;

    a = _IV[0];
    b = _IV[1];
    c = _IV[2];
    d = _IV[3];
    e = _IV[4];
    f = _IV[5];
    g = _IV[6];
    h = _IV[7];


    F(a, b, c, d, e, f, g, h, w[0], k[0]);
    F(h, a, b, c, d, e, f, g, w[1], k[1]);
    F(g, h, a, b, c, d, e, f, w[2], k[2]);
    F(f, g, h, a, b, c, d, e, w[3], k[3]);
    F(e, f, g, h, a, b, c, d, w[4], k[4]);
    F(d, e, f, g, h, a, b, c, w[5], k[5]);
    F(c, d, e, f, g, h, a, b, w[6], k[6]);
    F(b, c, d, e, f, g, h, a, w[7], k[7]);
    F(a, b, c, d, e, f, g, h, w[8], k[8]);
    F(h, a, b, c, d, e, f, g, w[9], k[9]);
    F(g, h, a, b, c, d, e, f, w[10], k[10]);
    F(f, g, h, a, b, c, d, e, w[11], k[11]);
    F(e, f, g, h, a, b, c, d, w[12], k[12]);
    F(d, e, f, g, h, a, b, c, w[13], k[13]);
    F(c, d, e, f, g, h, a, b, w[14], k[14]);
    F(b, c, d, e, f, g, h, a, w[15], k[15]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[16]);
    F(h, a, b, c, d, e, f, g, w[1], k[17]);
    F(g, h, a, b, c, d, e, f, w[2], k[18]);
    F(f, g, h, a, b, c, d, e, w[3], k[19]);
    F(e, f, g, h, a, b, c, d, w[4], k[20]);
    F(d, e, f, g, h, a, b, c, w[5], k[21]);
    F(c, d, e, f, g, h, a, b, w[6], k[22]);
    F(b, c, d, e, f, g, h, a, w[7], k[23]);
    F(a, b, c, d, e, f, g, h, w[8], k[24]);
    F(h, a, b, c, d, e, f, g, w[9], k[25]);
    F(g, h, a, b, c, d, e, f, w[10], k[26]);
    F(f, g, h, a, b, c, d, e, w[11], k[27]);
    F(e, f, g, h, a, b, c, d, w[12], k[28]);
    F(d, e, f, g, h, a, b, c, w[13], k[29]);
    F(c, d, e, f, g, h, a, b, w[14], k[30]);
    F(b, c, d, e, f, g, h, a, w[15], k[31]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[32]);
    F(h, a, b, c, d, e, f, g, w[1], k[33]);
    F(g, h, a, b, c, d, e, f, w[2], k[34]);
    F(f, g, h, a, b, c, d, e, w[3], k[35]);
    F(e, f, g, h, a, b, c, d, w[4], k[36]);
    F(d, e, f, g, h, a, b, c, w[5], k[37]);
    F(c, d, e, f, g, h, a, b, w[6], k[38]);
    F(b, c, d, e, f, g, h, a, w[7], k[39]);
    F(a, b, c, d, e, f, g, h, w[8], k[40]);
    F(h, a, b, c, d, e, f, g, w[9], k[41]);
    F(g, h, a, b, c, d, e, f, w[10], k[42]);
    F(f, g, h, a, b, c, d, e, w[11], k[43]);
    F(e, f, g, h, a, b, c, d, w[12], k[44]);
    F(d, e, f, g, h, a, b, c, w[13], k[45]);
    F(c, d, e, f, g, h, a, b, w[14], k[46]);
    F(b, c, d, e, f, g, h, a, w[15], k[47]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[48]);
    F(h, a, b, c, d, e, f, g, w[1], k[49]);
    F(g, h, a, b, c, d, e, f, w[2], k[50]);
    F(f, g, h, a, b, c, d, e, w[3], k[51]);
    F(e, f, g, h, a, b, c, d, w[4], k[52]);
    F(d, e, f, g, h, a, b, c, w[5], k[53]);
    F(c, d, e, f, g, h, a, b, w[6], k[54]);
    F(b, c, d, e, f, g, h, a, w[7], k[55]);
    F(a, b, c, d, e, f, g, h, w[8], k[56]);
    F(h, a, b, c, d, e, f, g, w[9], k[57]);
    F(g, h, a, b, c, d, e, f, w[10], k[58]);
    F(f, g, h, a, b, c, d, e, w[11], k[59]);
    F(e, f, g, h, a, b, c, d, w[12], k[60]);
    F(d, e, f, g, h, a, b, c, w[13], k[61]);
    F(c, d, e, f, g, h, a, b, w[14], k[62]);
    F(b, c, d, e, f, g, h, a, w[15], k[63]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[64]);
    F(h, a, b, c, d, e, f, g, w[1], k[65]);
    F(g, h, a, b, c, d, e, f, w[2], k[66]);
    F(f, g, h, a, b, c, d, e, w[3], k[67]);
    F(e, f, g, h, a, b, c, d, w[4], k[68]);
    F(d, e, f, g, h, a, b, c, w[5], k[69]);
    F(c, d, e, f, g, h, a, b, w[6], k[70]);
    F(b, c, d, e, f, g, h, a, w[7], k[71]);
    F(a, b, c, d, e, f, g, h, w[8], k[72]);
    F(h, a, b, c, d, e, f, g, w[9], k[73]);
    F(g, h, a, b, c, d, e, f, w[10], k[74]);
    F(f, g, h, a, b, c, d, e, w[11], k[75]);
    F(e, f, g, h, a, b, c, d, w[12], k[76]);
    F(d, e, f, g, h, a, b, c, w[13], k[77]);
    F(c, d, e, f, g, h, a, b, w[14], k[78]);
    F(b, c, d, e, f, g, h, a, w[15], k[79]);

    // Add the new state to the old state
    w[0] = a + _IV[0];
    w[1] = b + _IV[1];
    w[2] = c + _IV[2];
    w[3] = d + _IV[3];
    w[4] = e + _IV[4];
    w[5] = f + _IV[5];
    w[6] = g + _IV[6];
    w[7] = h + _IV[7];
}

static void sha512_hash(uint64_t x[8])
{
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t w[16];

    a = _IV[0];
    b = _IV[1];
    c = _IV[2];
    d = _IV[3];
    e = _IV[4];
    f = _IV[5];
    g = _IV[6];
    h = _IV[7];

    const uint64_t w8 = 0x8000000000000000;
    const uint64_t w15 = 512;

    F(a, b, c, d, e, f, g, h, x[0], k[0]);
    F(h, a, b, c, d, e, f, g, x[1], k[1]);
    F(g, h, a, b, c, d, e, f, x[2], k[2]);
    F(f, g, h, a, b, c, d, e, x[3], k[3]);
    F(e, f, g, h, a, b, c, d, x[4], k[4]);
    F(d, e, f, g, h, a, b, c, x[5], k[5]);
    F(c, d, e, f, g, h, a, b, x[6], k[6]);
    F(b, c, d, e, f, g, h, a, x[7], k[7]);
    F(a, b, c, d, e, f, g, h, w8, k[8]);
    F(h, a, b, c, d, e, f, g, 0, k[9]);
    F(g, h, a, b, c, d, e, f, 0, k[10]);
    F(f, g, h, a, b, c, d, e, 0, k[11]);
    F(e, f, g, h, a, b, c, d, 0, k[12]);
    F(d, e, f, g, h, a, b, c, 0, k[13]);
    F(c, d, e, f, g, h, a, b, 0, k[14]);
    F(b, c, d, e, f, g, h, a, w15, k[15]);

    w[0] = x[0] + S2(x[1]) + 0 + S3(0);
    w[1] = x[1] + S2(x[2]) + 0 + S3(w15);
    w[2] = x[2] + S2(x[3]) + 0 + S3(w[0]);
    w[3] = x[3] + S2(x[4]) + 0 + S3(w[1]);
    w[4] = x[4] + S2(x[5]) + 0 + S3(w[2]);
    w[5] = x[5] + S2(x[6]) + 0 + S3(w[3]);
    w[6] = x[6] + S2(x[7]) + w15 + S3(w[4]);
    w[7] = x[7] + S2(w8) + w[0] + S3(w[5]);
    w[8] = w8 + S2(0) + w[1] + S3(w[6]);
    w[9] = 0 + S2(0) + w[2] + S3(w[7]);
    w[10] = 0 + S2(0) + w[3] + S3(w[8]);
    w[11] = 0 + S2(0) + w[4] + S3(w[9]);
    w[12] = 0 + S2(0) + w[5] + S3(w[10]);
    w[13] = 0 + S2(0) + w[6] + S3(w[11]);
    w[14] = 0 + S2(w15) + w[7] + S3(w[12]);
    w[15] = w15 + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[16]);
    F(h, a, b, c, d, e, f, g, w[1], k[17]);
    F(g, h, a, b, c, d, e, f, w[2], k[18]);
    F(f, g, h, a, b, c, d, e, w[3], k[19]);
    F(e, f, g, h, a, b, c, d, w[4], k[20]);
    F(d, e, f, g, h, a, b, c, w[5], k[21]);
    F(c, d, e, f, g, h, a, b, w[6], k[22]);
    F(b, c, d, e, f, g, h, a, w[7], k[23]);
    F(a, b, c, d, e, f, g, h, w[8], k[24]);
    F(h, a, b, c, d, e, f, g, w[9], k[25]);
    F(g, h, a, b, c, d, e, f, w[10], k[26]);
    F(f, g, h, a, b, c, d, e, w[11], k[27]);
    F(e, f, g, h, a, b, c, d, w[12], k[28]);
    F(d, e, f, g, h, a, b, c, w[13], k[29]);
    F(c, d, e, f, g, h, a, b, w[14], k[30]);
    F(b, c, d, e, f, g, h, a, w[15], k[31]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[32]);
    F(h, a, b, c, d, e, f, g, w[1], k[33]);
    F(g, h, a, b, c, d, e, f, w[2], k[34]);
    F(f, g, h, a, b, c, d, e, w[3], k[35]);
    F(e, f, g, h, a, b, c, d, w[4], k[36]);
    F(d, e, f, g, h, a, b, c, w[5], k[37]);
    F(c, d, e, f, g, h, a, b, w[6], k[38]);
    F(b, c, d, e, f, g, h, a, w[7], k[39]);
    F(a, b, c, d, e, f, g, h, w[8], k[40]);
    F(h, a, b, c, d, e, f, g, w[9], k[41]);
    F(g, h, a, b, c, d, e, f, w[10], k[42]);
    F(f, g, h, a, b, c, d, e, w[11], k[43]);
    F(e, f, g, h, a, b, c, d, w[12], k[44]);
    F(d, e, f, g, h, a, b, c, w[13], k[45]);
    F(c, d, e, f, g, h, a, b, w[14], k[46]);
    F(b, c, d, e, f, g, h, a, w[15], k[47]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[48]);
    F(h, a, b, c, d, e, f, g, w[1], k[49]);
    F(g, h, a, b, c, d, e, f, w[2], k[50]);
    F(f, g, h, a, b, c, d, e, w[3], k[51]);
    F(e, f, g, h, a, b, c, d, w[4], k[52]);
    F(d, e, f, g, h, a, b, c, w[5], k[53]);
    F(c, d, e, f, g, h, a, b, w[6], k[54]);
    F(b, c, d, e, f, g, h, a, w[7], k[55]);
    F(a, b, c, d, e, f, g, h, w[8], k[56]);
    F(h, a, b, c, d, e, f, g, w[9], k[57]);
    F(g, h, a, b, c, d, e, f, w[10], k[58]);
    F(f, g, h, a, b, c, d, e, w[11], k[59]);
    F(e, f, g, h, a, b, c, d, w[12], k[60]);
    F(d, e, f, g, h, a, b, c, w[13], k[61]);
    F(c, d, e, f, g, h, a, b, w[14], k[62]);
    F(b, c, d, e, f, g, h, a, w[15], k[63]);

    w[0] = w[0] + S2(w[1]) + w[9] + S3(w[14]);
    w[1] = w[1] + S2(w[2]) + w[10] + S3(w[15]);
    w[2] = w[2] + S2(w[3]) + w[11] + S3(w[0]);
    w[3] = w[3] + S2(w[4]) + w[12] + S3(w[1]);
    w[4] = w[4] + S2(w[5]) + w[13] + S3(w[2]);
    w[5] = w[5] + S2(w[6]) + w[14] + S3(w[3]);
    w[6] = w[6] + S2(w[7]) + w[15] + S3(w[4]);
    w[7] = w[7] + S2(w[8]) + w[0] + S3(w[5]);
    w[8] = w[8] + S2(w[9]) + w[1] + S3(w[6]);
    w[9] = w[9] + S2(w[10]) + w[2] + S3(w[7]);
    w[10] = w[10] + S2(w[11]) + w[3] + S3(w[8]);
    w[11] = w[11] + S2(w[12]) + w[4] + S3(w[9]);
    w[12] = w[12] + S2(w[13]) + w[5] + S3(w[10]);
    w[13] = w[13] + S2(w[14]) + w[6] + S3(w[11]);
    w[14] = w[14] + S2(w[15]) + w[7] + S3(w[12]);
    w[15] = w[15] + S2(w[0]) + w[8] + S3(w[13]);

    F(a, b, c, d, e, f, g, h, w[0], k[64]);
    F(h, a, b, c, d, e, f, g, w[1], k[65]);
    F(g, h, a, b, c, d, e, f, w[2], k[66]);
    F(f, g, h, a, b, c, d, e, w[3], k[67]);
    F(e, f, g, h, a, b, c, d, w[4], k[68]);
    F(d, e, f, g, h, a, b, c, w[5], k[69]);
    F(c, d, e, f, g, h, a, b, w[6], k[70]);
    F(b, c, d, e, f, g, h, a, w[7], k[71]);
    F(a, b, c, d, e, f, g, h, w[8], k[72]);
    F(h, a, b, c, d, e, f, g, w[9], k[73]);
    F(g, h, a, b, c, d, e, f, w[10], k[74]);
    F(f, g, h, a, b, c, d, e, w[11], k[75]);
    F(e, f, g, h, a, b, c, d, w[12], k[76]);
    F(d, e, f, g, h, a, b, c, w[13], k[77]);
    F(c, d, e, f, g, h, a, b, w[14], k[78]);
    F(b, c, d, e, f, g, h, a, w[15], k[79]);

    // Add the new state to the old state
    x[0] = a + _IV[0];
    x[1] = b + _IV[1];
    x[2] = c + _IV[2];
    x[3] = d + _IV[3];
    x[4] = e + _IV[4];
    x[5] = f + _IV[5];
    x[6] = g + _IV[6];
    x[7] = h + _IV[7];
}

void sha512_iterations(uint64_t *msg, uint64_t *state, unsigned int iterations)
{
    uint64_t w[16];

    for(int i = 0; i < 16; i++) {
        w[i] = msg[i];
    }
 
    sha512(w);

    for(unsigned int i = 0; i < iterations - 1; i++) {
        sha512_hash(w);

    }

    for(int i = 0; i < 8; i++) {
        state[i] = w[i];
    }
}