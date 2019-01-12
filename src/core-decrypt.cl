

//////////////////////////////////// AES 256 ///////////////////////////////////////
__constant unsigned int _sbox[] = {
 0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76,
 0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0,
 0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15,
 0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75,
 0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84,
 0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf,
 0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8,
 0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2,
 0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73,
 0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb,
 0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79,
 0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08,
 0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a,
 0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e,
 0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf,
 0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16
};

__constant unsigned int _invSbox[] = {
0x00000052, 0x00000009, 0x0000006a, 0x000000d5, 0x00000030, 0x00000036, 0x000000a5, 0x00000038,
0x000000bf, 0x00000040, 0x000000a3, 0x0000009e, 0x00000081, 0x000000f3, 0x000000d7, 0x000000fb,
0x0000007c, 0x000000e3, 0x00000039, 0x00000082, 0x0000009b, 0x0000002f, 0x000000ff, 0x00000087,
0x00000034, 0x0000008e, 0x00000043, 0x00000044, 0x000000c4, 0x000000de, 0x000000e9, 0x000000cb,
0x00000054, 0x0000007b, 0x00000094, 0x00000032, 0x000000a6, 0x000000c2, 0x00000023, 0x0000003d,
0x000000ee, 0x0000004c, 0x00000095, 0x0000000b, 0x00000042, 0x000000fa, 0x000000c3, 0x0000004e,
0x00000008, 0x0000002e, 0x000000a1, 0x00000066, 0x00000028, 0x000000d9, 0x00000024, 0x000000b2,
0x00000076, 0x0000005b, 0x000000a2, 0x00000049, 0x0000006d, 0x0000008b, 0x000000d1, 0x00000025,
0x00000072, 0x000000f8, 0x000000f6, 0x00000064, 0x00000086, 0x00000068, 0x00000098, 0x00000016,
0x000000d4, 0x000000a4, 0x0000005c, 0x000000cc, 0x0000005d, 0x00000065, 0x000000b6, 0x00000092,
0x0000006c, 0x00000070, 0x00000048, 0x00000050, 0x000000fd, 0x000000ed, 0x000000b9, 0x000000da,
0x0000005e, 0x00000015, 0x00000046, 0x00000057, 0x000000a7, 0x0000008d, 0x0000009d, 0x00000084,
0x00000090, 0x000000d8, 0x000000ab, 0x00000000, 0x0000008c, 0x000000bc, 0x000000d3, 0x0000000a,
0x000000f7, 0x000000e4, 0x00000058, 0x00000005, 0x000000b8, 0x000000b3, 0x00000045, 0x00000006,
0x000000d0, 0x0000002c, 0x0000001e, 0x0000008f, 0x000000ca, 0x0000003f, 0x0000000f, 0x00000002,
0x000000c1, 0x000000af, 0x000000bd, 0x00000003, 0x00000001, 0x00000013, 0x0000008a, 0x0000006b,
0x0000003a, 0x00000091, 0x00000011, 0x00000041, 0x0000004f, 0x00000067, 0x000000dc, 0x000000ea,
0x00000097, 0x000000f2, 0x000000cf, 0x000000ce, 0x000000f0, 0x000000b4, 0x000000e6, 0x00000073,
0x00000096, 0x000000ac, 0x00000074, 0x00000022, 0x000000e7, 0x000000ad, 0x00000035, 0x00000085,
0x000000e2, 0x000000f9, 0x00000037, 0x000000e8, 0x0000001c, 0x00000075, 0x000000df, 0x0000006e,
0x00000047, 0x000000f1, 0x0000001a, 0x00000071, 0x0000001d, 0x00000029, 0x000000c5, 0x00000089,
0x0000006f, 0x000000b7, 0x00000062, 0x0000000e, 0x000000aa, 0x00000018, 0x000000be, 0x0000001b,
0x000000fc, 0x00000056, 0x0000003e, 0x0000004b, 0x000000c6, 0x000000d2, 0x00000079, 0x00000020,
0x0000009a, 0x000000db, 0x000000c0, 0x000000fe, 0x00000078, 0x000000cd, 0x0000005a, 0x000000f4,
0x0000001f, 0x000000dd, 0x000000a8, 0x00000033, 0x00000088, 0x00000007, 0x000000c7, 0x00000031,
0x000000b1, 0x00000012, 0x00000010, 0x00000059, 0x00000027, 0x00000080, 0x000000ec, 0x0000005f,
0x00000060, 0x00000051, 0x0000007f, 0x000000a9, 0x00000019, 0x000000b5, 0x0000004a, 0x0000000d,
0x0000002d, 0x000000e5, 0x0000007a, 0x0000009f, 0x00000093, 0x000000c9, 0x0000009c, 0x000000ef,
0x000000a0, 0x000000e0, 0x0000003b, 0x0000004d, 0x000000ae, 0x0000002a, 0x000000f5, 0x000000b0,
0x000000c8, 0x000000eb, 0x000000bb, 0x0000003c, 0x00000083, 0x00000053, 0x00000099, 0x00000061,
0x00000017, 0x0000002b, 0x00000004, 0x0000007e, 0x000000ba, 0x00000077, 0x000000d6, 0x00000026,
0x000000e1, 0x00000069, 0x00000014, 0x00000063, 0x00000055, 0x00000021, 0x0000000c, 0x0000007d,
};


/**
 Lookup table 1 for the InvMixColumns transform
 */
__constant unsigned int _invMixCol1[] = {
0x00000000, 0x0e090d0b, 0x1c121a16, 0x121b171d, 0x3824342c, 0x362d3927, 0x24362e3a, 0x2a3f2331,
0x70486858, 0x7e416553, 0x6c5a724e, 0x62537f45, 0x486c5c74, 0x4665517f, 0x547e4662, 0x5a774b69,
0xe090d0b0, 0xee99ddbb, 0xfc82caa6, 0xf28bc7ad, 0xd8b4e49c, 0xd6bde997, 0xc4a6fe8a, 0xcaaff381,
0x90d8b8e8, 0x9ed1b5e3, 0x8ccaa2fe, 0x82c3aff5, 0xa8fc8cc4, 0xa6f581cf, 0xb4ee96d2, 0xbae79bd9,
0xdb3bbb7b, 0xd532b670, 0xc729a16d, 0xc920ac66, 0xe31f8f57, 0xed16825c, 0xff0d9541, 0xf104984a,
0xab73d323, 0xa57ade28, 0xb761c935, 0xb968c43e, 0x9357e70f, 0x9d5eea04, 0x8f45fd19, 0x814cf012,
0x3bab6bcb, 0x35a266c0, 0x27b971dd, 0x29b07cd6, 0x038f5fe7, 0x0d8652ec, 0x1f9d45f1, 0x119448fa,
0x4be30393, 0x45ea0e98, 0x57f11985, 0x59f8148e, 0x73c737bf, 0x7dce3ab4, 0x6fd52da9, 0x61dc20a2,
0xad766df6, 0xa37f60fd, 0xb16477e0, 0xbf6d7aeb, 0x955259da, 0x9b5b54d1, 0x894043cc, 0x87494ec7,
0xdd3e05ae, 0xd33708a5, 0xc12c1fb8, 0xcf2512b3, 0xe51a3182, 0xeb133c89, 0xf9082b94, 0xf701269f,
0x4de6bd46, 0x43efb04d, 0x51f4a750, 0x5ffdaa5b, 0x75c2896a, 0x7bcb8461, 0x69d0937c, 0x67d99e77,
0x3daed51e, 0x33a7d815, 0x21bccf08, 0x2fb5c203, 0x058ae132, 0x0b83ec39, 0x1998fb24, 0x1791f62f,
0x764dd68d, 0x7844db86, 0x6a5fcc9b, 0x6456c190, 0x4e69e2a1, 0x4060efaa, 0x527bf8b7, 0x5c72f5bc,
0x0605bed5, 0x080cb3de, 0x1a17a4c3, 0x141ea9c8, 0x3e218af9, 0x302887f2, 0x223390ef, 0x2c3a9de4,
0x96dd063d, 0x98d40b36, 0x8acf1c2b, 0x84c61120, 0xaef93211, 0xa0f03f1a, 0xb2eb2807, 0xbce2250c,
0xe6956e65, 0xe89c636e, 0xfa877473, 0xf48e7978, 0xdeb15a49, 0xd0b85742, 0xc2a3405f, 0xccaa4d54,
0x41ecdaf7, 0x4fe5d7fc, 0x5dfec0e1, 0x53f7cdea, 0x79c8eedb, 0x77c1e3d0, 0x65daf4cd, 0x6bd3f9c6,
0x31a4b2af, 0x3fadbfa4, 0x2db6a8b9, 0x23bfa5b2, 0x09808683, 0x07898b88, 0x15929c95, 0x1b9b919e,
0xa17c0a47, 0xaf75074c, 0xbd6e1051, 0xb3671d5a, 0x99583e6b, 0x97513360, 0x854a247d, 0x8b432976,
0xd134621f, 0xdf3d6f14, 0xcd267809, 0xc32f7502, 0xe9105633, 0xe7195b38, 0xf5024c25, 0xfb0b412e,
0x9ad7618c, 0x94de6c87, 0x86c57b9a, 0x88cc7691, 0xa2f355a0, 0xacfa58ab, 0xbee14fb6, 0xb0e842bd,
0xea9f09d4, 0xe49604df, 0xf68d13c2, 0xf8841ec9, 0xd2bb3df8, 0xdcb230f3, 0xcea927ee, 0xc0a02ae5,
0x7a47b13c, 0x744ebc37, 0x6655ab2a, 0x685ca621, 0x42638510, 0x4c6a881b, 0x5e719f06, 0x5078920d,
0x0a0fd964, 0x0406d46f, 0x161dc372, 0x1814ce79, 0x322bed48, 0x3c22e043, 0x2e39f75e, 0x2030fa55,
0xec9ab701, 0xe293ba0a, 0xf088ad17, 0xfe81a01c, 0xd4be832d, 0xdab78e26, 0xc8ac993b, 0xc6a59430,
0x9cd2df59, 0x92dbd252, 0x80c0c54f, 0x8ec9c844, 0xa4f6eb75, 0xaaffe67e, 0xb8e4f163, 0xb6edfc68,
0x0c0a67b1, 0x02036aba, 0x10187da7, 0x1e1170ac, 0x342e539d, 0x3a275e96, 0x283c498b, 0x26354480,
0x7c420fe9, 0x724b02e2, 0x605015ff, 0x6e5918f4, 0x44663bc5, 0x4a6f36ce, 0x587421d3, 0x567d2cd8,
0x37a10c7a, 0x39a80171, 0x2bb3166c, 0x25ba1b67, 0x0f853856, 0x018c355d, 0x13972240, 0x1d9e2f4b,
0x47e96422, 0x49e06929, 0x5bfb7e34, 0x55f2733f, 0x7fcd500e, 0x71c45d05, 0x63df4a18, 0x6dd64713,
0xd731dcca, 0xd938d1c1, 0xcb23c6dc, 0xc52acbd7, 0xef15e8e6, 0xe11ce5ed, 0xf307f2f0, 0xfd0efffb,
0xa779b492, 0xa970b999, 0xbb6bae84, 0xb562a38f, 0x9f5d80be, 0x91548db5, 0x834f9aa8, 0x8d4697a3,
};

/**
 Lookup table 2 for the InvMixColumns transform
 */
__constant unsigned int _invMixCol2[] = {
0x00000000, 0x0b0e090d, 0x161c121a, 0x1d121b17, 0x2c382434, 0x27362d39, 0x3a24362e, 0x312a3f23,
0x58704868, 0x537e4165, 0x4e6c5a72, 0x4562537f, 0x74486c5c, 0x7f466551, 0x62547e46, 0x695a774b,
0xb0e090d0, 0xbbee99dd, 0xa6fc82ca, 0xadf28bc7, 0x9cd8b4e4, 0x97d6bde9, 0x8ac4a6fe, 0x81caaff3,
0xe890d8b8, 0xe39ed1b5, 0xfe8ccaa2, 0xf582c3af, 0xc4a8fc8c, 0xcfa6f581, 0xd2b4ee96, 0xd9bae79b,
0x7bdb3bbb, 0x70d532b6, 0x6dc729a1, 0x66c920ac, 0x57e31f8f, 0x5ced1682, 0x41ff0d95, 0x4af10498,
0x23ab73d3, 0x28a57ade, 0x35b761c9, 0x3eb968c4, 0x0f9357e7, 0x049d5eea, 0x198f45fd, 0x12814cf0,
0xcb3bab6b, 0xc035a266, 0xdd27b971, 0xd629b07c, 0xe7038f5f, 0xec0d8652, 0xf11f9d45, 0xfa119448,
0x934be303, 0x9845ea0e, 0x8557f119, 0x8e59f814, 0xbf73c737, 0xb47dce3a, 0xa96fd52d, 0xa261dc20,
0xf6ad766d, 0xfda37f60, 0xe0b16477, 0xebbf6d7a, 0xda955259, 0xd19b5b54, 0xcc894043, 0xc787494e,
0xaedd3e05, 0xa5d33708, 0xb8c12c1f, 0xb3cf2512, 0x82e51a31, 0x89eb133c, 0x94f9082b, 0x9ff70126,
0x464de6bd, 0x4d43efb0, 0x5051f4a7, 0x5b5ffdaa, 0x6a75c289, 0x617bcb84, 0x7c69d093, 0x7767d99e,
0x1e3daed5, 0x1533a7d8, 0x0821bccf, 0x032fb5c2, 0x32058ae1, 0x390b83ec, 0x241998fb, 0x2f1791f6,
0x8d764dd6, 0x867844db, 0x9b6a5fcc, 0x906456c1, 0xa14e69e2, 0xaa4060ef, 0xb7527bf8, 0xbc5c72f5,
0xd50605be, 0xde080cb3, 0xc31a17a4, 0xc8141ea9, 0xf93e218a, 0xf2302887, 0xef223390, 0xe42c3a9d,
0x3d96dd06, 0x3698d40b, 0x2b8acf1c, 0x2084c611, 0x11aef932, 0x1aa0f03f, 0x07b2eb28, 0x0cbce225,
0x65e6956e, 0x6ee89c63, 0x73fa8774, 0x78f48e79, 0x49deb15a, 0x42d0b857, 0x5fc2a340, 0x54ccaa4d,
0xf741ecda, 0xfc4fe5d7, 0xe15dfec0, 0xea53f7cd, 0xdb79c8ee, 0xd077c1e3, 0xcd65daf4, 0xc66bd3f9,
0xaf31a4b2, 0xa43fadbf, 0xb92db6a8, 0xb223bfa5, 0x83098086, 0x8807898b, 0x9515929c, 0x9e1b9b91,
0x47a17c0a, 0x4caf7507, 0x51bd6e10, 0x5ab3671d, 0x6b99583e, 0x60975133, 0x7d854a24, 0x768b4329,
0x1fd13462, 0x14df3d6f, 0x09cd2678, 0x02c32f75, 0x33e91056, 0x38e7195b, 0x25f5024c, 0x2efb0b41,
0x8c9ad761, 0x8794de6c, 0x9a86c57b, 0x9188cc76, 0xa0a2f355, 0xabacfa58, 0xb6bee14f, 0xbdb0e842,
0xd4ea9f09, 0xdfe49604, 0xc2f68d13, 0xc9f8841e, 0xf8d2bb3d, 0xf3dcb230, 0xeecea927, 0xe5c0a02a,
0x3c7a47b1, 0x37744ebc, 0x2a6655ab, 0x21685ca6, 0x10426385, 0x1b4c6a88, 0x065e719f, 0x0d507892,
0x640a0fd9, 0x6f0406d4, 0x72161dc3, 0x791814ce, 0x48322bed, 0x433c22e0, 0x5e2e39f7, 0x552030fa,
0x01ec9ab7, 0x0ae293ba, 0x17f088ad, 0x1cfe81a0, 0x2dd4be83, 0x26dab78e, 0x3bc8ac99, 0x30c6a594,
0x599cd2df, 0x5292dbd2, 0x4f80c0c5, 0x448ec9c8, 0x75a4f6eb, 0x7eaaffe6, 0x63b8e4f1, 0x68b6edfc,
0xb10c0a67, 0xba02036a, 0xa710187d, 0xac1e1170, 0x9d342e53, 0x963a275e, 0x8b283c49, 0x80263544,
0xe97c420f, 0xe2724b02, 0xff605015, 0xf46e5918, 0xc544663b, 0xce4a6f36, 0xd3587421, 0xd8567d2c,
0x7a37a10c, 0x7139a801, 0x6c2bb316, 0x6725ba1b, 0x560f8538, 0x5d018c35, 0x40139722, 0x4b1d9e2f,
0x2247e964, 0x2949e069, 0x345bfb7e, 0x3f55f273, 0x0e7fcd50, 0x0571c45d, 0x1863df4a, 0x136dd647,
0xcad731dc, 0xc1d938d1, 0xdccb23c6, 0xd7c52acb, 0xe6ef15e8, 0xede11ce5, 0xf0f307f2, 0xfbfd0eff,
0x92a779b4, 0x99a970b9, 0x84bb6bae, 0x8fb562a3, 0xbe9f5d80, 0xb591548d, 0xa8834f9a, 0xa38d4697,
};

/**
 Lookup table 3 for the InvMixColumns transform
 */
__constant unsigned int _invMixCol3[] = {
0x00000000, 0x0d0b0e09, 0x1a161c12, 0x171d121b, 0x342c3824, 0x3927362d, 0x2e3a2436, 0x23312a3f,
0x68587048, 0x65537e41, 0x724e6c5a, 0x7f456253, 0x5c74486c, 0x517f4665, 0x4662547e, 0x4b695a77,
0xd0b0e090, 0xddbbee99, 0xcaa6fc82, 0xc7adf28b, 0xe49cd8b4, 0xe997d6bd, 0xfe8ac4a6, 0xf381caaf,
0xb8e890d8, 0xb5e39ed1, 0xa2fe8cca, 0xaff582c3, 0x8cc4a8fc, 0x81cfa6f5, 0x96d2b4ee, 0x9bd9bae7,
0xbb7bdb3b, 0xb670d532, 0xa16dc729, 0xac66c920, 0x8f57e31f, 0x825ced16, 0x9541ff0d, 0x984af104,
0xd323ab73, 0xde28a57a, 0xc935b761, 0xc43eb968, 0xe70f9357, 0xea049d5e, 0xfd198f45, 0xf012814c,
0x6bcb3bab, 0x66c035a2, 0x71dd27b9, 0x7cd629b0, 0x5fe7038f, 0x52ec0d86, 0x45f11f9d, 0x48fa1194,
0x03934be3, 0x0e9845ea, 0x198557f1, 0x148e59f8, 0x37bf73c7, 0x3ab47dce, 0x2da96fd5, 0x20a261dc,
0x6df6ad76, 0x60fda37f, 0x77e0b164, 0x7aebbf6d, 0x59da9552, 0x54d19b5b, 0x43cc8940, 0x4ec78749,
0x05aedd3e, 0x08a5d337, 0x1fb8c12c, 0x12b3cf25, 0x3182e51a, 0x3c89eb13, 0x2b94f908, 0x269ff701,
0xbd464de6, 0xb04d43ef, 0xa75051f4, 0xaa5b5ffd, 0x896a75c2, 0x84617bcb, 0x937c69d0, 0x9e7767d9,
0xd51e3dae, 0xd81533a7, 0xcf0821bc, 0xc2032fb5, 0xe132058a, 0xec390b83, 0xfb241998, 0xf62f1791,
0xd68d764d, 0xdb867844, 0xcc9b6a5f, 0xc1906456, 0xe2a14e69, 0xefaa4060, 0xf8b7527b, 0xf5bc5c72,
0xbed50605, 0xb3de080c, 0xa4c31a17, 0xa9c8141e, 0x8af93e21, 0x87f23028, 0x90ef2233, 0x9de42c3a,
0x063d96dd, 0x0b3698d4, 0x1c2b8acf, 0x112084c6, 0x3211aef9, 0x3f1aa0f0, 0x2807b2eb, 0x250cbce2,
0x6e65e695, 0x636ee89c, 0x7473fa87, 0x7978f48e, 0x5a49deb1, 0x5742d0b8, 0x405fc2a3, 0x4d54ccaa,
0xdaf741ec, 0xd7fc4fe5, 0xc0e15dfe, 0xcdea53f7, 0xeedb79c8, 0xe3d077c1, 0xf4cd65da, 0xf9c66bd3,
0xb2af31a4, 0xbfa43fad, 0xa8b92db6, 0xa5b223bf, 0x86830980, 0x8b880789, 0x9c951592, 0x919e1b9b,
0x0a47a17c, 0x074caf75, 0x1051bd6e, 0x1d5ab367, 0x3e6b9958, 0x33609751, 0x247d854a, 0x29768b43,
0x621fd134, 0x6f14df3d, 0x7809cd26, 0x7502c32f, 0x5633e910, 0x5b38e719, 0x4c25f502, 0x412efb0b,
0x618c9ad7, 0x6c8794de, 0x7b9a86c5, 0x769188cc, 0x55a0a2f3, 0x58abacfa, 0x4fb6bee1, 0x42bdb0e8,
0x09d4ea9f, 0x04dfe496, 0x13c2f68d, 0x1ec9f884, 0x3df8d2bb, 0x30f3dcb2, 0x27eecea9, 0x2ae5c0a0,
0xb13c7a47, 0xbc37744e, 0xab2a6655, 0xa621685c, 0x85104263, 0x881b4c6a, 0x9f065e71, 0x920d5078,
0xd9640a0f, 0xd46f0406, 0xc372161d, 0xce791814, 0xed48322b, 0xe0433c22, 0xf75e2e39, 0xfa552030,
0xb701ec9a, 0xba0ae293, 0xad17f088, 0xa01cfe81, 0x832dd4be, 0x8e26dab7, 0x993bc8ac, 0x9430c6a5,
0xdf599cd2, 0xd25292db, 0xc54f80c0, 0xc8448ec9, 0xeb75a4f6, 0xe67eaaff, 0xf163b8e4, 0xfc68b6ed,
0x67b10c0a, 0x6aba0203, 0x7da71018, 0x70ac1e11, 0x539d342e, 0x5e963a27, 0x498b283c, 0x44802635,
0x0fe97c42, 0x02e2724b, 0x15ff6050, 0x18f46e59, 0x3bc54466, 0x36ce4a6f, 0x21d35874, 0x2cd8567d,
0x0c7a37a1, 0x017139a8, 0x166c2bb3, 0x1b6725ba, 0x38560f85, 0x355d018c, 0x22401397, 0x2f4b1d9e,
0x642247e9, 0x692949e0, 0x7e345bfb, 0x733f55f2, 0x500e7fcd, 0x5d0571c4, 0x4a1863df, 0x47136dd6,
0xdccad731, 0xd1c1d938, 0xc6dccb23, 0xcbd7c52a, 0xe8e6ef15, 0xe5ede11c, 0xf2f0f307, 0xfffbfd0e,
0xb492a779, 0xb999a970, 0xae84bb6b, 0xa38fb562, 0x80be9f5d, 0x8db59154, 0x9aa8834f, 0x97a38d46,
};

/**
 Lookup table 4 for the InvMixColumns transform
 */
__constant unsigned int _invMixCol4[] = {
0x00000000, 0x090d0b0e, 0x121a161c, 0x1b171d12, 0x24342c38, 0x2d392736, 0x362e3a24, 0x3f23312a,
0x48685870, 0x4165537e, 0x5a724e6c, 0x537f4562, 0x6c5c7448, 0x65517f46, 0x7e466254, 0x774b695a,
0x90d0b0e0, 0x99ddbbee, 0x82caa6fc, 0x8bc7adf2, 0xb4e49cd8, 0xbde997d6, 0xa6fe8ac4, 0xaff381ca,
0xd8b8e890, 0xd1b5e39e, 0xcaa2fe8c, 0xc3aff582, 0xfc8cc4a8, 0xf581cfa6, 0xee96d2b4, 0xe79bd9ba,
0x3bbb7bdb, 0x32b670d5, 0x29a16dc7, 0x20ac66c9, 0x1f8f57e3, 0x16825ced, 0x0d9541ff, 0x04984af1,
0x73d323ab, 0x7ade28a5, 0x61c935b7, 0x68c43eb9, 0x57e70f93, 0x5eea049d, 0x45fd198f, 0x4cf01281,
0xab6bcb3b, 0xa266c035, 0xb971dd27, 0xb07cd629, 0x8f5fe703, 0x8652ec0d, 0x9d45f11f, 0x9448fa11,
0xe303934b, 0xea0e9845, 0xf1198557, 0xf8148e59, 0xc737bf73, 0xce3ab47d, 0xd52da96f, 0xdc20a261,
0x766df6ad, 0x7f60fda3, 0x6477e0b1, 0x6d7aebbf, 0x5259da95, 0x5b54d19b, 0x4043cc89, 0x494ec787,
0x3e05aedd, 0x3708a5d3, 0x2c1fb8c1, 0x2512b3cf, 0x1a3182e5, 0x133c89eb, 0x082b94f9, 0x01269ff7,
0xe6bd464d, 0xefb04d43, 0xf4a75051, 0xfdaa5b5f, 0xc2896a75, 0xcb84617b, 0xd0937c69, 0xd99e7767,
0xaed51e3d, 0xa7d81533, 0xbccf0821, 0xb5c2032f, 0x8ae13205, 0x83ec390b, 0x98fb2419, 0x91f62f17,
0x4dd68d76, 0x44db8678, 0x5fcc9b6a, 0x56c19064, 0x69e2a14e, 0x60efaa40, 0x7bf8b752, 0x72f5bc5c,
0x05bed506, 0x0cb3de08, 0x17a4c31a, 0x1ea9c814, 0x218af93e, 0x2887f230, 0x3390ef22, 0x3a9de42c,
0xdd063d96, 0xd40b3698, 0xcf1c2b8a, 0xc6112084, 0xf93211ae, 0xf03f1aa0, 0xeb2807b2, 0xe2250cbc,
0x956e65e6, 0x9c636ee8, 0x877473fa, 0x8e7978f4, 0xb15a49de, 0xb85742d0, 0xa3405fc2, 0xaa4d54cc,
0xecdaf741, 0xe5d7fc4f, 0xfec0e15d, 0xf7cdea53, 0xc8eedb79, 0xc1e3d077, 0xdaf4cd65, 0xd3f9c66b,
0xa4b2af31, 0xadbfa43f, 0xb6a8b92d, 0xbfa5b223, 0x80868309, 0x898b8807, 0x929c9515, 0x9b919e1b,
0x7c0a47a1, 0x75074caf, 0x6e1051bd, 0x671d5ab3, 0x583e6b99, 0x51336097, 0x4a247d85, 0x4329768b,
0x34621fd1, 0x3d6f14df, 0x267809cd, 0x2f7502c3, 0x105633e9, 0x195b38e7, 0x024c25f5, 0x0b412efb,
0xd7618c9a, 0xde6c8794, 0xc57b9a86, 0xcc769188, 0xf355a0a2, 0xfa58abac, 0xe14fb6be, 0xe842bdb0,
0x9f09d4ea, 0x9604dfe4, 0x8d13c2f6, 0x841ec9f8, 0xbb3df8d2, 0xb230f3dc, 0xa927eece, 0xa02ae5c0,
0x47b13c7a, 0x4ebc3774, 0x55ab2a66, 0x5ca62168, 0x63851042, 0x6a881b4c, 0x719f065e, 0x78920d50,
0x0fd9640a, 0x06d46f04, 0x1dc37216, 0x14ce7918, 0x2bed4832, 0x22e0433c, 0x39f75e2e, 0x30fa5520,
0x9ab701ec, 0x93ba0ae2, 0x88ad17f0, 0x81a01cfe, 0xbe832dd4, 0xb78e26da, 0xac993bc8, 0xa59430c6,
0xd2df599c, 0xdbd25292, 0xc0c54f80, 0xc9c8448e, 0xf6eb75a4, 0xffe67eaa, 0xe4f163b8, 0xedfc68b6,
0x0a67b10c, 0x036aba02, 0x187da710, 0x1170ac1e, 0x2e539d34, 0x275e963a, 0x3c498b28, 0x35448026,
0x420fe97c, 0x4b02e272, 0x5015ff60, 0x5918f46e, 0x663bc544, 0x6f36ce4a, 0x7421d358, 0x7d2cd856,
0xa10c7a37, 0xa8017139, 0xb3166c2b, 0xba1b6725, 0x8538560f, 0x8c355d01, 0x97224013, 0x9e2f4b1d,
0xe9642247, 0xe0692949, 0xfb7e345b, 0xf2733f55, 0xcd500e7f, 0xc45d0571, 0xdf4a1863, 0xd647136d,
0x31dccad7, 0x38d1c1d9, 0x23c6dccb, 0x2acbd7c5, 0x15e8e6ef, 0x1ce5ede1, 0x07f2f0f3, 0x0efffbfd,
0x79b492a7, 0x70b999a9, 0x6bae84bb, 0x62a38fb5, 0x5d80be9f, 0x548db591, 0x4f9aa883, 0x4697a38d,
};

unsigned int sub_word(unsigned int t)
{
    return (_sbox[(unsigned char)(t >> 24)] << 24) | (_sbox[(unsigned char)(t >> 16)] << 16) | (_sbox[(unsigned char)(t >> 8)] << 8) | _sbox[(unsigned char)t]; \
}

unsigned int sub_and_rotate(unsigned int t)
{
    return (_sbox[(unsigned char)(t >> 16)] << 24) | (_sbox[(unsigned char)(t >> 8)] << 16) | (_sbox[(unsigned char)t] << 8) | _sbox[(unsigned char)(t >> 24)]; \
}

void aes_256_key_expand(__private const unsigned int *key, unsigned int *subkeys)
{
    unsigned int t;
    for(int i = 0; i < 8; i++) {
        subkeys[i] = key[i];
    }


    // Macro for key expansion
#define SUBKEY_EXPAND(i, rcon)\
        t = subkeys[((i-1)*8)+7];\
        t = sub_and_rotate(t) ^ (rcon);\
        t ^= subkeys[(i - 1)*8];\
        subkeys[i*8] = t;\
        t ^= subkeys[((i-1)*8)+1];\
        subkeys[i*8+1] = t;\
        t ^= subkeys[((i-1)*8) +2];\
        subkeys[i*8+2] = t;\
        t ^= subkeys[(i-1)*8+3];\
        subkeys[i*8+3] = t;\
        t = sub_word(t);\
        t ^= subkeys[(i-1)*8+4];\
        subkeys[i*8+4] = t;\
        t ^= subkeys[(i-1)*8+5];\
        subkeys[i*8+5] = t;\
        t ^= subkeys[(i-1)*8+6];\
        subkeys[i*8+6] = t;\
        t ^= subkeys[(i-1)*8+7];\
        subkeys[i*8+7] = t;\

#define SUBKEY_EXPAND_HALF(i, rcon)\
        t = subkeys[((i-1)*8)+7];\
        t = sub_and_rotate(t) ^ (rcon);\
        t ^= subkeys[(i - 1)*8];\
        subkeys[i*8] = t;\
        t ^= subkeys[((i-1)*8)+1];\
        subkeys[i*8+1] = t;\
        t ^= subkeys[((i-1)*8) +2];\
        subkeys[i*8+2] = t;\
        t ^= subkeys[(i-1)*8+3];\
        subkeys[i*8+3] = t;\

    // Unroll key expansion
    SUBKEY_EXPAND(1, 0x01000000)
        SUBKEY_EXPAND(2, 0x02000000)
        SUBKEY_EXPAND(3, 0x04000000)
        SUBKEY_EXPAND(4, 0x08000000)
        SUBKEY_EXPAND(5, 0x10000000)
        SUBKEY_EXPAND(6, 0x20000000)
        SUBKEY_EXPAND_HALF(7, 0x40000000)
}




void aes256_cbc_decrypt(const unsigned int *key, const __global unsigned int iv[4], const __global unsigned int ciphertext[4], unsigned int plaintext[4])
{
    unsigned int subkeys[60];
    unsigned int s0, s1, s2, s3;
    unsigned int t0, t1, t2, t3;

    aes_256_key_expand(key, subkeys);

    // AddRoundKey
    s0 = ciphertext[0] ^ subkeys[56];
    s1 = ciphertext[1] ^ subkeys[57];
    s2 = ciphertext[2] ^ subkeys[58];
    s3 = ciphertext[3] ^ subkeys[59];

    // Macro for AES round (InvSubBytes, InvShiftRows, InvMixCols)
#define AES_ROUND(i)\
        t0 = (_invSbox[(s0>>24)]<<24)\
                | (_invSbox[(unsigned char)(s3>>16)]<<16)\
                | (_invSbox[(unsigned char)(s2>>8)]<<8)\
                | (_invSbox[(unsigned char)(s1)]);\
        t1 = (_invSbox[(s1>>24)]<<24)\
                | (_invSbox[(unsigned char)(s0>>16)]<<16)\
                | (_invSbox[(unsigned char)(s3>>8)]<<8)\
                | (_invSbox[(unsigned char)(s2)]);\
        t2 = (_invSbox[(s2>>24)]<<24)\
                | (_invSbox[(unsigned char)(s1>>16)]<<16)\
                | (_invSbox[(unsigned char)(s0>>8)]<<8)\
                | (_invSbox[(unsigned char)(s3)]);\
        t3 = (_invSbox[(s3>>24)]<<24)\
                | (_invSbox[(unsigned char)(s2>>16)]<<16)\
                | (_invSbox[(unsigned char)(s1>>8)]<<8)\
                | (_invSbox[(unsigned char)(s0)]);\
        s0 = t0 ^ subkeys[i*4];\
        s1 = t1 ^ subkeys[i*4+1];\
        s2 = t2 ^ subkeys[i*4+2];\
        s3 = t3 ^ subkeys[i*4+3];\
        s0 = _invMixCol1[(s0>>24)]\
                    ^ _invMixCol2[(unsigned char)(s0>>16)]\
                    ^ _invMixCol3[(unsigned char)(s0>>8)]\
                    ^ _invMixCol4[(unsigned char)s0];\
        s1 = _invMixCol1[(s1>>24)]\
                    ^ _invMixCol2[(unsigned char)(s1>>16)]\
                    ^ _invMixCol3[(unsigned char)(s1>>8)]\
                    ^ _invMixCol4[(unsigned char)s1];\
        s2 = _invMixCol1[(s2>>24)]\
                    ^ _invMixCol2[(unsigned char)(s2>>16)]\
                    ^ _invMixCol3[(unsigned char)(s2>>8)]\
                    ^ _invMixCol4[(unsigned char)s2];\
        s3 = _invMixCol1[(s3>>24)]\
                    ^ _invMixCol2[(unsigned char)(s3>>16)]\
                    ^ _invMixCol3[(unsigned char)(s3>>8)]\
                    ^ _invMixCol4[(unsigned char)s3];\

    // Unroll first 13 AES rounds
    AES_ROUND(13)
        AES_ROUND(12)
        AES_ROUND(11)
        AES_ROUND(10)
        AES_ROUND(9)
        AES_ROUND(8)
        AES_ROUND(7)
        AES_ROUND(6)
        AES_ROUND(5)
        AES_ROUND(4)
        AES_ROUND(3)
        AES_ROUND(2)
        AES_ROUND(1)

        // Last round: InvSubBytes + InvShiftRows
        t0 = (_invSbox[(s0 >> 24)] << 24)
        | (_invSbox[(unsigned char)(s3 >> 16)] << 16)
        | (_invSbox[(unsigned char)(s2 >> 8)] << 8)
        | (_invSbox[(unsigned char)(s1)]);
    t1 = (_invSbox[(s1 >> 24)] << 24)
        | (_invSbox[(unsigned char)(s0 >> 16)] << 16)
        | (_invSbox[(unsigned char)(s3 >> 8)] << 8)
        | (_invSbox[(unsigned char)(s2)]);
    t2 = (_invSbox[(s2 >> 24)] << 24)
        | (_invSbox[(unsigned char)(s1 >> 16)] << 16)
        | (_invSbox[(unsigned char)(s0 >> 8)] << 8)
        | (_invSbox[(unsigned char)(s3)]);
    t3 = (_invSbox[(s3 >> 24)] << 24)
        | (_invSbox[(unsigned char)(s2 >> 16)] << 16)
        | (_invSbox[(unsigned char)(s1 >> 8)] << 8)
        | (_invSbox[(unsigned char)(s0)]);

    // Final AddRoundKey
    plaintext[0] = t0 ^ subkeys[0] ^ iv[0];
    plaintext[1] = t1 ^ subkeys[1] ^ iv[1];
    plaintext[2] = t2 ^ subkeys[2] ^ iv[2];
    plaintext[3] = t3 ^ subkeys[3] ^ iv[3];
}


//////////////////////////////////// SHA 512 ///////////////////////////////////////
#define ROTR( x, n ) (((x) >> (n)) | ((x) << (64 - (n))))

#define MAJ( x, y, z) ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) )

#define CH( x, y , z) ( ( x & y ) ^ ( ~x & z ) )

#define S0( x ) ( ROTR( (x), 28 ) ^ ROTR( (x), 34 ) ^ ROTR( (x), 39 ) )

#define S1( x ) ( ROTR( (x), 14 ) ^ ROTR( (x), 18 ) ^ ROTR( (x), 41 ) )

#define S2( x ) ( ROTR( (x), 1 ) ^ ROTR( (x), 8 ) ^ ( (x) >> 7 ) )

#define S3( x ) ( ROTR( (x), 19 ) ^ ROTR( (x), 61 ) ^ ( (x) >> 6 ) )

#define F( a, b, c, d, e, f, g, h, x, k ) (h) += S1( (e) ) + CH( (e), (f), (g) ) + (k) + (x); (d) += (h); (h) += S0((a)) + MAJ( (a), (b), (c) )

__constant ulong _K[] = {
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

__constant ulong _K2[] = {
0xac941600cae5772a,
0x2c9ef316a8ba0d08,
0xf22fef42eae2335a,
0x8f05d0dfe0a712ad,
0x8a6514dba12f3809,
0xf4f67a7de1443c38,
0xb1c35c50aa5b0d06,
0x06fd2beeedeba291
};

__constant ulong _IV[8] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};



void sha512(ulong w[16])
{
    ulong a, b, c, d, e, f, g, h;

    a = _IV[0];
    b = _IV[1];
    c = _IV[2];
    d = _IV[3];
    e = _IV[4];
    f = _IV[5];
    g = _IV[6];
    h = _IV[7];


    F(a, b, c, d, e, f, g, h, w[0], _K[0]);
    F(h, a, b, c, d, e, f, g, w[1], _K[1]);
    F(g, h, a, b, c, d, e, f, w[2], _K[2]);
    F(f, g, h, a, b, c, d, e, w[3], _K[3]);
    F(e, f, g, h, a, b, c, d, w[4], _K[4]);
    F(d, e, f, g, h, a, b, c, w[5], _K[5]);
    F(c, d, e, f, g, h, a, b, w[6], _K[6]);
    F(b, c, d, e, f, g, h, a, w[7], _K[7]);
    F(a, b, c, d, e, f, g, h, w[8], _K[8]);
    F(h, a, b, c, d, e, f, g, w[9], _K[9]);
    F(g, h, a, b, c, d, e, f, w[10], _K[10]);
    F(f, g, h, a, b, c, d, e, w[11], _K[11]);
    F(e, f, g, h, a, b, c, d, w[12], _K[12]);
    F(d, e, f, g, h, a, b, c, w[13], _K[13]);
    F(c, d, e, f, g, h, a, b, w[14], _K[14]);
    F(b, c, d, e, f, g, h, a, w[15], _K[15]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[16]);
    F(h, a, b, c, d, e, f, g, w[1], _K[17]);
    F(g, h, a, b, c, d, e, f, w[2], _K[18]);
    F(f, g, h, a, b, c, d, e, w[3], _K[19]);
    F(e, f, g, h, a, b, c, d, w[4], _K[20]);
    F(d, e, f, g, h, a, b, c, w[5], _K[21]);
    F(c, d, e, f, g, h, a, b, w[6], _K[22]);
    F(b, c, d, e, f, g, h, a, w[7], _K[23]);
    F(a, b, c, d, e, f, g, h, w[8], _K[24]);
    F(h, a, b, c, d, e, f, g, w[9], _K[25]);
    F(g, h, a, b, c, d, e, f, w[10], _K[26]);
    F(f, g, h, a, b, c, d, e, w[11], _K[27]);
    F(e, f, g, h, a, b, c, d, w[12], _K[28]);
    F(d, e, f, g, h, a, b, c, w[13], _K[29]);
    F(c, d, e, f, g, h, a, b, w[14], _K[30]);
    F(b, c, d, e, f, g, h, a, w[15], _K[31]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[32]);
    F(h, a, b, c, d, e, f, g, w[1], _K[33]);
    F(g, h, a, b, c, d, e, f, w[2], _K[34]);
    F(f, g, h, a, b, c, d, e, w[3], _K[35]);
    F(e, f, g, h, a, b, c, d, w[4], _K[36]);
    F(d, e, f, g, h, a, b, c, w[5], _K[37]);
    F(c, d, e, f, g, h, a, b, w[6], _K[38]);
    F(b, c, d, e, f, g, h, a, w[7], _K[39]);
    F(a, b, c, d, e, f, g, h, w[8], _K[40]);
    F(h, a, b, c, d, e, f, g, w[9], _K[41]);
    F(g, h, a, b, c, d, e, f, w[10], _K[42]);
    F(f, g, h, a, b, c, d, e, w[11], _K[43]);
    F(e, f, g, h, a, b, c, d, w[12], _K[44]);
    F(d, e, f, g, h, a, b, c, w[13], _K[45]);
    F(c, d, e, f, g, h, a, b, w[14], _K[46]);
    F(b, c, d, e, f, g, h, a, w[15], _K[47]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[48]);
    F(h, a, b, c, d, e, f, g, w[1], _K[49]);
    F(g, h, a, b, c, d, e, f, w[2], _K[50]);
    F(f, g, h, a, b, c, d, e, w[3], _K[51]);
    F(e, f, g, h, a, b, c, d, w[4], _K[52]);
    F(d, e, f, g, h, a, b, c, w[5], _K[53]);
    F(c, d, e, f, g, h, a, b, w[6], _K[54]);
    F(b, c, d, e, f, g, h, a, w[7], _K[55]);
    F(a, b, c, d, e, f, g, h, w[8], _K[56]);
    F(h, a, b, c, d, e, f, g, w[9], _K[57]);
    F(g, h, a, b, c, d, e, f, w[10], _K[58]);
    F(f, g, h, a, b, c, d, e, w[11], _K[59]);
    F(e, f, g, h, a, b, c, d, w[12], _K[60]);
    F(d, e, f, g, h, a, b, c, w[13], _K[61]);
    F(c, d, e, f, g, h, a, b, w[14], _K[62]);
    F(b, c, d, e, f, g, h, a, w[15], _K[63]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[64]);
    F(h, a, b, c, d, e, f, g, w[1], _K[65]);
    F(g, h, a, b, c, d, e, f, w[2], _K[66]);
    F(f, g, h, a, b, c, d, e, w[3], _K[67]);
    F(e, f, g, h, a, b, c, d, w[4], _K[68]);
    F(d, e, f, g, h, a, b, c, w[5], _K[69]);
    F(c, d, e, f, g, h, a, b, w[6], _K[70]);
    F(b, c, d, e, f, g, h, a, w[7], _K[71]);
    F(a, b, c, d, e, f, g, h, w[8], _K[72]);
    F(h, a, b, c, d, e, f, g, w[9], _K[73]);
    F(g, h, a, b, c, d, e, f, w[10], _K[74]);
    F(f, g, h, a, b, c, d, e, w[11], _K[75]);
    F(e, f, g, h, a, b, c, d, w[12], _K[76]);
    F(d, e, f, g, h, a, b, c, w[13], _K[77]);
    F(c, d, e, f, g, h, a, b, w[14], _K[78]);
    F(b, c, d, e, f, g, h, a, w[15], _K[79]);

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


void sha512_hash(ulong x[8])
{
    ulong a, b, c, d, e, f, g, h;
    ulong w[16];

    a = _IV[0];
    b = _IV[1];
    c = _IV[2];
    d = _IV[3];
    e = _IV[4];
    f = _IV[5];
    g = _IV[6];
    h = _IV[7];

    const ulong w8 = 0x8000000000000000;
    const ulong w15 = 512;

    F(a, b, c, d, e, f, g, h, x[0], _K[0]);
    F(h, a, b, c, d, e, f, g, x[1], _K[1]);
    F(g, h, a, b, c, d, e, f, x[2], _K[2]);
    F(f, g, h, a, b, c, d, e, x[3], _K[3]);
    F(e, f, g, h, a, b, c, d, x[4], _K[4]);
    F(d, e, f, g, h, a, b, c, x[5], _K[5]);
    F(c, d, e, f, g, h, a, b, x[6], _K[6]);
    F(b, c, d, e, f, g, h, a, x[7], _K[7]);
    F(a, b, c, d, e, f, g, h, w8, _K[8]);
    F(h, a, b, c, d, e, f, g, 0, _K[9]);
    F(g, h, a, b, c, d, e, f, 0, _K[10]);
    F(f, g, h, a, b, c, d, e, 0, _K[11]);
    F(e, f, g, h, a, b, c, d, 0, _K[12]);
    F(d, e, f, g, h, a, b, c, 0, _K[13]);
    F(c, d, e, f, g, h, a, b, 0, _K[14]);
    F(b, c, d, e, f, g, h, a, w15, _K[15]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[16]);
    F(h, a, b, c, d, e, f, g, w[1], _K[17]);
    F(g, h, a, b, c, d, e, f, w[2], _K[18]);
    F(f, g, h, a, b, c, d, e, w[3], _K[19]);
    F(e, f, g, h, a, b, c, d, w[4], _K[20]);
    F(d, e, f, g, h, a, b, c, w[5], _K[21]);
    F(c, d, e, f, g, h, a, b, w[6], _K[22]);
    F(b, c, d, e, f, g, h, a, w[7], _K[23]);
    F(a, b, c, d, e, f, g, h, w[8], _K[24]);
    F(h, a, b, c, d, e, f, g, w[9], _K[25]);
    F(g, h, a, b, c, d, e, f, w[10], _K[26]);
    F(f, g, h, a, b, c, d, e, w[11], _K[27]);
    F(e, f, g, h, a, b, c, d, w[12], _K[28]);
    F(d, e, f, g, h, a, b, c, w[13], _K[29]);
    F(c, d, e, f, g, h, a, b, w[14], _K[30]);
    F(b, c, d, e, f, g, h, a, w[15], _K[31]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[32]);
    F(h, a, b, c, d, e, f, g, w[1], _K[33]);
    F(g, h, a, b, c, d, e, f, w[2], _K[34]);
    F(f, g, h, a, b, c, d, e, w[3], _K[35]);
    F(e, f, g, h, a, b, c, d, w[4], _K[36]);
    F(d, e, f, g, h, a, b, c, w[5], _K[37]);
    F(c, d, e, f, g, h, a, b, w[6], _K[38]);
    F(b, c, d, e, f, g, h, a, w[7], _K[39]);
    F(a, b, c, d, e, f, g, h, w[8], _K[40]);
    F(h, a, b, c, d, e, f, g, w[9], _K[41]);
    F(g, h, a, b, c, d, e, f, w[10], _K[42]);
    F(f, g, h, a, b, c, d, e, w[11], _K[43]);
    F(e, f, g, h, a, b, c, d, w[12], _K[44]);
    F(d, e, f, g, h, a, b, c, w[13], _K[45]);
    F(c, d, e, f, g, h, a, b, w[14], _K[46]);
    F(b, c, d, e, f, g, h, a, w[15], _K[47]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[48]);
    F(h, a, b, c, d, e, f, g, w[1], _K[49]);
    F(g, h, a, b, c, d, e, f, w[2], _K[50]);
    F(f, g, h, a, b, c, d, e, w[3], _K[51]);
    F(e, f, g, h, a, b, c, d, w[4], _K[52]);
    F(d, e, f, g, h, a, b, c, w[5], _K[53]);
    F(c, d, e, f, g, h, a, b, w[6], _K[54]);
    F(b, c, d, e, f, g, h, a, w[7], _K[55]);
    F(a, b, c, d, e, f, g, h, w[8], _K[56]);
    F(h, a, b, c, d, e, f, g, w[9], _K[57]);
    F(g, h, a, b, c, d, e, f, w[10], _K[58]);
    F(f, g, h, a, b, c, d, e, w[11], _K[59]);
    F(e, f, g, h, a, b, c, d, w[12], _K[60]);
    F(d, e, f, g, h, a, b, c, w[13], _K[61]);
    F(c, d, e, f, g, h, a, b, w[14], _K[62]);
    F(b, c, d, e, f, g, h, a, w[15], _K[63]);

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

    F(a, b, c, d, e, f, g, h, w[0], _K[64]);
    F(h, a, b, c, d, e, f, g, w[1], _K[65]);
    F(g, h, a, b, c, d, e, f, w[2], _K[66]);
    F(f, g, h, a, b, c, d, e, w[3], _K[67]);
    F(e, f, g, h, a, b, c, d, w[4], _K[68]);
    F(d, e, f, g, h, a, b, c, w[5], _K[69]);
    F(c, d, e, f, g, h, a, b, w[6], _K[70]);
    F(b, c, d, e, f, g, h, a, w[7], _K[71]);
    F(a, b, c, d, e, f, g, h, w[8], _K[72]);
    F(h, a, b, c, d, e, f, g, w[9], _K[73]);
    F(g, h, a, b, c, d, e, f, w[10], _K[74]);
    F(f, g, h, a, b, c, d, e, w[11], _K[75]);
    F(e, f, g, h, a, b, c, d, w[12], _K[76]);
    F(d, e, f, g, h, a, b, c, w[13], _K[77]);
    F(c, d, e, f, g, h, a, b, w[14], _K[78]);
    F(b, c, d, e, f, g, h, a, w[15], _K[79]);

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


struct password_info {
    //struct dictionary dictionaries[8];
    char *words[8];
    unsigned int *index[8];
    unsigned int size[8];

    int num_dictionaries;

    // Number of words in the password
    int password_len;

    // Array of integers specifying which dictionary
    // the letter/word in that place comes from
    int password_structure[8];
};

struct password_offset {
    unsigned int start;
    unsigned int count;
};

void next_password_alpha(__global char *alphabet, int alphabet_size, char *password, int len, ulong count)
{
    for(int i = len - 1; i >= 0; i--) {
        int idx = count % alphabet_size;
        password[i] = alphabet[idx];
        count -= idx;
        count /= alphabet_size;
    }
}



void next_password_dictionary(__global char *dictionary, __global unsigned int *index, __global struct password_offset *offsets, int num_words, char *password, int *length, ulong x)
{
    int curr_index = 0;

    for(int i = 0; i < num_words; i++) {
        unsigned int s = offsets[i].start;
        unsigned int idx = x % offsets[i].count;

        unsigned int start = index[s + idx];
        unsigned int len = index[s + idx + 1] - start;

        for(int j = 0; j < len; j++) {
            password[curr_index + j] = dictionary[start + j];
        }
        curr_index += len;

        x -= idx;
        x /= offsets[i].count;
    }
    *length = curr_index;
}


bool test_key(__private unsigned int key[8], __global unsigned int encrypted_block[4], __global unsigned int iv[4])
{
    unsigned int pt[4];

    aes256_cbc_decrypt(key, iv, encrypted_block, pt);

    return pt[0] == 0x10101010 && pt[1] == 0x10101010 && pt[2] == 0x10101010 && pt[3] == 0x10101010;
}

__kernel void dictionary_attack(__global char *dictionary, __global unsigned int *password_index, __global struct password_offset *offsets, int num_words, ulong total_passwords, unsigned int iterations, __global unsigned char *salt, ulong start, int stride, __global ulong *state)
{
    
    int length = 0;

    char password[20] = { 0 };

    int idx = get_global_id(0);

    start += idx * stride;

    if(start >= total_passwords) {
        return;
    }

    next_password_dictionary(dictionary, password_index, offsets, num_words, password, &length, start);

    ulong msg[16] = { 0 };

    // Encode password into the message
    int shift = 56;
    for(int i = 0; i < length; i++) {
        if(i >= 8 && i % 8 == 0) {
            shift = 56;
        }
        ulong c = (ulong)password[i];

        msg[i / 8] |= c << shift;
        shift -= 8;
    }

    // Encode salt
    for(int i = 0; i < 8; i++) {
        ulong b = salt[i];
        msg[(length + i) / 8] |= b << ((7 - ((length + i) % 8))) * 8;
    }

    // Apply padding byte
    msg[(length + 8) / 8] |= (ulong)0x80 << (7 - ((length + 8) % 8)) * 8;
    msg[15] = (length + 8) * 8;

    sha512(msg);

    for(unsigned int i = 0; i < iterations - 1; i++) {
        sha512_hash(msg);
    }

    // Save state to device memory
    for(int i = 0; i < 8; i++) {
        state[idx * 8 + i] = msg[i];
    }
}

__kernel void brute_force_alphabet(__global char *alphabet, int alphabet_size, int password_len, unsigned int iterations, __global unsigned char *salt, ulong start, int stride, __global ulong *state)
{
    char password[12] = { 0 };

    int idx = get_global_id(0);

    start += idx * stride;

    next_password_alpha(alphabet, alphabet_size, password, password_len, start);

    ulong msg[16] = { 0 };

    // Encode password into the message
    int shift = 56;
    for(int i = 0; i < password_len; i++) {
        if(i >= 8 && i % 8 == 0) {
            shift = 56;
        }
        ulong c = (ulong)password[i];

        msg[i / 8] |= c << shift;
        shift -= 8;
    }

    // Encode salt
    for(int i = 0; i < 8; i++) {
        ulong b = salt[i];
        msg[(password_len + i) / 8] |= b << ((7 - ((password_len + i) % 8))) * 8;
    }

    // Apply padding byte
    msg[(password_len + 8) / 8] |= (ulong)0x80 << (7 - ((password_len + 8) % 8)) * 8;
    msg[15] = (password_len + 8) * 8;

    sha512(msg);

    for(unsigned int i = 0; i < iterations - 1; i++) {
        sha512_hash(msg);
    }

    // Save state to device memory
    for(int i = 0; i < 8; i++) {
        state[idx * 8 + i] = msg[i];
    }
}

__kernel void hash_middle(__global ulong *state, unsigned int iterations)
{
    ulong msg[8];
    int idx = get_global_id(0);

    for(int i = 0; i < 8; i++) {
        msg[i] = state[idx * 8 + i];
    }

    for(unsigned int i = 0; i < iterations; i++) {
        sha512_hash(msg);
    }

    // Save state to device memory
    for(int i = 0; i < 8; i++) {
        state[idx * 8 + i] = msg[i];
    }
}

__kernel void hash_end(__global unsigned int *encrypted_block, __global unsigned int *iv, __global ulong *state, unsigned int iterations, __global int *result)
{
    ulong msg[8];
    int idx = get_global_id(0);

    for(int i = 0; i < 8; i++) {
        msg[i] = state[idx * 8 + i];
    }

    for(int i = 0; i < iterations; i++) {
        sha512_hash(msg);
    }

    // Save state to device memory
    for(int i = 0; i < 8; i++) {
        state[idx * 8 + i] = msg[i];
    }

    unsigned int key[8];
    key[0] = (unsigned int)(msg[0] >> 32);
    key[1] = (unsigned int)msg[0];

    key[2] = (unsigned int)(msg[1] >> 32);
    key[3] = (unsigned int)msg[1];

    key[4] = (unsigned int)(msg[2] >> 32);
    key[5] = (unsigned int)msg[2];

    key[6] = (unsigned int)(msg[3] >> 32);
    key[7] = (unsigned int)msg[3];

    if(test_key(key, encrypted_block, iv)) {
        *result = idx;
    }
}