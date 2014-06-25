#ifndef __RETAIN_H
#define __RETAIN_H

#ifdef PLATFORM_TELOSB
    #include <avr/pgmspace.h>
#endif

// Copy ROM data to RAM:
	//unsigned char buffer[16];
	//memcpy_P(buffer,retain_values[0],16); or
	//memcpy_P(buffer,&retain_values[0],16); depending on the retain_values declaration
// Print ROM data:
	//printf_P(retain_values[0]);


// The seed used to generate the retain instances is {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF}

#if (MSS_HEIGHT == 8) && (MSS_K == 6) && (WINTERNITZ_W == 2)

	unsigned char retain_height[57] PROGMEM = {
	0x06,0x05,0x05,0x05,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x03,0x03,0x03,0x03,0x03,
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02};

	unsigned char retain_pos[57] PROGMEM = {
	0x03,0x03,0x05,0x07,0x03,0x05,0x07,0x09,0x0B,0x0D,0x0F,0x03,0x05,0x07,0x09,0x0B,
	0x0D,0x0F,0x11,0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x03,0x05,0x07,0x09,0x0B,0x0D,
	0x0F,0x11,0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x21,0x23,0x25,0x27,0x29,0x2B,0x2D,
	0x2F,0x31,0x33,0x35,0x37,0x39,0x3B,0x3D,0x3F};

	unsigned char retain_values[57][16] PROGMEM = {
	{0x5D,0xAA,0x10,0xBE,0xFB,0xFB,0x6C,0xCD,0x44,0x4A,0xE6,0x70,0xEE,0xD7,0x4B,0x4D},
	{0xC3,0xEF,0xDA,0xEE,0x5C,0x4C,0x6A,0xFD,0x4E,0x04,0x25,0x33,0x4E,0x7D,0xB9,0xD0},
	{0xED,0x4F,0x31,0x10,0xFE,0x19,0xD8,0x93,0x6A,0x40,0x0A,0x43,0xFA,0x77,0xD7,0x27},
	{0x13,0x7D,0x97,0x32,0x83,0xBA,0xBD,0x2E,0xAC,0x4C,0x4D,0x81,0xB2,0x58,0x33,0xBC},
	{0x6E,0x8C,0x94,0xC2,0x0C,0xC7,0x5F,0xF7,0x50,0xBC,0xC3,0x8D,0xC1,0xAD,0xC5,0xD1},
	{0x0B,0x06,0xAD,0xD5,0x6A,0x25,0x7F,0x2B,0x11,0x75,0xCD,0x77,0x08,0xAB,0x86,0x6C},
	{0x3C,0xDB,0x96,0xD2,0xC5,0x66,0x68,0xFF,0xBF,0xFD,0x5F,0xA6,0xE6,0x7F,0x9D,0x7E},
	{0xE1,0xCB,0xFC,0x3C,0x1D,0x8E,0xDA,0x2C,0x88,0xC3,0x74,0x97,0xBF,0xD1,0x15,0x11},
	{0x37,0x3B,0xDF,0x33,0xC8,0xBA,0xF6,0x19,0xCF,0x61,0xCA,0x0E,0x5E,0xCD,0x8F,0x49},
	{0xDD,0x9F,0xC4,0x45,0x5A,0x82,0xAD,0x37,0x34,0xA7,0xB8,0x80,0xED,0x54,0x20,0x41},
	{0x22,0x47,0xFF,0x7F,0xF8,0xE9,0xEB,0x15,0x58,0xEA,0xB1,0x8E,0xC9,0x94,0x47,0xC9},
	{0xFB,0x8F,0xEC,0x12,0x2B,0xB6,0xF1,0xB5,0xD3,0x98,0x38,0xCB,0xDD,0xAE,0xA2,0xAD},
	{0x56,0xF9,0x59,0xA8,0x55,0x03,0xFB,0x07,0x0E,0x87,0x94,0x28,0xBD,0x16,0x11,0xDD},
	{0x36,0x49,0xBC,0xDF,0xED,0xBC,0x52,0x89,0xE5,0x1D,0x9B,0x33,0x2B,0x2C,0xC5,0x76},
	{0x5F,0x93,0xD6,0x7A,0x6A,0xDF,0xBA,0x4E,0xFD,0x24,0x17,0xB2,0xCA,0xED,0x75,0xF0},
	{0x06,0x45,0xA6,0xC9,0x83,0x0D,0x14,0xD3,0x72,0xBF,0xD2,0x30,0x3A,0xB5,0x17,0x26},
	{0xCD,0xD5,0x03,0xAD,0x34,0xE9,0x70,0x20,0xEF,0x35,0xBC,0x6E,0xF9,0xA7,0x03,0x91},
	{0x19,0x20,0xDF,0xFA,0xBC,0xB2,0x91,0x47,0x7D,0xCF,0xEF,0xF8,0xC8,0xFF,0xE1,0xD3},
	{0x54,0x22,0x4D,0x9F,0x59,0x35,0xE4,0x6C,0x30,0x80,0xDE,0x21,0x7E,0x10,0x59,0x61},
	{0x99,0x50,0x18,0x95,0xC4,0x46,0xBD,0xEF,0xFB,0x37,0x65,0x97,0x77,0x9F,0xC8,0x99},
	{0x09,0x83,0xE0,0xA5,0xAD,0x35,0x65,0x1E,0x7C,0xAA,0x2F,0x0B,0xF5,0x88,0x71,0x87},
	{0xFE,0xB3,0xC9,0x3C,0x84,0x1D,0xA6,0x19,0x84,0x16,0x7F,0xA8,0x68,0x15,0xE6,0x10},
	{0x00,0x10,0xA6,0xF8,0x7B,0x06,0xEB,0xEE,0xF7,0x1C,0xBA,0x2F,0x2F,0x2D,0x5E,0x06},
	{0x23,0x90,0x37,0xF5,0xEB,0xEC,0xA9,0xA8,0xB3,0xC5,0x14,0xAA,0xCB,0xF4,0x6A,0x1B},
	{0x54,0xCE,0x30,0xD1,0xA7,0x14,0x4E,0xC8,0x60,0xBF,0x20,0x65,0x33,0xFF,0x7B,0x83},
	{0xCE,0x37,0x33,0xE6,0xEC,0x20,0x7C,0x65,0x23,0xAC,0x59,0xF4,0xF5,0x71,0x83,0xB6},
	{0xB1,0x99,0xC4,0x1F,0xB5,0x6A,0x27,0xB2,0xC8,0x45,0xA3,0xAE,0x13,0x01,0x2E,0x29},
	{0x9F,0x27,0xB6,0xA8,0x0C,0xB8,0x75,0x98,0x52,0xB4,0x01,0x4B,0x51,0xBB,0xB9,0x5F},
	{0x74,0x0A,0xD0,0x54,0xBA,0xE6,0x90,0xC5,0xA6,0xE6,0x69,0x19,0x50,0xEE,0x2C,0x58},
	{0x72,0x8B,0xC0,0x0A,0xE6,0xA6,0xDF,0xFD,0x28,0xDE,0x60,0xBF,0xBD,0xC2,0xBB,0x35},
	{0xA0,0xB2,0xA7,0xD1,0xAD,0x2E,0x94,0xF6,0x0C,0xC7,0x4D,0xA6,0x3C,0x40,0x51,0x24},
	{0x85,0x5F,0xA2,0xDF,0x9D,0xE3,0x90,0x19,0x5C,0x8F,0xF0,0x74,0x40,0xE6,0x3E,0x70},
	{0xDC,0x08,0x46,0x10,0x98,0xA9,0xF7,0xCF,0x3E,0x02,0x65,0x5B,0x77,0x5E,0x2B,0x9A},
	{0x34,0x0C,0xA8,0xB7,0x6C,0x72,0x91,0xC3,0x2D,0x96,0x29,0x05,0xE5,0xCC,0xEC,0xAB},
	{0xAD,0x11,0xF8,0xC7,0x78,0x5C,0x20,0xD2,0xEB,0x22,0xBF,0x06,0x7A,0x1D,0x99,0x66},
	{0xA0,0xF9,0xE2,0xB1,0xFA,0xA7,0x87,0x43,0xC4,0x00,0xB7,0x16,0x8B,0x85,0xAE,0x05},
	{0xB8,0x23,0x4B,0x40,0xE7,0x03,0x35,0xB2,0x98,0x75,0x6E,0xA6,0x0B,0x22,0x91,0x54},
	{0x90,0x20,0x74,0xD7,0xB6,0x8A,0x24,0x46,0x33,0xBE,0xE9,0x72,0x1C,0xDE,0x40,0xDA},
	{0xD4,0x88,0x54,0xFD,0x63,0x12,0x8C,0x39,0x71,0x4A,0xAB,0x23,0xD8,0x53,0x07,0xC3},
	{0x67,0xAF,0xE9,0x12,0xA7,0x48,0xA4,0x0C,0x5F,0xBD,0xCE,0x08,0x94,0xE9,0x49,0x35},
	{0xEB,0xDC,0x38,0x33,0x1A,0x6D,0x51,0x3B,0x41,0xE9,0x9A,0x66,0x35,0x75,0x76,0xBE},
	{0xD2,0x3E,0x27,0x27,0x03,0x95,0x9F,0x5C,0x7E,0x07,0xCA,0x25,0xBA,0xBA,0x6B,0x7E},
	{0x92,0xA4,0xCF,0x23,0x26,0x6D,0x66,0xD4,0xD6,0xB9,0x45,0x08,0xB6,0x30,0xE8,0xF2},
	{0x4F,0x62,0xDF,0x04,0xEE,0x00,0x85,0xA9,0xC7,0x00,0xD9,0xE6,0x93,0x16,0x86,0xDD},
	{0xE9,0x8D,0x22,0x37,0x58,0xF7,0x3D,0x3C,0x3B,0xDB,0x42,0x10,0xD6,0x3B,0xC4,0x83},
	{0x0F,0x1A,0x50,0x2F,0x2C,0xFC,0x52,0xA6,0x7C,0x5D,0xBA,0xB2,0xB0,0x53,0x45,0xAB},
	{0xDC,0xEA,0x38,0x15,0x68,0x62,0x40,0xAC,0x74,0xF9,0x22,0x30,0x97,0xDA,0xC7,0x72},
	{0xCB,0x77,0x1C,0x26,0x5D,0xB8,0xF6,0xE5,0x78,0x62,0x55,0xC4,0xFA,0x0B,0xE7,0x2A},
	{0x39,0x1B,0xB9,0xA5,0xE9,0xEA,0x58,0xD4,0x7D,0x1D,0x95,0x15,0xBB,0x92,0xD0,0x80},
	{0x60,0xC7,0x33,0x15,0x8F,0xD2,0x79,0x0A,0x60,0x77,0xE7,0xAB,0x5F,0x48,0xE8,0x03},
	{0x55,0xAD,0x2F,0xE3,0x12,0xE7,0x7A,0x08,0x48,0xE4,0xF9,0xD4,0x50,0x41,0x1D,0x4A},
	{0x60,0x89,0x8F,0x64,0xEA,0xAF,0x4B,0x73,0x63,0x13,0x0C,0x83,0x7F,0xCF,0x86,0xA4},
	{0xA6,0x42,0xAD,0x4E,0xF2,0x4D,0x0F,0x49,0xDC,0xDB,0x02,0xC7,0x15,0xCE,0x40,0xF4},
	{0xA1,0x6A,0xD0,0x7A,0xD1,0x2D,0x75,0x4F,0x20,0x8B,0xF7,0x10,0x60,0xB3,0xFE,0xBF},
	{0x90,0x49,0xB6,0x87,0xBE,0x65,0x07,0x73,0x87,0xA0,0x78,0xA1,0x20,0xCD,0x9C,0xD7},
	{0xE5,0x56,0xB9,0x36,0x9D,0xB1,0x76,0x30,0x20,0x36,0x08,0x47,0x1B,0xB2,0x78,0x9B},
	{0x3E,0x40,0x40,0xBF,0xE6,0x08,0x91,0xC2,0x6E,0xAD,0x78,0xB8,0xD4,0x2F,0x52,0x96}
	};
#endif

#if (MSS_HEIGHT == 10) && (MSS_K == 6) && (WINTERNITZ_W == 2)

	unsigned char retain_height[57] PROGMEM = {
	0x08,0x07,0x07,0x07,0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x05,0x05,0x05,0x05,0x05,
	0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x04,0x04,0x04,0x04,0x04,0x04,
	0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
	0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04};

	unsigned char retain_pos[57] PROGMEM = {
	0x03,0x03,0x05,0x07,0x03,0x05,0x07,0x09,0x0B,0x0D,0x0F,0x03,0x05,0x07,0x09,0x0B,
	0x0D,0x0F,0x11,0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x03,0x05,0x07,0x09,0x0B,0x0D,
	0x0F,0x11,0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x21,0x23,0x25,0x27,0x29,0x2B,0x2D,
	0x2F,0x31,0x33,0x35,0x37,0x39,0x3B,0x3D,0x3F};

	unsigned char retain_values[57][16] PROGMEM = {
	{0x6A,0x5E,0x81,0xB4,0x0D,0xC3,0x42,0x4D,0x1B,0x27,0x80,0xC4,0x0A,0x53,0x38,0xDC},
	{0xEA,0xAC,0xE4,0xC6,0xD5,0x66,0x0D,0x2F,0x06,0x9B,0x55,0x8A,0x4E,0x4D,0xB9,0xCB},
	{0x4A,0x65,0x69,0xC7,0x36,0x4B,0x48,0x20,0x00,0x68,0xA1,0xBE,0xB8,0x94,0xE1,0x4D},
	{0x60,0x70,0x63,0x76,0x82,0xE6,0x4A,0x12,0x36,0xCA,0x30,0xCB,0x2C,0x88,0x83,0x17},
	{0x5D,0xAA,0x10,0xBE,0xFB,0xFB,0x6C,0xCD,0x44,0x4A,0xE6,0x70,0xEE,0xD7,0x4B,0x4D},
	{0x12,0x60,0x88,0xB9,0xF0,0xA1,0x7D,0xDC,0x02,0x01,0x95,0xD0,0x48,0x91,0x6F,0x71},
	{0x65,0x9C,0x66,0x4D,0x59,0x5F,0xAE,0x7B,0x63,0xB0,0x95,0x81,0xD6,0x7B,0xEE,0x03},
	{0x3E,0x6C,0xF5,0xE5,0xFC,0x87,0xA0,0x8F,0x00,0xB8,0x5D,0xA2,0x54,0xC7,0xFC,0x1D},
	{0x09,0x13,0xC0,0xA6,0xD2,0x15,0x9A,0x6F,0x2F,0xE3,0x47,0xB0,0x26,0x19,0xE1,0x31},
	{0xE0,0xFF,0xC8,0x04,0x44,0x1E,0x91,0xB0,0xED,0x80,0x6D,0x85,0xAE,0x87,0x5B,0x4C},
	{0xF2,0xE4,0x8F,0xDE,0x18,0xB0,0x7E,0x47,0xF6,0xFF,0xD9,0x41,0x10,0x49,0xE1,0x70},
	{0xC3,0xEF,0xDA,0xEE,0x5C,0x4C,0x6A,0xFD,0x4E,0x04,0x25,0x33,0x4E,0x7D,0xB9,0xD0},
	{0xED,0x4F,0x31,0x10,0xFE,0x19,0xD8,0x93,0x6A,0x40,0x0A,0x43,0xFA,0x77,0xD7,0x27},
	{0x13,0x7D,0x97,0x32,0x83,0xBA,0xBD,0x2E,0xAC,0x4C,0x4D,0x81,0xB2,0x58,0x33,0xBC},
	{0xEE,0x1F,0x23,0x7F,0xFE,0x81,0x23,0x0D,0x22,0x2A,0x50,0x03,0xA0,0x66,0xDB,0x20},
	{0x59,0xCC,0xA8,0x3A,0xC2,0x12,0x03,0xBF,0xDC,0x59,0x13,0xB3,0x12,0xD1,0x3E,0x0D},
	{0x7F,0xB6,0xAB,0x4C,0x1B,0x80,0xA2,0xF2,0xCC,0x60,0xCC,0x13,0x24,0x99,0x59,0x8C},
	{0x16,0xA7,0xC1,0xE4,0x3B,0x5C,0xA3,0x01,0xEE,0x72,0x45,0x2F,0xE6,0x0A,0xD4,0x18},
	{0x7A,0x9A,0xBD,0xA6,0x3A,0x0D,0xED,0x97,0x10,0xCD,0x33,0x2D,0xA3,0xBD,0x15,0x4F},
	{0x5F,0x67,0xFC,0xA7,0xC2,0x9E,0xA6,0x7C,0x23,0x57,0x23,0xF9,0x73,0x6F,0x68,0xDB},
	{0xFA,0x8D,0xC4,0x20,0xB1,0x36,0x40,0xAF,0x3D,0xC1,0x22,0xF5,0xDB,0xA9,0x6D,0xEF},
	{0x59,0xE9,0xAF,0x26,0x96,0x9B,0x25,0x12,0x09,0xA4,0x55,0xDE,0xD7,0xD0,0x6C,0xD4},
	{0x09,0xA3,0x64,0xB0,0x2C,0x43,0x9F,0xE9,0x92,0x64,0x45,0xD8,0xEB,0x7D,0x04,0x00},
	{0x17,0x83,0xF1,0x53,0x50,0xEF,0xA1,0x58,0x83,0x35,0xEF,0x4F,0x7B,0xED,0x97,0xE5},
	{0x28,0x67,0xDC,0xE3,0x7D,0x53,0x45,0x59,0xCC,0xBF,0x96,0xE4,0x54,0xCC,0xB0,0xC9},
	{0x5E,0x64,0x63,0xD6,0x04,0x9E,0x2C,0xAB,0xA7,0xCB,0x97,0x4B,0x45,0x82,0x97,0x5D},
	{0x6E,0x8C,0x94,0xC2,0x0C,0xC7,0x5F,0xF7,0x50,0xBC,0xC3,0x8D,0xC1,0xAD,0xC5,0xD1},
	{0x0B,0x06,0xAD,0xD5,0x6A,0x25,0x7F,0x2B,0x11,0x75,0xCD,0x77,0x08,0xAB,0x86,0x6C},
	{0x3C,0xDB,0x96,0xD2,0xC5,0x66,0x68,0xFF,0xBF,0xFD,0x5F,0xA6,0xE6,0x7F,0x9D,0x7E},
	{0xE1,0xCB,0xFC,0x3C,0x1D,0x8E,0xDA,0x2C,0x88,0xC3,0x74,0x97,0xBF,0xD1,0x15,0x11},
	{0x37,0x3B,0xDF,0x33,0xC8,0xBA,0xF6,0x19,0xCF,0x61,0xCA,0x0E,0x5E,0xCD,0x8F,0x49},
	{0xDD,0x9F,0xC4,0x45,0x5A,0x82,0xAD,0x37,0x34,0xA7,0xB8,0x80,0xED,0x54,0x20,0x41},
	{0x22,0x47,0xFF,0x7F,0xF8,0xE9,0xEB,0x15,0x58,0xEA,0xB1,0x8E,0xC9,0x94,0x47,0xC9},
	{0x04,0xB2,0xCC,0x81,0x7B,0x4E,0xC3,0x67,0x35,0xF5,0x77,0x07,0x5A,0xA0,0x5E,0x6B},
	{0x9E,0xDD,0x4F,0xEF,0x73,0x89,0x4A,0xB9,0x05,0xCF,0x9C,0xA7,0x05,0x18,0xF5,0xC1},
	{0xFF,0x2E,0xAF,0x1A,0xE7,0x61,0xAE,0xE9,0x1C,0xF3,0xA6,0xDB,0x38,0xAB,0x88,0x8A},
	{0x67,0x7E,0x37,0xBF,0x30,0x29,0x12,0x8C,0x37,0x51,0x18,0x04,0xD8,0xBE,0x9B,0xB0},
	{0x6F,0x15,0x10,0x75,0x51,0x30,0x75,0x4B,0xB5,0x1B,0x28,0xAF,0x02,0xF2,0xEC,0xC5},
	{0x92,0x27,0xEA,0xC1,0x30,0x9F,0x46,0x21,0xAD,0xC6,0x23,0x02,0xB5,0x5A,0x6C,0xEE},
	{0xF0,0xCF,0xE7,0x7A,0x4F,0xA2,0x7C,0xB7,0xD0,0xF0,0xDE,0xC0,0x7D,0xB0,0x21,0xA5},
	{0x0B,0xB4,0xFD,0x19,0xF9,0x25,0x89,0x61,0x9D,0x8A,0x74,0x99,0xF8,0x34,0x2D,0x90},
	{0x1F,0x30,0x51,0xAE,0xB2,0xF6,0x6D,0xD8,0xD6,0xB6,0xB8,0x46,0x27,0x91,0x49,0x92},
	{0x4E,0x71,0xEA,0x0A,0xE2,0xB8,0x08,0xC1,0xB6,0x04,0x20,0x53,0xDA,0xF3,0xA0,0x22},
	{0xD9,0x2F,0xB2,0xC3,0x8F,0x57,0x02,0x94,0xF6,0x0B,0xDF,0x0A,0xE0,0xDD,0x9A,0xBA},
	{0x5A,0x8F,0x96,0x27,0xD9,0x9D,0xCB,0x70,0x63,0xBD,0x3E,0xF8,0xFD,0x7A,0x38,0xB3},
	{0x0B,0x3F,0x0B,0x99,0xA1,0x69,0x77,0xFE,0x3D,0x4F,0x18,0x81,0xBD,0xA1,0xEC,0x34},
	{0x7D,0xB7,0x81,0x0B,0x6E,0x41,0xD9,0x3D,0x2C,0xAF,0x23,0x76,0x3E,0xEB,0xBE,0x96},
	{0x72,0xB3,0x09,0x72,0xFC,0xB6,0x03,0x5C,0x9C,0xF2,0x35,0x21,0xDE,0x83,0xB7,0xEA},
	{0x7A,0x8D,0xD6,0x30,0xD3,0x45,0xB6,0x27,0x14,0xF1,0x29,0x17,0x3D,0x3F,0xCF,0x2F},
	{0x8B,0x5D,0xD6,0xD8,0xAF,0xC6,0x2B,0xA9,0x24,0x23,0x13,0x42,0x4E,0x7B,0x0C,0x55},
	{0x4C,0x74,0x94,0xDE,0xD5,0xE1,0xA8,0x28,0xC8,0x73,0xBB,0x7F,0xDB,0x51,0x3C,0x9B},
	{0x03,0xA7,0xA9,0xBF,0x00,0x40,0x57,0x22,0x56,0xEE,0x0D,0x95,0x66,0x8E,0x27,0x36},
	{0xA9,0xF5,0xB8,0x8B,0x7A,0x84,0xFF,0x9A,0x6A,0x21,0xD4,0x66,0xF4,0x0D,0x5A,0x7E},
	{0x96,0x34,0x61,0xDA,0x98,0x5E,0x35,0xFA,0x64,0x6E,0x81,0x73,0xA0,0x57,0x6A,0x58},
	{0x8E,0xCE,0x8F,0xF8,0xF7,0x32,0xEB,0x4C,0x42,0x17,0xB4,0x09,0x2E,0x23,0xC4,0xFB},
	{0x19,0x01,0x18,0x1D,0xC5,0x64,0xBD,0xA1,0x31,0xBC,0xDD,0xDF,0xDE,0xC7,0xC5,0x59},
	{0x80,0xEA,0xF9,0x50,0xB3,0x90,0x00,0xBF,0x0F,0x51,0xB2,0x63,0xBB,0x1E,0x31,0x2F}
	};
#endif

#if (MSS_HEIGHT == 10) && (MSS_K == 8) && (WINTERNITZ_W == 2)
	unsigned char retain_height[247] PROGMEM = {
	0x08,0x07,0x07,0x07,0x06,0x06,0x06,0x06,0x06,0x06,0x06,0x05,0x05,0x05,0x05,0x05,
	0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x05,0x04,0x04,0x04,0x04,0x04,0x04,
	0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,
	0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x04,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02};

	unsigned char retain_pos[247] PROGMEM = {
	0x03,0x03,0x05,0x07,0x03,0x05,0x07,0x09,0x0B,0x0D,0x0F,0x03,0x05,0x07,0x09,0x0B,
	0x0D,0x0F,0x11,0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x03,0x05,0x07,0x09,0x0B,0x0D,
	0x0F,0x11,0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x21,0x23,0x25,0x27,0x29,0x2B,0x2D,
	0x2F,0x31,0x33,0x35,0x37,0x39,0x3B,0x3D,0x3F,0x03,0x05,0x07,0x09,0x0B,0x0D,0x0F,
	0x11,0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x21,0x23,0x25,0x27,0x29,0x2B,0x2D,0x2F,
	0x31,0x33,0x35,0x37,0x39,0x3B,0x3D,0x3F,0x41,0x43,0x45,0x47,0x49,0x4B,0x4D,0x4F,
	0x51,0x53,0x55,0x57,0x59,0x5B,0x5D,0x5F,0x61,0x63,0x65,0x67,0x69,0x6B,0x6D,0x6F,
	0x71,0x73,0x75,0x77,0x79,0x7B,0x7D,0x7F,0x03,0x05,0x07,0x09,0x0B,0x0D,0x0F,0x11,
	0x13,0x15,0x17,0x19,0x1B,0x1D,0x1F,0x21,0x23,0x25,0x27,0x29,0x2B,0x2D,0x2F,0x31,
	0x33,0x35,0x37,0x39,0x3B,0x3D,0x3F,0x41,0x43,0x45,0x47,0x49,0x4B,0x4D,0x4F,0x51,
	0x53,0x55,0x57,0x59,0x5B,0x5D,0x5F,0x61,0x63,0x65,0x67,0x69,0x6B,0x6D,0x6F,0x71,
	0x73,0x75,0x77,0x79,0x7B,0x7D,0x7F,0x81,0x83,0x85,0x87,0x89,0x8B,0x8D,0x8F,0x91,
	0x93,0x95,0x97,0x99,0x9B,0x9D,0x9F,0xA1,0xA3,0xA5,0xA7,0xA9,0xAB,0xAD,0xAF,0xB1,
	0xB3,0xB5,0xB7,0xB9,0xBB,0xBD,0xBF,0xC1,0xC3,0xC5,0xC7,0xC9,0xCB,0xCD,0xCF,0xD1,
	0xD3,0xD5,0xD7,0xD9,0xDB,0xDD,0xDF,0xE1,0xE3,0xE5,0xE7,0xE9,0xEB,0xED,0xEF,0xF1,
	0xF3,0xF5,0xF7,0xF9,0xFB,0xFD,0xFF};

	unsigned char retain_values[247][16] PROGMEM = {
	{0x6A,0x5E,0x81,0xB4,0x0D,0xC3,0x42,0x4D,0x1B,0x27,0x80,0xC4,0x0A,0x53,0x38,0xDC},
	{0xEA,0xAC,0xE4,0xC6,0xD5,0x66,0x0D,0x2F,0x06,0x9B,0x55,0x8A,0x4E,0x4D,0xB9,0xCB},
	{0x4A,0x65,0x69,0xC7,0x36,0x4B,0x48,0x20,0x00,0x68,0xA1,0xBE,0xB8,0x94,0xE1,0x4D},
	{0x60,0x70,0x63,0x76,0x82,0xE6,0x4A,0x12,0x36,0xCA,0x30,0xCB,0x2C,0x88,0x83,0x17},
	{0x5D,0xAA,0x10,0xBE,0xFB,0xFB,0x6C,0xCD,0x44,0x4A,0xE6,0x70,0xEE,0xD7,0x4B,0x4D},
	{0x12,0x60,0x88,0xB9,0xF0,0xA1,0x7D,0xDC,0x02,0x01,0x95,0xD0,0x48,0x91,0x6F,0x71},
	{0x65,0x9C,0x66,0x4D,0x59,0x5F,0xAE,0x7B,0x63,0xB0,0x95,0x81,0xD6,0x7B,0xEE,0x03},
	{0x3E,0x6C,0xF5,0xE5,0xFC,0x87,0xA0,0x8F,0x00,0xB8,0x5D,0xA2,0x54,0xC7,0xFC,0x1D},
	{0x09,0x13,0xC0,0xA6,0xD2,0x15,0x9A,0x6F,0x2F,0xE3,0x47,0xB0,0x26,0x19,0xE1,0x31},
	{0xE0,0xFF,0xC8,0x04,0x44,0x1E,0x91,0xB0,0xED,0x80,0x6D,0x85,0xAE,0x87,0x5B,0x4C},
	{0xF2,0xE4,0x8F,0xDE,0x18,0xB0,0x7E,0x47,0xF6,0xFF,0xD9,0x41,0x10,0x49,0xE1,0x70},
	{0xC3,0xEF,0xDA,0xEE,0x5C,0x4C,0x6A,0xFD,0x4E,0x04,0x25,0x33,0x4E,0x7D,0xB9,0xD0},
	{0xED,0x4F,0x31,0x10,0xFE,0x19,0xD8,0x93,0x6A,0x40,0x0A,0x43,0xFA,0x77,0xD7,0x27},
	{0x13,0x7D,0x97,0x32,0x83,0xBA,0xBD,0x2E,0xAC,0x4C,0x4D,0x81,0xB2,0x58,0x33,0xBC},
	{0xEE,0x1F,0x23,0x7F,0xFE,0x81,0x23,0x0D,0x22,0x2A,0x50,0x03,0xA0,0x66,0xDB,0x20},
	{0x59,0xCC,0xA8,0x3A,0xC2,0x12,0x03,0xBF,0xDC,0x59,0x13,0xB3,0x12,0xD1,0x3E,0x0D},
	{0x7F,0xB6,0xAB,0x4C,0x1B,0x80,0xA2,0xF2,0xCC,0x60,0xCC,0x13,0x24,0x99,0x59,0x8C},
	{0x16,0xA7,0xC1,0xE4,0x3B,0x5C,0xA3,0x01,0xEE,0x72,0x45,0x2F,0xE6,0x0A,0xD4,0x18},
	{0x7A,0x9A,0xBD,0xA6,0x3A,0x0D,0xED,0x97,0x10,0xCD,0x33,0x2D,0xA3,0xBD,0x15,0x4F},
	{0x5F,0x67,0xFC,0xA7,0xC2,0x9E,0xA6,0x7C,0x23,0x57,0x23,0xF9,0x73,0x6F,0x68,0xDB},
	{0xFA,0x8D,0xC4,0x20,0xB1,0x36,0x40,0xAF,0x3D,0xC1,0x22,0xF5,0xDB,0xA9,0x6D,0xEF},
	{0x59,0xE9,0xAF,0x26,0x96,0x9B,0x25,0x12,0x09,0xA4,0x55,0xDE,0xD7,0xD0,0x6C,0xD4},
	{0x09,0xA3,0x64,0xB0,0x2C,0x43,0x9F,0xE9,0x92,0x64,0x45,0xD8,0xEB,0x7D,0x04,0x00},
	{0x17,0x83,0xF1,0x53,0x50,0xEF,0xA1,0x58,0x83,0x35,0xEF,0x4F,0x7B,0xED,0x97,0xE5},
	{0x28,0x67,0xDC,0xE3,0x7D,0x53,0x45,0x59,0xCC,0xBF,0x96,0xE4,0x54,0xCC,0xB0,0xC9},
	{0x5E,0x64,0x63,0xD6,0x04,0x9E,0x2C,0xAB,0xA7,0xCB,0x97,0x4B,0x45,0x82,0x97,0x5D},
	{0x6E,0x8C,0x94,0xC2,0x0C,0xC7,0x5F,0xF7,0x50,0xBC,0xC3,0x8D,0xC1,0xAD,0xC5,0xD1},
	{0x0B,0x06,0xAD,0xD5,0x6A,0x25,0x7F,0x2B,0x11,0x75,0xCD,0x77,0x08,0xAB,0x86,0x6C},
	{0x3C,0xDB,0x96,0xD2,0xC5,0x66,0x68,0xFF,0xBF,0xFD,0x5F,0xA6,0xE6,0x7F,0x9D,0x7E},
	{0xE1,0xCB,0xFC,0x3C,0x1D,0x8E,0xDA,0x2C,0x88,0xC3,0x74,0x97,0xBF,0xD1,0x15,0x11},
	{0x37,0x3B,0xDF,0x33,0xC8,0xBA,0xF6,0x19,0xCF,0x61,0xCA,0x0E,0x5E,0xCD,0x8F,0x49},
	{0xDD,0x9F,0xC4,0x45,0x5A,0x82,0xAD,0x37,0x34,0xA7,0xB8,0x80,0xED,0x54,0x20,0x41},
	{0x22,0x47,0xFF,0x7F,0xF8,0xE9,0xEB,0x15,0x58,0xEA,0xB1,0x8E,0xC9,0x94,0x47,0xC9},
	{0x04,0xB2,0xCC,0x81,0x7B,0x4E,0xC3,0x67,0x35,0xF5,0x77,0x07,0x5A,0xA0,0x5E,0x6B},
	{0x9E,0xDD,0x4F,0xEF,0x73,0x89,0x4A,0xB9,0x05,0xCF,0x9C,0xA7,0x05,0x18,0xF5,0xC1},
	{0xFF,0x2E,0xAF,0x1A,0xE7,0x61,0xAE,0xE9,0x1C,0xF3,0xA6,0xDB,0x38,0xAB,0x88,0x8A},
	{0x67,0x7E,0x37,0xBF,0x30,0x29,0x12,0x8C,0x37,0x51,0x18,0x04,0xD8,0xBE,0x9B,0xB0},
	{0x6F,0x15,0x10,0x75,0x51,0x30,0x75,0x4B,0xB5,0x1B,0x28,0xAF,0x02,0xF2,0xEC,0xC5},
	{0x92,0x27,0xEA,0xC1,0x30,0x9F,0x46,0x21,0xAD,0xC6,0x23,0x02,0xB5,0x5A,0x6C,0xEE},
	{0xF0,0xCF,0xE7,0x7A,0x4F,0xA2,0x7C,0xB7,0xD0,0xF0,0xDE,0xC0,0x7D,0xB0,0x21,0xA5},
	{0x0B,0xB4,0xFD,0x19,0xF9,0x25,0x89,0x61,0x9D,0x8A,0x74,0x99,0xF8,0x34,0x2D,0x90},
	{0x1F,0x30,0x51,0xAE,0xB2,0xF6,0x6D,0xD8,0xD6,0xB6,0xB8,0x46,0x27,0x91,0x49,0x92},
	{0x4E,0x71,0xEA,0x0A,0xE2,0xB8,0x08,0xC1,0xB6,0x04,0x20,0x53,0xDA,0xF3,0xA0,0x22},
	{0xD9,0x2F,0xB2,0xC3,0x8F,0x57,0x02,0x94,0xF6,0x0B,0xDF,0x0A,0xE0,0xDD,0x9A,0xBA},
	{0x5A,0x8F,0x96,0x27,0xD9,0x9D,0xCB,0x70,0x63,0xBD,0x3E,0xF8,0xFD,0x7A,0x38,0xB3},
	{0x0B,0x3F,0x0B,0x99,0xA1,0x69,0x77,0xFE,0x3D,0x4F,0x18,0x81,0xBD,0xA1,0xEC,0x34},
	{0x7D,0xB7,0x81,0x0B,0x6E,0x41,0xD9,0x3D,0x2C,0xAF,0x23,0x76,0x3E,0xEB,0xBE,0x96},
	{0x72,0xB3,0x09,0x72,0xFC,0xB6,0x03,0x5C,0x9C,0xF2,0x35,0x21,0xDE,0x83,0xB7,0xEA},
	{0x7A,0x8D,0xD6,0x30,0xD3,0x45,0xB6,0x27,0x14,0xF1,0x29,0x17,0x3D,0x3F,0xCF,0x2F},
	{0x8B,0x5D,0xD6,0xD8,0xAF,0xC6,0x2B,0xA9,0x24,0x23,0x13,0x42,0x4E,0x7B,0x0C,0x55},
	{0x4C,0x74,0x94,0xDE,0xD5,0xE1,0xA8,0x28,0xC8,0x73,0xBB,0x7F,0xDB,0x51,0x3C,0x9B},
	{0x03,0xA7,0xA9,0xBF,0x00,0x40,0x57,0x22,0x56,0xEE,0x0D,0x95,0x66,0x8E,0x27,0x36},
	{0xA9,0xF5,0xB8,0x8B,0x7A,0x84,0xFF,0x9A,0x6A,0x21,0xD4,0x66,0xF4,0x0D,0x5A,0x7E},
	{0x96,0x34,0x61,0xDA,0x98,0x5E,0x35,0xFA,0x64,0x6E,0x81,0x73,0xA0,0x57,0x6A,0x58},
	{0x8E,0xCE,0x8F,0xF8,0xF7,0x32,0xEB,0x4C,0x42,0x17,0xB4,0x09,0x2E,0x23,0xC4,0xFB},
	{0x19,0x01,0x18,0x1D,0xC5,0x64,0xBD,0xA1,0x31,0xBC,0xDD,0xDF,0xDE,0xC7,0xC5,0x59},
	{0x80,0xEA,0xF9,0x50,0xB3,0x90,0x00,0xBF,0x0F,0x51,0xB2,0x63,0xBB,0x1E,0x31,0x2F},
	{0xFB,0x8F,0xEC,0x12,0x2B,0xB6,0xF1,0xB5,0xD3,0x98,0x38,0xCB,0xDD,0xAE,0xA2,0xAD},
	{0x56,0xF9,0x59,0xA8,0x55,0x03,0xFB,0x07,0x0E,0x87,0x94,0x28,0xBD,0x16,0x11,0xDD},
	{0x36,0x49,0xBC,0xDF,0xED,0xBC,0x52,0x89,0xE5,0x1D,0x9B,0x33,0x2B,0x2C,0xC5,0x76},
	{0x5F,0x93,0xD6,0x7A,0x6A,0xDF,0xBA,0x4E,0xFD,0x24,0x17,0xB2,0xCA,0xED,0x75,0xF0},
	{0x06,0x45,0xA6,0xC9,0x83,0x0D,0x14,0xD3,0x72,0xBF,0xD2,0x30,0x3A,0xB5,0x17,0x26},
	{0xCD,0xD5,0x03,0xAD,0x34,0xE9,0x70,0x20,0xEF,0x35,0xBC,0x6E,0xF9,0xA7,0x03,0x91},
	{0x19,0x20,0xDF,0xFA,0xBC,0xB2,0x91,0x47,0x7D,0xCF,0xEF,0xF8,0xC8,0xFF,0xE1,0xD3},
	{0x54,0x22,0x4D,0x9F,0x59,0x35,0xE4,0x6C,0x30,0x80,0xDE,0x21,0x7E,0x10,0x59,0x61},
	{0x99,0x50,0x18,0x95,0xC4,0x46,0xBD,0xEF,0xFB,0x37,0x65,0x97,0x77,0x9F,0xC8,0x99},
	{0x09,0x83,0xE0,0xA5,0xAD,0x35,0x65,0x1E,0x7C,0xAA,0x2F,0x0B,0xF5,0x88,0x71,0x87},
	{0xFE,0xB3,0xC9,0x3C,0x84,0x1D,0xA6,0x19,0x84,0x16,0x7F,0xA8,0x68,0x15,0xE6,0x10},
	{0x00,0x10,0xA6,0xF8,0x7B,0x06,0xEB,0xEE,0xF7,0x1C,0xBA,0x2F,0x2F,0x2D,0x5E,0x06},
	{0x23,0x90,0x37,0xF5,0xEB,0xEC,0xA9,0xA8,0xB3,0xC5,0x14,0xAA,0xCB,0xF4,0x6A,0x1B},
	{0x54,0xCE,0x30,0xD1,0xA7,0x14,0x4E,0xC8,0x60,0xBF,0x20,0x65,0x33,0xFF,0x7B,0x83},
	{0xCE,0x37,0x33,0xE6,0xEC,0x20,0x7C,0x65,0x23,0xAC,0x59,0xF4,0xF5,0x71,0x83,0xB6},
	{0x0F,0x6B,0x93,0x62,0x09,0x0A,0xF1,0xB1,0x96,0xE4,0x34,0x3A,0x57,0x98,0x80,0xC6},
	{0xC0,0xEA,0x79,0x23,0xBE,0x46,0xBB,0x27,0xEF,0x2D,0xE7,0x49,0x67,0x01,0x75,0x0D},
	{0x22,0xD7,0x3A,0x6F,0x3B,0x3A,0x8E,0xD2,0x9D,0x27,0x49,0xE3,0x86,0xD7,0xB7,0x6F},
	{0x7B,0x2B,0xCB,0x05,0xED,0xBE,0xD2,0xEB,0xDD,0x1B,0x26,0x7C,0x6D,0x47,0xF0,0xE9},
	{0x9A,0x82,0x9B,0xAD,0x0A,0xB8,0xFA,0x7C,0x1D,0x7C,0x3B,0x07,0x13,0xF4,0x8A,0x16},
	{0x8A,0x55,0xDF,0x0D,0x1E,0x73,0x3C,0x1F,0x8C,0x7A,0xEA,0x48,0x5A,0x1D,0x52,0xDA},
	{0x6E,0xEC,0x46,0x7C,0x63,0x2D,0x75,0x8D,0x26,0x5B,0x48,0x19,0x63,0x60,0xED,0xD8},
	{0x8B,0x86,0x06,0x2E,0x8C,0xA0,0xA6,0x81,0xFE,0x02,0xD6,0xE6,0xC6,0xB3,0x19,0x5B},
	{0x72,0xB3,0xA3,0x8A,0x63,0x7B,0x44,0xFE,0xE1,0xC4,0xCC,0xE7,0x55,0x89,0x6B,0xA7},
	{0x99,0x12,0xE8,0xCE,0x4E,0x21,0xDE,0x10,0xF9,0xE8,0x2D,0xF2,0x18,0x7E,0x9B,0x46},
	{0x27,0x23,0x08,0x41,0xF0,0xC1,0x26,0xAE,0x51,0x79,0x4F,0x75,0x9E,0x24,0x1B,0x5E},
	{0x3B,0x72,0xF6,0xA9,0x6A,0xA1,0x5B,0xCC,0x01,0xEC,0x57,0xA7,0x27,0x0C,0xDD,0x7C},
	{0x4D,0xC8,0x74,0x3C,0x3A,0xE4,0xAF,0x0E,0x02,0xA1,0xAF,0xDA,0x19,0x6A,0x0E,0x41},
	{0x24,0x24,0x27,0x70,0x6D,0xD6,0x32,0xFD,0x43,0x60,0x85,0x28,0x92,0xE0,0x76,0xA1},
	{0xF7,0x02,0xE0,0x7F,0x08,0x72,0x2B,0x1B,0xD3,0x3D,0x00,0xB9,0xB2,0xEA,0x80,0x20},
	{0xCF,0x12,0x3F,0x84,0xD8,0x7A,0xF7,0x55,0x0B,0xB1,0xD5,0xD7,0xB6,0xBE,0x5E,0x17},
	{0x14,0xDB,0x72,0x70,0x12,0x8D,0xE7,0x85,0xC2,0x1C,0x78,0x3A,0x4F,0x57,0xFC,0x7B},
	{0xE9,0x51,0x31,0xE1,0x9F,0xA2,0x75,0xAB,0x95,0x7E,0xB3,0x2A,0x50,0x8C,0xA3,0x94},
	{0x46,0xEA,0x90,0xA5,0xDD,0x3A,0xB6,0xAB,0x49,0xF2,0xFE,0xCE,0x22,0xA5,0x2A,0x51},
	{0xDC,0x5E,0xFA,0x13,0x2E,0x69,0xD5,0x3D,0x26,0xA9,0xB4,0xA3,0x4F,0x97,0xEF,0xB1},
	{0x59,0xFC,0x3E,0x7E,0xBA,0x6F,0xD6,0xD7,0x04,0xAA,0x69,0x74,0x56,0x35,0x11,0x6A},
	{0xFC,0x40,0x15,0x4A,0x60,0xB0,0x6C,0x2F,0x04,0x0B,0xB1,0x95,0x5B,0x16,0xC1,0x93},
	{0x81,0x67,0xD7,0xBF,0xF9,0xC1,0x9B,0x5B,0xBA,0x91,0xBA,0x9D,0x70,0x3D,0xDF,0xFA},
	{0x23,0xAE,0xAF,0x05,0x54,0xF3,0x15,0xC8,0x8E,0x9D,0xA5,0xE8,0xA8,0x1B,0xE4,0x68},
	{0x75,0x24,0x92,0xE4,0xDC,0x94,0xE2,0x9E,0x28,0xEF,0x5D,0x43,0x43,0x85,0x02,0x8D},
	{0x0B,0xE0,0x19,0x8D,0xDB,0x88,0x66,0x2C,0x2E,0x36,0x55,0x20,0xFC,0xCB,0xE3,0x8F},
	{0x52,0x0F,0x4E,0xC4,0xAE,0xA2,0x24,0xF1,0x88,0xC0,0xC4,0xDE,0x30,0x1D,0xA0,0x46},
	{0x72,0x9F,0xF9,0x54,0x83,0x91,0x6D,0xC8,0xCA,0x0B,0xAE,0x9E,0xF5,0xEB,0x82,0x1A},
	{0x21,0x54,0x9C,0x16,0x5C,0x96,0x92,0x3D,0xA0,0x59,0xD0,0xC1,0x04,0xC1,0xF9,0xD7},
	{0xA6,0x3D,0x54,0x38,0xFE,0x73,0xCE,0xA0,0x4B,0xA7,0x30,0x38,0x9B,0x0C,0x5C,0xDC},
	{0x04,0xED,0xF7,0x7C,0xC3,0x8D,0xC5,0xEF,0x49,0x4B,0xD2,0x15,0xBB,0xA7,0x39,0xD5},
	{0xE8,0x5A,0x4D,0xE1,0xDF,0x02,0x66,0xF0,0x72,0x3B,0x01,0x82,0xB4,0xC1,0x04,0x9A},
	{0x1B,0x8A,0xBB,0x48,0x53,0x50,0x37,0x50,0x9C,0x3B,0x06,0xF0,0xFF,0xD5,0x4B,0x4D},
	{0x84,0xAC,0xED,0x01,0xD6,0x31,0xFB,0x28,0x7F,0xFA,0xFC,0xFB,0xC4,0xC1,0xAB,0x4F},
	{0xF2,0x93,0x0F,0xBD,0x62,0x9E,0xE9,0x10,0xBB,0xA0,0x93,0xE9,0x41,0xEE,0x14,0x78},
	{0xF1,0xE7,0x18,0x18,0x5A,0x12,0xBC,0x82,0x9E,0xE5,0xFF,0x12,0x35,0xDA,0xDB,0x05},
	{0x5F,0x99,0xCD,0x04,0x26,0xDE,0x5D,0x56,0x47,0x8A,0x20,0xBA,0x80,0xDA,0xC4,0x67},
	{0x9F,0xA3,0x8A,0xE1,0x51,0x53,0xC3,0x45,0x58,0xBF,0xFD,0xBC,0x09,0x47,0x1C,0xDD},
	{0xA8,0xA2,0x8F,0x20,0x34,0xF4,0x92,0x16,0xBA,0xFE,0x0E,0x94,0x71,0x33,0x0A,0xAC},
	{0x25,0x46,0xEA,0x25,0xC9,0x88,0xD4,0x83,0xC2,0x05,0xF0,0xA3,0x46,0x29,0x7C,0x93},
	{0x35,0x3F,0xC7,0x59,0x22,0xF5,0x6E,0x0A,0xD3,0x30,0xB1,0x21,0x33,0xEC,0xC8,0x25},
	{0xA6,0x24,0x6A,0xC9,0x79,0x45,0x42,0x2C,0x7A,0xFF,0x3C,0xD6,0x8E,0xF3,0x79,0xAF},
	{0x9D,0x0B,0xD8,0x2D,0xB3,0x57,0x9A,0x8E,0xC4,0x7D,0x91,0xC0,0xA1,0xEF,0xB6,0xCB},
	{0x38,0xED,0x35,0xA7,0xDB,0xB4,0xC8,0x57,0x44,0x46,0x3A,0x78,0x03,0x69,0x0C,0xFA},
	{0x1C,0x87,0x45,0x37,0x8A,0x1D,0x40,0x24,0x6D,0x84,0x7D,0xA3,0xB3,0x6C,0xF1,0x1C},
	{0x4C,0xA8,0xD6,0xB0,0x8F,0xBB,0xD8,0xCE,0x1A,0xD5,0x39,0x5C,0xC3,0xBF,0xE2,0xA5},
	{0x74,0x44,0x4E,0x73,0x02,0x6B,0x44,0x2E,0xDA,0x25,0xBA,0x76,0x4D,0x29,0x41,0x7F},
	{0x7E,0xA9,0x1C,0xFD,0x4D,0xDC,0x71,0xB1,0xF7,0x85,0xC7,0xE5,0x0A,0x21,0x2C,0xB2},
	{0xB1,0x99,0xC4,0x1F,0xB5,0x6A,0x27,0xB2,0xC8,0x45,0xA3,0xAE,0x13,0x01,0x2E,0x29},
	{0x9F,0x27,0xB6,0xA8,0x0C,0xB8,0x75,0x98,0x52,0xB4,0x01,0x4B,0x51,0xBB,0xB9,0x5F},
	{0x74,0x0A,0xD0,0x54,0xBA,0xE6,0x90,0xC5,0xA6,0xE6,0x69,0x19,0x50,0xEE,0x2C,0x58},
	{0x72,0x8B,0xC0,0x0A,0xE6,0xA6,0xDF,0xFD,0x28,0xDE,0x60,0xBF,0xBD,0xC2,0xBB,0x35},
	{0xA0,0xB2,0xA7,0xD1,0xAD,0x2E,0x94,0xF6,0x0C,0xC7,0x4D,0xA6,0x3C,0x40,0x51,0x24},
	{0x85,0x5F,0xA2,0xDF,0x9D,0xE3,0x90,0x19,0x5C,0x8F,0xF0,0x74,0x40,0xE6,0x3E,0x70},
	{0xDC,0x08,0x46,0x10,0x98,0xA9,0xF7,0xCF,0x3E,0x02,0x65,0x5B,0x77,0x5E,0x2B,0x9A},
	{0x34,0x0C,0xA8,0xB7,0x6C,0x72,0x91,0xC3,0x2D,0x96,0x29,0x05,0xE5,0xCC,0xEC,0xAB},
	{0xAD,0x11,0xF8,0xC7,0x78,0x5C,0x20,0xD2,0xEB,0x22,0xBF,0x06,0x7A,0x1D,0x99,0x66},
	{0xA0,0xF9,0xE2,0xB1,0xFA,0xA7,0x87,0x43,0xC4,0x00,0xB7,0x16,0x8B,0x85,0xAE,0x05},
	{0xB8,0x23,0x4B,0x40,0xE7,0x03,0x35,0xB2,0x98,0x75,0x6E,0xA6,0x0B,0x22,0x91,0x54},
	{0x90,0x20,0x74,0xD7,0xB6,0x8A,0x24,0x46,0x33,0xBE,0xE9,0x72,0x1C,0xDE,0x40,0xDA},
	{0xD4,0x88,0x54,0xFD,0x63,0x12,0x8C,0x39,0x71,0x4A,0xAB,0x23,0xD8,0x53,0x07,0xC3},
	{0x67,0xAF,0xE9,0x12,0xA7,0x48,0xA4,0x0C,0x5F,0xBD,0xCE,0x08,0x94,0xE9,0x49,0x35},
	{0xEB,0xDC,0x38,0x33,0x1A,0x6D,0x51,0x3B,0x41,0xE9,0x9A,0x66,0x35,0x75,0x76,0xBE},
	{0xD2,0x3E,0x27,0x27,0x03,0x95,0x9F,0x5C,0x7E,0x07,0xCA,0x25,0xBA,0xBA,0x6B,0x7E},
	{0x92,0xA4,0xCF,0x23,0x26,0x6D,0x66,0xD4,0xD6,0xB9,0x45,0x08,0xB6,0x30,0xE8,0xF2},
	{0x4F,0x62,0xDF,0x04,0xEE,0x00,0x85,0xA9,0xC7,0x00,0xD9,0xE6,0x93,0x16,0x86,0xDD},
	{0xE9,0x8D,0x22,0x37,0x58,0xF7,0x3D,0x3C,0x3B,0xDB,0x42,0x10,0xD6,0x3B,0xC4,0x83},
	{0x0F,0x1A,0x50,0x2F,0x2C,0xFC,0x52,0xA6,0x7C,0x5D,0xBA,0xB2,0xB0,0x53,0x45,0xAB},
	{0xDC,0xEA,0x38,0x15,0x68,0x62,0x40,0xAC,0x74,0xF9,0x22,0x30,0x97,0xDA,0xC7,0x72},
	{0xCB,0x77,0x1C,0x26,0x5D,0xB8,0xF6,0xE5,0x78,0x62,0x55,0xC4,0xFA,0x0B,0xE7,0x2A},
	{0x39,0x1B,0xB9,0xA5,0xE9,0xEA,0x58,0xD4,0x7D,0x1D,0x95,0x15,0xBB,0x92,0xD0,0x80},
	{0x60,0xC7,0x33,0x15,0x8F,0xD2,0x79,0x0A,0x60,0x77,0xE7,0xAB,0x5F,0x48,0xE8,0x03},
	{0x55,0xAD,0x2F,0xE3,0x12,0xE7,0x7A,0x08,0x48,0xE4,0xF9,0xD4,0x50,0x41,0x1D,0x4A},
	{0x60,0x89,0x8F,0x64,0xEA,0xAF,0x4B,0x73,0x63,0x13,0x0C,0x83,0x7F,0xCF,0x86,0xA4},
	{0xA6,0x42,0xAD,0x4E,0xF2,0x4D,0x0F,0x49,0xDC,0xDB,0x02,0xC7,0x15,0xCE,0x40,0xF4},
	{0xA1,0x6A,0xD0,0x7A,0xD1,0x2D,0x75,0x4F,0x20,0x8B,0xF7,0x10,0x60,0xB3,0xFE,0xBF},
	{0x90,0x49,0xB6,0x87,0xBE,0x65,0x07,0x73,0x87,0xA0,0x78,0xA1,0x20,0xCD,0x9C,0xD7},
	{0xE5,0x56,0xB9,0x36,0x9D,0xB1,0x76,0x30,0x20,0x36,0x08,0x47,0x1B,0xB2,0x78,0x9B},
	{0x3E,0x40,0x40,0xBF,0xE6,0x08,0x91,0xC2,0x6E,0xAD,0x78,0xB8,0xD4,0x2F,0x52,0x96},
	{0x78,0x7E,0x8B,0xA7,0x64,0x0A,0x23,0x67,0x96,0xF2,0x79,0x49,0x41,0x8F,0xA0,0x53},
	{0x2D,0x3E,0x51,0xE6,0x09,0x75,0x08,0x91,0xE0,0x01,0xF5,0x55,0xDD,0xF5,0xFA,0x35},
	{0xF5,0xDC,0x2C,0x09,0x13,0x4A,0x93,0x30,0x4A,0xFB,0x1C,0x43,0x1B,0x4D,0x2F,0xDB},
	{0x3A,0x47,0x29,0x0B,0x46,0x5B,0xD7,0xC5,0x9D,0x9C,0xC1,0xF8,0x1D,0xD4,0xEC,0x03},
	{0x2D,0x74,0xC1,0xB4,0xEA,0xE3,0x4D,0x14,0x29,0x0D,0x28,0x57,0x19,0x64,0x9B,0x6D},
	{0x22,0x3F,0x7E,0x7A,0x99,0x3D,0xAA,0x60,0x72,0xEA,0x2E,0x39,0x09,0x09,0x80,0x8D},
	{0x79,0x4C,0xAF,0x34,0xC4,0x3F,0xD4,0xD8,0x0A,0xAF,0x10,0x17,0x8B,0x79,0x22,0x0A},
	{0x70,0x35,0xA6,0x3D,0x96,0x5F,0x3A,0x6D,0xB5,0xCE,0x48,0x51,0x96,0x0F,0xFE,0x4E},
	{0xAB,0xA1,0x94,0xFB,0x89,0x86,0xE0,0x80,0x31,0x57,0x35,0x08,0x20,0xBA,0x83,0x7A},
	{0x5D,0x6E,0x97,0x3F,0x75,0x9C,0xA1,0xF9,0x47,0x81,0x53,0x2E,0x09,0x36,0xA3,0x71},
	{0xE8,0xF1,0xDB,0x69,0x22,0x86,0x08,0xC8,0xEF,0x25,0xBF,0x6D,0x6D,0x7B,0xC9,0x95},
	{0xCD,0xA7,0x95,0x1D,0xC5,0x38,0x4B,0x5C,0xF7,0x8D,0x7C,0xA5,0xB6,0x47,0xBD,0x57},
	{0x5B,0x3F,0x70,0x7C,0x1C,0xD8,0x5A,0x95,0x5C,0xAF,0x24,0x32,0x82,0x36,0x56,0x5B},
	{0x78,0xF8,0x9C,0x3F,0x8B,0x48,0xEF,0x88,0xC6,0xFE,0x59,0x3A,0xFE,0x39,0xB8,0xD3},
	{0x66,0xB4,0x7B,0x15,0x70,0xBF,0x1E,0x12,0x66,0x05,0xE5,0x85,0xA0,0x77,0xBC,0x10},
	{0xE2,0x2C,0xAE,0x62,0x05,0xAC,0x38,0xC0,0xDE,0xBD,0xFD,0x53,0x12,0x1D,0x47,0xBD},
	{0xBC,0x8A,0xCF,0xE6,0x90,0x5D,0x28,0x39,0x43,0x3C,0x16,0xC3,0xB8,0xE8,0x38,0x09},
	{0x0B,0x76,0x1F,0x66,0x12,0x04,0x5A,0xA0,0x80,0xA1,0xBC,0x4B,0x4A,0xD7,0x70,0x84},
	{0xA0,0x9E,0xA1,0x30,0xCB,0xF7,0xE8,0x13,0xB5,0x4D,0xD2,0xA4,0xA3,0x94,0xAA,0xEB},
	{0x3E,0xEF,0x2D,0xA2,0x46,0xD9,0x33,0x3C,0x34,0x34,0x65,0x6F,0x12,0x0D,0x89,0x76},
	{0x58,0x0D,0xE1,0xFE,0x08,0xCA,0x2E,0xA2,0x33,0xF8,0x3D,0x05,0x35,0x2B,0xAD,0xAF},
	{0x9F,0xE9,0xE6,0xF9,0x79,0x3B,0x25,0xA5,0xDF,0xBD,0x86,0xA6,0x21,0x62,0x0D,0x52},
	{0xBF,0xCE,0xB0,0xA5,0x0D,0xEF,0xAC,0x0F,0xE2,0xD8,0x50,0xBB,0x67,0xCD,0x0A,0x6E},
	{0xAF,0x74,0x55,0xBB,0x2D,0x2A,0x8A,0x82,0x3C,0x74,0x28,0x41,0xEA,0xA9,0x9D,0x99},
	{0xB8,0xE9,0x25,0x9F,0x07,0x12,0xE9,0x04,0xDD,0x77,0x7B,0x32,0x2B,0xE3,0x27,0x6A},
	{0x1F,0x60,0xB6,0x30,0xBB,0x2D,0x97,0x13,0x9C,0xAC,0x8E,0x47,0x24,0x99,0xD2,0x65},
	{0xBF,0xDA,0x6E,0x89,0xCD,0x83,0xE8,0x1F,0x55,0x80,0x27,0x7B,0x09,0xCB,0x4E,0x8B},
	{0xA6,0xE5,0x99,0xDC,0x5C,0x01,0x81,0x12,0x03,0xFD,0x5E,0xE1,0x29,0x19,0x88,0x68},
	{0x0B,0x47,0xDD,0x12,0x2A,0x4A,0x5B,0x42,0x9C,0xC8,0x6E,0xAA,0xE7,0x28,0x0B,0xCE},
	{0xAE,0xB9,0x3F,0x87,0xB6,0x0A,0x15,0xC7,0x26,0x34,0xAC,0x3E,0x96,0x40,0xB9,0xEE},
	{0x60,0xC1,0x4C,0x5A,0xF9,0x54,0xB4,0xBD,0xB5,0x78,0x03,0x93,0xE7,0x0E,0x68,0x41},
	{0x76,0x02,0xAB,0x77,0xD3,0x77,0x51,0x71,0x3C,0xD6,0x1C,0xE0,0x8C,0x13,0x06,0xD2},
	{0x33,0xD9,0xC8,0xE7,0x42,0x4C,0xCE,0x6C,0x9B,0x11,0x50,0x50,0x07,0xA7,0x57,0x23},
	{0x13,0xF3,0x1F,0xA2,0xF0,0xA5,0x04,0xEF,0xE3,0x5E,0xD2,0xA2,0xE4,0x66,0x0A,0x81},
	{0xAA,0xCF,0x29,0xF1,0x9C,0x79,0x94,0x65,0xE9,0xFA,0xC4,0xF5,0x0E,0x80,0x5A,0xF7},
	{0xC5,0xE4,0xDC,0x2D,0x88,0xED,0x98,0x44,0xD2,0xC8,0x6C,0x73,0x1A,0x63,0x7E,0xAC},
	{0x4D,0x73,0x88,0xB8,0x34,0xBA,0xE0,0x47,0xE9,0xD1,0x50,0x89,0xB5,0x18,0x25,0x5F},
	{0x3E,0xBF,0x50,0x31,0x76,0x1B,0x4B,0x06,0x66,0x67,0x75,0x11,0x26,0x9F,0x0B,0xB5},
	{0x59,0xD2,0x26,0x6D,0x02,0x30,0xF5,0x07,0xDA,0x7A,0x2E,0x7F,0xCA,0x65,0x61,0x8B},
	{0xE5,0x1C,0xC1,0xE2,0xFB,0x4D,0x38,0xD6,0x91,0xF0,0x5B,0xCC,0x1E,0x16,0x59,0x35},
	{0xBB,0x08,0x65,0xA0,0xD7,0x82,0xB0,0xD9,0xF2,0x9D,0x48,0x5C,0xC9,0x49,0x2F,0x86},
	{0xE0,0x12,0x17,0xD1,0x2A,0x36,0x06,0x36,0xF0,0xE5,0xAA,0x22,0x49,0xF5,0xBB,0x04},
	{0x15,0x79,0xD5,0x7B,0xA8,0x57,0x03,0x13,0x6F,0x0B,0xD4,0xB5,0x0B,0xCF,0xEB,0x07},
	{0x54,0x4F,0x6E,0x33,0x48,0x03,0xC1,0x7E,0x29,0x08,0xA0,0xEA,0x60,0x12,0x3C,0xC9},
	{0x1E,0xAB,0x81,0x20,0xFC,0x70,0xA3,0x6E,0x7E,0x82,0xC3,0xC9,0xAC,0x3E,0x14,0x05},
	{0x7F,0x0F,0x5B,0xEA,0xF1,0x8F,0x36,0x7C,0x72,0x6C,0x16,0x3E,0xB5,0xC9,0xA7,0x9B},
	{0x8B,0x5C,0x96,0xE9,0x55,0x74,0x39,0xE6,0x09,0x40,0x9D,0xBD,0xAD,0xEA,0xBB,0x48},
	{0xCA,0xC4,0x87,0xAB,0x95,0x73,0x69,0x55,0x37,0x42,0x8C,0xFC,0xCF,0xF8,0x07,0x45},
	{0x02,0x31,0xCA,0x10,0x1C,0xFD,0x5D,0x56,0x47,0xD6,0x5F,0x45,0x65,0xF3,0x7A,0x51},
	{0x93,0xC3,0xE4,0x11,0xAE,0xF1,0xAB,0x2C,0x4F,0x6B,0x40,0x75,0x85,0x23,0x29,0x1C},
	{0xBD,0x5B,0xC2,0x49,0x6C,0x99,0xC5,0x48,0xA1,0x6C,0x07,0x6C,0x55,0x3F,0xCE,0x53},
	{0x67,0xE3,0xCF,0x4A,0xA0,0x3F,0x2D,0xA9,0x45,0xED,0x3F,0x6F,0x5C,0xC6,0x6A,0x93},
	{0x22,0x34,0x8E,0x9B,0x92,0xD4,0x49,0x8B,0xEF,0x84,0xAC,0x18,0xCE,0xD0,0xFD,0xC9},
	{0xAE,0x06,0xFE,0xE1,0xAC,0x3B,0xBD,0x5E,0xEA,0xA9,0x56,0x19,0x3D,0xB9,0x50,0x95},
	{0xA3,0x49,0x49,0x40,0xC7,0x5C,0x35,0x81,0x7E,0x1C,0xFB,0x92,0x8E,0xDD,0x05,0xE0},
	{0xD9,0xC9,0xC9,0x33,0xCD,0x5B,0x63,0x89,0x5C,0x27,0xDC,0x81,0xFA,0x49,0xB1,0x4B},
	{0x35,0x71,0x4B,0xD5,0x1C,0x90,0x1D,0x20,0x1B,0xDD,0x81,0xFC,0x07,0x68,0x03,0xBE},
	{0x8F,0x55,0xFA,0x0C,0xB7,0x9C,0xDF,0x97,0x81,0x19,0x1C,0x3E,0xC2,0x01,0xE6,0x7B},
	{0x73,0xB8,0x4D,0x03,0xBB,0x0E,0x19,0x0E,0x9F,0x86,0x9C,0x49,0xF6,0x4C,0xE1,0xC3},
	{0x39,0xD6,0x9E,0xB9,0xB1,0x11,0xAA,0xE4,0xDC,0x7E,0xBD,0x7D,0x9B,0x32,0x57,0x3E},
	{0xC4,0xAF,0x11,0xCB,0xA9,0x22,0x52,0x2C,0xD5,0x2A,0x13,0x06,0x5B,0xF0,0x4C,0x03},
	{0xE0,0xE1,0x8E,0xD5,0x89,0x72,0x2A,0x3B,0xAF,0x5D,0xFA,0xEE,0x26,0x07,0x75,0x0F},
	{0xFC,0x2F,0xFE,0xEB,0x8D,0xA2,0x8F,0x0C,0x29,0x4C,0x18,0x95,0x41,0xF6,0x70,0xFB},
	{0x14,0x6C,0xDF,0x7D,0x2C,0xF4,0x37,0x14,0x11,0xD6,0x71,0xA1,0xF7,0x8D,0x9F,0xAF},
	{0xAD,0x57,0xA9,0x16,0x69,0x89,0x55,0xE6,0x7B,0xF7,0x1B,0xFF,0x19,0xE0,0x7E,0x00},
	{0xA4,0x5E,0xA6,0x46,0xDA,0xCA,0x03,0xEB,0xC3,0x85,0xAF,0xA4,0x05,0x8B,0xBF,0x47},
	{0xB8,0x11,0x3D,0x0C,0xD7,0xF8,0xB3,0x4D,0x91,0xF0,0xBB,0x89,0xF7,0xD7,0x57,0xB3},
	{0x9C,0x2D,0x38,0x03,0x65,0x93,0x29,0x8E,0x84,0xF2,0xA9,0xAF,0xB1,0x35,0xC3,0x95},
	{0x0C,0x33,0x30,0x8F,0x04,0xE9,0x98,0xA6,0x52,0xFF,0x4C,0xD2,0x13,0x25,0x35,0x2B},
	{0x22,0x3C,0xDE,0xEB,0xA6,0x66,0x8B,0x27,0x7B,0x77,0xCB,0x01,0xB2,0x74,0x75,0x18},
	{0x69,0x83,0x11,0x81,0xE6,0xF8,0x6B,0xD4,0x36,0x2F,0xCF,0x0C,0x53,0xDD,0x1D,0xBC},
	{0xF2,0x5B,0xD5,0x49,0xEE,0x73,0x7D,0x97,0x25,0xA5,0x54,0x88,0x31,0x9D,0x67,0x79},
	{0xDA,0x8E,0x42,0xB9,0xE3,0x5C,0x7F,0x3B,0x1E,0xAA,0x1E,0x51,0x8E,0x8E,0xD4,0x4C},
	{0x9E,0x3A,0xA4,0x8F,0x11,0xB9,0x25,0xE2,0x78,0x06,0xEA,0x26,0x05,0x31,0x33,0xBE},
	{0x53,0x72,0x8A,0x3F,0x1C,0xA8,0xB0,0x8F,0x8A,0xE6,0x23,0x6A,0x58,0x56,0xF8,0x3B},
	{0x7A,0x76,0xC6,0x6E,0x55,0xC9,0xFC,0xF3,0xC0,0x99,0xA5,0x96,0x84,0x68,0x13,0xB6},
	{0x5C,0xF2,0x99,0x5D,0x6D,0x96,0xE3,0x25,0x83,0x0F,0x85,0x5A,0x79,0xE3,0x96,0x3A},
	{0xDC,0x91,0x1C,0x6E,0x5E,0x4D,0xCF,0xDE,0x78,0xB1,0x48,0xD3,0x09,0xE6,0x02,0x42},
	{0xCE,0x82,0xB8,0x0C,0x50,0x6A,0xE8,0x92,0x1F,0x52,0xF7,0x42,0x56,0x5D,0x70,0x5C},
	{0x72,0xED,0x38,0x9E,0x75,0x67,0x06,0x81,0xF7,0x98,0x31,0x8F,0xA2,0xA0,0xE2,0x38},
	{0xDC,0x95,0xA6,0x63,0x43,0xCA,0xCF,0x71,0x48,0x62,0x4F,0xA3,0x0E,0x18,0x4B,0x0E},
	{0xB5,0xAE,0x3E,0xE0,0x78,0x83,0x45,0x98,0x10,0x6C,0x4E,0x20,0xF5,0xAF,0x0F,0xF4},
	{0xA3,0xBA,0x8D,0xE6,0x94,0xBD,0x40,0xB4,0xF8,0xC8,0x28,0xFA,0xC5,0x11,0x24,0xD1},
	{0x4F,0xCC,0xE8,0x46,0xF5,0x73,0x42,0x0D,0x57,0x2A,0xDC,0xA3,0xF8,0x5C,0xC0,0xBF},
	{0x2C,0xFA,0xAE,0x16,0x0A,0x33,0x94,0xAC,0xAC,0xFB,0xCF,0x76,0x84,0xBC,0x73,0xB5},
	{0xF4,0xF8,0x05,0x52,0x16,0xFC,0x59,0x2D,0x84,0x01,0x00,0xDC,0xC1,0x45,0x15,0x7D},
	{0x07,0x21,0xAC,0x02,0x07,0x2D,0x26,0x77,0x6E,0x5F,0x1A,0x02,0xCA,0xB7,0x27,0x58},
	{0xDF,0x76,0xFE,0x5A,0xA6,0x13,0x1E,0xF0,0xDB,0x4D,0x6B,0x30,0x4E,0x74,0x2B,0xB2},
	{0x61,0x48,0xF1,0x2A,0xD9,0x31,0xFD,0x7C,0x8F,0xAD,0x8C,0xE9,0x45,0xA0,0x1E,0x26},
	{0x26,0xB4,0x06,0x94,0xAB,0x14,0xBE,0x89,0x10,0x79,0x39,0x91,0xEB,0xED,0x61,0x37},
	{0xA5,0x5D,0x52,0xD3,0x8B,0xFE,0x07,0xC5,0xF8,0xFF,0xE8,0x16,0x4C,0xC2,0x3B,0x56},
	{0x5F,0x55,0xA9,0x3B,0xDD,0x41,0xA2,0x1E,0x62,0x78,0x0E,0x7E,0x51,0x91,0xBB,0xF1},
	{0x36,0xBE,0x2E,0x6B,0xE1,0x64,0x80,0xCC,0x5F,0xF2,0xF3,0x98,0xC7,0x70,0xB2,0xC7},
	{0x93,0x9F,0xAB,0xCC,0x20,0xCE,0x40,0xBA,0x0B,0x38,0x7B,0x33,0x35,0xD1,0x47,0x55},
	{0x7B,0x19,0x3B,0xB9,0xB4,0x73,0xBE,0xE5,0x9E,0x72,0x58,0x8D,0x16,0x7C,0xF3,0xD9},
	{0x36,0xAA,0xF3,0xC3,0x7E,0xD3,0xF0,0xDB,0x49,0xD3,0xC9,0x6A,0x77,0x5D,0xBD,0xB1}
	};
#endif

#endif // __RETAIN_H