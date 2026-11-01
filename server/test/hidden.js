// Hidden code points used by the masking tests.
// 29 hidden code points: default-ignorable ones that are not Cf (Hangul fillers, combining grapheme joiner, Mongolian vowel separator, variation selectors, Khmer
// vowel inherent), Cf ones that are not default-ignorable (Arabic number signs), tag characters, bidi and invisible operators, and U+FFFD.
export const HIDDEN = [0x3164, 0xffa0, 0x115f, 0x1160, 0x034f, 0x180e, 0xfe00, 0xfe0f, 0xe0020, 0xe0001, 0xe007f, 0x061c, 0x206a, 0x206f, 0x17b4, 0x17b5, 0xfffd, 0x0600, 0x0601, 0x06dd, 0x070f, 0x200b, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x202e, 0x2066, 0x180b];
