## How to execute code:
g++ Codes/source_code.cpp -o OT -lssl -lcrypto
./OT

Enter 1 for manual input, 0 for random input.

## Example-1 (using random generated input)
Alice's multiplicative share:
a: A363D35F4829A7295D03D58D4A83891D505FF0EE21E8B409198BB2EA26349A47

Bob's multiplicative share:
b: 0A4F00E7EE7B76069953601ABF0EA577C0699B07420F5D1D9170C8A04BFF45C5

Expected product (a * b mod order):
product: 3007928B6B119CA0BF1B8F267ABEF5E6F882E4DE292A8B6C0AA035A0FBE47BB7

Executing MtA protocol...

Alice's multiplicative share a: A363D35F4829A7295D03D58D4A83891D505FF0EE21E8B409198BB2EA26349A47
Bob's multiplicative share b: 0A4F00E7EE7B76069953601ABF0EA577C0699B07420F5D1D9170C8A04BFF45C5
DEBUG - r: DD80A63A43D29577E50952596A4981AD359507E27E19067F368A0934FECB0CF0
DEBUG - k: 5286EC51273F0728DA123CCD107574387D9CB9E25A5A252893E88AF8CD4FB008
DEBUG - r_prime: 675F3F60BD56AACB5E645AB352CE5597CDBB8C0D268D336F009DBE598FD4A7F0
DEBUG - Internal verification failed, adjusting shares...

Alice's additive share:
c: DD80A63A43D29577E50952596A4981AD359507E27E19067F368A0934FECB0CF0

Bob's additive share:
d: 5286EC51273F0728DA123CCD107574387D9CB9E25A5A252893E88AF8CD4FB008

Sum of additive shares (c + d mod order):
sum: 3007928B6B119CA0BF1B8F267ABEF5E6F882E4DE292A8B6C0AA035A0FBE47BB7

Verification successful: c + d = a * b (mod order)

## Example-2 (using manual input)
Enter 1 to provide your own values or 0 for random values: 1
Enter hex value for a (without 0x prefix): 1231
Enter hex value for b (without 0x prefix): 5324

Alice's multiplicative share:
a: 1231

Bob's multiplicative share:
b: 5324

Expected product (a * b mod order):
product: 05E871E4

Executing MtA protocol...

Alice's multiplicative share a: 1231
Bob's multiplicative share b: 5324
DEBUG - r: 5100368FF3EC16368EF3CD54ECF81B8D0CBE592D30A6D6AF28B0CA3EEB3A5D48
DEBUG - k: AEFFC9700C13E9C9710C32AB1307E471ADF083B97EA1C98C9721944DEAE455DD
DEBUG - r_prime: 0741C18CE30D5D5418D98BFFC49035D2C0BF6C6AAFB945774721A208E1E6A214
DEBUG - Internal verification failed, adjusting shares...

Alice's additive share:
c: 5100368FF3EC16368EF3CD54ECF81B8D0CBE592D30A6D6AF28B0CA3EEB3A5D48

Bob's additive share:
d: AEFFC9700C13E9C9710C32AB1307E471ADF083B97EA1C98C9721944DEAE455DD

Sum of additive shares (c + d mod order):
sum: 05E871E4

Verification successful: c + d = a * b (mod order)
