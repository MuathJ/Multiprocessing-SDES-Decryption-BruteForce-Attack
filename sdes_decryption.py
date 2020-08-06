import os
import sys
import time
from timeit import default_timer as timer
from multiprocessing import Pool as ThreadPool

key_hex = '3DA'  # 1111011010   # 986
cipher_text_hex = '69'  # 01101001   # 105

key = bin(int(key_hex, 16))[2:].zfill(10)
cipher_text = bin(int(cipher_text_hex, 16))[2:].zfill(8)

# plain_text = '01001101'  # 77 # 119

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
P4 = (2, 4, 3, 1)

IP = (2, 6, 3, 1, 4, 8, 5, 7)
IPi = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)

S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


def permutate(input, acc):
    output = ''
    for a in acc:
        output += input[a - 1]
    return output


def half(x, b):
    if x == 'R':
        return b[len(b) // 2:]
    elif x == 'L':
        return b[:len(b) // 2]


def shift(b):
    return (half('L', b)[1:] + half('L', b)[0]) + (half('R', b)[1:] + half('R', b)[0])


def fk(b, k):
    # Permutate Right half of 'b' according to EP
    fK = permutate(half('R', b), EP)

    # XOR -> fK & key
    fK = format(int(fK, 2) ^ int(k, 2), 'b').zfill(len(fK))

    # S0 & S1 s-boxes operations
    L = half('L', fK)
    R = half('R', fK)
    L_S0 = format(S0[int(L[0] + L[3], 2)][int(L[1] + L[2], 2)], 'b').zfill(2)
    R_S1 = format(S1[int(R[0] + R[3], 2)][int(R[1] + R[2], 2)], 'b').zfill(2)
    fK = L_S0 + R_S1

    # Permutate fk according to P4
    fK = permutate(fK, P4)

    # XOR -> fK & Left half of 'b'
    fK = format(int(fK, 2) ^ int(half('L', b), 2), 'b').zfill(len(fK))

    return fK


def decrypt(cipher_text, key):
    print('\nKey:')
    print('\t Bin = ', key)
    print('\t Dec = ', int(key, 2))
    print('\t Hex = ', key_hex)

    print('\nCipherText:')
    print('\t Bin = ', cipher_text)
    print('\t Dec = ', int(cipher_text, 2))
    print('\t Hex = ', cipher_text_hex)

    print('\n' + '-' * 50)
    # Generate k1
    k1 = permutate(key, P10)
    k1 = shift(k1)
    k1 = permutate(k1, P8)
    print(k1 + ' = Key 1')

    # Generate k2
    k2 = permutate(key, P10)
    k2 = shift(shift(shift(k2)))
    k2 = permutate(k2, P8)
    print(k2 + ' = Key 2')

    # Rearrange the cipher_text '0110 1001' according to IP '2631 4857' ==> '1010 0110'
    per1 = permutate(cipher_text, IP)
    print(per1 + ' = Permutate1 (cipherText & IP) ')

    # Perform function fk1 <- permutate(key, P10) & Key2
    fk1 = fk(per1, k2)
    print(fk1 + '     = Function fk1 (Per1 & Key2)')

    # Right Half of 'per1' + fk1
    per1_fk1 = per1[len(per1) // 2:] + fk1
    print(per1_fk1 + ' = Right Half of (Per1 & fk1)')

    # Perform function fk2 <- per1+fk1 & Key1
    fk2 = fk(per1_fk1, k1)
    print(fk2 + '     = Function fk2 (Per1+fk1 & Key1)')

    # Rearrange 'fk2 + fk1' according to IP inverse
    per2 = permutate(fk2 + fk1, IPi)
    print(per2 + ' = Permutate2 (fk2+fk1 & IPi)')
    print('-' * 50)

    plain_text_hex = hex(int(per2, 2))[2:].upper()

    print('\nPlainText:')
    print('\t Bin = ', per2)
    print('\t Dec = ', int(per2, 2))
    print('\t Hex = ', plain_text_hex)

    return per2


sys.stdout = open(os.devnull, 'w')
plain_text = decrypt(cipher_text, key)
sys.stdout = sys.__stdout__


def SearchAndDestroy(Key):
    Key_hex = hex(Key)[2:].upper()
    Key_bin = bin(Key)[2:].zfill(10)

    if Key != 1023:
        print('\t\t\tTESTING KEY: ' + Key_hex + ' = ' + Key_bin + ' = ' + str(Key), end="\r")
    time.sleep(0.002)

    sys.stdout = open(os.devnull, 'w')
    plain_test = decrypt(cipher_text, Key_bin)
    sys.stdout = sys.__stdout__

    if plain_test == plain_text:
        print(' \t\t SUCCESS! KEY FOUND = ' + Key_hex + ' = ' + Key_bin + ' = ' + str(Key))


def BF(x):
    list = []
    for i in range(2 ** 10):
        list.append(i)

    print('\n' + '*' * 80)

    if x == 'S':
        print('\n \t\t     SERIAL BRUTE FORCE ATTACK INITIATED \n\n')
        start = timer()
        for l in list:
            SearchAndDestroy(l)

    if x == 'P':
        print('\n \t\t     PARALLEL BRUTE FORCE ATTACK INITIATED \n\n')
        start = timer()
        pool = ThreadPool(10)
        pool.map(SearchAndDestroy, list)
        pool.close()
        pool.join()

    end = timer()
    print('\n\n \t\t\t ELAPSED TIME =', round((end - start), 3), 'Seconds')

    print('\n' + '*' * 80)


if __name__ == '__main__':
    plain_text = decrypt(cipher_text, key)
    BF('S')
    BF('P')


## References
# https://www.rapidtables.com/convert/number/binary-to-hex.html
# https://terenceli.github.io/assets/file/mimaxue/SDES.pdf
# http://homepage.smc.edu/morgan_david/vpn/assignments/assgt-sdes-encrypt-sample.htm
# https://sandilands.info/sgordon/teaching/css322y11s2/unprotected/CSS322Y11S2H01-DES-Examples.pdf
# https://www.kth.se/blogs/pdc/2019/02/parallel-programming-in-python-multiprocessing-part-1/
# And Infinite StackOverflow Pages
