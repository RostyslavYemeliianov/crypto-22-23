import random
import math

# Клас RSA

class RSA:
    def __init__(self):
        self.gen_keys = self.generete_key()
        self.p, self.q, self.p_1, self.q_1 = self.gen_keys[0], self.gen_keys[1], self.gen_keys[2], self.gen_keys[3]
        self.rsa_keys_a = self.rsa_key_pair(self.p, self.q)
        self.e, self.n, self.d = self.rsa_keys_a[0], self.rsa_keys_a[1], self.rsa_keys_a[2]
        self.rsa_keys_b = self.rsa_key_pair(self.p_1, self.q_1)
        self.e_1, self.n_1, self.d_1 = self.rsa_keys_b[0], self.rsa_keys_b[1], self.rsa_keys_b[2]
        self.message = random.randint(0, self.n)
        self.start_key = random.randint(0, self.n)
    def generete_key(self):
        while True:
            keys = []
            for _ in range(4):
                key = self.primary()
                keys.append(key)
            if keys[0] * keys[1] < keys[2] * keys[3]:
                return keys
    def miller_test(self, num, k=8):
        if num == 2 or num == 3:
            return True
        if num % 2 == 0:
            return False
        r, s = 0, num - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, num - 1)
            x = pow(a, s, num)
            if x == 1 or x == num - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, num)
                if x == num - 1:
                    break
            else:
                return False
        return True

    def primary(self):
        bits = 256
        while True:
            prim_number = (random.randrange(2 ** (bits - 1), 2 ** bits))
            if not self.miller_test(prim_number):
                # print(f"{prim_number}")
                pass
            else:
                return prim_number

    def evclid_extended(self, first_number, second_number):
        if first_number == 0:
            return second_number, 0, 1
        else:
            div, koef_x, koef_y = self.evclid_extended(second_number % first_number, first_number)
        return div, koef_y - (second_number // first_number) * koef_x, koef_x

    def mod_inverse(self, first_number, second_number):
        return list(self.evclid_extended(first_number, second_number))[1]

    def rsa_key_pair(self, first_key, second_key):
        res = []
        n = first_key * second_key
        oiler = (first_key - 1) * (second_key - 1)
        e = random.randrange(2, oiler - 1)
        while math.gcd(e, oiler) != 1:
            e = random.randrange(2, oiler - 1)
        d = self.mod_inverse(e, oiler) % oiler
        res.append(d)
        res.append(n)
        res.append(e)
        return res

    def encrypting(self, m, e, n):
        return pow(m, e, n)

    def decryption(self, c, d, n):
        return pow(c, d, n)

    def digital_sign(self, m, d, n):
        return pow(m, d, n)

    def sign_check(self, m, s, e, n):
        return m == pow(s, e, n)

    def key_send(self, k, d, e_1, n_1, n):
        k_1 = self.encrypting(k, e_1, n_1)
        s = self.digital_sign(k, d, n)
        s_1 = self.encrypting(s, e_1, n_1)
        return k_1, s_1

    def key_receiving(self, key_1, s_1, d_1, n_1, e, n):
        key = self.decryption(key_1, d_1, n_1)
        s = self.decryption(s_1, d_1, n_1)
        if self.sign_check(key, s, e, n):
            return True, key
        else:
            return False, 0

    def set_test_custom(self, m, s, e, n):
        self.m = int(m, 16)
        self.s = int(s, 16)
        self.e = int(e, 16)
        self.n = int(n, 16)

    def test_case(self):
        print(f'n: {self.n}')
        print(f'e: {self.e}')
        print(f'mes: {self.m}')
        print(f'Ciphertext: {hex(self.encrypting(self.m, self.e, self.n))}')
        print(f'sign: {self.s}')
        if self.m == pow(self.s, self.e, self.n):
            print('Passed!')
        else:
            print('Failed!')
        return self.m == pow(self.s, self.e, self.n)


rsa_test = RSA()

print("\nКлючі  А ")
print(f'e: {rsa_test.e}\nn: {rsa_test.n}\nd: {rsa_test.d}\np: {rsa_test.p}\nq: {rsa_test.q}\n')

print(" Ключі  B ")
print(f'e_1: {rsa_test.e_1}\nn_1: {rsa_test.n_1}\nd_1: {rsa_test.d_1}\np_1: {rsa_test.p_1}\nq_1: {rsa_test.q_1}\n')
print(f'Start k: {rsa_test.start_key}\nMessage: {rsa_test.message}\n')

encrypted_key, dig_sign = rsa_test.key_send(rsa_test.start_key, rsa_test.d, rsa_test.e_1, rsa_test.n_1, rsa_test.n)
encrypted_msg = rsa_test.encrypting(rsa_test.message, rsa_test.e, rsa_test.n)
received_key = rsa_test.key_receiving(encrypted_key, dig_sign, rsa_test.d_1, rsa_test.n_1, rsa_test.e, rsa_test.n)
decrypted_msg = rsa_test.decryption(encrypted_msg, rsa_test.d, rsa_test.n)

if received_key[0]:
    print(f'The key has been received: {received_key[1]}\n')
if not received_key[0]:
    print('Error getting the key')
print(f"Encrypted message: {encrypted_msg}\nDecrypted: message: {decrypted_msg}")

rsa_test.set_test_custom(
    "C32",
    "59FEFB74834333B39449082D48CFA5F930F463E26AE86079B8BDD124AADC1855",
    "10001",
    "801073D97D3D40CA083CAB93E2AF4F7FC6FDE8C3F4F7886D34F5D526FF12C06D"
    )
rsa_test.test_case()
