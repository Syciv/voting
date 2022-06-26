import os
from random import *
import json
import uuid


from Crypto.Cipher import AES


class Voter:
    m = None

    def __init__(self, num, vote):
        self.num = num
        self.vote = vote
        self.key = os.urandom(32)

    def set_m(self, m):
        self.m = m

    def get_m_and_vote(self):
        msg = bytes(json.dumps({'m': self.m, 'b': self.vote}), 'UTF-8')
        aes_cipher = AES.new(self.key, AES.MODE_GCM)
        cipher_text, auth_tag = aes_cipher.encrypt_and_digest(msg)
        return self.m, (cipher_text, aes_cipher.nonce, auth_tag)

    def get_key(self):
        return self.key

    def get_m(self):
        return self.m

    def get_vote(self):
        return self.vote

    def get_info(self):
        return self.num, self.m, self.vote


class Registrator:
    m_list = []
    voters = []

    def generate_m(self):
        m = uuid.uuid4().hex
        self.m_list.append(m)
        return m

    def add_voter(self, voter):
        return self.voters.append(voter)

    def get_m_list(self):
        return self.m_list

    def get_voters(self):
        return self.voters


class Counter:
    encrypted_records = dict()
    decrypted_records = dict()
    m_list = []
    results = dict()

    def add_encrypted_record(self, m, b):
        self.encrypted_records[m] = b

    def decrypt_record(self, m, key):
        (ciphertext, nonce, authTag) = self.encrypted_records[m]
        aes_cipher = AES.new(key, AES.MODE_GCM, nonce)
        result = aes_cipher.decrypt_and_verify(ciphertext, authTag)
        self.decrypted_records[m] = result

    def calculate_votes(self):
        self.results = dict()
        for key, value in self.decrypted_records.items():
            record = json.loads(value.decode("utf-8"))
            m = record['m']
            b = record['b']
            if b in self.results:
                self.results[b] += 1
            else:
                self.results[b] = 1

        return self.results

    def show(self):
        print(self.encrypted_records)
        print(self.decrypted_records)


if __name__ == '__main__':
    voters = []
    voters_num = 15
    registrator = Registrator()
    counter = Counter()

    for i in range(voters_num):
        registrator.add_voter(i)

    print(f'ID голосующих : {registrator.get_voters()}')

    for i in range(voters_num):
        v = Voter(i, randint(1, 5))
        v.set_m(registrator.generate_m())
        voters.append(v)
        vote = v.get_m_and_vote()
        counter.add_encrypted_record(vote[0], vote[1])

    for v in voters:
        counter.decrypt_record(v.get_m(), v.get_key())

    check = dict()
    print('Голосующие:')
    for v in voters:
        info = v.get_info()
        print(f'ID:{info[0]} M:{info[1]} Кандидат: {info[2]}')
        if info[2] in check:
            check[info[2]] += 1
        else:
            check[info[2]] = 1

    calc = counter.calculate_votes()
    for i in calc:
        print(f'Кандидат {i} - {calc[i]}')

    print('Проверка:')
    for i in check:
        print(f'Кандидат {i} - {check[i]}')
