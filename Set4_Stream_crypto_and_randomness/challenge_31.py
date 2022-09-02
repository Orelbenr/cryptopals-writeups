"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/31

Implement and break HMAC-SHA1 with an artificial timing leak
The psuedocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing (Sinatra, web.py, whatever),
write a tiny application that has a URL that takes a "file" argument and a "signature" argument, like so:
http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51

Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file",
using the "==" operator to compare the valid MAC for a file with the "signature" parameter
(in other words, verify the HMAC the way any normal programmer would verify it).

Write a function, call it "insecure_compare", that implements the == operation by doing byte-at-a-time comparisons
with early exit (ie, return false at the first non-matching byte).

In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).

Use your "insecure_compare" function to verify the HMACs on incoming requests,
and test that the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.

Using the timing leak in this application, write a program that discovers the valid MAC for any file.

Why artificial delays?
Early-exit string compares are probably the most common source of cryptographic timing leaks,
but they aren't especially easy to exploit.
In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python) probably aren't exploitable over
a wide-area network at all. To play with attacking real-world timing leaks,
you have to start writing low-level timing code. We're keeping things cryptographic in these challenges.
"""

import multiprocessing
import time

import numpy as np
import requests
from tqdm import tqdm


def insecure_compare(mac1: str, mac2: str, sleep_time: float) -> bool:
    for i in range(min(len(mac1), len(mac2))):
        if mac1[i] != mac2[i]:
            return False
        time.sleep(sleep_time)

    if len(mac1) != len(mac2):
        return False

    return True


class Attack:
    # Constants
    mac_len = 40  # in digits

    def __init__(self, url: str, file: bytes, num_repetitions: int):
        self.url = url
        self.file = file
        self.num_repetitions = num_repetitions

    def try_mac(self, mac: str) -> (bool, float):
        # defining a params dict for the parameters to be sent to the API
        params = {'file': self.file.decode(), 'signature': mac}

        # mean the results over number of repetitions
        time_list = np.empty(self.num_repetitions)
        for i in range(self.num_repetitions):
            # sending get request
            start = time.time()
            status_code = requests.get(url=self.url, params=params).status_code
            end = time.time()
            time_list[i] = end - start

        flag = True if status_code == 200 else False
        elapsed_time = np.mean(time_list)

        return flag, elapsed_time

    def attack(self):
        # initialize empty mac
        mac = ''
        pool = multiprocessing.Pool(1)

        for _ in tqdm(range(self.mac_len)):
            # test all 2**4 possibilities
            tests = [mac + format(num, '1x') for num in range(2**4)]
            res = pool.map(self.try_mac, tests)

            # check for success or best result
            best_time = 0
            best_num = 0
            for num in range(len(res)):
                if res[num][0]:
                    return tests[num]
                if res[num][1] > best_time:
                    best_time = res[num][1]
                    best_num = num

            # update best_num
            mac += format(best_num, '1x')
            print(f'mac = {mac}')

        raise Exception('attack failed')


def main():
    url = 'http://localhost:9000/test?'
    file = b'The quick brown fox jumps over the lazy dog'

    # find mac
    mac = Attack(file=file, url=url, num_repetitions=5).attack()
    print(f'Recovered MAC = {mac}')

    # verify result
    params = {'file': file.decode(), 'signature': mac}
    response = requests.get(url=url, params=params)
    print(f'{response.status_code=}')
    print(f'{response.content=}')


if __name__ == '__main__':
    main()
