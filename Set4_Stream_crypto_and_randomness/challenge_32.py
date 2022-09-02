"""
Orel Ben-Reuven
https://cryptopals.com/sets/4/challenges/32

Break HMAC-SHA1 with a slightly less artificial timing leak
Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)

Now break it again.
"""

import multiprocessing
import time
import requests

import numpy as np
from tqdm import tqdm


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

        # sending get request
        start = time.time()
        status_code = requests.get(url=self.url, params=params).status_code
        end = time.time()

        flag = True if status_code == 200 else False
        elapsed_time = end - start

        return elapsed_time

    def attack(self):
        # initialize empty mac
        mac = ''
        pool = multiprocessing.Pool(60)
        num_iterations = 2 ** 4

        for _ in tqdm(range(self.mac_len)):
            # test all 2**4 possibilities
            tests = (mac + format(num, '1x') for _ in range(self.num_repetitions) for num in range(num_iterations))
            times = pool.map(self.try_mac, tests)

            # mean the time over the repetitions
            times = np.array([np.mean(times[i:num_iterations:]) for i in range(num_iterations)])

            # find best num
            best_num = np.argmax(times)

            # update mac based on best_num
            mac += format(best_num, '1x')
            print(f'mac = {mac}')

        raise Exception('attack failed')


def main():
    url = 'http://localhost:9000/test?'
    file = b'The quick brown fox jumps over the lazy dog'

    # find mac
    mac = Attack(file=file, url=url, num_repetitions=10).attack()
    print(f'Recovered MAC = {mac}')

    # verify result
    params = {'file': file.decode(), 'signature': mac}
    response = requests.get(url=url, params=params)
    print(f'{response.status_code=}')
    print(f'{response.content=}')


if __name__ == '__main__':
    main()
