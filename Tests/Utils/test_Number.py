import unittest

from Utils.Number import integer_division_ceil
from Utils.Number import chinese_remainder


class TestIntegerDivisionCeil(unittest.TestCase):
    def test_division(self):
        big_num = 9872348765785678657865876587658776578675876587686585865876587658765675775675776857857587658678
        res = integer_division_ceil(big_num*5-1, 5)
        self.assertEqual(big_num, res)


class TestChineseRemainder(unittest.TestCase):
    def test_thm(self):
        x = 1192013
        n_list = [2, 3, 5, 7, 13, 19, 23]
        a_list = [x % ni for ni in n_list]
        x_est = chinese_remainder(n_list, a_list)
        self.assertEqual(x_est, x)


if __name__ == '__main__':
    unittest.main()
