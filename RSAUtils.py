#####################################################################################################################
# RSA 加密
#####################################################################################################################

def str_to_num(string, block_size):
    """
    对明文 ASCII 字符串进行分组转换成数字数组
    Groups plaintext ASCII strings into an array of digits

    1. 第一步，首先根据 block_size 对字符串进行分组，不够的用空格填充； First block according to the string grouping, not enough to fill with spaces;
        eg：string = "hello", block_size = 2
        =>
            "he" # "ll" # "o "
    2. 然后将所有的字符替换成对应的ASCII值；All characters are then replaced with the corresponding ASCII value;
            "h" => 104
            "e" => 101
            "l" => 108
            "o" => 111
            " " => 032
            [104101, 108108, 111032] => 这个就是返回值的形式，是一个数字数组 This is the form of the return value, which is an array of numbers
    :param string:
    :param block_size:
    :return:
    """
    result = []

    # 首先进行填充处理 Padding
    for i in range(len(string) % block_size):
        string += " "

    # 然后进行分组转换 Convert
    for i in range(0, len(string), block_size):
        value = ""
        for j in string[i: i + block_size]:
            temp = str(ord(j))
            for k in range(3 - len(temp)):
                temp = "0" + temp  # 填充为3位，例如：a => 97 => 097
            value += temp
        result.append(int(value))
    return result


def rsa_encrypt_number(number, e, n):
    """
    使用RSA公钥对一个数字进行加密Encrypts a number using the RSA public key
    :param number:
    :param e:
    :param n:
    :return:
    """

    def fast(base):
        prev = base
        for bit in bin(e)[3:]:
            if bit == '1':
                prev = ((prev ** 2) * base) % n
            else:
                prev = (prev ** 2) % n
        return prev

    return fast(number)


def get_max_block_size(n):
    """
    计算分组的大小
    计算原则如下：
        假设鲍勃要向爱丽丝发送加密信息m，他就要用爱丽丝的公钥 (n,e) 对m进行加密。这里需要注意，m必须是整数，且m必须小于n。
        => 所以只要保证得到的字符串分组转成的数字比n小就行
        => 比如："he" => 104101
    Calculate the size of the packet
    The calculation principles are as follows:
        Suppose that Bob wants to send Elise an encrypted message M which he encrypts with Elise’s public key (n, e) . Note here that m must be an integer and m must be less than n.
        = > so just make sure that the resulting string is grouped into smaller numbers than N
        = > eg: he = > 104101
    :param n:
    :return:
    """
    # 首先得到所有字母中ASCII最大的值 get the maximum ASCII value of all the letters
    baseNum = ord("z")
    result = 0
    while baseNum < n:
        result += 1
        baseNum = baseNum * 1000 + baseNum
    return result


def rsa_encrypt(plain_text, e, n, block_size):
    """
    Encrypt a plain_text, and indicate block_size => 对一串字符串使用RSA进行非对称加密 Using RSA to public-key cryptography a string

    （对于RSA做非对称加密，通常是使用公钥加密，然后用私钥解密）=> RSA 用于非对称加解密，用公钥加密，私钥解密

    （虽然也可以用私钥加密，公钥解密，但是公钥是公开的，所以私钥加密的内容，所有人都可以解密，所以通常用私钥加密作为签名，然后公钥去验证签名）
    :param plain_text: eg.=> "hello world"
    :param e: (e, n) => Public Key
    :param n: (e, n) => Public Key
    :param block_size: 分组大小，几个字符为一组。例如：
                        block_size = 1 => 则，"hello" 加密时分成五组，"h" # "e" # "l" # "l" # "o"
                        block_size = 2 => 则，"hello" 加密时分成三组，"he" # "ll" # "o "

                        PS: 需要注意的是，block_size 不为1的情况下，如果输入的明文不能整除时，填充若干个空格。
    :return:
    """
    result = []
    for number in str_to_num(plain_text, block_size):
        result.append(str(rsa_encrypt_number(number, e, n)))
    return " # ".join(result)


#####################################################################################################################
# RSA decryption 解密
#####################################################################################################################

def num_to_str(num):
    """
    数字转字符串 number to string
    :param num:
    :return:
    """
    num_str = str(num)
    # 填充为3的倍数，例如：97102 => 097102
    for k in range(3 - len(num_str) % 3):
        num_str = "0" + num_str

    # 然后每3个字符转成数字，按 ASCII 表转换为字符，例如：097102 => 097, 102 => a, f => "af"
    #Each three characters converts to a number, using the ASCII table, eg:097102 => 097, 102 => a, f => "af"
    result = ""
    for i in range(0, len(num_str), 3):
        result += chr(int(num_str[i: i + 3]))
    return result


def rsa_decrypt_number(number, d, n):
    """
    使用RSA私钥对一个数字进行解密 Decrypts a number using the RSA private key
    :param number:
    :param d:
    :param n:
    :return:
    """
    def fast(base):
        prev = base
        for bit in bin(d)[3:]:
            if bit == '1':
                prev = ((prev ** 2) * base) % n
            else:
                prev = (prev ** 2) % n
        return prev

    return fast(number)


def rsa_decrypt(encoded_text, d, n):
    """
    对加密后的加密字符串进行解密: Decrypts the ciphertxt after encryption
    :param encoded_text: eg：548828 # 485875 # 327452
    :param d:
    :param n:
    :return:
    """
    result = ""
    numbers = encoded_text.split(" # ")
    for number in numbers:
        result += num_to_str(rsa_decrypt_number(int(number), d, n))
    return result
