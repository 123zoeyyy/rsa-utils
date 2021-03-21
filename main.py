from RSAUtils import rsa_decrypt, rsa_encrypt, get_max_block_size

if __name__ == '__main__':
    # 使用示例
    plain_text = "hello world!"
    n = 603241          # p = 719, q = 839
    e = 2**16 + 1
    d = 459069

    # 测试加密
    encoded_text = rsa_encrypt(plain_text, e, n, get_max_block_size(n))

    # 输出：encoded_text:  116507 # 171059 # 547248 # 410930 # 465355 # 16695
    print("encoded_text: ", encoded_text)

    # 测试解密
    # 输出：decrypt result:  hello world!
    print("decrypt result: ", rsa_decrypt(encoded_text, d, n))