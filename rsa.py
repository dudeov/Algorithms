
class RSA:
    def __init__(self, p, q):
        self.phi = (p - 1) * (q - 1)
        self.n = p*q
        self.e = RSA.find_e(self.phi)
        self.d = self.find_d(self.e, self.phi, self.n)
        self.public_key = self.e, self.n
        self.private_key = self.d, self.n
        print(f"Private key is: '{self.private_key}'")
        print(f"Public key is : '{self.public_key}'")

    @staticmethod
    def find_d(e, phi, n) -> int:
        """
        Brute force algorithm: d*e % phi == 1, where d < n
        """
        d = 1
        while d < n:
            if d*e % phi == 1:
                return d
            d += 1

    class Decorators:
        @staticmethod
        def args_to_int(decorated):
            def worker(self, message):
                if type(message) is str:
                    temp_l = []
                    for char in message:
                        # ord(char) returns a Unicode position of the char, for example, "HI": H -> 72, I -> 73
                        temp_l.append(str(ord(char)))
                    # for "Hi" it would return 7273
                    new_message = int("".join(temp_l))
                else:
                    try:
                        new_message = int(message)
                    except Exception as e:
                        raise Exception("Message is not integer or string")
                return decorated(self, new_message)
            return worker

    @staticmethod
    def find_e(phi):
        e = 2
        while e < phi:
            if RSA.gcd(e, phi) == 1:
                return e
            else:
                e += 1

    # Euclid algorithm
    @staticmethod
    def gcd(divisor, dividend):
        quotient = divisor // dividend  ## not used
        remainder = divisor % dividend
        if remainder == 0:
            return dividend
        return RSA.gcd(dividend, remainder)

    @Decorators.args_to_int
    def create_signature(self, message):
        signature = (message**self.e) % self.n
        print(f"Signature for '{message}' has been created: {signature}")
        return signature

    def check_signature(self, signature):
        message = signature**self.d % self.n
        print(f"Signature '{signature}' is decrypted to '{message}'")
        return message

def main():
    """
    Private key is: '(191, 462)'
    Public key is : '(11, 462)'
    Signature for '150' has been created: 348
    Signature '348' is decrypted to '150'
    """
    rsa_worker = RSA(21,22)
    s = 150
    e = rsa_worker.create_signature(s)
    d = rsa_worker.check_signature(e)

