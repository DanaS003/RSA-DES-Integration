import random


# Function to calculate the GCD (Greatest Common Divisor) using Euclid's algorithm
def calculate_gcd(num1, num2):
    while num2 != 0:
        num1, num2 = num2, num1 % num2
    return num1


# Function to check if a number is prime
def is_prime_number(number):
    if number == 2:
        return True
    if number < 2 or number % 2 == 0:
        return False
    for divisor in range(3, int(number**0.5) + 2, 2):
        if number % divisor == 0:
            return False
    return True


# Function to generate a random prime number within a range
def generate_random_prime(min_value, max_value):
    prime_candidate = random.randint(min_value, max_value)
    while not is_prime_number(prime_candidate):
        prime_candidate = random.randint(min_value, max_value)
    return prime_candidate


# Function to find the modular multiplicative inverse using the Extended Euclidean Algorithm
def find_modular_inverse(e, totient):
    modular_inverse = 0
    x1, x2 = 0, 1
    y1 = 1
    temp_totient = totient

    while e > 0:
        quotient = temp_totient // e
        remainder = temp_totient - quotient * e
        temp_totient, e = e, remainder

        x = x2 - quotient * x1
        y = modular_inverse - quotient * y1

        x2, x1 = x1, x
        modular_inverse, y1 = y1, y

    if temp_totient == 1:
        return modular_inverse + totient


# Function to generate a key pair (public and private keys) using two prime numbers p and q
def generate_key_pair(prime1, prime2):
    if not (is_prime_number(prime1) and is_prime_number(prime2)):
        raise ValueError("Both numbers must be prime.")
    if prime1 == prime2:
        raise ValueError("The two primes must be distinct.")

    # Calculate n (modulus for both keys)
    modulus = prime1 * prime2

    # Calculate totient (φ(n)) = (p-1) * (q-1)
    totient = (prime1 - 1) * (prime2 - 1)

    # Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = random.randrange(1, totient)
    while calculate_gcd(e, totient) != 1:
        e = random.randrange(1, totient)

    # Calculate the modular inverse of e
    d = find_modular_inverse(e, totient)

    # Public key (e, n) and private key (d, n)
    return ((e, modulus), (d, modulus))


# Helper function to parse a key from a string representation
def parse_key(key_string):
    key, modulus = map(int, key_string.strip("()").split(", "))
    return key, modulus


# Function to encrypt plaintext using a public key
def encrypt_message(plaintext, public_key):
    # Parse the public key
    key, modulus = parse_key(public_key)
    
    # Encrypt each character in the plaintext using (char^key) mod modulus
    ciphertext = [pow(ord(char), key, modulus) for char in plaintext]
    
    return ciphertext


# Function to decrypt ciphertext using a private key
def decrypt_message(ciphertext, private_key):
    # Parse the private key
    key, modulus = parse_key(private_key)
    
    # Decrypt each number in the ciphertext using (num^key) mod modulus
    decrypted_chars = [chr(pow(num, key, modulus)) for num in ciphertext]
    
    # Convert the decrypted characters into a string
    return ''.join(decrypted_chars)
